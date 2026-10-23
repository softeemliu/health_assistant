"""
health_assistant.checks.security — 安全与账号类巡检项

包含: ftp.discovery / account.inventory

密码显示规则：
  · 默认显示明文（config["reveal"]=True）。这些条目本来就是本机当前用户
    自己能读到的（凭据管理器 CredRead / FileZilla Base64 / WinSCP DPAPI /
    资源管理器保存的网络位置密码），不涉及任何提权或绕过。
  · 需要打码或把报告外发时，命令行加 --mask。
  · 浏览器 v20 应用绑定加密不做还原，并在结论里说明替代路径。
"""

from __future__ import annotations

from .. import credentials, metrics
from ..core import Result, Severity, check, short_path

__all__ = ["ftp_discovery", "account_inventory"]

from ..credentials import ABE_MARK, MASK

FTP_PORT_LABEL = {21: "FTP", 2121: "FTP-alt", 990: "FTPS"}


def _clip(s, n):
    s = str(s)
    return s if len(s) <= n else s[:n - 1] + "…"


def _pw_cell(row, width=72):
    """密码单元格：v20 显示明确标记，不显示星号（星号会被误读成「工具在遮罩」）。"""
    state = row.get("pw_state")
    if state == "v20":
        return ABE_MARK
    if state == "fail":
        return "⟨解不开⟩"
    if state == "masked":
        return MASK
    return _clip(row.get("password") or "", width)


@check("ftp.discovery", "FTP 巡检", group="security", order=10,
       desc="本机 FTP 服务端 + 所有已保存的 FTP 连接（多客户端，密码默认明文）")
def ftp_discovery(ctx):
    res = Result()
    reveal = bool(ctx.config.get("reveal"))
    ports = set(ctx.config.get("ftp_ports", [21, 2121, 990]))

    # ---- 服务端：监听端口 ----
    listeners = [r for r in metrics.net_listeners() if r["port"] in ports]
    if listeners:
        res.text("本机 FTP 服务端")
        res.table(["端口", "PID", "进程", "绑定地址", "启动参数"],
                  [[r["port"], r["pid"], r["name"][:22],
                    "全部网卡" if r["ip"] in ("0.0.0.0", "::") else r["ip"],
                    (r.get("cmdline") or r.get("exe") or "-")[:48]]
                   for r in listeners],
                  ["r", "r", "l", "l", "l"])
        res.add(Severity.INFO, f"发现 {len(listeners)} 个 FTP 端口在监听")
    else:
        res.kv([("FTP 服务端", f"未发现监听 {sorted(ports)} 的进程")])

    # ---- 服务端：Windows 服务 ----
    ftp_svcs = [s for s in metrics.service_list()
                if "ftp" in f"{s[0]} {s[1]}".lower() or "filezilla" in f"{s[0]} {s[1]}".lower()]
    if ftp_svcs:
        res.text("FTP 相关服务")
        res.table(["服务名", "显示名", "状态"],
                  [[n[:22], d[:36], st] for n, d, st, _s in ftp_svcs],
                  ["l", "l", "l"])

    # ---- 客户端 / 系统里已保存的 FTP 与网络位置（全渠道） ----
    sites, errors = credentials.ftp_sites_all(reveal=reveal)
    if sites:
        headers = ["来源", "方式", "主机 / 目标", "用户名"]
        aligns = ["l", "l", "l", "l"]
        if reveal:
            headers += ["密码", "备注"]
            aligns += ["l", "l"]
        else:
            headers += ["密码"]
            aligns += ["l"]
        rows = []
        for s in sites:
            kind = s.get("protocol") or "ftp"
            kind_desc = {"ftp": "FTP", "smb": "SMB", "webdav": "WebDAV",
                         "cred": "凭据", "ftp-url": "ftp://", "credential": "凭据"}.get(kind, kind)
            row = [s["client"][:12], f"{kind_desc}/{s.get('src', '')}"[:18],
                   str(s["host"])[:40], str(s["user"])[:20]]
            row.append(str(s.get("password") or "无"))
            if reveal:
                row.append(str(s.get("pw_note") or "")[:24])
            rows.append(row)
        res.text("已保存的 FTP 连接与网络位置")
        res.table(headers, rows, aligns)
        if not reveal:
            res.text("  密码已遮罩（--mask 生效）；去掉 --mask 即显示明文")

        details = [s for s in sites if s.get("detail")]
        if details:
            res.text("来源明细")
            res.text("\n".join(f"  · {d['client']}/{d.get('src', '')}: {d['detail'][:96]}"
                               for d in details[:10]))
        res.add(Severity.INFO, f"发现 {len(sites)} 条已保存的 FTP / 网络位置")
    else:
        # 没找到也要讲清楚查了哪些地方，避免"静默无输出"
        res.text("未发现已保存的 FTP 连接或网络位置。已检查的位置：")
        rows = []
        for label, path, exist in credentials.ftp_scan_targets():
            state = "存在" if exist else ("未安装/无此项" if exist is False else "见上表")
            rows.append([label[:14], state, short_path(path, 50)])
        res.table(["项目", "状态", "检查位置"], rows, ["l", "l", "l"])
        res.text("  说明：本机未安装 FTP 客户端、也没映射过网络驱动器时，"
                 "确实没有可读取的连接数据。\n"
                 "  在资源管理器地址栏敲 \\\\192.168.x.x 的连接，凭据会存在「凭据管理器」，"
                 "可在 accounts 检查里看到。")

        # 按文件名再寻迹一遍：便携版 / 装在非标准目录 / 数据目录改了名
        try:
            traces = credentials.ftp_trace()
        except Exception:
            traces = []
        if traces:
            res.text("按文件名寻迹到的客户端数据文件（可能是便携版或非标准安装）")
            res.table(["类型", "大小", "修改日期", "文件"],
                      [[t["kind"], f"{t['size']}B", t["mtime"], short_path(t["path"], 46)]
                       for t in traces],
                      ["l", "r", "l", "l"])
            res.add(Severity.INFO, f"寻迹到 {len(traces)} 个 FTP 客户端数据文件")

    # ---- 凭据管理器里的 FTP 条目 ----
    try:
        ftp_creds = [c for c in credentials.cred_enum(reveal=reveal)
                     if "ftp" in (c["target"] or "").lower()]
    except Exception:
        ftp_creds = []
    if ftp_creds:
        res.text("Windows 凭据管理器中的 FTP 条目")
        headers = ["凭据目标", "用户名", "类型"] + (["密码"] if reveal else [])
        rows = []
        for c in ftp_creds:
            row = [c["target"][:40], (c["user"] or "-")[:20], c["type_name"]]
            if reveal:
                row.append(c.get("password", "") or "")
            rows.append(row)
        res.table(headers, rows, ["l", "l", "l"] + (["l"] if reveal else []))

    if errors:
        for e in errors:
            res.add(Severity.WARN, f"部分渠道读取失败: {e}")

    if not (listeners or ftp_svcs or sites or ftp_creds):
        res.add(Severity.OK, "本机无 FTP 服务端，也没有已保存的 FTP 连接")

    res.metrics.update({"ftp_listeners": len(listeners), "ftp_sites": len(sites)})
    return res


@check("account.inventory", "账号清单", group="security", order=20,
       desc="Windows 凭据管理器 + 浏览器已保存登录（密码默认明文，--mask 遮罩）")
def account_inventory(ctx):
    res = Result()
    reveal = bool(ctx.config.get("reveal"))

    # ---- Windows 凭据管理器 ----
    try:
        creds = credentials.cred_enum(reveal=reveal)
    except Exception as exc:
        creds = []
        res.add(Severity.WARN, f"枚举 Windows 凭据失败: {exc}")

    if creds:
        res.text("Windows 凭据管理器")
        headers = ["凭据目标", "用户名", "类型", "持久化", "最后写入"]
        aligns = ["l", "l", "l", "l", "l"]
        if reveal:
            headers.append("密码")
            aligns.append("l")
        rows = []
        for c in creds:
            row = [c["target"][:38], (c["user"] or "-")[:20], c["type_name"],
                   c["persist"], c["last"]]
            if reveal:
                row.append(_clip(str(c.get("password") or ""), 72))
            rows.append(row)
        res.table(headers, rows, aligns)
        res.kv([("凭据条数", len(creds))])
        if reveal:
            notes = [c for c in creds if c.get("pw_note")]
            for c in notes[:4]:
                res.text(f"  · {c['target'][:44]}：{c['pw_note']}")
        else:
            res.text("  密码已遮罩（--mask 生效）；去掉 --mask 即显示明文")
    else:
        res.kv([("Windows 凭据", "无条目")])

    # ---- 浏览器 ----
    logins = credentials.browser_logins(reveal=reveal)
    if logins:
        res.text("浏览器已保存登录")
        headers = ["浏览器", "配置", "站点", "用户名", "密码"]
        aligns = ["l", "l", "l", "l", "l"]
        if reveal:
            headers.append("备注")
            aligns.append("l")
        rows = []
        for r in logins:
            row = [r["browser"], r["profile"][:11], r["origin"][:34],
                   (r["user"] or "-")[:20], _pw_cell(r)]
            if reveal:
                row.append(str(r.get("pw_note") or "")[:24])
            rows.append(row)
        res.table(headers, rows, aligns)
        res.kv([("登录条目", f"{len(logins)} 条")])

        blocked = [r for r in logins if r.get("pw_state") == "v20"]
        imported = sum(1 for r in logins if "来自导出CSV" in str(r.get("pw_note")))
        if imported:
            res.text(f"  其中 {imported} 条明文来自浏览器导出的 CSV（缓存: "
                     f"{short_path(credentials.IMPORT_CACHE, 46)}）")
        if blocked:
            res.text(
                f"  {len(blocked)} 条显示为 {ABE_MARK}：v20 应用绑定加密，密钥只在 SYSTEM 权限的"
                "提权服务里，Chrome 以外的进程解不开（本机安全策略也封了拿 SYSTEM 的通道）。\n"
                "  取明文只需一次导出，之后本工具自动补齐，不用再敲命令：\n"
                "    chrome://password-manager/settings → 导出密码 → 确认一次 Windows 登录\n"
                f"  导出文件落在下载目录后，本工具自动发现并直接用（也可显式并入: "
                f"import-passwords --auto）")
            res.add(Severity.INFO, f"{len(blocked)} 条浏览器密码为 v20 应用绑定加密，需用浏览器一次性导出")
    else:
        res.kv([("浏览器登录", "未发现（或浏览器运行中导致读取失败）")])

    if creds or logins:
        res.add(Severity.INFO,
                f"{len(creds)} 条凭据 / {len(logins)} 条浏览器登录；"
                f"维护用 accounts 子命令组")

    res.metrics.update({"credentials": len(creds), "browser_logins": len(logins),
                        "browser_v20": sum(1 for r in logins
                                           if r.get("pw_state") == "v20")})
    return res
