"""
health_assistant.checks.network — 网络类巡检项

包含: network.connectivity / network.ports
"""

from __future__ import annotations

import socket

from .. import metrics
from ..core import Result, Severity, check, cli_cmd

__all__ = ["network_connectivity", "network_ports"]

KNOWN_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP", 135: "RPC", 139: "NetBIOS",
    443: "HTTPS", 445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-alt", 8888: "HTTP-alt",
    27017: "MongoDB",
}

# 命名管道之外，这些端口暴露在 0.0.0.0 时值得提醒
SENSITIVE = {21, 23, 445, 1433, 3306, 3389, 5432, 6379, 27017}

# 数据库 / 缓存 / 管理端点：绑在全部网卡基本等于「把库交出去」，能直接给防火墙命令
DB_PORTS = {1433: "SQL Server", 3306: "MySQL",
            5432: "PostgreSQL", 6379: "Redis", 9200: "Elasticsearch",
            27017: "MongoDB"}

# 远程桌面单独处理：很多人就是靠它连这台机器，一条 block 规则会把自己的入口关掉
RDP_PORT = 3389

# 系统必需端口：绝不建议关闭（关了共享/打印/域登录就废了）
SYS_KEEP_PORTS = {135, 139, 445}


def _proxy_setting():
    try:
        import winreg
        out = {}
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as k:
            for name in ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL"):
                try:
                    out[name] = winreg.QueryValueEx(k, name)[0]
                except FileNotFoundError:
                    pass
        return out
    except Exception:
        return {}


@check("network.connectivity", "网络连通性", group="network", order=10,
       desc="网卡/网关/DNS/代理/ping/DNS解析/TCP握手")
def network_connectivity(ctx):
    res = Result()
    gw_dns = metrics.adapter_gw_dns()

    # ---- 网卡 ----
    if metrics.HAS_PSUTIL:
        try:
            addrs = metrics.psutil.net_if_addrs()
            stats = metrics.psutil.net_if_stats()
        except Exception:
            addrs, stats = {}, {}

        up = [n for n, s in stats.items() if s.isup]
        res.kv([("活动网卡", f"{len(up)}/{len(stats)}  ({', '.join(up[:6])}"
                            f"{'...' if len(up) > 6 else ''})")])

        nic_rows = []
        primary = None
        for nic, lst in addrs.items():
            st = stats.get(nic)
            if not (st and st.isup) or nic.lower().startswith("loopback"):
                continue
            v4 = [a.address for a in lst if a.family == socket.AF_INET]
            extra = gw_dns.get(nic, {})
            nic_rows.append([
                nic,
                ", ".join(v4) or "-",
                ", ".join(extra.get("gateway", [])) or "-",
                ", ".join(extra.get("dns", [])) or "-",
                f"{st.speed}Mbps" if st.speed else "-",
            ])
            if v4 and primary is None:
                primary = extra.get("gateway", [None])[0]
        res.table(["网卡", "IPv4", "网关", "DNS", "速率"], nic_rows,
                  ["l", "l", "l", "l", "r"])
        if not nic_rows:
            res.add(Severity.ERROR, "没有处于 UP 状态的网卡（未联网）")
    else:
        primary = None
        res.add(Severity.INFO, "psutil 缺失，跳过网卡明细")

    # ---- 代理 ----
    px = _proxy_setting()
    if px.get("ProxyEnable"):
        res.add(Severity.WARN, f"系统代理已启用：{px.get('ProxyServer', '(未指定)')}")
    else:
        res.add(Severity.OK, "系统代理未启用")
    if px.get("AutoConfigURL"):
        res.kv([("PAC 脚本", str(px["AutoConfigURL"]))])

    # ---- 连通性 ----
    ok_cnt = 0
    rows = []
    targets = []
    if primary:
        targets.append(("默认网关", primary))
    for t in ctx.net("ping_targets", ["223.5.5.5", "8.8.8.8"]):
        targets.append((t, t))

    for label, host in targets:
        r = metrics.ping(host)
        ok_cnt += 1 if r["ok"] else 0
        rows.append(["ping", label, "通" if r["ok"] else "不通",
                     f"{r['avg']:.0f}ms" if r["avg"] is not None else "-"])

    for host in ctx.net("dns_targets", ["www.baidu.com", "www.qq.com"]):
        r = metrics.dns_resolve(host)
        rows.append(["DNS", host, "OK" if r["ok"] else "失败",
                     f"{r['ms']:.0f}ms" if r["ok"] else r.get("err", "")[:24]])

    for pair in ctx.net("tcp_targets", [["223.5.5.5", 443]]):
        try:
            host, port = pair[0], int(pair[1])
        except Exception:
            continue
        r = metrics.tcp_connect(host, port)
        rows.append(["TCP", f"{host}:{port}", "OK" if r["ok"] else "失败",
                     f"{r['ms']:.0f}ms" if r["ok"] else r.get("err", "")])

    res.table(["类型", "目标", "结果", "耗时"], rows, ["l", "l", "l", "r"])

    if ok_cnt == 0:
        res.add(Severity.ERROR, "所有 ping 目标均不通：本机可能未联网或网卡未连接")
    elif ok_cnt >= len(targets) and targets:
        res.add(Severity.OK, f"{ok_cnt}/{len(targets)} 个 ping 目标可达")

    bad_dns = [r for r in rows if r[0] == "DNS" and r[2] != "OK"]
    if bad_dns:
        res.add(Severity.WARN, f"{len(bad_dns)} 个域名解析失败，检查 DNS 配置")

    res.metrics["ping_ok"] = ok_cnt
    res.metrics["ping_total"] = len(targets)
    return res


@check("network.ports", "监听端口", group="network", order=20,
       desc="LISTEN 端口 + 对应进程/服务/启动参数，可配合 kill 子命令终止")
def network_ports(ctx):
    res = Result()
    lst = metrics.net_listeners()
    if not lst:
        return res.fail("读取端口列表失败（需要管理员权限，或 psutil 缺失）")

    pcfg = ctx.config.get("ports", {}) or {}
    top_n = int(pcfg.get("top", 40))
    det_n = int(pcfg.get("detail", 8))
    watch = set(ctx.net("watch_ports", []))

    # 同一进程同一端口常同时绑 v4/v6，合并成一行，绑定地址显示成"全部网卡"
    merged = {}
    for r in lst:
        key = (r["port"], r["pid"])
        if key in merged:
            merged[key]["ips"].append(r["ip"])
        else:
            merged[key] = dict(r, ips=[r["ip"]])
    rows_all = sorted(merged.values(), key=lambda r: (r["port"], r["name"]))

    def bind_of(r):
        ips = set(r["ips"])
        if ips & {"0.0.0.0", "::"}:
            return "全部网卡"
        if all(i in ("127.0.0.1", "::1") for i in ips):
            return "仅本机"
        return ", ".join(sorted(ips))[:28]

    def exposure(r):
        b = bind_of(r)
        if b == "全部网卡":
            return "对外"
        if b == "仅本机":
            return "本机"
        return "指定网卡"

    def clip(s, n):
        s = str(s or "-")
        return s if len(s) <= n else s[:n - 3] + "…"

    res.kv([("监听条目", f"{len(lst)} 条（合并 v4/v6 后 {len(rows_all)} 个端口/PID 组合）"),
            ("监听进程", f"{len({r['pid'] for r in rows_all})} 个")])

    rows = []
    risky = []
    for r in rows_all[:top_n]:
        svc = r.get("service") or ""
        rows.append([r["port"], bind_of(r), exposure(r), r["pid"],
                     r["name"][:22], svc[:24], clip(r.get("cmdline") or r.get("exe"), 56)])
        if exposure(r) == "对外" and (r["port"] in SENSITIVE or r["port"] in watch):
            risky.append(r)

    res.table(["端口", "绑定", "暴露", "PID", "进程", "服务", "启动参数 / 路径"], rows,
              ["r", "l", "l", "r", "l", "l", "l"])
    if len(rows_all) > top_n:
        res.text(f"... 其余 {len(rows_all) - top_n} 条已省略（--config 调 ports.top，"
                 f"或 {cli_cmd('port', '--all')} 看全量）")

    # 明细：把"对外 + 敏感"的进程完整信息摆出来，配合 kill 用
    focus = risky[:det_n] or [r for r in rows_all if r["port"] in SENSITIVE][:det_n]
    if focus:
        lines = []
        for r in focus:
            lines.append(f"  :{r['port']}  {r['name']}  PID {r['pid']}"
                         + (f"  服务 {r['service']}" if r.get("service") else ""))
            if r.get("exe"):
                lines.append(f"      路径: {r['exe']}")
            lines.append(f"      命令: {r.get('cmdline') or r.get('exe') or '-'}")
            if r["pid"] <= 4:
                lines.append("      终止: 系统核心进程（System / 内核监听），不可终止")
            else:
                short = r["name"].replace(".exe", "")
                lines.append(f"      终止: {cli_cmd('kill', r['pid'])}"
                             f"   或  {cli_cmd('kill', short, '--tree')}")
        res.text("对外暴露端口对应进程的完整信息")
        res.text("\n".join(lines))

    if risky:
        # 只给「关掉不坏事」的端口出防火墙命令。
        # 445 SMB / 135 RPC / 139 NetBIOS 是系统文件共享与远程管理必需，
        # 一旦 block 会让局域网共享、打印机、域登录全部失效，绝不能建议关闭。
        db_like = [r for r in risky if r["port"] in DB_PORTS
                   and r["port"] not in SYS_KEEP_PORTS]
        rdp_like = [r for r in risky if r["port"] == RDP_PORT]
        sys_like = [r for r in risky if r["port"] in SYS_KEEP_PORTS]
        watch_like = [r for r in risky if r["port"] in watch
                      and r["port"] != RDP_PORT
                      and r["port"] not in DB_PORTS and r["port"] not in SYS_KEEP_PORTS]

        if db_like:
            ports = ",".join(str(r["port"]) for r in db_like[:5])
            res.add(
                Severity.WARN,
                f"{len(db_like)} 个数据/服务端口对局域网开放："
                + "、".join(f"{r['port']} {DB_PORTS.get(r['port'], r['name'].replace('.exe', ''))}"
                            for r in db_like[:5]),
                impact="同网段任何人都能直连这些端口（数据库、缓存、管理端点），"
                       "弱密码等于直接敞开",
                # 说明行不加 "#"：整块粘进 cmd 时 "#" 开头的行会被当成命令报错，
                # 只把真正的命令单独占一行，用户挑着粘就行
                fix="首选：改配置只监听本机（最干净，不影响别人连你）\n"
                    "  MySQL  my.ini → bind-address = 127.0.0.1\n"
                    "  PG     postgresql.conf → listen_addresses = 'localhost'\n"
                    "  Redis  redis.conf → bind 127.0.0.1\n"
                    "次选：用防火墙挡住外部连入（管理员权限执行）\n"
                    f'netsh advfirewall firewall add rule name="health_assistant-block-db" '
                    f"dir=in action=block protocol=TCP localport={ports}\n"
                    "这条只挡外部连入，本机访问不受影响",
                gain="缩小攻击面")

        if rdp_like:
            # 不能直接给 block 命令：用户很可能正靠 RDP 连这台机器，
            # 一条规则下去会把自己的远程入口关掉，只能给「收紧」而不是「关掉」。
            res.add(Severity.WARN,
                    f"远程桌面（3389）对局域网开放：{len(rdp_like)} 个监听",
                    impact="同网段任何人看到 3389 就能试密码登录；弱口令/无口令等于把桌面交出去",
                    fix="自己要用远程桌面就别 block，改成「只允许指定来源 IP」：\n"
                        'netsh advfirewall firewall add rule name="health_assistant-rdp" dir=in action=allow '
                        'protocol=TCP localport=3389 remoteip=192.168.8.0/24\n'
                        "之前加过旧规则就先删：\n"
                        'netsh advfirewall firewall delete rule name="health_assistant-rdp"\n'
                        "不用远程桌面就关掉：系统属性 → 远程 → 取消勾选「允许远程连接到此计算机」\n"
                        "公司管控的电脑：防火墙策略可能被 IT 统一下发覆盖，改之前先问 IT",
                    gain="把远程入口收窄到可信网段")

        if sys_like:
            res.text("以下端口由系统组件监听（445 文件共享 / 135 RPC / 139 NetBIOS）——"
                     "关掉会导致局域网共享、网络打印机、域登录失效，"
                     "属于 Windows 正常工作方式，不要关："
                     + "、".join(str(r["port"]) for r in sys_like))
            res.add(Severity.INFO,
                    f"{len(sys_like)} 个系统共享端口对外监听（445/135 等，系统必需）",
                    impact="属于 Windows 正常行为，关掉反而会让共享和网络打印用不了",
                    kind="notice")

        if watch_like:
            res.add(Severity.INFO,
                    f"{len(watch_like)} 个配置里关注的自定义端口对外监听："
                    + "、".join(f"{r['port']}({r['name'].replace('.exe', '')})"
                                for r in watch_like[:6]),
                    impact="",
                    fix=f'netsh advfirewall firewall add rule name="health_assistant-block-'
                        f'{watch_like[0]["port"]}" dir=in action=block protocol=TCP '
                        f'localport={watch_like[0]["port"]}',
                    gain="按需收紧")
    else:
        res.add(Severity.OK, f"{len(rows_all)} 个监听项，无敏感端口暴露在全部网卡")

    local_only = sum(1 for r in rows_all if exposure(r) == "本机")
    if local_only:
        res.add(Severity.INFO, f"{local_only} 个端口只绑在 127.0.0.1，不对外")

    res.metrics.update({"listeners": len(lst), "listener_groups": len(rows_all),
                        "risky": len(risky), "local_only": local_only})
    return res
