"""health_assistant.netfix — 常见网络故障的诊断与修复（站在 IT 网管视角）

思路是网管的排查顺序，一层一层往下排：

    网卡/链路 → IP/网关 → DNS → 代理 → 协议栈（LSP/MTU）→ 时间/策略

每一层只回答一个问题，前一层的结论是后一层的**前提**：
网关都不通就别急着刷 DNS 缓存，DNS 解析失败但 ping IP 正常才是 DNS 的事。
所以 `diagnose()` 会先采集事实（`collect()`），再按依赖关系出结论，
而不是把一堆检查项平铺给用户自己猜。

修复分三类，只有第一类会被界面真正执行：

    safe    幂等、不改变配置：清 DNS 缓存、重新注册 DNS —— 可批量「一键修复」
    caution 会改配置或短暂断网：续租 DHCP、DNS 改回自动、重置 WinHTTP 代理、
            关掉失效的系统代理、重新启用网卡、校时 —— 逐条确认后才执行
    manual  有风险或需要人判断：netsh winsock reset / int ip reset、改 MTU、
            改防火墙、编辑 hosts —— **只给命令和步骤，绝不代跑**

公司管控机（亿格云云枢 / DataCloak 等）上，防火墙与服务策略可能是 IT 统一下发的，
文案里会明确提示「改之前先问 IT」，避免用户改完被策略覆盖还以为工具没用。
"""

from __future__ import annotations

import json
import os
import socket
import struct
import subprocess
import time

from . import metrics
from .core import is_admin, run_cmd

__all__ = ["collect", "diagnose", "run_fix", "apply_safe", "SEV_ORDER"]

SEV_ORDER = {"error": 0, "warn": 1, "info": 2, "ok": 3}

# 常见被「网络修复大师」类工具改坏 / 被挖矿样本劫持的域名
_WATCH_DOMAINS = ("baidu.com", "qq.com", "taobao.com", "weixin.qq.com",
                  "microsoft.com", "windowsupdate.com", "github.com")

# 公司管控 / DLP 客户端：出现时提示「策略可能覆盖你的改动」
_CORP_AGENTS = (
    ("云枢", ("yunshu", "egnac", "egsrv", "bzprotect", "pigeon")),
    ("DataCloak", ("datacloak", "dacsfile", "dccube")),
)


# ───────────────────────── 基础探测 ─────────────────────────

def _run(args, timeout=20):
    return run_cmd(args, timeout=timeout)


def _local_ipv4s():
    """本机所有 IPv4（不含回环），用于判断有没有地址。"""
    if not metrics.HAS_PSUTIL:
        return []
    out = []
    try:
        for nic, lst in metrics.psutil.net_if_addrs().items():
            if nic.lower().startswith(("loopback", "lo")):
                continue
            for a in lst:
                if a.family == socket.AF_INET:
                    out.append(a.address)
    except Exception:
        return []
    return out


def _nic_admin_state():
    """netsh 里每块网卡的「管理状态」：已连接 / 已断开 / 已禁用。

    psutil 只能告诉你 isup，分不清「网线拔了」和「网卡被禁用了」——
    这两种的修法完全不同，所以以 netsh 为准。
    """
    code, out = _run(["netsh", "interface", "show", "interface"], timeout=15)
    res = {}
    if code != 0:
        return res
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith(("Admin", "管理", "---", "已启用", "Enabled")):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        state = parts[0]
        name = " ".join(parts[3:])
        if "已启用" in state or "Enabled" in state:
            res[name] = "enabled"
        elif "已禁用" in state or "Disabled" in state:
            res[name] = "disabled"
        elif "已断开" in state or "Disconnected" in state:
            res[name] = "disconnected"
    return res


def _adapters():
    """活动网卡清单（名称 / IPv4 / 网关 / DNS / 状态）。"""
    gw_dns = metrics.adapter_gw_dns()
    states = _nic_admin_state()
    out = []
    if not metrics.HAS_PSUTIL:
        return out
    try:
        addrs = metrics.psutil.net_if_addrs()
        stats = metrics.psutil.net_if_stats()
    except Exception:
        return out
    for nic, lst in addrs.items():
        if nic.lower().startswith(("loopback", "lo")):
            continue
        st = stats.get(nic)
        v4 = [a.address for a in lst if a.family == socket.AF_INET]
        extra = gw_dns.get(nic, {}) or {}
        state = states.get(nic) or ("enabled" if (st and st.isup) else "disconnected")
        out.append({
            "name": nic,
            "up": bool(st and st.isup),
            "state": state,
            "ip": v4,
            "gateway": extra.get("gateway") or [],
            "dns": extra.get("dns") or [],
            "speed": st.speed if st else 0,
            "apipa": any(ip.startswith("169.254.") for ip in v4),
        })
    return out


def _primary(adapters):
    """挑主用网卡：UP + 有 IPv4 + 有网关，优先非虚拟网卡。"""
    cands = [a for a in adapters if a["up"] and a["ip"]]
    cands.sort(key=lambda a: (not a["gateway"],
                              any(k in a["name"].lower() for k in
                                  ("vmware", "virtual", "vethernet", "loopback",
                                   "tap", "tun", "wsl", "hyper-v")),
                              -a["speed"]))
    return cands[0] if cands else None


def _proxy():
    """系统代理（WinINET）+ WinHTTP 代理 + 环境变量。"""
    out = {"enable": 0, "server": "", "pac": "", "winhttp": "", "env": {}}
    try:
        import winreg
        with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as k:
            for name, key in (("ProxyEnable", "enable"), ("ProxyServer", "server"),
                              ("AutoConfigURL", "pac")):
                try:
                    out[key] = winreg.QueryValueEx(k, name)[0]
                except FileNotFoundError:
                    pass
    except Exception:
        pass
    code, txt = _run(["netsh", "winhttp", "show", "proxy"], timeout=15)
    if code == 0:
        for line in txt.splitlines():
            line = line.strip()
            if line.startswith(("代理服务器", "Proxy Server")):
                out["winhttp"] = line.split(":", 1)[-1].strip()
            elif "Direct access" in line or "直接访问" in line:
                out["winhttp"] = ""
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                "http_proxy", "https_proxy"):
        v = os.environ.get(var)
        if v:
            out["env"][var] = v
    return out


def _proxy_alive(server):
    """代理地址是否连得上：支持 host:port / http://host:port / host:80。"""
    s = str(server or "").strip()
    if not s:
        return None
    s = s.split(";")[0].strip()
    if "=" in s:                      # 形如 http=1.2.3.4:8080;https=...
        s = s.split("=", 1)[1]
    s = s.replace("http://", "").replace("https://", "").rstrip("/")
    if ":" not in s:
        s += ":80"
    host, port = s.rsplit(":", 1)
    try:
        port = int(port)
    except ValueError:
        return None
    r = metrics.tcp_connect(host, port, timeout=2.0)
    return bool(r["ok"])


def _dns_udp_query(server, name="www.baidu.com", timeout=2.0):
    """直接向指定 DNS 发一个 A 查询，验证「这台 DNS 能不能用」。

    不能用系统解析器测 —— 那个只会告诉你「解析失败」，不会告诉你是哪台 DNS 的问题。
    """
    def qname(n):
        out = b""
        for part in n.split("."):
            out += bytes([len(part)]) + part.encode("ascii", "ignore")
        return out + b"\x00"

    pkt = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
           + qname(name) + struct.pack(">HH", 1, 1))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    t0 = time.perf_counter()
    try:
        s.sendto(pkt, (server, 53))
        data, _ = s.recvfrom(512)
        ms = (time.perf_counter() - t0) * 1000
        if len(data) < 12:
            return {"ok": False, "ms": ms, "err": "应答过短"}
        rcode = data[3] & 0x0F
        if rcode == 3:
            return {"ok": False, "ms": ms, "err": "NXDOMAIN（域名不存在）"}
        if rcode != 0:
            return {"ok": False, "ms": ms, "err": f"rcode={rcode}"}
        return {"ok": True, "ms": ms}
    except socket.timeout:
        return {"ok": False, "ms": timeout * 1000, "err": "超时无应答"}
    except OSError as exc:
        return {"ok": False, "ms": (time.perf_counter() - t0) * 1000, "err": str(exc)}
    finally:
        s.close()


_NET_CLASS = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
_NET_CONN = r"SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}"


def _nic_drivers():
    """注册表里的网卡驱动清单：设备描述 / 驱动版本 / 厂商 / 对应的连接名。

    连接名（如「以太网」「WLAN」）是「网络连接」里显示的友好名，靠它才能和
    psutil 的网卡名对上号 —— 设备描述是 "Realtek Gaming 2.5GbE ..."，两者根本不是一回事。
    """
    out = []
    try:
        import winreg
    except Exception:
        return out
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _NET_CLASS) as k:
            subs = [winreg.EnumKey(k, i) for i in range(winreg.QueryInfoKey(k)[0])]
    except OSError:
        return out

    for sub in subs:
        if not sub.isdigit():
            continue
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _NET_CLASS + "\\" + sub) as k:

                def q(name):
                    try:
                        v = winreg.QueryValueEx(k, name)[0]
                        return v if isinstance(v, str) else ""
                    except FileNotFoundError:
                        return ""
                    except OSError:
                        return ""

                desc = q("DriverDesc")
                if not desc:
                    continue
                guid = q("NetCfgInstanceId")
                friendly = ""
                if guid:
                    try:
                        with winreg.OpenKey(
                                winreg.HKEY_LOCAL_MACHINE,
                                _NET_CONN + "\\" + guid + "\\Connection") as ck:
                            friendly = winreg.QueryValueEx(ck, "Name")[0]
                    except OSError:
                        pass
                out.append({"idx": sub, "desc": desc, "version": q("DriverVersion"),
                            "provider": q("ProviderName"), "guid": guid,
                            "friendly": friendly})
        except OSError:
            continue
    return out


_DEV_FIELDS = {"实例 ID": "instance", "设备描述": "desc", "状态": "status",
               "驱动程序名称": "inf", "设备实例路径": "instance"}
_STATUS_OK = ("已启动", "Started")


def _pnp_net_devices():
    """pnputil 列一遍网络类设备：状态 + 实例 ID + 驱动版本。

    设备管理器里的「黄色感叹号」在命令行对应的是 status 不是「已启动」，
    后面带「问题代码 10/28/31/43」时 pnputil 会把它写在状态里。
    """
    code, out = _run(["pnputil", "/enum-devices", "/class", "Net", "/drivers"],
                     timeout=40)
    if code != 0:
        return []
    devs = []
    cur = {}
    for raw in out.splitlines():
        line = raw.strip()
        if not line:
            if cur.get("instance"):
                devs.append(cur)
                cur = {}
            continue
        if ":" not in line and "：" not in line:
            continue
        key, _, val = line.replace("：", ":").partition(":")
        key, val = key.strip(), val.strip()
        if key in _DEV_FIELDS:
            field = _DEV_FIELDS[key]
            if field not in cur or key == "驱动程序名称":
                if field == "instance" and cur.get("instance"):
                    devs.append(cur)
                    cur = {}
                cur[field] = val
        elif key in ("驱动程序版本", "Driver Version") and "driver_ver" not in cur:
            cur["driver_ver"] = val
        elif key in ("提供程序名称", "Provider Name") and "provider" not in cur:
            cur["provider"] = val
    if cur.get("instance"):
        devs.append(cur)

    for dv in devs:
        inst = dv.get("instance", "")
        dv["physical"] = inst.upper().startswith(("PCI\\", "USB\\", "ACPI\\", "VMBUS\\"))
        st = dv.get("status", "")
        dv["started"] = any(k in st for k in _STATUS_OK) and "不" not in st
        dv["problem"] = bool(st) and not dv["started"]
    return devs


def _driver_date(text):
    """pnputil 的 "09/27/2019 9.24.2.601" → (date_str, 距今年数)。"""
    import datetime as _dt
    s = (text or "").strip()
    head = s.split(" ")[0] if s else ""
    for fmt in ("%m/%d/%Y", "%Y/%m/%d", "%d/%m/%Y"):
        try:
            d = _dt.datetime.strptime(head, fmt).date()
            return d.strftime("%Y-%m-%d"), (_dt.date.today() - d).days / 365.0
        except ValueError:
            continue
    return "", None


def _hosts():
    path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                        "System32", "drivers", "etc", "hosts")
    info = {"path": path, "exists": False, "total": 0, "entries": [], "suspicious": [],
            "size": 0}
    try:
        info["size"] = os.path.getsize(path)
        info["exists"] = True
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                info["total"] += 1
                ip, host = parts[0], parts[1]
                info["entries"].append(f"{ip}  {host}")
                low = host.lower()
                if ip.split(".")[0] in ("0", "127") and any(d in low for d in _WATCH_DOMAINS):
                    info["suspicious"].append(f"{ip}  {host}")
    except OSError:
        pass
    return info


def _lsp():
    """第三方 LSP（分层服务提供者）：被装上后常见症状是「能 ping 通但网页打不开」。"""
    code, out = _run(["netsh", "winsock", "show", "catalog"], timeout=20)
    if code != 0:
        return {"ok": False, "vendors": [], "err": "读不到（需要管理员权限）"}
    vendors, cur = [], ""
    for line in out.splitlines():
        s = line.strip()
        if s.lower().startswith(("条目类型", "winsock catalog", "entry type")):
            continue
        if s.startswith(("描述", "Description")):
            cur = s.split(":", 1)[-1].strip()
        elif s.startswith(("提供程序路径", "Provider Path")):
            path = s.split(":", 1)[-1].strip()
            if path and "system32" not in path.lower() and cur:
                vendors.append(f"{cur} → {path}")
    return {"ok": True, "vendors": vendors}


def _firewall():
    code, out = _run(["netsh", "advfirewall", "show", "allprofiles", "state"], timeout=15)
    res = []
    if code != 0:
        return res
    cur = ""
    for line in out.splitlines():
        s = line.strip()
        if s.lower().startswith(("域配置文件", "domain profile")):
            cur = "域"
        elif s.lower().startswith(("专用配置文件", "private profile")):
            cur = "专用"
        elif s.lower().startswith(("公用配置文件", "public profile")):
            cur = "公用"
        elif s.lower().startswith(("状态", "state")) and cur:
            v = s.split()[-1]
            res.append((cur, v))
    return res


def _time_skew():
    """用 HTTP 响应头的 Date 估本机时间偏差（偏差大会导致 HTTPS/域认证失败）。"""
    import urllib.request
    for url in ("http://www.baidu.com", "http://www.qq.com"):
        try:
            req = urllib.request.Request(url, method="HEAD",
                                         headers={"User-Agent": "health_assistant"})
            t0 = time.time()
            with urllib.request.urlopen(req, timeout=4) as resp:
                date = resp.headers.get("Date")
            if not date:
                continue
            ts = time.mktime(time.strptime(date, "%a, %d %b %Y %H:%M:%S GMT"))
            # Date 头是 GMT 字符串，mktime 按本地时区解释，用 timezone 校正回 UTC
            ts -= time.timezone
            return {"ok": True, "skew": time.time() - (ts + (time.time() - t0) / 2)}
        except Exception:
            continue
    return {"ok": False, "skew": 0.0}


def _corp_agents():
    """检测公司管控客户端（改动可能被策略覆盖）。"""
    hits = []
    try:
        import psutil
        names = []
        for p in psutil.process_iter(["name"]):
            try:
                names.append((p.info["name"] or "").lower())
            except Exception:
                continue
        blob = " ".join(names)
        for label, keys in _CORP_AGENTS:
            if any(k in blob for k in keys):
                hits.append(label)
    except Exception:
        pass
    return hits


def _mtu_probe(target):
    """路径 MTU：1472 不分片失败、1400 成功 → 典型的 MTU 黑洞（VPN/PPPoE 常见）。"""
    def ping_size(size):
        args = ["ping", "-f", "-l", str(size), "-n", "1", "-w", "1500", target]
        code, out = _run(args, timeout=8)
        return code == 0 or "TTL=" in out.upper()

    if not ping_size(1472):
        if ping_size(1400):
            return {"ok": False, "detail": "1472 不通 / 1400 通"}
        return {"ok": None, "detail": "两个尺寸都不通（可能 ICMP 被拦）"}
    return {"ok": True, "detail": "1472 可通（MTU 正常）"}


# ───────────────────────── 结论（网管的分层判断） ─────────────────────────

def _issue(iid, area, sev, title, evidence, impact="", **fix):
    d = {"id": iid, "area": area, "severity": sev, "title": title,
         "evidence": [e for e in evidence if e], "impact": impact,
         "fix_label": fix.get("label", ""), "fix_kind": fix.get("kind", "manual"),
         "fix_cmd": fix.get("cmd"), "fix_text": fix.get("text", ""),
         "risk": fix.get("risk", "manual"), "admin": fix.get("admin", False),
         "reboot": fix.get("reboot", False), "note": fix.get("note", "")}
    return d


def _new_ctx():
    """一次诊断的上下文：每一步的探测结果都写进来，后面的步骤复用。"""
    return {
        "admin": is_admin(),
        "adapters": [], "primary": None, "drivers": [], "pnp": [],
        "proxy": {}, "lsp": {}, "hosts": {"path": "", "exists": False, "total": 0,
                                          "entries": [], "suspicious": [], "size": 0},
        "firewall": [], "corp": [],
        "ping": {}, "tcp": {}, "dns": {}, "dns_probe": [],
        "time": {"ok": False, "skew": 0.0}, "mtu": {"ok": None, "detail": "未测"},
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def collect():
    """一次性采完所有事实（CLI / 单元测试用；界面走 diagnose_stream 逐条出）。"""
    ctx = _new_ctx()
    for _label, fn in STEPS:
        fn(ctx, probe=True)
    return ctx


# ─────────────── 第 1 步：网卡与驱动 ───────────────

def _step_link(ctx, probe=True):
    if probe:
        ctx["adapters"] = _adapters()
        ctx["primary"] = _primary(ctx["adapters"])
        ctx["drivers"] = _nic_drivers()
        ctx["pnp"] = _pnp_net_devices()

    issues, passed = [], []
    d = ctx
    prim = d.get("primary")
    nics = d.get("adapters") or []
    up = [a for a in nics if a["up"]]
    disabled = [a for a in nics if a["state"] == "disabled"]
    drvs = d.get("drivers") or []
    pnp = d.get("pnp") or []
    adapter_names = {a["name"] for a in nics}
    pnp_by_desc = {(p.get("desc") or "").lower(): p for p in pnp}
    phys = [p for p in pnp if p.get("physical")]
    dev_ok = []

    if not up:
        if disabled:
            issues.append(_issue(
                "link.disabled", "链路", "error",
                f"{len(disabled)} 块网卡被禁用，当前没有可用网卡",
                [f"已禁用：{', '.join(a['name'] for a in disabled[:4])}",
                 "管理员状态来自 netsh interface show interface"],
                "所有需要联网的程序都会失败（浏览器、域登录、更新）",
                label="重新启用这些网卡",
                kind="cmd", risk="caution", admin=True,
                cmd=["netsh", "interface", "set", "interface",
                     f"name={disabled[0]['name']}", "admin=enabled"],
                text=f'netsh interface set interface name="{disabled[0]["name"]}" admin=enabled',
                note="如有线/无线都禁用，逐块启用；启用后重新诊断一次"))
        else:
            ev = ["所有网卡状态：已断开" if nics else "系统里没有可用的网络适配器",
                  "可能是网线未插、Wi-Fi 未连接、或飞行模式开启"]
            if not nics and phys:
                ev.append(f"设备管理器里有 {len(phys)} 块物理网卡"
                          f"（{phys[0].get('desc', '')[:32]}），但系统没生成网络连接 "
                          f"→ 大概率是驱动问题，看下面「驱动」那几条")
            issues.append(_issue(
                "link.down", "链路", "error", "没有处于连接状态的网卡（没联网）",
                ev,
                "本机当前完全离线"))
    elif prim is None:
        issues.append(_issue(
            "link.noaddr", "链路", "error", "网卡是连着的，但没拿到 IPv4 地址",
            [f"活动网卡：{', '.join(a['name'] for a in up[:4])}",
             "没有 IPv4 地址通常意味着 DHCP 没响应或 IP 配置被清空"],
            "等于没有网络可用"))
    else:
        passed.append(f"{len(up)} 块网卡已连接（主用：{prim['name']}）")

    # 驱动与设备状态
    for dev in [p for p in pnp if p.get("problem")][:3]:
        inst = dev.get("instance", "")
        st = dev.get("status", "")
        issues.append(_issue(
            "drv.problem:" + inst[:30], "驱动", "error",
            f"网卡设备状态异常：{dev.get('desc', '')}（{st}）",
            [f"设备实例：{inst}",
             f"驱动程序：{dev.get('inf') or '-'}　版本：{dev.get('driver_ver') or '-'}",
             "设备管理器里这块设备通常带黄色感叹号（代码 10/28/31/43 一类），"
             "即驱动加载失败或被系统停用"],
            "这块网卡不可用：只有一块网卡时等于整机断网，多网卡时会少一条链路",
            label="重启这块网卡设备（等同禁用后再启用）",
            kind="cmd", risk="caution", admin=True,
            cmd=["pnputil", "/restart-device", inst],
            text=f'pnputil /restart-device "{inst}"\n'
                 "—— 重启后还不行，按顺序试（设备管理器 devmgmt.msc）：\n"
                 "1) 双击该设备看「设备状态」里的错误代码：10/28/31 多为驱动问题，"
                 "43 多为硬件被系统丢弃（笔记本先彻底断电再开机）\n"
                 "2) 属性 → 驱动程序 → 回滚驱动程序（灰色说明没有旧版本可退）\n"
                 "3) 卸载设备并勾选「删除此设备的驱动程序软件」→ 操作 → 扫描检测硬件改动\n"
                 "4) 去厂商官网/主板官网下载对应型号驱动重装；USB 网卡换一个口试\n"
                 "5) 以上都不行：PCIe 网卡换插槽、笔记本放电，仍失败多半是硬件本身坏了",
            note="第 2 步之后可能要重新配 IP/DNS"))

    for dv in drvs:
        p = pnp_by_desc.get((dv.get("desc") or "").lower())
        if not p or not p.get("physical") or p.get("problem"):
            continue
        if dv.get("friendly") and dv["friendly"] not in adapter_names:
            issues.append(_issue(
                "drv.noadapter:" + dv.get("desc", "")[:30], "驱动", "warn",
                f"网卡「{dv['friendly']}」在设备管理器里是好的，但「网络连接」里没有它",
                [f"设备：{dv['desc']}　驱动 {dv.get('version') or '-'}"
                 f"（{dv.get('provider') or '-'}）",
                 "设备已启动却没有生成网络连接 → 适配器对象没起来（被禁用或被策略隐藏）",
                 "还有一种情况是刚装完驱动没重启"],
                "这块网卡上不了网，但设备管理器看起来一切正常，最容易被忽略",
                text="先看「网络连接」（ncpa.cpl）里有没有被禁用的图标，右键启用；\n"
                     "没有的话在设备管理器「查看 → 显示隐藏的设备」里找；\n"
                     "都没有就重启一次，仍不出现按上一条的驱动重装步骤处理"))
        else:
            date_s, years = _driver_date(p.get("driver_ver"))
            if years is not None and years >= 5:
                issues.append(_issue(
                    "drv.old:" + dv.get("desc", "")[:30], "驱动", "info",
                    f"网卡驱动偏老：{dv['desc'][:36]}（{date_s}，{years:.0f} 年前）",
                    [f"驱动版本 {dv.get('version') or '-'}　厂商 {dv.get('provider') or '-'}",
                     "驱动老本身不等于有问题；但若伴随断流、掉速、休眠后不认网卡，"
                     "优先升级驱动"],
                    "长期不更新的驱动在新系统版本上容易出现兼容性抽风",
                    text="去厂商官网/主板支持页下载该型号最新驱动；\n"
                         "或 设备管理器 → 右键网卡 → 更新驱动程序 → 自动搜索"))
            else:
                dev_ok.append(f"{dv.get('desc', '')[:32]} {dv.get('version') or ''}")

    if dev_ok:
        passed.append("网卡驱动状态正常：" + "；".join(dev_ok[:2]))
    if not pnp:
        issues.append(_issue(
            "drv.unknown", "驱动", "info", "读不到设备状态（pnputil 不可用）",
            ["这台机器上 pnputil /enum-devices 执行失败，无法判断驱动是否带感叹号",
             "驱动问题只能靠设备管理器（devmgmt.msc）确认"],
            "不影响其它检查项；只是驱动这一层没有结论",
            text="Win+R → devmgmt.msc → 看「网络适配器」下有没有黄色感叹号"))
    return issues, passed


# ─────────────── 第 2 步：IP / 网关 ───────────────

def _step_ip(ctx, probe=True):
    issues, passed = [], []
    prim = ctx.get("primary")
    if probe and prim:
        for gw in prim["gateway"][:2]:
            ctx["ping"][gw] = metrics.ping(gw, count=2, timeout_ms=1000)

    if prim and prim["apipa"]:
        issues.append(_issue(
            "ip.apipa", "IP", "error",
            "拿到的是 169.254.x.x 自动地址（DHCP 没给地址）",
            [f"网卡 {prim['name']}：{', '.join(prim['ip'])}",
             "169.254 是 Windows 自己编的地址，无法上网"],
            "网关不通、DNS 不可用，表现为「连上了但上不了网」",
            label="重新申请 DHCP 地址",
            kind="cmd", risk="caution", admin=True,
            cmd=["ipconfig", "/renew"],
            text="ipconfig /renew",
            note="执行后会短暂断网 5~15 秒；如果反复拿不到地址，查交换机端口/无线密码/DHCP 服务"))
    elif prim and not prim["gateway"]:
        issues.append(_issue(
            "ip.nogw", "IP", "warn", "活动网卡没有默认网关",
            [f"网卡 {prim['name']}：IP {', '.join(prim['ip'])}，网关为空",
             "静态 IP 漏填网关，或 DHCP 只给了地址没给网关"],
            "只能访问同网段设备，出不了本网段（解析、更新、访问外网都会失败）",
            text="手动配置网关（改成你自己的内网网关地址）：\n"
                 f'netsh interface ip set address name="{prim["name"]}" '
                 f'static {prim["ip"][0]} 255.255.255.0 192.168.1.1\n'
                 "不确定网关地址就问 IT / 看路由器背面",
            note="静态地址填错会导致 IP 冲突，改之前先确认网段"))

    if prim and prim["gateway"]:
        gw = prim["gateway"][0]
        r = (ctx.get("ping") or {}).get(gw) or {}
        if r.get("ok"):
            passed.append(f"网关 {gw} 可达（{r.get('avg') or 0:.0f}ms）")
        elif r:
            issues.append(_issue(
                "ip.gw_dead", "IP", "error", f"网关 {gw} ping 不通",
                [f"本机 {prim['ip'][0]} → 网关 {gw} 无应答",
                 "DNS 与密码说的「网管第一句话」：网关不通，先别碰 DNS 和代理"],
                "整个内网出口断了：可能网线/交换机端口/VLAN/ARP 或网关设备本身故障",
                text="先在本机确认 ARP 与地址冲突：\n"
                     "arp -a\n"
                     "若网关 MAC 显示为 00-00-00-00-00-00 或反复变化，说明链路层有问题。\n"
                     "接着换一根网线/换交换机端口；公司网络请直接报 IT（VLAN 或端口被关）",
                note="这条不建议自己乱改 IP，很容易把地址冲突搞得更难查"))
    return issues, passed


# ─────────────── 第 3 步：出口 / 外网 ───────────────

def _step_wan(ctx, probe=True):
    issues, passed = [], []
    if probe:
        ctx["ping"]["223.5.5.5"] = metrics.ping("223.5.5.5", count=2, timeout_ms=1200)
        ctx["tcp"]["223.5.5.5:443"] = metrics.tcp_connect("223.5.5.5", 443, timeout=3)
        ctx["tcp"]["www.baidu.com:443"] = metrics.tcp_connect("www.baidu.com", 443, timeout=3)

    pub = (ctx.get("ping") or {}).get("223.5.5.5") or {}
    tcp_ip = (ctx.get("tcp") or {}).get("223.5.5.5:443") or {}
    if pub.get("ok"):
        passed.append("公网 IP 可达（223.5.5.5）")
    if tcp_ip.get("ok"):
        passed.append("公网 TCP 443 可建立连接")
    if not pub.get("ok") and not tcp_ip.get("ok"):
        issues.append(_issue(
            "wan.dead", "出口", "error", "公网完全不通（ping 与 TCP 都不通）",
            [f"223.5.5.5 ping：{'通' if pub.get('ok') else '不通'}",
             f"223.5.5.5:443 TCP：{'通' if tcp_ip.get('ok') else '失败'}",
             "网关若可达，说明问题在出口（NAT/防火墙/欠费/公司上网认证）"],
            "本机可以用内网，但所有外网业务（浏览器、更新、登录鉴权）都会失败",
            text="先确认是否需要网页认证（很多公司网络要先登录准入页面）。\n"
                 "再看系统代理是否指向一个已经下线的代理服务器（见「代理」一节）。\n"
                 "公司网络：问 IT 是否出口策略/准入/欠费；家里：重启光猫与路由器",
            note="出口问题通常不在本机，改本机设置没用"))
    elif pub.get("ok") and not tcp_ip.get("ok"):
        issues.append(_issue(
            "wan.tcp_block", "出口", "warn", "能 ping 通但 TCP 443 连不上",
            ["ICMP 通、TCP 握手失败：常见于出口防火墙只放行部分端口，或上网需要认证",
             "也可能是本机安全软件拦了出站连接"],
            "浏览器打不开 https 站点，但 ping 正常，容易被误判成「断网」",
            text='检查本机防火墙出站规则：\n'
                 'netsh advfirewall firewall show rule name=all dir=out | more\n'
                 "公司网络请确认是否需要准入认证"))
    if not pub.get("ok") and tcp_ip.get("ok"):
        passed.append("ICMP 被拦但 TCP 可用（正常，多为防火墙策略）")
    return issues, passed


# ─────────────── 第 4 步：DNS ───────────────

def _step_dns(ctx, probe=True):
    issues, passed = [], []
    prim = ctx.get("primary")
    if probe:
        for name in ("www.baidu.com", "www.qq.com"):
            ctx["dns"][name] = metrics.dns_resolve(name)
        if prim:
            for srv in prim["dns"][:3]:
                if srv and ":" not in srv:
                    ctx["dns_probe"].append((srv, _dns_udp_query(srv)))

    pub = (ctx.get("ping") or {}).get("223.5.5.5") or {}
    if prim and not prim["dns"]:
        issues.append(_issue(
            "dns.none", "DNS", "error", "活动网卡没有配置 DNS 服务器",
            [f"网卡 {prim['name']}：DNS 列表为空",
             "DNS 为空时只能靠 hosts 或缓存解析，绝大多数域名都会失败"],
            "能 ping IP、打不开网页 —— 最典型的「DNS 没配」表现",
            label="DNS 改为自动获取（DHCP）",
            kind="cmd", risk="caution", admin=True,
            cmd=["netsh", "interface", "ip", "set", "dns",
                 f"name={prim['name']}", "source=dhcp"],
            text=f'netsh interface ip set dns name="{prim["name"]}" source=dhcp',
            note="如果公司要求指定内网 DNS，改成静态会更稳（问 IT 要地址）"))
    dead_dns = [s for s, r in ctx.get("dns_probe") or [] if not r.get("ok")]
    good_dns = [(s, r) for s, r in ctx.get("dns_probe") or [] if r.get("ok")]
    if good_dns:
        s, r = good_dns[0]
        passed.append(f"DNS {s} 应答正常（{r['ms']:.0f}ms）")
    if prim and prim["dns"] and not good_dns and (ctx.get("dns_probe") or []):
        issues.append(_issue(
            "dns.unreachable", "DNS", "error", "配置的 DNS 服务器全部无应答",
            [f"DNS：{', '.join(prim['dns'][:3])}",
             "对这每一台 DNS 直接发 A 查询都没有响应（不是域名问题，是服务器不可达）",
             "DNS 不可达常见于：配了外网 DNS 但公司内网封了 53、或 DNS 地址写错"],
            "所有域名解析失败，浏览器报「找不到服务器」",
            text="把 DNS 改回自动获取，或改成公司内网 DNS：\n"
                 f'netsh interface ip set dns name="{prim["name"]}" source=dhcp\n'
                 f'netsh interface ip add dns name="{prim["name"]}" addr=223.5.5.5 index=2\n'
                 "公司内网域名（如 gitlab.内网）只能用内网 DNS 解析"))
    bad_res = [n for n, r in (ctx.get("dns") or {}).items() if not r.get("ok")]
    slow_res = [n for n, r in (ctx.get("dns") or {}).items()
                if r.get("ok") and r.get("ms", 0) > 800]
    if bad_res and not dead_dns:
        issues.append(_issue(
            "dns.resolve_fail", "DNS", "error",
            f"{len(bad_res)} 个常见域名解析失败",
            [f"失败：{', '.join(bad_res)}",
             f"同一时刻 ping 公网 IP：{'通' if pub.get('ok') else '不通'}",
             "IP 通而域名解析失败 → 问题在 DNS 链路或本机缓存"],
            "浏览器能打开 IP 直连的地址，但域名一律打不开",
            label="清空 DNS 解析缓存",
            kind="cmd", risk="safe", admin=False,
            cmd=["ipconfig", "/flushdns"],
            text="ipconfig /flushdns",
            note="清完再诊断一次；还失败就换 DNS（见上一条）"))
    if slow_res and not bad_res:
        issues.append(_issue(
            "dns.slow", "DNS", "warn",
            f"域名解析偏慢（{max(ctx['dns'][n].get('ms', 0) for n in slow_res):.0f}ms）",
            [f"慢：{', '.join(slow_res)}",
             "正常内网 DNS 应在 50ms 内应答，超过 800ms 通常是 DNS 绕了远路或被代理接管"],
            "网页首屏卡顿、程序启动慢，容易被当成「电脑卡」",
            label="清空 DNS 解析缓存",
            kind="cmd", risk="safe", cmd=["ipconfig", "/flushdns"],
            text="ipconfig /flushdns"))
    elif good_dns and not bad_res:
        passed.append("常见域名解析正常")
    return issues, passed


# ─────────────── 第 5 步：代理 ───────────────

def _step_proxy(ctx, probe=True):
    issues, passed = [], []
    if probe:
        ctx["proxy"] = _proxy()
    px = ctx.get("proxy") or {}
    if px.get("enable") and px.get("server"):
        alive = _proxy_alive(px["server"]) if probe else None
        if alive is False:
            issues.append(_issue(
                "proxy.dead", "代理", "error",
                f"系统代理指向的服务器连不上：{str(px['server'])[:40]}",
                [f"WinINET 代理已启用，ProxyServer={px['server']}",
                 "对该地址做 TCP 探测失败（代理程序没启动 / 已换地址 / 需要公司网络才能连）"],
                "浏览器与大部分 HTTP 客户端全都走这个代理 → 表现为「全部网站打不开」，"
                "但 ping 正常、命令行 curl 反而可能能用",
                label="关闭系统代理",
                kind="action", risk="caution",
                text="等价操作：设置 → 网络和 Internet → 代理 → 关闭「使用代理服务器」",
                note="公司要求走代理的话别关，先问 IT 要正确的代理地址"))
        elif alive:
            passed.append(f"系统代理 {str(px['server'])[:30]} 可连接")
    elif px:
        passed.append("系统代理未启用（走直连）")
    if px.get("pac"):
        issues.append(_issue(
            "proxy.pac", "代理", "info", f"启用了 PAC 自动配置脚本：{str(px['pac'])[:60]}",
            ["PAC 拉不到时会静默回退，表现为「某些网站时好时坏」"],
            "排查时容易被忽略：浏览器行为由脚本决定，不是系统代理开关",
            text="打开浏览器看 设置 → 代理，确认 PAC 地址可访问；不需要就取消勾选"))
    if px.get("winhttp") and (px.get("winhttp") != str(px.get("server") or "")):
        issues.append(_issue(
            "proxy.winhttp_mismatch", "代理", "info",
            "WinHTTP 代理与浏览器代理不一致",
            [f"WinHTTP：{px['winhttp']}",
             f"WinINET（浏览器）：{px.get('server') or '未启用'}",
             "命令行 / PowerShell / 系统更新走 WinHTTP，浏览器走 WinINET —— 两边不一致就会出现"
             "「浏览器能上网、命令行不能」"],
            "典型症状：更新失败、git/npm 拉不下来、某些服务连不上",
            label="重置 WinHTTP 代理",
            kind="cmd", risk="caution", admin=True,
            cmd=["netsh", "winhttp", "reset", "proxy"],
            text="netsh winhttp reset proxy",
            note="重置后 WinHTTP 走直连；需要代理的程序要单独配置"))
    if px.get("env"):
        issues.append(_issue(
            "proxy.env", "代理", "info",
            "环境变量里设置了代理",
            [f"{k}={v}" for k, v in px["env"].items()],
            "只影响命令行程序（git/npm/pip/docker），和系统代理是两套东西",
            text="如非有意设置，可在「系统属性 → 环境变量」里删掉 HTTP_PROXY / HTTPS_PROXY"))
    return issues, passed


# ─────────────── 第 6 步：协议栈 / 本机拦截 ───────────────

def _step_stack(ctx, probe=True):
    issues, passed = [], []
    if probe:
        ctx["lsp"] = _lsp()
        ctx["hosts"] = _hosts()
        if (ctx.get("ping") or {}).get("223.5.5.5", {}).get("ok"):
            ctx["mtu"] = _mtu_probe("223.5.5.5")

    lsp = ctx.get("lsp") or {}
    if lsp.get("vendors"):
        issues.append(_issue(
            "stack.lsp", "协议栈", "warn",
            f"检测到 {len(lsp['vendors'])} 个第三方网络分层提供者（LSP）",
            lsp["vendors"][:4] + ["第三方 LSP 会接管所有 socket，装过加速器/抓包/VPN 后常见"],
            "表现为「ping 通、DNS 也正常，但网页就是打不开」，或只有部分程序能联网",
            text="管理员命令行执行后**必须重启**（会重置所有网卡绑定，VPN 客户端可能要重装）：\n"
                 "netsh winsock reset\n"
                 "执行前先把下面这行输出保存下来，方便排查是谁留下的：\n"
                 "netsh winsock show catalog",
            risk="manual", admin=True, reboot=True,
            note="这条风险较高且必须重启，工具不代跑"))
    elif lsp.get("ok"):
        passed.append("没有第三方 LSP 接管 socket")

    hs = ctx.get("hosts") or {}
    if hs.get("suspicious"):
        issues.append(_issue(
            "hosts.suspect", "本机拦截", "warn",
            f"hosts 里有 {len(hs['suspicious'])} 条可疑映射（常见域名被指到本机/0.0.0.0）",
            hs["suspicious"][:5] + [f"hosts 路径：{hs['path']}"],
            "常见于去广告脚本、破解/加速工具、以及恶意样本的域名劫持",
            text="先备份再改（管理员）：\n"
                 f'copy "{hs["path"]}" "%USERPROFILE%\\hosts.bak"\n'
                 f'notepad "{hs["path"]}"\n'
                 "只删你确认不需要的行，其余保持原样"))
    elif hs.get("total"):
        passed.append(f"hosts 有 {hs['total']} 条自定义映射（未发现可疑劫持）")

    mtu = ctx.get("mtu") or {}
    if mtu.get("ok") is False:
        issues.append(_issue(
            "stack.mtu", "协议栈", "warn", f"疑似路径 MTU 偏小：{mtu['detail']}",
            ["1472 字节不分片 ping 失败、1400 成功 → 路径上某一跳的 MTU 更小",
             "VPN / PPPoE / 部分 4G 网络常见：小包能通，大包被丢"],
            "症状很典型：网页能开一半、SSH 能登录但卡在传输、下载总是失败重试",
            text="先测出真实 MTU（把数字往上试到不分片失败为止）：\n"
                 'ping -f -l 1400 223.5.5.5\n'
                 "确认后按最小可用值设置（管理员）：\n"
                 'netsh interface ipv4 set subinterface "以太网" mtu=1400 store=persistent\n'
                 "把「以太网」换成你实际网卡名，MTU 一般取 1400~1472"))
    elif mtu.get("ok"):
        passed.append("路径 MTU 正常（1472 字节不分片可通）")
    return issues, passed


# ─────────────── 第 7 步：时间与策略 ───────────────

def _step_time(ctx, probe=True):
    issues, passed = [], []
    if probe:
        ctx["firewall"] = _firewall()
        ctx["corp"] = _corp_agents()
        if (ctx.get("ping") or {}).get("223.5.5.5", {}).get("ok"):
            ctx["time"] = _time_skew()

    t = ctx.get("time") or {}
    if t.get("ok") and abs(t.get("skew", 0)) > 300:
        issues.append(_issue(
            "time.skew", "时间", "warn",
            f"本机时间与网络时间相差 {abs(t.get('skew', 0)) / 60:.0f} 分钟",
            [f"偏差 {t.get('skew', 0):+.0f} 秒（>5 分钟即会出问题）",
             "以 HTTP 响应头的 Date 为参照"],
            "HTTPS 证书校验、域登录（Kerberos）、部分 API 签名都会失败，"
            "报错往往是「证书无效 / 认证失败」，很难想到是时间问题",
            label="立即与时间服务器同步",
            kind="cmd", risk="caution", admin=True,
            cmd=["w32tm", "/resync"],
            text="w32tm /resync",
            note="同步失败就检查「日期和时间 → 立即更新」，或确认时区是否为 UTC+8"))
    elif t.get("ok"):
        passed.append("本机时间与网络时间一致")

    fw = ctx.get("firewall") or []
    if fw and all(v.lower() in ("off", "关闭", "关") for _p, v in fw):
        issues.append(_issue(
            "fw.off", "策略", "info", "三个网络配置文件（域/专用/公用）的防火墙都是关闭的",
            [f"{p}：{v}" for p, v in fw],
            "不是连不上网的原因，但会让本机在没有边界防护的状态下运行",
            text="启用防火墙（管理员）：\n"
                 "netsh advfirewall set allprofiles state on"))

    if ctx.get("corp"):
        issues.append(_issue(
            "corp.policy", "策略", "info",
            f"检测到公司管控客户端：{' / '.join(ctx['corp'])}",
            ["这类客户端会接管网络准入、DNS、防火墙与代理策略",
             "它下发的策略会周期性回写，本机改动可能被覆盖"],
            "改了没生效不是工具没做事，而是被策略刷回去了",
            text="涉及防火墙、DNS、代理、网卡的改动，先在公司 IT 那里确认再动；"
                 "需要放行某个端口/域名请走 IT 工单"))
    return issues, passed


STEPS = (
    ("网卡与驱动", _step_link),
    ("IP / 网关", _step_ip),
    ("出口连通", _step_wan),
    ("DNS 解析", _step_dns),
    ("代理设置", _step_proxy),
    ("协议栈与拦截", _step_stack),
    ("时间与策略", _step_time),
)


def _wrap(ctx, issues, passed):
    """出总览文案；注意 errors 数量决定措辞，别把 info 说成问题。"""
    issues = sorted(issues, key=lambda i: (SEV_ORDER.get(i["severity"], 9), i["area"]))
    errs = sum(1 for i in issues if i["severity"] == "error")
    warns = sum(1 for i in issues if i["severity"] == "warn")
    if errs:
        head = f"发现 {errs} 个会导致断网的问题"
    elif warns:
        head = f"网络可用，但有 {warns} 个影响体验的隐患"
    elif issues:
        head = "网络正常，下面只是可以优化的细节"
    else:
        head = "这一轮没查出网络问题"
    if not ctx.get("admin"):
        head += "（当前不是管理员，下面需要管理员的修复会被拦下）"
    return {"issues": issues, "passed": passed, "summary": head, "data": ctx}


def diagnose_stream(should_stop=None):
    """逐条产出：每完成一步就 yield 一次，界面可以边查边显示。

    yield 的字典：
      {"i","n","label","issues","passed"}   某一步的结果（issues 只是这一步新发现的）
      {"done": True, "issues","passed","summary","data"}   全部完成
    """
    ctx = _new_ctx()
    all_issues, all_passed = [], []
    n = len(STEPS)
    did, stopped = 0, False
    for i, (label, fn) in enumerate(STEPS, 1):
        if should_stop and should_stop():
            stopped = True
            break
        issues, passed = fn(ctx, probe=True)
        all_issues += issues
        all_passed += passed
        did = i
        yield {"i": i, "n": n, "label": label, "issues": issues, "passed": passed}
    if not stopped and should_stop and should_stop():
        stopped = True
    res = _wrap(ctx, all_issues, all_passed)
    res["done"] = True
    res["stopped"] = stopped
    res["steps_done"] = did
    if stopped:
        # 中止时别用「网络正常」这种总览 —— 只查了前几层，结论本来就不完整
        res["summary"] = (f"已中止：只查了前 {did}/{n} 层，下列结论不完整"
                          if did else "已中止：还没有开始检查")
    yield res


def diagnose(data=None):
    """一次性拿到完整结论（CLI / 单元测试用）。

    传 data 时只跑规则、不做任何探测（单元测试注入假数据走这条路）。
    """
    if data is not None:
        ctx = _new_ctx()
        ctx.update(data or {})
        issues, passed = [], []
        for _label, fn in STEPS:
            i, p = fn(ctx, probe=False)
            issues += i
            passed += p
        return _wrap(ctx, issues, passed)

    last = None
    for ev in diagnose_stream():
        last = ev
    return last or _wrap(_new_ctx(), [], [])


# ───────────────────────── 修复执行 ─────────────────────────

_PROXY_BACKUP = os.path.join(
    os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"),
    "health_assistant", "proxy-backup.json")


def _disable_wininet_proxy():
    """关掉系统代理，先把原值备份成 json，方便一键还原。"""
    import winreg
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0,
                            winreg.KEY_READ) as k:
            old = {}
            for name in ("ProxyEnable", "ProxyServer", "AutoConfigURL"):
                try:
                    old[name] = winreg.QueryValueEx(k, name)[0]
                except FileNotFoundError:
                    pass
        os.makedirs(os.path.dirname(_PROXY_BACKUP), exist_ok=True)
        with open(_PROXY_BACKUP, "w", encoding="utf-8") as fh:
            json.dump({"key": key_path, "values": old,
                       "time": time.strftime("%Y-%m-%d %H:%M:%S")},
                      fh, ensure_ascii=False, indent=2)
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0,
                            winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        return True, f"已关闭系统代理（原值备份在 {_PROXY_BACKUP}）"
    except OSError as exc:
        return False, f"改注册表失败：{exc}"


_ACTIONS = {"disable_wininet_proxy": _disable_wininet_proxy}


def run_fix(issue, log=None):
    """执行一条修复。返回 {"ok": bool, "msg": str, "text": str}。不抛异常。"""
    log = log or (lambda _s: None)
    kind = issue.get("fix_kind")
    text = issue.get("fix_text") or ""
    if kind == "manual" or not kind:
        return {"ok": False, "msg": "这条需要人工执行，命令已给出", "text": text}
    if issue.get("admin") and not is_admin():
        return {"ok": False, "msg": "需要管理员权限：请右键 health_assistant.cmd「以管理员身份运行」",
                "text": text}
    if kind == "action":
        fn = _ACTIONS.get(issue.get("id", "").replace(".", "_")) or \
            _ACTIONS.get("disable_wininet_proxy")
        log(f"执行动作：{issue.get('fix_label')}")
        ok, msg = fn()
        return {"ok": ok, "msg": msg, "text": text}

    cmd = issue.get("fix_cmd")
    if not cmd:
        return {"ok": False, "msg": "这条没有可直接执行的命令", "text": text}
    log("执行命令：" + " ".join(cmd))
    code, out = run_cmd(cmd, timeout=60)
    tail = (out or "").strip().splitlines()
    tail = tail[-4:] if tail else []
    ok = code == 0
    msg = ("执行成功" if ok else f"返回码 {code}") + (("：" + " / ".join(tail)) if tail else "")
    return {"ok": ok, "msg": msg, "text": text, "code": code, "out": out}


def apply_safe(issues, log=None):
    """批量执行所有 safe 级修复（幂等、不改配置）。"""
    log = log or (lambda _s: None)
    out = []
    for it in issues or []:
        if it.get("risk") != "safe":
            continue
        out.append((it, run_fix(it, log=log)))
    return out
