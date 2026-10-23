"""
health_assistant.metrics — 数据采集层（纯取数，不做判断/不输出）

把"取数"与"判断+呈现"分离：checks/ 里的巡检项只负责解读这些数据，
替换数据源（比如换成 WMI 或远程采集）时只需改这里。
"""

from __future__ import annotations

import ctypes
import os
import re
import socket
import time

from .core import IS_WINDOWS, sockaddr_text

try:
    import psutil
except Exception:                                              # pragma: no cover
    psutil = None

__all__ = [
    "psutil", "HAS_PSUTIL", "memory_status", "proc_snapshot", "top_procs",
    "proc_detail", "kill_process", "mask_cmdline", "cmdline_text",
    "adapter_gw_dns", "ping", "tcp_connect", "dns_resolve",
    "net_listeners", "listener_for_pid", "service_pid_map",
    "disk_usage_rows", "disk_io", "service_list",
    "KILL_BLOCK_NAMES",
]

HAS_PSUTIL = psutil is not None


# ───────────────────────────── 内存 ─────────────────────────────

class _MEMSTATUS(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


def memory_status():
    """物理内存 + 提交(Commit) 总览，口径对齐任务管理器。"""
    if not IS_WINDOWS:
        return None
    try:
        st = _MEMSTATUS()
        st.dwLength = ctypes.sizeof(_MEMSTATUS)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
            return {
                "load": int(st.dwMemoryLoad),
                "total_phys": st.ullTotalPhys,
                "avail_phys": st.ullAvailPhys,
                "total_commit": st.ullTotalPageFile,
                "avail_commit": st.ullAvailPageFile,
            }
    except Exception:
        pass
    return None


# ───────────────────────────── 进程 ─────────────────────────────
#
# 进程信息里最容易踩的两件事：
#   1. 启动参数常常带密码（--password xxx / ?token= / user:pass@host），
#      默认一律遮罩，需要明文得显式 mask=False（本工具巡检路径从不这么做）。
#   2. 受保护进程（系统/安全软件）拿不到 exe / cmdline，必须容忍失败。

_SECRET_ARG_RE = re.compile(
    r"(?i)(--?(?:password|passwd|pwd|pass|token|secret|api[-_]?key|access[-_]?key|"
    r"private[-_]?key|client[-_]?secret|auth[-_]?key|credential|session)[=\s:]+)"
    r"(\"[^\"]*\"|'[^']*'|\S+)")
_URL_CRED_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^:/\s@]+):([^@/\s]+)@")
_BEARER_RE = re.compile(r"(?i)\b(bearer\s+)([A-Za-z0-9._~+/=-]{8,})")
_LONG_TOKEN_RE = re.compile(r"\b(sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{12,}|xox[baprs]-[A-Za-z0-9-]{10,})\b")

# 这些进程不能随便杀：杀了会蓝屏 / 掉登录会话 / 断网
KILL_BLOCK_NAMES = {
    "system", "system idle process", "registry", "memory compression",
    # Win10 起的「内存压缩仓库」：任务管理器里叫 MemCompression（无空格、无 .exe），
    # 父进程 System(4)，是内核内存管理器自己建的 minimal process ——
    # 磁盘上没有可执行文件、也没有服务项，杀不掉也不需要杀。
    "memcompression",
    "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
    "lsass.exe", "lsaiso.exe", "fontdrvhost.exe", "dwm.exe", "svchost.exe",
    "logonui.exe", "userinit.exe", "sihost.exe", "ctfmon.exe",
} if IS_WINDOWS else set()


def mask_cmdline(text):
    """把命令行里的密码 / token / URL 凭据替换成 ***。"""
    if not text:
        return ""
    out = _SECRET_ARG_RE.sub(lambda m: m.group(1) + "***", str(text))
    out = _URL_CRED_RE.sub(lambda m: f"{m.group(1)}:***@", out)
    out = _BEARER_RE.sub(lambda m: m.group(1) + "***", out)
    out = _LONG_TOKEN_RE.sub("***", out)
    return out


def cmdline_text(exe, cmdline, mask=True, width=None):
    """把 exe + 参数拼成一行可读命令（过长时中间省略尾巴）。"""
    parts = [p for p in (cmdline or []) if p is not None]
    text = " ".join(parts).strip() or (exe or "")
    if mask:
        text = mask_cmdline(text)
    if width and len(text) > width:
        head = max(12, width // 3)
        text = text[:head] + " … " + text[-(width - head - 3):]
    return text


def _proc_row(p, ncpu):
    """把 psutil.Process 摊平成一条基础记录（不取 exe/cmdline，那步很贵）。"""
    info = p.info
    pid = info["pid"]
    name = info.get("name") or "?"
    if pid == 0 or name.lower().startswith("system idle"):
        return None
    mi = info.get("memory_info")
    return {
        "pid": pid,
        "ppid": info.get("ppid") or 0,
        "name": name,
        "cpu": p.cpu_percent(None) / ncpu,
        "mem": mi.rss if mi else 0,
        "mem_priv": getattr(mi, "private", 0) if mi else 0,
        "exe": "",
        "cmdline": "",
        "user": "",
        "started": 0,
        "status": "",
        "detail": False,
    }


# 只取便宜字段：带上 cmdline/username 会让 process_iter 从 0.5s 涨到 7s（近 400 个进程）
_PROC_FIELDS = ["pid", "ppid", "name", "memory_info"]


def proc_snapshot(sample=0.5):
    """采一次进程快照：cpu 为归一化后的百分比（对齐任务管理器）。

    只取廉价字段。要启动参数/路径/用户，对关心的那几行调 enrich_procs()。
    """
    if not HAS_PSUTIL:
        return []
    ncpu = psutil.cpu_count(logical=True) or 1
    try:
        for p in psutil.process_iter(["pid"]):
            try:
                p.cpu_percent(None)
            except Exception:
                pass
        time.sleep(sample)
    except Exception:
        pass

    rows = []
    for p in psutil.process_iter(_PROC_FIELDS):
        try:
            r = _proc_row(p, ncpu)
            if r:
                rows.append(r)
        except Exception:
            continue
    return rows


_ENRICH_CACHE = {}              # (pid, 启动时间) -> 补齐好的字段
_ENRICH_CACHE_MAX = 3000


def enrich_procs(rows):
    """给指定进程行补 exe / 启动参数 / 用户 / 启动时间 / 状态（原地修改）。

    4.6.0 起带缓存。``cmdline()`` 要打开目标进程读它的 PEB，本机实测单个 ~50ms
    （装了安全管控驱动的机器更慢），400 个进程顺下来 13s —— 「进程」页原来点一次
    要等 7 秒、8 个线程全跑满，主要就花在这里。同一台机器上半分钟内进程列表几乎
    不变，所以按 ``(pid, 启动时间)`` 缓存结果：第二次打开基本是瞬间。
    键里带启动时间，PID 被回收复用也不会张冠李戴。
    """
    if not HAS_PSUTIL:
        return rows
    if len(_ENRICH_CACHE) > _ENRICH_CACHE_MAX:
        _ENRICH_CACHE.clear()
    for r in rows:
        if r.get("detail"):
            continue
        try:
            p = psutil.Process(r["pid"])
            ctime = p.create_time()
            key = (r["pid"], round(ctime, 3))
            hit = _ENRICH_CACHE.get(key)
            if hit is not None:
                r.update(hit)
                r["detail"] = True
                continue
            with p.oneshot():
                exe = p.exe() or ""
                try:
                    cmd = cmdline_text(exe, p.cmdline(), mask=True)
                except Exception:
                    cmd = exe
                try:
                    user = (p.username() or "").split("\\")[-1]
                except Exception:
                    user = ""
                status = p.status() or ""
            got = {"exe": exe, "cmdline": cmd, "user": user,
                   "started": ctime, "status": status}
            r.update(got)
            _ENRICH_CACHE[key] = got
        except Exception:
            r["cmdline"] = r["cmdline"] or r["exe"]
        r["detail"] = True
    return rows


def top_procs(snapshot, by="cpu", limit=10, detail=True):
    key = "cpu" if by == "cpu" else "mem"
    rows = sorted(snapshot, key=lambda r: r[key], reverse=True)[:limit]
    return enrich_procs(rows) if detail else rows


def proc_detail(pid):
    """单进程详情：路径、参数、父进程、启动时间、监听端口、连接数。"""
    if not HAS_PSUTIL:
        return None
    try:
        p = psutil.Process(int(pid))
        with p.oneshot():
            info = p.as_dict(attrs=["pid", "ppid", "name", "exe", "cmdline", "cwd",
                                    "username", "create_time", "status", "num_threads",
                                    "memory_info", "cpu_percent", "nice"])
    except Exception:
        return None

    ncpu = psutil.cpu_count(logical=True) or 1
    mi = info.get("memory_info")
    cmd = info.get("cmdline") or []
    d = {
        "pid": info["pid"],
        "ppid": info["ppid"],
        "name": info.get("name") or "?",
        "exe": info.get("exe") or "",
        "cmdline": cmdline_text(info.get("exe"), cmd, mask=True),
        "cwd": info.get("cwd") or "",
        "user": info.get("username") or "",
        "started": info.get("create_time") or 0,
        "status": info.get("status") or "",
        "threads": info.get("num_threads") or 0,
        "mem": mi.rss if mi else 0,
        "mem_priv": getattr(mi, "private", 0) if mi else 0,
        "cpu": (info.get("cpu_percent") or 0) / ncpu,
        "service": "",
        "listening": [],
        "connections": 0,
        "children": [],
    }

    svc = service_pid_map()
    if d["pid"] in svc:
        d["service"] = ", ".join(svc[d["pid"]])

    try:
        d["children"] = [(c.pid, c.name()) for c in p.children(recursive=False)]
    except Exception:
        pass

    try:
        conns = p.net_connections(kind="inet")
        d["connections"] = len(conns)
        for c in conns:
            if c.status == (psutil.CONN_LISTEN if HAS_PSUTIL else "LISTEN"):
                try:
                    d["listening"].append(f"{c.laddr.ip}:{c.laddr.port}")
                except Exception:
                    pass
    except Exception:
        pass
    return d


def kill_process(pid, tree=False, timeout=3.0, force=False):
    """终止进程。返回 (ok, 说明列表)。

    安全闸：拒绝 PID<=4、拒绝系统关键进程、拒绝当前进程及其祖先进程。
    tree=True 时先终止子进程再终止自身；先 terminate，超时后才 kill。
    """
    notes = []
    if not HAS_PSUTIL:
        return False, ["未安装 psutil，无法终止进程"]
    try:
        pid = int(pid)
    except Exception:
        return False, [f"非法 PID: {pid}"]

    if pid <= 4:
        return False, [f"拒绝：PID {pid} 是系统核心进程"]
    if pid == os.getpid():
        return False, ["拒绝：这是巡检工具自己"]

    try:
        p = psutil.Process(pid)
        name = p.name()
    except Exception as exc:
        return False, [f"进程不存在或无权访问: {type(exc).__name__}"]

    # 祖先进程也不能杀（杀掉了本工具自己也得跟着死，且通常是终端/IDE）
    try:
        me = psutil.Process()
        anc = {a.pid for a in me.parents()}
        if pid in anc:
            return False, [f"拒绝：PID {pid}（{name}）是当前会话的父进程，终止会连带结束本工具"]
    except Exception:
        pass

    low = name.lower()
    if low in KILL_BLOCK_NAMES and not force:
        return False, [f"拒绝：{name} 属于系统关键进程（确认要杀请加 --force，风险自负）"]

    targets = []
    if tree:
        try:
            kids = p.children(recursive=True)
        except Exception:
            kids = []
        targets = [(c.pid, c.name()) for c in reversed(kids)]
    targets.append((p.pid, name))

    ok_any = False
    for tpid, tname in targets:
        try:
            tp = psutil.Process(tpid)
        except Exception:
            continue
        try:
            tp.terminate()
            notes.append(f"terminate  {tname}({tpid})")
            ok_any = True
        except Exception as exc:
            notes.append(f"terminate 失败 {tname}({tpid}): {type(exc).__name__}")
            continue

    procs = []
    for tpid, _tname in targets:
        try:
            procs.append(psutil.Process(tpid))
        except Exception:
            continue
    try:
        _gone, alive = psutil.wait_procs(procs, timeout=timeout)
    except Exception:
        alive = procs
    for ap in alive:
        try:
            ap.kill()
            notes.append(f"kill(强杀)  {ap.name()}({ap.pid})")
        except Exception as exc:
            notes.append(f"kill 失败 {ap.pid}: {type(exc).__name__}")

    still = [t for t in targets if psutil.pid_exists(t[0])]
    if still:
        return False, notes + [f"仍有 {len(still)} 个进程存活（可能受保护，需管理员权限）"]
    return ok_any, notes



# ───────────────────────────── 网络 ─────────────────────────────

def _adapter_gw_dns():
    """GetAdaptersAddresses → {friendly_name: {gateway, dns, mtu, speed}}
    不依赖 ipconfig 的本地化输出。
    """
    if not IS_WINDOWS:
        return {}

    class SOCKADDR(ctypes.Structure):
        _fields_ = [("sa_family", ctypes.c_ushort), ("sa_data", ctypes.c_ubyte * 26)]

    class SOCKET_ADDRESS(ctypes.Structure):
        _fields_ = [("lpSockaddr", ctypes.POINTER(SOCKADDR)), ("iSockaddrLength", ctypes.c_int)]

    class ADDR_NODE(ctypes.Structure):
        pass
    ADDR_NODE._fields_ = [
        ("Alignment", ctypes.c_ulonglong),
        ("Next", ctypes.POINTER(ADDR_NODE)),
        ("Address", SOCKET_ADDRESS),
    ]

    class UNI_NODE(ctypes.Structure):
        pass
    UNI_NODE._fields_ = [
        ("Alignment", ctypes.c_ulonglong),
        ("Next", ctypes.POINTER(UNI_NODE)),
        ("Address", SOCKET_ADDRESS),
        ("PrefixOrigin", ctypes.c_ulong),
        ("SuffixOrigin", ctypes.c_ulong),
        ("DadState", ctypes.c_ulong),
        ("ValidLifetime", ctypes.c_ulong),
        ("PreferredLifetime", ctypes.c_ulong),
        ("LeaseLifetime", ctypes.c_ulong),
        ("OnLinkPrefixLength", ctypes.c_ubyte),
    ]

    class ADAPTER(ctypes.Structure):
        pass
    ADAPTER._fields_ = [
        ("Alignment", ctypes.c_ulonglong),
        ("Next", ctypes.POINTER(ADAPTER)),
        ("AdapterName", ctypes.c_char_p),
        ("FirstUnicastAddress", ctypes.POINTER(UNI_NODE)),
        ("FirstAnycastAddress", ctypes.c_void_p),
        ("FirstMulticastAddress", ctypes.c_void_p),
        ("FirstDnsServerAddress", ctypes.POINTER(ADDR_NODE)),
        ("DnsSuffix", ctypes.c_wchar_p),
        ("Description", ctypes.c_wchar_p),
        ("FriendlyName", ctypes.c_wchar_p),
        ("PhysicalAddress", ctypes.c_ubyte * 8),
        ("PhysicalAddressLength", ctypes.c_ulong),
        ("Flags", ctypes.c_ulong),
        ("Mtu", ctypes.c_ulong),
        ("IfType", ctypes.c_ulong),
        ("OperStatus", ctypes.c_ulong),
        ("Ipv6IfIndex", ctypes.c_ulong),
        ("ZoneIndices", ctypes.c_ulong * 16),
        ("FirstPrefix", ctypes.c_void_p),
        ("TransmitLinkSpeed", ctypes.c_ulonglong),
        ("ReceiveLinkSpeed", ctypes.c_ulonglong),
        ("FirstWinsServerAddress", ctypes.c_void_p),
        ("FirstGatewayAddress", ctypes.POINTER(ADDR_NODE)),
    ]

    out = {}
    try:
        fn = ctypes.windll.iphlpapi.GetAdaptersAddresses
        fn.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p,
                       ctypes.POINTER(ADAPTER), ctypes.POINTER(ctypes.c_ulong)]
        fn.restype = ctypes.c_ulong
        flags = 0x0080 | 0x0002 | 0x0004        # INCLUDE_GATEWAYS | SKIP_ANYCAST | SKIP_MULTICAST

        size = ctypes.c_ulong(32 * 1024)
        buf = None
        for _ in range(6):
            buf = ctypes.create_string_buffer(size.value)
            rc = fn(0, flags, None, ctypes.cast(buf, ctypes.POINTER(ADAPTER)), ctypes.byref(size))
            if rc == 111:                        # ERROR_BUFFER_OVERFLOW
                continue
            if rc != 0:
                return {}
            break
        else:
            return {}

        node = ctypes.cast(buf, ctypes.POINTER(ADAPTER))
        while node:
            a = node.contents
            if a.OperStatus == 1:                # IfOperStatusUp
                gates, dnss = [], []
                p = a.FirstGatewayAddress
                while p:
                    s = sockaddr_text(p.contents.Address)
                    if s:
                        gates.append(s)
                    p = p.contents.Next
                p = a.FirstDnsServerAddress
                while p:
                    s = sockaddr_text(p.contents.Address)
                    if s:
                        dnss.append(s)
                    p = p.contents.Next
                out[a.FriendlyName or str(a.AdapterName, "ascii", "replace")] = {
                    "gateway": gates, "dns": dnss,
                    "mtu": int(a.Mtu), "speed": int(a.ReceiveLinkSpeed), "iftype": int(a.IfType),
                }
            node = a.Next
    except Exception:
        return {}
    return out


def adapter_gw_dns():
    return _adapter_gw_dns()


def _run(cmd, timeout=20):
    from .core import run_cmd
    return run_cmd(cmd, timeout=timeout)


def ping(host, count=2, timeout_ms=1000):
    """返回 {ok, avg, n}。正则同时兼容中英文 ping 输出。"""
    import re
    code, out = _run(["ping", "-n", str(count), "-w", str(timeout_ms), host],
                     timeout=count * (timeout_ms / 1000.0) + 6)
    ok = code == 0 or "TTL=" in out.upper()
    ms = [int(m) for m in re.findall(r"[=<]\s*(\d+)\s*ms", out)]
    return {"ok": bool(ok), "avg": (sum(ms) / len(ms)) if ms else None, "n": len(ms)}


def tcp_connect(host, port, timeout=3.0):
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"ok": True, "ms": (time.perf_counter() - t0) * 1000}
    except Exception as exc:
        return {"ok": False, "ms": (time.perf_counter() - t0) * 1000, "err": type(exc).__name__}


def dns_resolve(host):
    t0 = time.perf_counter()
    try:
        infos = socket.getaddrinfo(host, None)
        addrs = sorted({i[4][0] for i in infos})
        return {"ok": True, "ms": (time.perf_counter() - t0) * 1000, "addrs": addrs[:4]}
    except Exception as exc:
        return {"ok": False, "ms": (time.perf_counter() - t0) * 1000, "err": str(exc)}


_SVC_PID_CACHE = {"ts": 0.0, "map": {}}


def service_pid_map():
    """pid → [服务名]。缓存 30 秒，svchost 这类共享进程会对应多个服务。"""
    if not HAS_PSUTIL or not hasattr(psutil, "win_service_iter"):
        return {}
    if time.time() - _SVC_PID_CACHE["ts"] < 30:
        return _SVC_PID_CACHE["map"]
    out = {}
    try:
        for s in psutil.win_service_iter():
            try:
                d = s.as_dict()
            except Exception:
                continue
            pid = d.get("pid") or 0
            if pid:
                out.setdefault(pid, []).append(d.get("name") or "")
    except Exception:
        pass
    _SVC_PID_CACHE.update({"ts": time.time(), "map": out})
    return out


def net_listeners(detail=True):
    """本机 LISTEN 套接字，尽量带全"谁在听"。

    返回 [{port, ip, pid, name, exe, cmdline, ppid, user, service, family}]
    detail=False 时不查 exe/cmdline（快，但定位能力弱）。
    """
    if not HAS_PSUTIL:
        return []
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        return []

    svc = service_pid_map() if detail else {}
    cache = {}
    rows, seen = [], set()

    def proc_of(pid):
        if pid in cache:
            return cache[pid]
        d = {"name": "?", "exe": "", "cmdline": "", "ppid": 0, "user": ""}
        if pid:
            try:
                p = psutil.Process(pid)
                with p.oneshot():
                    d["name"] = p.name() or "?"
                    if detail:
                        d["exe"] = p.exe() or ""
                        d["ppid"] = p.ppid()
                        try:
                            d["cmdline"] = cmdline_text(d["exe"], p.cmdline(), mask=True)
                        except Exception:
                            d["cmdline"] = d["exe"]
                        try:
                            u = p.username() or ""
                            d["user"] = u.split("\\")[-1]
                        except Exception:
                            pass
            except Exception:
                d["name"] = "?"
        cache[pid] = d
        return d

    for c in conns:
        if c.status != psutil.CONN_LISTEN:
            continue
        try:
            port = c.laddr.port
            ip = getattr(c.laddr, "ip", None) or str(c.laddr[0])
        except Exception:
            continue
        pid = c.pid or 0
        key = (port, ip, pid)
        if key in seen:
            continue
        seen.add(key)
        d = proc_of(pid)
        rows.append({
            "port": port, "ip": ip, "pid": pid,
            "name": d["name"], "exe": d["exe"], "cmdline": d["cmdline"],
            "ppid": d["ppid"], "user": d["user"],
            "service": ", ".join(svc.get(pid, [])[:3]),
            "family": "v6" if ":" in ip else "v4",
        })
    rows.sort(key=lambda r: (r["port"], r["ip"]))
    return rows


def listener_for_pid(pid, listeners=None):
    """某进程在监听的端口，如 ['0.0.0.0:8080']。"""
    lst = listeners if listeners is not None else net_listeners()
    return [f"{r['ip']}:{r['port']}" for r in lst if r["pid"] == pid]



# ───────────────────────────── 磁盘 / 服务 ─────────────────────────────

def disk_usage_rows():
    if not HAS_PSUTIL:
        return []
    out = []
    try:
        for p in psutil.disk_partitions(all=False):
            try:
                u = psutil.disk_usage(p.mountpoint)
            except Exception:
                continue
            out.append({"device": p.device, "fstype": p.fstype,
                        "total": u.total, "used": u.used, "free": u.free})
    except Exception:
        pass
    return out


def disk_io():
    if not HAS_PSUTIL:
        return {}
    try:
        return psutil.disk_io_counters(perdisk=True) or {}
    except Exception:
        return {}


def service_list():
    """[(name, display_name, status, start_type)]"""
    if not HAS_PSUTIL or not hasattr(psutil, "win_service_iter"):
        return []
    out = []
    try:
        for s in psutil.win_service_iter():
            try:
                d = s.as_dict()
            except Exception:
                continue
            out.append((d.get("name") or "", d.get("display_name") or "",
                        (d.get("status") or "").lower(), (d.get("start_type") or "").lower()))
    except Exception:
        pass
    return out
