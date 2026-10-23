"""health_assistant.memtrim — 内存加速：把用不着的工作集换出去 / 清空待机缓存

先把话说清楚（界面上也要这么写）：Windows 的「内存加速」没有魔法。
真有用的只有两件事，都**可逆、不动数据、不结束进程**：

1. **释放工作集**（EmptyWorkingSet）——把某个进程占着的物理页交还给系统。
   进程本身还在、数据还在（只是暂时挪到页面文件/待机列表），下次用到会被读回来，
   代价是那一下略微卡顿。任务管理器里「可用」立刻变大。
2. **清空待机列表**（Standby list）——需要管理员。待机列表是"已缓存"的那部分，
   清掉后可用内存马上变多，但文件缓存没了，之后读盘会慢一些。

刻意不做：
  · 不结束进程（那是进程页的事，结束会丢未保存数据）；
  · 不动内存压缩（MemCompression 是内核在帮忙省内存，关掉只会更糟）；
  · 不改虚拟内存 / 注册表；
  · 不做"定时自动清理"——反复换出再换回，只会让系统更忙。
"""

from __future__ import annotations

import ctypes
import os
import struct
from ctypes import wintypes

from . import metrics

__all__ = ["status", "candidates", "trim", "purge_standby", "blocked_reason",
           "TRIM_SAFE_MB"]

# 低于这个体积不值得动（换出去也省不了多少，反而增加一次缺页）
TRIM_SAFE_MB = 300

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_psapi = ctypes.WinDLL("psapi", use_last_error=True)

# 显式声明原形：HANDLE 默认按 c_int 返回，x64 上会被截断成垃圾值 ——
# 这个坑在凭据模块踩过一次（OpenProcessToken 报错 6），这里一开始又踩了一次
# （_enable_privilege 假失败）。凡返回 HANDLE 的都必须写 restype。
_k32.GetCurrentProcess.restype = wintypes.HANDLE
_k32.OpenProcess.restype = wintypes.HANDLE
_k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
_k32.CloseHandle.argtypes = [wintypes.HANDLE]
_psapi.EmptyWorkingSet.restype = wintypes.BOOL
_psapi.EmptyWorkingSet.argtypes = [wintypes.HANDLE]
_psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
_psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                        wintypes.DWORD]
_psapi.GetPerformanceInfo.restype = wintypes.BOOL
_psapi.GetPerformanceInfo.argtypes = [ctypes.c_void_p, wintypes.DWORD]


class _PERF_INFO(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD),
                ("CommitTotal", ctypes.c_size_t),
                ("CommitLimit", ctypes.c_size_t),
                ("CommitPeak", ctypes.c_size_t),
                ("PhysicalTotal", ctypes.c_size_t),
                ("PhysicalAvailable", ctypes.c_size_t),
                ("SystemCache", ctypes.c_size_t),
                ("KernelTotal", ctypes.c_size_t),
                ("KernelPaged", ctypes.c_size_t),
                ("KernelNonpaged", ctypes.c_size_t),
                ("PageSize", ctypes.c_size_t),
                ("HandleCount", wintypes.DWORD),
                ("ProcessCount", wintypes.DWORD),
                ("ThreadCount", wintypes.DWORD),
                ("Reserved", wintypes.DWORD)]


class _PMC(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t)]


def _standby_pages():
    """待机列表页数。GlobalMemoryStatusEx 的"可用"已经把待机算进去了，
    想单独显示"其中待机缓存多少"只能问内核 —— 查不到就返回 None，不瞎猜。

    坑：SYSTEM_MEMORY_LIST_INFORMATION 实际要 176 字节（22 个 SIZE_T，比公开文档
    多一个尾巴）。按 168 字节的结构体传进去会直接 INFO_LENGTH_MISMATCH(0xC0000004)，
    所以这里给足 256 字节缓冲区，只按偏移取 PageCountByPriority（第 6~13 个 SIZE_T）。
    """
    try:
        ntdll = ctypes.WinDLL("ntdll")
        buf = ctypes.create_string_buffer(256)
        ret = wintypes.ULONG()
        st = ntdll.NtQuerySystemInformation(80, buf, 256, ctypes.byref(ret))
        if st != 0:
            return None
        vals = struct.unpack_from("<22Q", buf.raw, 0)
        return int(sum(vals[5:13]))          # 待机列表按优先级分 8 档
    except Exception:
        return None


def status():
    """内存总览。口径对齐任务管理器：可用 = 空闲 + 待机。"""
    base = metrics.memory_status() or {}
    out = {
        "total": base.get("total_phys", 0),
        "avail": base.get("avail_phys", 0),
        "load": base.get("load", 0),
        "commit_used": max(0, base.get("total_commit", 0) - base.get("avail_commit", 0)),
        "commit_limit": base.get("total_commit", 0),
        "cache": 0,
        "phys_avail": base.get("avail_phys", 0),   # 含待机的"可用"
        "standby": 0,
        "admin": False,
    }
    try:
        from .core import is_admin
        out["admin"] = bool(is_admin())
    except Exception:
        pass
    ps = 4096
    try:
        pi = _PERF_INFO()
        pi.cb = ctypes.sizeof(_PERF_INFO)
        if _psapi.GetPerformanceInfo(ctypes.byref(pi), pi.cb):
            ps = int(pi.PageSize) or 4096
            out["cache"] = int(pi.SystemCache) * ps
            out["phys_avail"] = int(pi.PhysicalAvailable) * ps
            out["commit_used"] = int(pi.CommitTotal) * ps
            out["commit_limit"] = int(pi.CommitLimit) * ps
    except Exception:
        pass
    pages = _standby_pages()
    if pages:
        out["standby"] = pages * ps
    if not out["total"]:
        out["total"] = out["phys_avail"] + int(out.get("commit_used", 0))
    return out


def blocked_reason(pid, name):
    """这些进程不给动：系统核心 / 本工具自己。返回原因或空串。"""
    low = (name or "").lower()
    if pid <= 4:
        return "系统核心进程"
    if pid == os.getpid():
        return "巡检工具自己"
    if low in metrics.KILL_BLOCK_NAMES:
        return "系统关键进程"
    if low in ("memcompression",):
        return "内存压缩仓库（内核在用）"
    return ""


def candidates(min_mb=0.0):
    """按内存占用从大到小列出可释放的进程（只读，不动任何东西）。"""
    if not metrics.HAS_PSUTIL:
        return []
    ps = metrics.psutil
    out = []
    for p in ps.process_iter(["pid", "name", "memory_info", "username"]):
        try:
            info = p.info
            mi = info.get("memory_info")
            if mi is None:
                continue
            rss = int(getattr(mi, "rss", 0) or 0)
            if rss <= 0:
                continue
            pid = info["pid"]
            name = info.get("name") or "?"
            if pid == 0 or name.lower().startswith("system idle"):
                continue
            if rss / 1024 ** 2 < min_mb:
                continue
            out.append({
                "pid": pid,
                "name": name,
                "rss": rss,
                "user": info.get("username") or "",
                "blocked": blocked_reason(pid, name),
            })
        except Exception:
            continue
    out.sort(key=lambda r: -r["rss"])
    return out


def _open_for_trim(pid):
    PROCESS_SET_QUOTA = 0x0100
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_QUERY_LIMITED = 0x1000
    for access in (PROCESS_SET_QUOTA | PROCESS_QUERY_INFORMATION,
                   PROCESS_SET_QUOTA | PROCESS_QUERY_LIMITED):
        h = _k32.OpenProcess(access, False, pid)
        if h:
            return h
    return None


def _working_set(h):
    pmc = _PMC()
    pmc.cb = ctypes.sizeof(_PMC)
    if _psapi.GetProcessMemoryInfo(h, ctypes.byref(pmc), pmc.cb):
        return int(pmc.WorkingSetSize)
    return 0


def trim(pids):
    """对给定 PID 调 EmptyWorkingSet。返回 (结果列表, 释放字节合计, 失败数)。

    不需要管理员：对自己有权限的进程（同用户、非受保护）就能做。
    失败的通常是受保护进程（杀毒/系统服务），如实报错误码，不当成成功。
    """
    rows, freed, failed = [], 0, 0
    for pid in pids:
        h = _open_for_trim(int(pid))
        if not h:
            err = ctypes.get_last_error()
            rows.append((int(pid), False, f"打不开（Windows 错误 {err}）", 0))
            failed += 1
            continue
        try:
            before = _working_set(h)
            ok = bool(_psapi.EmptyWorkingSet(h))
            err = ctypes.get_last_error()
            after = _working_set(h)
        finally:
            _k32.CloseHandle(h)
        if ok:
            saved = max(0, before - after)
            freed += saved
            rows.append((int(pid), True, "已释放", saved))
        else:
            rows.append((int(pid), False, f"释放失败（Windows 错误 {err}）", 0))
            failed += 1
    return rows, freed, failed


# ─────────────────── 待机列表（需要管理员，未公开 API） ───────────────────

_SYSTEM_MEMORY_LIST_INFORMATION = 80
_MEMORY_PURGE_STANDBY_LIST = 4


class _LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]


class _LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", _LUID), ("Attributes", wintypes.DWORD)]


class _TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wintypes.DWORD),
                ("Privileges", _LUID_AND_ATTRIBUTES * 1)]


def _enable_privilege(name):
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    adv.OpenProcessToken.restype = wintypes.BOOL
    adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                     ctypes.POINTER(wintypes.HANDLE)]
    adv.LookupPrivilegeValueW.restype = wintypes.BOOL
    adv.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR,
                                          ctypes.POINTER(_LUID)]
    adv.AdjustTokenPrivileges.restype = wintypes.BOOL
    adv.AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL,
                                          ctypes.POINTER(_TOKEN_PRIVILEGES),
                                          wintypes.DWORD, ctypes.c_void_p,
                                          ctypes.c_void_p]
    TOKEN_ADJUST_PRIVILEGES = 0x0020
    TOKEN_QUERY = 0x0008
    SE_PRIVILEGE_ENABLED = 0x0002
    tok = wintypes.HANDLE()
    if not adv.OpenProcessToken(_k32.GetCurrentProcess(),
                                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                ctypes.byref(tok)):
        return False
    try:
        luid = _LUID()
        if not adv.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
            return False
        tp = _TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        ctypes.set_last_error(0)
        if not adv.AdjustTokenPrivileges(tok, False, ctypes.byref(tp), 0, None, None):
            return False
        # 调整成功但特权"没全分配"时，GetLastError 仍是 ERROR_NOT_ALL_ASSIGNED(1300)
        return ctypes.get_last_error() == 0
    finally:
        _k32.CloseHandle(tok)


def purge_standby():
    """清空待机列表（Standby list）。返回 dict(ok, msg, before, after)。

    需要管理员 + SeProfileSingleProcessPrivilege。用的是 NtSetSystemInformation，
    属"能用但未公开"的路径 —— 失败就把 Windows 错误码如实返回，不假装成功。
    """
    before = status()
    if not before.get("admin"):
        return {"ok": False, "before": before, "after": before,
                "msg": "需要管理员身份：右键 health_assistant.cmd → 以管理员身份运行，或用管理员启动 GUI"}
    if not _enable_privilege("SeProfileSingleProcessPrivilege"):
        return {"ok": False, "before": before, "after": before,
                "msg": "拿不到「性能配置」特权（SeProfileSingleProcessPrivilege），已被系统策略拒绝"}
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    cmd = wintypes.ULONG(_MEMORY_PURGE_STANDBY_LIST)
    st = ntdll.NtSetSystemInformation(_SYSTEM_MEMORY_LIST_INFORMATION,
                                      ctypes.byref(cmd), ctypes.sizeof(cmd))
    after = status()
    if st == 0:
        saved = max(0, after.get("phys_avail", 0) - before.get("phys_avail", 0))
        return {"ok": True, "before": before, "after": after, "freed": saved,
                "msg": "待机缓存已清空"}
    return {"ok": False, "before": before, "after": after,
            "msg": f"系统拒绝（NTSTATUS 0x{st & 0xFFFFFFFF:08X}）"}
