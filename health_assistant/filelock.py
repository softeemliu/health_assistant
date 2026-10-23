"""health_assistant.filelock — 查谁占着文件 / 文件夹，并让它松手

能做的（从温和到强硬）：
  1. **看清是谁占着**：Restart Manager（系统自带的"谁在用这个文件"接口）
     + 工作目录 / 可执行文件落在该文件夹里的进程；
  2. **让它正常退出**：给那个进程的主窗口发 WM_CLOSE（等于替用户点 ×，
     程序自己有未保存内容会弹提示 —— 这是最安全的一条）；
  3. **强制结束**：kill（会丢未保存数据，只在用户明确要的时候做）。

刻意不做：
  · 不替别的进程单独关掉某个文件句柄 —— 那要往别人进程里注入代码，
    风险远大于收益（轻则程序崩，重则数据损坏），不干；
  · 不代删任意文件 —— 解除占用后回资源管理器自己删。
    本工具的删除动作只走白名单通道（见 slim / leftover）。

顺带一个常识：文件"删不掉"有两种完全不同的原因 ——
  A. 被占用（有进程开着它）→ 这个模块管；
  B. 权限不足 / 只读（没有进程占用也删不掉）→ 给诊断和命令，不代跑。
"""

from __future__ import annotations

import ctypes
import os
import stat
import time
from ctypes import wintypes

from . import metrics

__all__ = ["lockers", "close_gracefully", "permission_report", "has_window",
           "APP_TYPES"]

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_user32 = ctypes.WinDLL("user32", use_last_error=True)

# 返回 HANDLE 的函数必须写 restype，否则 x64 上按 c_int 截断（本模块吃过一次亏）
_k32.GetCurrentProcess.restype = wintypes.HANDLE

APP_TYPES = {
    1000: "后台程序", 1001: "有界面的程序", 1002: "后台窗口",
    1003: "Windows 服务", 1004: "资源管理器", 1005: "控制台程序",
    1006: "关键系统进程",
}


# ─────────────────── Restart Manager ───────────────────

class _RM_UNIQUE_PROCESS(ctypes.Structure):
    _fields_ = [("dwProcessId", wintypes.DWORD),
                ("ProcessStartTime", wintypes.FILETIME)]


class _RM_PROCESS_INFO(ctypes.Structure):
    _fields_ = [("Process", _RM_UNIQUE_PROCESS),
                ("strAppName", wintypes.WCHAR * 256),
                ("strServiceShortName", wintypes.WCHAR * 64),
                ("ApplicationType", wintypes.UINT),
                ("AppStatus", wintypes.ULONG),
                ("TSSessionId", wintypes.DWORD),
                ("bRestartable", wintypes.BOOL)]


def _rm_query(files):
    """问系统：这些文件被谁占着。返回 [(pid, 应用名, 服务名, 类型码)]。

    RmGetList 第一次调用按 0 容量问，返回 ERROR_MORE_DATA(234) 并给出需要的条数，
    再按需要数重新取 —— 一次给足也行，但那样要猜上限。
    """
    if not files:
        return []
    rm = ctypes.WinDLL("rstrtmgr", use_last_error=True)
    handle = wintypes.DWORD()
    key = ctypes.create_unicode_buffer(33)          # CCH_RM_SESSION_KEY + 1
    rc = rm.RmStartSession(ctypes.byref(handle), 0, key)
    if rc != 0:
        raise OSError(f"RmStartSession 失败（{rc}）")
    try:
        arr = (ctypes.c_wchar_p * len(files))(*files)
        rc = rm.RmRegisterResources(handle, len(files), arr, 0, None, 0, None)
        if rc != 0:
            raise OSError(f"RmRegisterResources 失败（{rc}）")
        need = wintypes.UINT(0)
        got = wintypes.UINT(0)
        reasons = wintypes.DWORD(0)
        rc = rm.RmGetList(handle, ctypes.byref(need), ctypes.byref(got),
                          None, ctypes.byref(reasons))
        if rc == 0 and need.value == 0:
            return []
        if rc not in (0, 234):
            raise OSError(f"RmGetList 失败（{rc}）")
        n = max(need.value, 1)
        buf = (_RM_PROCESS_INFO * n)()
        got.value = n
        rc = rm.RmGetList(handle, ctypes.byref(need), ctypes.byref(got),
                          buf, ctypes.byref(reasons))
        if rc not in (0, 234):
            raise OSError(f"RmGetList 取详情失败（{rc}）")
        out = []
        for i in range(got.value):
            info = buf[i]
            out.append((int(info.Process.dwProcessId),
                        (info.strAppName or "").strip(),
                        (info.strServiceShortName or "").strip(),
                        int(info.ApplicationType)))
        return out
    finally:
        rm.RmEndSession(handle)


# ─────────────────── 有没有主窗口（决定能不能"劝退"） ───────────────────

def _enum_windows():
    """返回 {pid: [hwnd, ...]}，只收可见、且不是控制台窗口的顶层窗口。

    为什么要排掉控制台窗口（ConsoleWindowClass）：给控制台窗口发 WM_CLOSE
    等于把那个 cmd 窗口关掉 —— 里面的进程会被直接终止（还会连坐子进程），
    这和"强制结束"没区别，不能算"正常退出"。这类只能走强制结束，让用户自己决定。
    """
    out = {}

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def _cb(hwnd, _lp):
        if _user32.IsWindowVisible(hwnd):
            buf = ctypes.create_unicode_buffer(64)
            _user32.GetClassNameW(hwnd, buf, 64)
            if buf.value in ("ConsoleWindowClass", "PseudoConsoleWindow"):
                return True
            pid = wintypes.DWORD()
            _user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if pid.value:
                out.setdefault(pid.value, []).append(hwnd)
        return True

    _user32.EnumWindows(_cb, 0)
    return out


def has_window(pid, _cache={}):
    if not _cache:
        _cache.update(_enum_windows())
    return bool(_cache.get(int(pid)))


def close_gracefully(pids):
    """给这些进程的主窗口发 WM_CLOSE（等于替用户点 ×）。返回 (sent, no_window)。

    **跳过本工具自己**：万一占用者是 health_assistant（比如它正读着这个文件），
    把关闭消息发给自己就是把界面关掉，用户会以为崩了。
    """
    wins = _enum_windows()
    WM_CLOSE = 0x0010
    me = os.getpid()
    sent, no_window = [], []
    for pid in pids:
        pid = int(pid)
        if pid == me:
            no_window.append(pid)
            continue
        hwnds = wins.get(pid) or []
        if not hwnds:
            no_window.append(pid)
            continue
        ok = False
        for hwnd in hwnds:
            if _user32.PostMessageW(hwnd, WM_CLOSE, 0, 0):
                ok = True
        (sent if ok else no_window).append(pid)
    return sent, no_window


# ─────────────────── 收集要问的文件 ───────────────────

def _files_for(path, max_files=400, budget=1.5):
    """文件 → 它自己；文件夹 → 里面前 N 个文件（Restart Manager 只认文件）。"""
    if os.path.isfile(path):
        return [path]
    out, t0 = [], time.time()
    for root, dirs, names in os.walk(path):
        if time.time() - t0 > budget or len(out) >= max_files:
            break
        # 跳过明显是缓存/版本库的海量目录，问它们没意义还慢
        dirs[:] = [d for d in dirs if d.lower() not in
                   (".git", ".svn", "node_modules", "__pycache__", "cache",
                    "caches", "temp", "tmp")]
        for n in names:
            out.append(os.path.join(root, n))
            if len(out) >= max_files:
                break
    return out


def lockers(path, max_files=400):
    """查占用。返回 dict：
        {path, is_dir, files_checked, holders:[{pid,name,kind,reason,can_close,exe}], error}
    """
    ap = os.path.abspath(path)
    res = {"path": ap, "is_dir": os.path.isdir(ap), "files_checked": 0,
           "holders": [], "error": ""}
    if not os.path.exists(ap):
        res["error"] = "路径不存在"
        return res

    files = _files_for(ap, max_files=max_files)
    res["files_checked"] = len(files)

    seen = {}

    def add(pid, name, kind, reason):
        if pid in seen:
            if reason not in seen[pid]["reason"]:
                seen[pid]["reason"] += "；" + reason
            return
        exe = ""
        try:
            exe = metrics.psutil.Process(pid).exe() or ""
        except Exception:
            pass
        seen[pid] = {"pid": pid, "name": name or f"PID {pid}", "kind": kind,
                     "reason": reason, "exe": exe,
                     "can_close": has_window(pid)}
        res["holders"].append(seen[pid])

    try:
        for pid, app, svc, atype in _rm_query(files):
            if pid == 0:
                continue
            name = app or (f"{svc}（服务）" if svc else f"PID {pid}")
            kind = APP_TYPES.get(atype, "进程")
            if svc:
                kind += "·服务"
            add(pid, name, kind, "正打开着这里的文件")
    except Exception as exc:
        res["error"] = f"Restart Manager 查询失败：{type(exc).__name__}: {exc}"

    # 目录还有一类占用：某个进程的工作目录 / 可执行文件就在里面（删目录时会挡着）
    if res["is_dir"] and metrics.HAS_PSUTIL:
        low = ap.lower().rstrip("\\") + "\\"
        me = os.getpid()
        for p in metrics.psutil.process_iter(["pid", "name"]):
            try:
                pid = p.info["pid"]
                if pid == me or pid in seen:
                    continue
                hit = ""
                try:
                    cwd = p.cwd() or ""
                    if cwd and (cwd.lower().rstrip("\\") + "\\").startswith(low):
                        hit = "工作目录在这个文件夹里"
                except Exception:
                    pass
                if not hit:
                    try:
                        exe = p.exe() or ""
                        if exe and exe.lower().startswith(low):
                            hit = "程序文件就在这个文件夹里"
                    except Exception:
                        pass
                if hit:
                    add(pid, p.info.get("name") or f"PID {pid}", "进程", hit)
            except Exception:
                continue

    res["holders"].sort(key=lambda h: (not h["can_close"], h["pid"]))
    return res


# ─────────────────── 权限诊断（"没占用也删不掉"的另一半） ───────────────────

def permission_report(path):
    """只读诊断：只读属性 / 能否写入 / 给用户自己执行的命令。

    没有占用却删不掉，九成是 ACL（权限）或只读属性。
    **不代跑 takeown / icacls** —— 改 ACL 属于重度操作，只给命令让用户自己决定。
    """
    ap = os.path.abspath(path)
    out = {"path": ap, "exists": os.path.exists(ap), "is_dir": os.path.isdir(ap),
           "readonly": False, "writable": False, "commands": [], "note": ""}
    if not out["exists"]:
        out["note"] = "路径不存在（可能已经被删掉了）"
        return out
    try:
        st = os.stat(ap)
        out["readonly"] = not bool(st.st_mode & stat.S_IWRITE)
    except OSError as exc:
        out["note"] = f"读属性失败：{exc}"
    try:
        out["writable"] = os.access(ap, os.W_OK)
    except Exception:
        pass
    q = f'"{ap}"'
    if out["readonly"]:
        out["note"] = "带只读属性：先去掉只读，再删。"
        out["commands"].append(f'attrib -r -s -h {q}')
    if not out["writable"] or out["readonly"]:
        out["commands"].append(f'takeown /f {q} /r /d y')
        out["commands"].append(f'icacls {q} /grant "%USERNAME%":F /t')
        if not out["note"]:
            out["note"] = "当前账号对这个位置没有写权限：需要先接管所有权再授权。"
    return out
