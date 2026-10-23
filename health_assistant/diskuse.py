"""health_assistant.diskuse — 空间去哪了：目录体积逐层下钻

为什么单独做
    现有体检回答的是「系统盘还剩多少」「用户目录里谁大」。
    但 C 盘满了的时候，人真正想知道的是「C:\\ 底下哪个文件夹最占地方」，
    然后一层层点下去 —— 这就是本模块 + 「空间去哪了」窗口做的事。

三条硬规则
    1. **不跟随 junction / 符号链接**。Windows 自带一堆（C:\\Users\\All Users、
       C:\\Documents and Settings、OneDrive 占位符…），跟进去不是重复计算就是
       无限循环。判断用 st_file_attributes 的 REPARSE_POINT 位，只认一次。
    2. **有时间预算**。一个盘几十万文件，扫到底要几分钟。到点就停，
       被截断的那项标 partial=True，界面显示「≥」，绝不假装测准了
       （口径：截断了就不能给确定数字）。
    3. **只读**。这里不算「可释放」，只回答「谁占着」。要清理走清理页的白名单通道。
"""

from __future__ import annotations

import os
import time

__all__ = ["drives", "children", "walk_size", "quick_jump", "is_reparse"]

FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def is_reparse(entry):
    """这个条目是不是 junction / 符号链接（不跟进去）。"""
    try:
        st = entry.stat(follow_symlinks=False)
    except OSError:
        return True
    return bool(getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)


def drives():
    """所有固定磁盘（含盘符、卷标、总量、可用）。"""
    if os.name != "nt":
        return []
    import ctypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.GetLogicalDrives.restype = ctypes.c_uint
    mask = k32.GetLogicalDrives()
    k32.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
    k32.GetDriveTypeW.restype = ctypes.c_uint
    k32.GetDiskFreeSpaceExW.argtypes = [
        ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_ulonglong),
        ctypes.POINTER(ctypes.c_ulonglong), ctypes.POINTER(ctypes.c_ulonglong)]
    k32.GetDiskFreeSpaceExW.restype = ctypes.c_int
    k32.GetVolumeInformationW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint,
        ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint),
        ctypes.POINTER(ctypes.c_uint), ctypes.c_wchar_p, ctypes.c_uint]

    out = []
    for i in range(26):
        if not mask & (1 << i):
            continue
        root = f"{chr(65 + i)}:\\"
        # 只留本地固定盘（DRIVE_FIXED=3）；U 盘/网络盘扫起来慢且意义不大
        if k32.GetDriveTypeW(root) != 3:
            continue
        free = ctypes.c_ulonglong(0)
        total = ctypes.c_ulonglong(0)
        if not k32.GetDiskFreeSpaceExW(root, None, ctypes.byref(total),
                                       ctypes.byref(free)):
            continue
        name = ctypes.create_unicode_buffer(64)
        k32.GetVolumeInformationW(root, name, 64, None, None, None, None, 0)
        out.append({
            "path": root,
            "letter": root[:2],
            "label": name.value or "",
            "total": int(total.value),
            "free": int(free.value),
            "used": max(0, int(total.value) - int(free.value)),
        })
    return out


def walk_size(path, deadline=None, should_stop=None):
    """递归算一个目录的体积。

    返回 dict(size, files, dirs, partial, denied)。
    partial=True 表示预算用完了、后面没算完 —— 体积是**下界**。
    denied 计数表示有多少子目录因为权限读不进去（体积同样只是下界）。
    should_stop 是个无参函数，返回 True 就立刻收手（用户换了目录 / 关了窗口）。
    """
    total = files = dirs = denied = 0
    partial = False
    stack = [path]
    while stack:
        if deadline is not None and time.monotonic() > deadline:
            partial = True
            break
        if should_stop is not None and should_stop():
            partial = True
            break
        cur = stack.pop()
        try:
            with os.scandir(cur) as it:
                for e in it:
                    try:
                        if e.is_dir(follow_symlinks=False):
                            if is_reparse(e):
                                continue          # junction / 符号链接：不跟
                            dirs += 1
                            stack.append(e.path)
                        else:
                            total += e.stat(follow_symlinks=False).st_size
                            files += 1
                    except OSError:
                        continue
        except PermissionError:
            denied += 1
        except OSError:
            denied += 1
    return {"size": total, "files": files, "dirs": dirs,
            "partial": partial, "denied": denied}


def children(path, budget=20.0, min_bytes=0, keep=0, on_item=None, workers=4,
             should_stop=None):
    """列出一个目录下各子项的体积，大的在前。

    keep=0 表示全列；>0 时只保留前 keep 项，其余合成「另有 N 项」汇总，
    保证表格不被上百个小文件淹掉。

    on_item：每算完一项就回调一次（界面据此边算边出结果，不必等全部算完）。
    并行：同一层的几个大目录用 4 个线程同时统计 —— 单项预算 = 总预算 / 线程数，
    所以最慢的一层大约就是 budget 秒。某项没算完（partial）时它的体积是**下界**，
    界面会标「≥」；点进那一层会重新按更大预算精算。
    """
    path = os.path.normpath(path)
    t0 = time.monotonic()
    try:
        with os.scandir(path) as it:
            entries = list(it)
    except PermissionError:
        return {"path": path, "items": [], "rest": None, "denied": 0,
                "error": "没有权限读取这个文件夹", "truncated": False, "elapsed": 0.0}
    except OSError as exc:
        return {"path": path, "items": [], "rest": None, "denied": 0,
                "error": f"{type(exc).__name__}: {exc}", "truncated": False,
                "elapsed": 0.0}

    # 先分流：目录（排除 junction）和文件。文件体积是现成的，不用 worker
    dirs, files = [], []
    for e in entries:
        try:
            if e.is_dir(follow_symlinks=False):
                if is_reparse(e):
                    continue                      # 链接不占空间，也不算
                dirs.append(e)
            else:
                st = e.stat(follow_symlinks=False)
                files.append((e.name, e.path, st.st_size))
        except OSError:
            continue

    workers = max(1, min(workers, len(dirs) or 1))
    per_item = max(1.0, float(budget) / workers)
    items = []

    def work(entry):
        info = walk_size(entry.path, time.monotonic() + per_item, should_stop)
        return {
            "name": entry.name, "path": entry.path, "is_dir": True,
            "size": info["size"], "files": info["files"],
            "partial": info["partial"] or bool(info["denied"]),
            # 一点都没算到（排队时预算就耗光了）—— 界面要写「没算完」而不是 0B
            "unscanned": info["files"] == 0 and info["dirs"] == 0
                         and info["size"] == 0 and info["partial"],
        }

    denied = 0
    truncated = False
    if dirs:
        from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
        with ThreadPoolExecutor(max_workers=workers) as ex:
            pending = {ex.submit(work, e) for e in dirs}
            while pending:
                if should_stop is not None and should_stop():
                    truncated = True
                    for f in pending:
                        f.cancel()
                    break
                done, pending = wait(pending, timeout=0.4,
                                     return_when=FIRST_COMPLETED)
                for fut in done:
                    try:
                        item = fut.result()
                    except Exception:
                        denied += 1
                        continue
                    if item["partial"]:
                        truncated = True
                    items.append(item)
                    if on_item is not None:
                        try:
                            on_item(item)
                        except Exception:
                            pass

    for name, full, size in files:
        items.append({"name": name, "path": full, "is_dir": False,
                      "size": size, "files": 1, "partial": False,
                      "unscanned": False})

    items.sort(key=lambda x: -x["size"])
    if min_bytes:
        items = [i for i in items if i["size"] >= min_bytes]

    rest = None
    if keep and len(items) > keep:
        tail = items[keep:]
        rest = {"count": len(tail), "size": sum(i["size"] for i in tail)}
        items = items[:keep]

    return {
        "path": path,
        "items": items,
        "rest": rest,
        "denied": denied,
        "error": None,
        "truncated": truncated,
        "elapsed": round(time.monotonic() - t0, 2),
    }


def quick_jump():
    """几个「十有八九在这儿」的位置，省掉从上往下一层层点。

    只列真实存在的，路径对不上就不出现 —— 不猜。
    """
    env = os.environ
    sysd = env.get("SystemDrive") or "C:"
    home = env.get("USERPROFILE") or ""
    cands = [
        (sysd + "\\", "系统盘根目录"),
        (os.path.join(sysd + "\\", "Users"), "各用户的文件"),
        (os.path.join(sysd + "\\", "Windows"), "Windows 系统"),
        (os.path.join(sysd + "\\", "ProgramData"), "程序公共数据"),
        (os.path.join(sysd + "\\", "Program Files"), "64 位程序"),
        (os.path.join(sysd + "\\", "Program Files (x86)"), "32 位程序"),
        (env.get("LOCALAPPDATA") or "", "当前用户 AppData(Local)"),
        (env.get("APPDATA") or "", "当前用户 AppData(Roaming)"),
        (env.get("TEMP") or "", "临时文件夹"),
        (os.path.join(home, "Downloads") if home else "", "我的下载"),
        (os.path.join(home, "Documents") if home else "", "我的文档"),
        (os.path.join(home, "Desktop") if home else "", "桌面"),
    ]
    out, seen = [], set()
    for path, desc in cands:
        if not path:
            continue
        try:
            full = os.path.normpath(path)
        except (ValueError, OSError):
            continue
        if not full or full.lower() in seen or not os.path.isdir(full):
            continue
        seen.add(full.lower())
        out.append({"path": full, "desc": desc})
    return out
