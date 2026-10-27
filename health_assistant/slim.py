"""
health_assistant.slim — 系统盘瘦身：僵尸文件 / 无用用户文件 / 空间大头

三块内容，危险等级完全不同，必须分开对待：

A. 僵尸文件（zombie）—— "没有主人"的东西
   · 断链快捷方式：.lnk 的目标 exe 已经不存在（程序卸了，图标还留着）
     用户能直接感觉到：双击没反应 / 弹「找不到项目」。
   · 崩溃转储：%LOCALAPPDATA%\\CrashDumps、C:\\Windows\\Minidump、MEMORY.DMP。
   · Temp 里的内容：%LOCALAPPDATA%\\Temp、C:\\Windows\\Temp。
     **只列/只清内容，永远不删 Temp 目录本身** —— Windows 和大量程序要它存在。
     现有的 cache_candidates 把 temp / tmp 放在 _NEVER_TRASH 里，所以这 12GB
     从来没被清过，是这台机器最大的可回收项。

B. 无用用户文件（userjunk）—— "有用过但现在不需要"的东西
   · 下载目录里的旧安装包（.exe/.msi/.zip/.7z/.rar/.iso）。
     **删了要重下**，所以标 caution，必须用户自己勾。
   · Office 残留临时文件（~$xxx.docx）—— 对应文档不存在、或文档比它还新，
     说明是上次崩溃留下的锁文件。

C. 系统空间大头（只报告，绝不代删）
   · hiberfil.sys / pagefile.sys / swapfile.sys
   · Windows.old / SoftwareDistribution\\Download / WinSxS
   这些要么需要 SYSTEM 权限、要么关掉会丢功能（休眠、蓝屏分析、系统回退），
   按项目既定约定只给命令，不代跑。

刻意不做的两类（实测结论，别再往回加）：
   1. **0 字节文件**：桌面/文档下扫出 141 个，90% 是 SQLite 的 `-journal`、
      `.svn/wc.db-journal`、程序自己的 `lock.ini` 占位。删了会让数据库/版本库
      误判事务状态，收益接近 0（本来就不占空间），风险不是 0。不做。
   2. **重复文件**：要对整个用户目录做哈希，耗时以分钟计；而且"内容相同"不等于
      "可以删"（同名配置、多版本备份都是有意义的）。收益不确定，误删不可逆，不做。

删除一律走回收站（可还原），且必须逐个通过白名单 + 保护关键词 + 在用检测。
"""

from __future__ import annotations

import ctypes
import os
import struct
import time

from . import leftover

__all__ = ["scan", "trash", "space_hogs", "lnk_target", "KIND_LABELS",
           "format_size", "ALL_ROOTS"]

format_size = leftover.format_size

KIND_LABELS = {
    "shortcut": "断链快捷方式",
    "crashdump": "崩溃转储",
    "temp": "临时文件",
    "oldinstaller": "旧安装包",
    "officetmp": "Office 残留临时文件",
}

# 删除白名单：这三个列表的并集。根本身永远不允许删（只能删它下面的条目）。
ALL_ROOTS = ()          # 在文件末尾由 ZOMBIE_ROOTS + USER_ROOTS + TEMP_ROOTS 填充

HOME = os.path.expanduser("~")
LOCAL = os.environ.get("LOCALAPPDATA", "")
ROAMING = os.environ.get("APPDATA", "")
PROGRAMDATA = os.environ.get("ProgramData", "")
WINDIR = os.environ.get("SystemRoot", r"C:\Windows")

# ─────────────────── 白名单：只在这些位置动手 ───────────────────
# (路径, 说明)  —— 目录型根，删除时子项都必须在某个根之下
ZOMBIE_ROOTS = [
    (os.path.join(HOME, "Desktop"), "桌面"),
    (os.path.join(ROAMING, "Microsoft", "Windows", "Start Menu"), "开始菜单"),
    (os.path.join(PROGRAMDATA, "Microsoft", "Windows", "Start Menu"), "开始菜单（所有用户）"),
    (os.path.join(ROAMING, "Microsoft", "Internet Explorer", "Quick Launch"), "快速启动栏"),
    (os.path.join(LOCAL, "CrashDumps"), "程序崩溃转储"),
    (os.path.join(WINDIR, "Minidump"), "蓝屏小转储"),
]

USER_ROOTS = [
    (os.path.join(HOME, "Downloads"), "下载"),
    (os.path.join(HOME, "Desktop"), "桌面"),
    (os.path.join(HOME, "Documents"), "文档"),
]

TEMP_ROOTS = [
    (os.path.join(LOCAL, "Temp"), "用户临时文件"),
    (os.path.join(WINDIR, "Temp"), "系统临时文件"),
]

# 用户目录里这些子目录是"程序自己的数据",不是用户的散文件
# （微信/企业微信的 cache 里全是 -journal 和 Sns 缓存，动它等于动程序数据）
#
# 注意：这里**不能**放 "\\appdata" —— 用户的「开始菜单」本身就在
# %APPDATA%\Microsoft\Windows\Start Menu 下面，按 \appdata 拦会把整片开始菜单
# 的断链快捷方式全部漏掉（实测 22 条断链只剩 8 条）。要排程序数据就用具体目录名。
USER_DATA_DENY = (
    "\\xwechat_files", "\\wxwork", "\\wechat files", "\\tencent files",
    "\\.svn", "\\.git", "\\.hg", "\\node_modules",
    "\\$recycle.bin", "\\system volume information",
)

# 旧安装包按扩展名区分说法：exe/msi 才是"安装包"，zip/7z/rar 只是压缩包
INSTALLER_EXT = (".exe", ".msi", ".msix", ".appx")
ARCHIVE_EXT = (".zip", ".7z", ".rar", ".iso", ".tar", ".gz")

# .exe 不能一律当安装包 —— 桌面上大量「绿色软件/小工具」也是 .exe
# （实测把 Desktop\同步数据库\MysqlSync.exe 误判成安装包，那东西是有人在用的工具）。
# 只有文件名带这些特征才认为是安装程序。.msi 天生就是安装包，不受此限。
_INSTALLER_WORDS = ("setup", "install", "安装", "update", "upgrade",
                    "-x64", "_x64", "-x86", "_x86", "-amd64", "_amd64", "-win64")

# Temp 里这些顶层条目不碰：可能是正在运行的程序的工作目录
TEMP_KEEP = ("systemtemp", "hsperfdata_system")

# 瘦身自己的保护词（在 leftover.HARD_BLOCK_WORDS 之外再补几条）。
# edr_package 是本机企业管控（亿格云）推下来的组件包，删了会被策略重新下发、
# 还可能触发告警 —— 收益是省 160MB，代价是惹事，不值得。
SLIM_GUARD = ("edr_package", "\\bzprotect", "yunshu", "datacloak", "egnac",
              "\\windows defender", "\\installer")


# ─────────────────────── 工具 ───────────────────────

def _norm(p):
    return os.path.normcase(os.path.abspath(p)).rstrip("\\")


def _under(path, roots):
    """path 是否在某个白名单根之下（不是根本身）。返回根的说明或 None。"""
    ap = _norm(path)
    for root, desc in roots:
        if not root:
            continue
        rx = _norm(root)
        if ap.startswith(rx + "\\"):
            return desc
    return None


def _denied(path):
    low = _norm(path)
    return any(w in low for w in USER_DATA_DENY) or \
        any(w in low for w in leftover.HARD_BLOCK_WORDS) or \
        any(w in low for w in SLIM_GUARD)


def _walk(top, budget=8.0, max_files=60000, max_depth=6):
    """带预算的遍历，产出 (path, stat)。"""
    started = time.time()
    stack = [(top, 0)]
    n = 0
    while stack:
        if time.time() - started > budget or n > max_files:
            return
        cur, depth = stack.pop()
        try:
            with os.scandir(cur) as it:
                for e in it:
                    n += 1
                    if n > max_files or time.time() - started > budget:
                        return
                    try:
                        if e.is_dir(follow_symlinks=False):
                            if depth < max_depth:
                                stack.append((e.path, depth + 1))
                        elif e.is_file(follow_symlinks=False):
                            yield e.path, e.stat(follow_symlinks=False)
                    except OSError:
                        continue
        except OSError:
            continue


def _idle_days(st):
    try:
        return max(0, int((time.time() - st.st_mtime) / 86400))
    except Exception:
        return 0


def _tail(text, width):
    """长路径保留尾部（前面对比意义不大）。"""
    text = str(text or "")
    return text if len(text) <= width else "…" + text[-(width - 1):]


def _entry(path, st, category, kind, note, confidence, files=1):
    return {
        "path": path, "name": os.path.basename(path.rstrip("\\")) or path,
        "size": st.st_size if st is not None else 0,
        "files": files, "idle_days": _idle_days(st) if st is not None else 0,
        "category": category, "kind": kind, "note": note,
        "confidence": confidence, "truncated": False,
        "is_dir": st is None,
    }


# ─────────────────── 断链快捷方式 ───────────────────

def lnk_target(path):
    """解析 .lnk 的目标路径。返回 str 或 None（解析不了就返回 None，不猜）。

    只读 LinkInfo 里的 LocalBasePath —— 这是 MS-SHLLINK 里对本地文件最直接的
    记录。注意偏移：LinkInfo 头是 size(0..4) / headerSize(4..8) / flags(8..12) /
    volumeIDOffset(12..16) / localBasePathOffset(16..20)，
    flags 在 8..12，**不是** 4..8（照着 headerSize 判 flags 会恒为 0，全部解析失败）。
    """
    try:
        with open(path, "rb") as fh:
            data = fh.read(16384)
    except OSError:
        return None
    if len(data) < 76 or data[:4] != b"L\x00\x00\x00":
        return None
    try:
        flags = struct.unpack("<I", data[20:24])[0]
        pos = 76
        if flags & 0x01:                                  # HasLinkTargetIDList
            idl = struct.unpack("<H", data[pos:pos + 2])[0]
            pos += 2 + idl
        if not flags & 0x02:                              # HasLinkInfo
            return None
        li_size = struct.unpack("<I", data[pos:pos + 4])[0]
        li = data[pos:pos + li_size]
        if len(li) < 20:
            return None
        li_flags = struct.unpack("<I", li[8:12])[0]
        base_off = struct.unpack("<I", li[16:20])[0]
        if not li_flags & 0x1 or not (0 < base_off < len(li)):
            return None
        raw = li[base_off:]
        end = raw.find(b"\x00")
        txt = raw[:end if end >= 0 else len(li)].decode("mbcs", "replace").strip()
        return txt or None
    except (struct.error, IndexError):
        return None


def scan_shortcuts(budget=6.0):
    """断链快捷方式：目标不存在。只认能解析出目标的那种，解析不了的不动。"""
    items, seen = [], set()
    for root, desc in ZOMBIE_ROOTS:
        if not root or not os.path.isdir(root):
            continue
        if "CrashDumps" in root or "Minidump" in root:
            continue
        for p, st in _walk(root, budget=budget):
            if not p.lower().endswith(".lnk") or _denied(p):
                continue
            key = _norm(p)
            if key in seen:
                continue
            seen.add(key)
            target = lnk_target(p)
            if not target:
                continue
            try:
                if os.path.exists(target):
                    continue
            except OSError:
                continue
            items.append(_entry(p, st, "zombie", "shortcut",
                                f"指向的程序已不在：{_tail(target, 56)}", "high"))
    return items


# ─────────────────── 崩溃转储 ───────────────────

def scan_crashdumps():
    items = []
    for root, desc in ZOMBIE_ROOTS:
        if not root or not os.path.isdir(root) or \
                not ("CrashDumps" in root or "Minidump" in root):
            continue
        for p, st in _walk(root, budget=4.0, max_depth=2):
            if not p.lower().endswith((".dmp", ".mdmp")):
                continue
            if st.st_size < 1024:            # 几十字节的残片没意义
                continue
            items.append(_entry(p, st, "zombie", "crashdump",
                                "程序崩溃时留下的内存快照", "high"))
    dmp = os.path.join(WINDIR, "MEMORY.DMP")
    if os.path.isfile(dmp):
        try:
            st = os.stat(dmp)
            items.append(_entry(dmp, st, "zombie", "crashdump",
                                "整机内存转储（蓝屏分析用，通常可删）", "high"))
        except OSError:
            pass
    return items


# ─────────────────── Temp 内容 ───────────────────

def scan_temp(budget=8.0, min_mb=0.0):
    """Temp 目录的**内容**（一级条目按体积聚合），永远不列 Temp 目录本身。

    `min_mb=0`（默认）表示**一个都不漏**：Temp 里每个文件、每个目录都列出来。
    实测本机 Temp 顶层 21375 个条目 / 5.24 GB（最大 2.8GB，最小几十字节），
    全列出来表格 2 万多行 —— 用户要的就是「我自己挑」，那就全给。
    `min_mb > 0` 时低于它的一律并进一条「零散小文件」汇总项，体积照样进合计，
    不会让人误以为「已经干净了」（以前只在悬浮提示里带一句，等于看不见）。

    返回 (items, skipped_count, skipped_bytes)
    """
    items = []
    skip_n = 0
    skip_b = 0
    for root, desc in TEMP_ROOTS:
        if not root or not os.path.isdir(root):
            continue
        try:
            entries = list(os.scandir(root))
        except OSError:
            continue
        for e in entries:
            if e.name.lower() in TEMP_KEEP or _denied(e.path):
                continue
            try:
                if e.is_dir(follow_symlinks=False):
                    size, files, trunc = leftover.dir_size(e.path, budget=max(1.0, budget / 4))
                    if size <= 0:
                        continue
                    if size / 1048576 < min_mb:
                        skip_n += files
                        skip_b += size
                        continue
                    try:
                        latest = e.stat(follow_symlinks=False).st_mtime
                    except OSError:
                        latest = time.time()
                    items.append({
                        "path": e.path, "name": e.name, "size": size, "files": files,
                        "idle_days": int((time.time() - latest) / 86400),
                        "category": "zombie", "kind": "temp",
                        "note": f"{desc}（目录，可整块移到回收站）",
                        "confidence": "medium", "truncated": trunc, "is_dir": True,
                    })
                else:
                    st = e.stat(follow_symlinks=False)
                    if st.st_size <= 0:
                        continue
                    if st.st_size / 1048576 < min_mb:
                        skip_n += 1
                        skip_b += st.st_size
                        continue
                    items.append(_entry(e.path, st, "zombie", "temp",
                                        f"{desc}（单个文件）", "medium"))
            except OSError:
                continue
    items.sort(key=lambda x: -x["size"])
    if skip_n:
        # 被阈值挡掉的那批聚成**一条**：以前只在悬浮提示里带一句「另有 N 个未列出」，
        # 用户看到的是「Temp 里明明有东西，工具说没有」。实测本机 Temp 顶层 21375 个
        # 条目里 21041 个小于 1MB（合计 885MB），全被 10MB 阈值挡在外面 —— 其中就有
        # 用户来问的 BIT9E84.tmp。聚合成一条既不淹没列表，也不会让人误以为「干净了」。
        items.append({
            # path 故意给一段**不存在的文字**：这类条目不能真去删（两万多个文件逐个
            # 移回收站要几十分钟，而且 Temp 目录本身绝不许删）。trash() 第一步就会判
            # 「已经不存在」并跳过，白名单也因此不会被绕开。
            "path": "（用户 Temp + 系统 Temp）", "name": f"Temp 里的零散小文件（{skip_n} 个）",
            "size": skip_b, "files": skip_n, "idle_days": 0,
            "category": "zombie", "kind": "temp_small",
            "note": (f"合计 {skip_b / 1048576:.0f} MB，每个都小于 {min_mb:g}MB。"
                     f"建议用 Windows「磁盘清理 / 存储感知」一次清掉（它直接删、更快）"),
            "confidence": "low", "is_dir": False, "aggregate": True,
        })
    return items, skip_n, skip_b


# ─────────────────── 旧安装包 ───────────────────

def scan_old_installers(older_days=60, budget=6.0, min_mb=0.0):
    items = []
    cut = older_days * 86400
    now = time.time()
    exts = INSTALLER_EXT + ARCHIVE_EXT
    for root, desc in USER_ROOTS:
        if not root or not os.path.isdir(root):
            continue
        for p, st in _walk(root, budget=budget, max_depth=4):
            low = p.lower()
            if not low.endswith(exts):
                continue
            if st.st_size / 1048576 < min_mb:
                continue
            if _denied(p):
                continue
            if now - st.st_mtime < cut:
                continue
            name = os.path.basename(low)
            if low.endswith(".exe") and not any(w in name for w in _INSTALLER_WORDS):
                continue          # 看不出是安装程序的 exe 不动（可能是绿色软件）
            what = "安装包" if low.endswith(INSTALLER_EXT) else "压缩包"
            items.append(_entry(p, st, "userjunk", "oldinstaller",
                                f"{desc}目录里的{what}（{older_days} 天没动过，删了要重新下载）",
                                "medium"))
    items.sort(key=lambda x: -x["size"])
    return items


# ─────────────────── Office 临时文件 ───────────────────

def scan_office_tmp(older_days=3, budget=5.0):
    """~$ 开头的 Office 锁文件：对应文档不存在，或文档比它还新 → 是残留。

    判断依据（不靠猜）：
      ~$报告.docx  → 真实文档是 报告.docx
      · 文档不存在 → 残留（文档可能被删/改名了）
      · 文档的修改时间 >= 锁文件 → 说明文档已正常保存过，锁文件是旧的
    反过来，文档比锁文件旧 → 可能真有未保存的编辑，不动。
    """
    items = []
    for root, desc in USER_ROOTS:
        if not root or not os.path.isdir(root):
            continue
        for p, st in _walk(root, budget=budget, max_depth=4):
            name = os.path.basename(p)
            if not name.startswith("~$") or _denied(p):
                continue
            stem = name[2:]
            doc = os.path.join(os.path.dirname(p), stem)
            reason = ""
            if not os.path.exists(doc):
                reason = "对应文档已不在这里"
            else:
                try:
                    dmt = os.stat(doc).st_mtime
                    if dmt >= st.st_mtime - 1:
                        reason = "对应文档已正常保存过"
                except OSError:
                    continue
            if not reason:
                continue
            items.append(_entry(p, st, "userjunk", "officetmp",
                                f"Office 残留锁文件：{reason}", "high"))
    return items


# ─────────────────── 空间大头（只报告） ───────────────────

def _safe_size(path, budget=6.0):
    if os.path.isfile(path):
        try:
            return os.path.getsize(path), 1, False
        except OSError:
            return 0, 0, False
    if os.path.isdir(path):
        return leftover.dir_size(path, budget=budget)
    return 0, 0, False


def _recycle_size():
    """回收站占用（SHQueryRecycleBin）。返回 (字节, 文件数) 或 None。"""
    try:
        class SHQUERYRBINFO(ctypes.Structure):
            _fields_ = [("cbSize", ctypes.c_ulong), ("i64Size", ctypes.c_longlong),
                        ("i64NumItems", ctypes.c_longlong)]
        info = SHQUERYRBINFO()
        info.cbSize = ctypes.sizeof(SHQUERYRBINFO)
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        shell32.SHQueryRecycleBinW.argtypes = [ctypes.c_wchar_p,
                                               ctypes.POINTER(SHQUERYRBINFO)]
        hr = shell32.SHQueryRecycleBinW(None, ctypes.byref(info))
        if hr == 0:
            return int(info.i64Size), int(info.i64NumItems)
    except Exception:
        pass
    return None


def space_hogs(budget=6.0):
    """系统盘的大头。全部只报告，删除/关闭一律给命令让用户自己执行。"""
    hogs = []

    def add(path, title, note, cmd="", admin=False):
        size, files, trunc = _safe_size(path, budget=budget)
        if size <= 0:
            return
        hogs.append({"path": path, "title": title, "size": size, "files": files,
                     "note": note, "cmd": cmd, "admin": admin,
                     "truncated": trunc, "is_dir": os.path.isdir(path)})

    add(os.path.join(os.environ.get("SystemDrive", "C:") + "\\", "hiberfil.sys"),
        "休眠文件",
        "不用休眠/快速启动就能关掉，立刻回收同等空间",
        "powercfg /h off", admin=True)
    add(os.path.join(os.environ.get("SystemDrive", "C:") + "\\", "pagefile.sys"),
        "虚拟内存文件",
        "系统托管，内存充足才调小，别直接删",
        "sysdm.cpl → 高级 → 性能设置 → 高级", admin=True)
    add(os.path.join(os.environ.get("SystemDrive", "C:") + "\\", "swapfile.sys"),
        "UWP 交换文件",
        "随虚拟内存自动生成，无需单独处理", "")
    add(os.path.join(os.environ.get("SystemDrive", "C:") + "\\", "Windows.old"),
        "旧系统备份",
        "升级后留下的上一版本，删了不能回退",
        "设置 → 系统 → 存储 → 临时文件", admin=True)
    add(os.path.join(WINDIR, "SoftwareDistribution", "Download"),
        "系统更新缓存",
        "更新装完就没用了，删了会按需重下",
        "net stop wuauserv（停服务后清 Download）", admin=True)
    add(os.path.join(HOME, "AppData", "Local", "CrashDumps"),
        "程序崩溃转储",
        "程序崩溃时的内存快照，排查完即可删", "")

    rb = _recycle_size()
    if rb and rb[0] > 0:
        hogs.append({"path": "回收站", "title": "回收站",
                     "size": rb[0], "files": rb[1], "truncated": False,
                     "note": "确认不需要还原就清空",
                     "cmd": "右键回收站 → 清空回收站", "admin": False,
                     "is_dir": False})

    hogs.sort(key=lambda x: -x["size"])
    return hogs


# ─────────────────── 主扫描 ───────────────────

def scan(kind="all", older_days=60, min_mb=0.0, budget=20.0):
    """只读扫描。kind: zombie / userjunk / all。

    min_mb 只作用于 Temp 里的散落条目（目录型残留不受影响）。
    返回 {items, elapsed, errors, counts, small_files, small_bytes}
    """
    started = time.time()
    items, errors = [], []
    small_n = small_b = 0

    want_zombie = kind in ("zombie", "all")
    want_user = kind in ("userjunk", "all")

    if want_zombie:
        try:
            items.extend(scan_shortcuts(budget=budget / 4))
        except Exception as exc:
            errors.append(f"快捷方式扫描失败: {type(exc).__name__}: {exc}")
        try:
            items.extend(scan_crashdumps())
        except Exception as exc:
            errors.append(f"崩溃转储扫描失败: {type(exc).__name__}: {exc}")
        try:
            t_items, small_n, small_b = scan_temp(budget=budget / 2, min_mb=min_mb)
            items.extend(t_items)
        except Exception as exc:
            errors.append(f"临时文件扫描失败: {type(exc).__name__}: {exc}")

    if want_user:
        try:
            items.extend(scan_old_installers(older_days=older_days,
                                             budget=budget / 4, min_mb=min_mb))
        except Exception as exc:
            errors.append(f"安装包扫描失败: {type(exc).__name__}: {exc}")
        try:
            items.extend(scan_office_tmp(budget=budget / 4))
        except Exception as exc:
            errors.append(f"Office 临时文件扫描失败: {type(exc).__name__}: {exc}")

    # 去重 + 排序
    seen, uniq = set(), []
    for it in sorted(items, key=lambda x: -x["size"]):
        key = _norm(it["path"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(it)

    counts = {}
    for it in uniq:
        counts[it["kind"]] = counts.get(it["kind"], 0) + 1

    return {"items": uniq, "elapsed": round(time.time() - started, 1),
            "errors": errors, "counts": counts,
            "small_files": small_n, "small_bytes": small_b,
            "total": sum(i["size"] for i in uniq)}


# ─────────────────── 删除（移到回收站，可还原） ───────────────────

ALL_ROOTS = tuple(ZOMBIE_ROOTS + USER_ROOTS + TEMP_ROOTS)


def _recycle_stats():
    """(字节, 条目数)；查不到给 None。

    判断「是否真进了回收站」两个都要看：删 0 字节文件时字节数**完全不变**，
    只看字节会把正常删除误报成「可能被永久删除」（3.8.2 实测踩到）。
    """
    return _recycle_size()


# 删不掉时用来问"到底为什么"的探测（只开句柄，不删除）
_K32 = None
_ERR_TEXT = {
    2: "文件已经不在了", 3: "路径已经不在了",
    5: "没有权限（需要管理员，或文件被系统/管控软件保护）",
    19: "磁盘写保护", 32: "正被别的程序占用", 33: "文件区域被锁定",
}


def _why_stuck(path):
    """删除失败的真实原因。CreateFileW 要 DELETE 权限 + 独占共享，能开就说明能删。

    只用于**已经失败**的那几条（几十个），所以不在乎开销；
    比笼统写一句「可能被占用，或者需要管理员权限」有用得多 —— 用户能据此决定
    是关掉程序重试、还是直接跳过。
    """
    global _K32
    try:
        if _K32 is None:
            from ctypes import wintypes
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.CreateFileW.restype = wintypes.HANDLE
            k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                        wintypes.DWORD, wintypes.LPVOID,
                                        wintypes.DWORD, wintypes.DWORD,
                                        wintypes.HANDLE]
            k32.CloseHandle.argtypes = [wintypes.HANDLE]
            _K32 = k32
        DELETE = 0x00010000
        BACKUP_SEMANTICS = 0x02000000        # 打开目录句柄必须带这个
        h = _K32.CreateFileW(path, DELETE, 0, None, 3,
                             BACKUP_SEMANTICS, None)
        err = ctypes.get_last_error()
        if h and h != ctypes.c_void_p(-1).value:
            _K32.CloseHandle(h)
            # 能拿到 DELETE 权限、也能独占打开 → 不是权限也不是占用。
            # 目录和文件要分开说：目录句柄能开不代表里面的子项删得掉。
            if os.path.isdir(path):
                return ("目录本身有权限，但里面的内容删不掉"
                        "（可能被系统或管控软件锁定，或需要管理员）")
            return ("可以删但回收站没收下"
                    "（可能被安全/管控软件拦截，或超过回收站容量）")
        if err == 5:
            return "没有权限（需要管理员，或文件被系统/管控软件保护）"
        if err == 32:
            return "正被别的程序占用（关掉对应程序后重试）"
        return f"删不掉（Windows 错误 {err}：{_ERR_TEXT.get(err, '未知')}）"
    except Exception as exc:                       # 探测失败不影响主流程
        return f"删不掉（探测原因时出错：{type(exc).__name__}）"


def trash(paths, max_batch=500, batch_size=None, progress=None):
    """把扫出来的条目移到回收站。返回 (成功[(path, 说明)], 失败[(path, 原因)])。

    每条都要过四道闸，任何一道不过就跳过、不删：
      1. 存在性 —— 扫描到现在可能已经被用户自己删了/移走了；
      2. 白名单 —— 必须在 ZOMBIE_ROOTS / USER_ROOTS / TEMP_ROOTS 之下，
         **根本身不许删**（尤其 Temp 目录，删了 Windows 和一堆程序会出问题）；
      3. 保护规则 —— 安全/驱动/管控类关键词、微信与版本库数据目录；
      4. 在用检测 —— 目录里有进程的 exe 在跑就不动。

    **一条一条删，不打包批量**（3.8.2 踩过的坑）：SHFileOperation 的 pFrom 是
    多字符串，它遇到第一个出错项就**中止整批**——实测一条 Temp 下的 Diagnostics
    目录权限不足，把后面 47 条本来能删的临时文件全连坐了，界面显示「失败 47 个」。
    逐条调用多花的是毫秒级开销，换来的是「一条坏的不影响其他」。
    batch_size 仅为兼容旧调用方保留，传了也不再用。

    `progress(已处理, 总数)`：不放限制之后用户可以一次勾上万个文件，
    逐个 SHFileOperation 要一两分钟 —— 没有进度反馈，界面看起来就是卡死。
    """
    ok_list, bad = [], []
    todo = []
    for p in paths[:max_batch]:
        ap = os.path.abspath(p)
        if not os.path.exists(ap):
            bad.append((p, "已经不存在"))
            continue
        if not _under(ap, ALL_ROOTS):
            bad.append((p, "不在允许清理的位置"))
            continue
        if _denied(ap):
            bad.append((p, "命中保护规则（安全/驱动/程序数据目录）"))
            continue
        if os.path.isdir(ap):
            busy = leftover.path_in_use(ap)
            if busy:
                bad.append((p, f"仍有进程在使用: {', '.join(busy)}"))

                continue
        todo.append(ap)

    # 回收站状态只查一次开头，之后每轮把上一轮的结果当作「before」——
    # SHQueryRecycleBin 一次 27ms，逐条查两遍的话 200 项白等 10 秒。
    prev = _recycle_stats()
    total = len(todo)
    for idx, ap in enumerate(todo):
        if progress and (idx % 10 == 0 or idx == total - 1):
            progress(idx + 1, total)
        leftover._shell_delete([ap])
        cur = _recycle_stats()
        grew = None
        if prev and cur:
            grew = cur[0] > prev[0] or cur[1] > prev[1]
        prev = cur
        if not os.path.exists(ap):
            if grew is False:
                ok_list.append((ap, "已删除，但回收站没变大 —— 可能被永久删除，请注意"))
            else:
                ok_list.append((ap, "已移入回收站（可还原）"))
        else:
            bad.append((ap, _why_stuck(ap)))
    return ok_list, bad
