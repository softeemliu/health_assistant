"""
health_assistant.leftover — 卸载残留 / 程序数据目录 发现与清理

判定思路（靠"有没有主"，而不是靠名字像不像）：
  1. 已知集合：注册表 Uninstall 键里登记的程序（显示名/发布者/安装目录/卸载命令路径）。
  2. 活体证据：Windows 服务的 ImagePath、Run 自启项、当前进程 exe —— 这些路径指向的
     目录说明"还有东西在用它"，即使名字和程序名完全对不上也算有主
     （例：飞书程序在 %LOCALAPPDATA%\\Feishu，数据却在 %APPDATA%\\LarkShell）。
  3. 最近活动：目录及其一级子项的最近修改时间。还在被写 = 程序还在用。
  4. 三条都不成立 → 疑似「程序已卸载但数据没清」，再按体积/闲置天数给可信度。
  5. 反向也查：注册表登记了安装目录但目录已不存在 → 卸载残留的注册表项。

删除一律走回收站（SHFileOperation + FOF_ALLOWUNDO），不永久删除；
默认只报告，必须显式 --yes 才动手，且受白名单根目录 / 黑名单名字 / 在用检测三重约束。
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os
import re
import time

__all__ = [
    "installed_programs", "scan", "trash_paths", "dir_size", "path_in_use",
    "CANDIDATE_ROOTS", "KNOWN_JUNK", "format_size", "live_paths",
    "trash_by_user", "named_block_reason",
]

# ───────────────────────── 扫描根目录 ─────────────────────────

LOCAL = os.environ.get("LOCALAPPDATA", "")
ROAMING = os.environ.get("APPDATA", "")

# (路径, 类型, 说明)  program=程序安装目录  data=运行数据
CANDIDATE_ROOTS = [
    (r"C:\Program Files", "program", "程序安装目录"),
    (r"C:\Program Files (x86)", "program", "程序安装目录(32位)"),
    (r"C:\ProgramData", "data", "全用户共享数据"),
    (LOCAL, "data", "当前用户本地数据"),
    (ROAMING, "data", "当前用户漫游数据"),
    (os.path.join(LOCAL, "Low"), "data", "低完整性数据"),
]

# OS / 运行库自有目录：永远不作为"残留"提出
SYSTEM_OWNED = {
    "common files", "internet explorer", "modifiablewindowsapps", "windows defender",
    "windows mail", "windows media player", "windows nt", "windows photo viewer",
    "windows portable devices", "windows sidebar", "windowsapps", "dotnet",
    "msbuild", "reference assemblies", "uninstall information", "windowspowershell",
    "microsoft", "microsoft office", "microsoft.net", "application verifier",
    "windows security", "windows journal", "windows media", "wsl",
    "windows multimedia platform", "windows photo viewer", "windows sync",
    "windows identity foundation", "microsoft update health tools", "ruxim",
    "microsoft vs code", "microsoft visual studio", "microsoft sdks",
    "microsoft sql server", "microsoft analysis services", "microsoft help viewer",
    "msys", "git", "nvidia corporation", "intel", "amd", "realtek", "apple",
    "package cache", "packages", "usoshared", "usoprivate", "ssh",
    "microsoft oneget", "microsoft help", "microsoft network", "microsoft sqm",
    "microsoft cryptneturlcache", "microsoft device stage", "microsoft identity",
    "users", "desktop.ini", "documents", "start menu", "templates", "regid.*",
    "temp", "templow", "tmp", "crashdumps", "d3dscache", "connecteddevicesplatform",
    "application data", "history", "temporary internet files", "elevateddiagnostics",
    "comms", "publishers", "placeholdertilelogofolder", "virtualstore",
    "downloaded installations", "windows", "group policy", "adobe systems",
    "regid.1991-06.com.microsoft",
}

# 名字里带这些词的一律不动（系统/安全/驱动类）
HARD_BLOCK_WORDS = (
    "defender", "antivirus", "security", "firewall", "driver", "winsxs",
    "\\installer", "package cache", "\\system32", "protect", "yunshu",
    "datacloak", "egnac",
)

# 工具链缓存：可安全清理（会重新生成），单独归类，不算"卸载残留"
KNOWN_JUNK = {
    "pip": "pip 下载缓存（安全）", "npm-cache": "npm 下载缓存（安全）",
    "yarn": "yarn 缓存（安全）", "uv": "uv 缓存（安全）",
    "hermes": "Hermes 缓存（安全）", "node-gyp": "node-gyp 缓存（安全）",
    "go-build": "Go 构建缓存（安全）", "gopehpeh": "Go 缓存（安全）",
    "cmake": "CMake 缓存（安全）", "pypoetry": "Poetry 缓存（安全）",
    "npm": "npm 全局包（删后需重装）", "ms-playwright": "Playwright 浏览器（删后需重下）",
    "electron": "Electron 运行时（删后需重下）", ".m2": "Maven 本地仓库（删后需重下）",
    ".gradle": "Gradle 缓存（删后需重下）", ".cargo": "Cargo 缓存（删后需重下）",
    ".nuget": "NuGet 缓存（删后需重下）", "nuget": "NuGet 缓存（删后需重下）",
    ".conda": "Conda 缓存（删后需重下）", "conda": "Conda 环境（删后需重建）",
    "vcpkg": "vcpkg 缓存（删后需重下）", "pyenv": "pyenv 版本", "nvm": "nvm 版本",
}

_VENDOR_SUFFIX = {
    "inc", "ltd", "llc", "co", "corp", "corporation", "gmbh", "sarl",
    "technologies", "technology", "software", "studio", "studios", "team",
    "project", "projects", "company", "limited", "international", "group",
    "the", "and", "for", "with", "app", "apps", "application", "version",
}


def format_size(n):
    try:
        n = float(n)
    except Exception:
        return str(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0 or unit == "TB":
            return f"{int(n)}B" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}TB"


# ───────────────────────── 已安装程序 ─────────────────────────

_UNINSTALL_PATHS = [
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM", 64),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM", 32),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKCU", 0),
    (r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM", 0),
]


def _q(sk, name):
    """读字符串值，非字符串一律返回空。"""
    try:
        import winreg
        v = winreg.QueryValueEx(sk, name)[0]
        return v if isinstance(v, str) else ("" if v is None else str(v))
    except Exception:
        return ""


def installed_programs():
    """汇总注册表里登记的程序。"""
    try:
        import winreg
    except Exception:
        return []

    out, seen = [], set()
    for path, hive, flag in _UNINSTALL_PATHS:
        root = winreg.HKEY_LOCAL_MACHINE if hive == "HKLM" else winreg.HKEY_CURRENT_USER
        access = winreg.KEY_READ | (winreg.KEY_WOW64_64KEY if flag == 64 else
                                    winreg.KEY_WOW64_32KEY if flag == 32 else 0)
        try:
            key = winreg.OpenKey(root, path, 0, access)
        except OSError:
            continue
        i = 0
        while True:
            try:
                sub = winreg.EnumKey(key, i)
            except OSError:
                break
            i += 1
            try:
                with winreg.OpenKey(key, sub) as sk:
                    name = _q(sk, "DisplayName").strip()
                    if not name:
                        continue
                    uri = f"{hive}\\{sub}".lower()
                    if uri in seen:
                        continue
                    seen.add(uri)
                    out.append({
                        "name": name,
                        "publisher": _q(sk, "Publisher").strip(),
                        "version": _q(sk, "DisplayVersion").strip(),
                        "location": _q(sk, "InstallLocation").strip().strip('"'),
                        "uninstall": _q(sk, "UninstallString").strip(),
                        "icon": _q(sk, "DisplayIcon").strip(),
                        "key": sub,
                        "source": uri,
                        "hive": hive,          # HKLM / HKCU，删除时要用
                        "parent": path,        # 完整父键，删除时要用
                        "view": flag,          # 64 / 32 / 0，删除时要按同一视图打开
                        "system_component": _q(sk, "SystemComponent").strip() == "1",
                    })
            except OSError:
                continue
        try:
            winreg.CloseKey(key)
        except Exception:
            pass
    return out


# ───────────────────────── 活体证据（服务/自启/进程） ─────────────────────────

_EXE_RE = re.compile(r'([A-Za-z]:\\[^"]+?\.exe)', re.I)


def _service_paths():
    import winreg
    out = []
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services")
    except OSError:
        return out
    i = 0
    while True:
        try:
            name = winreg.EnumKey(key, i)
        except OSError:
            break
        i += 1
        try:
            with winreg.OpenKey(key, name) as sk:
                ip = _q(sk, "ImagePath")
        except OSError:
            continue
        if not ip:
            continue
        m = _EXE_RE.search(ip.replace('"', ""))
        if m:
            out.append(m.group(1))
    return out


def _run_key_paths():
    import winreg
    out = []
    for hive, path in ((winreg.HKEY_LOCAL_MACHINE,
                        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                       (winreg.HKEY_CURRENT_USER,
                        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                       (winreg.HKEY_LOCAL_MACHINE,
                        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")):
        try:
            key = winreg.OpenKey(hive, path)
        except OSError:
            continue
        i = 0
        while True:
            try:
                _n, v, _t = winreg.EnumValue(key, i)
            except OSError:
                break
            i += 1
            if not isinstance(v, str):
                continue
            m = _EXE_RE.search(v.replace('"', ""))
            if m:
                out.append(m.group(1))
    return out


def _process_paths():
    try:
        import psutil
    except Exception:
        return []
    out = []
    for p in psutil.process_iter(["exe"]):
        try:
            exe = p.info.get("exe")
            if exe:
                out.append(exe)
        except Exception:
            continue
    return out


def live_paths():
    """返回所有"有主"的 exe 路径（小写）。失败项自动跳过。"""
    paths = []
    for fn in (_service_paths, _run_key_paths, _process_paths):
        try:
            paths.extend(fn())
        except Exception:
            continue
    return sorted({p.lower() for p in paths if p})


# ───────────────────────── 名字归一化与匹配 ─────────────────────────

def _norm_tokens(text):
    s = (text or "").lower()
    s = s.replace("（", "(").replace("）", ")").replace("【", " ").replace("】", " ")
    s = re.sub(r"\([^)]*\)", " ", s)                       # (x64) / (64-bit) / 中文别名
    s = re.sub(r"\bv?\d+(\.\d+)+[a-z0-9]*\b", " ", s)      # 1.2.3 / v2.0
    s = re.sub(r"[^0-9a-z\u4e00-\u9fff]+", " ", s)
    out = []
    for t in s.split():
        if not t or t.isdigit() or t in _VENDOR_SUFFIX:
            continue
        out.append(t)
    return out


def _basename(path):
    p = (path or "").replace("/", "\\").rstrip("\\")
    return p.split("\\")[-1] if p else ""


def _app_dir_names():
    """磁盘上现存的程序目录名（含用户级 Programs），作为旁证。"""
    names = set()
    dirs = [r"C:\Program Files", r"C:\Program Files (x86)",
            os.path.join(LOCAL, "Programs"), os.path.join(LOCAL, "Programs", "Common")]
    for d in dirs:
        try:
            for e in os.scandir(d):
                if e.is_dir(follow_symlinks=False):
                    names.add(e.name.lower())
        except OSError:
            continue
    return names


def _build_index(programs):
    tokens, paths = {}, []
    for p in programs:
        if p.get("system_component"):
            continue
        for src in (p["name"], p["publisher"], _basename(p["location"]),
                    _basename(_EXE_RE.search(p["icon"].replace('"', "")).group(1))
                    if _EXE_RE.search(p["icon"].replace('"', "")) else ""):
            for t in _norm_tokens(src):
                if len(t) >= 3:
                    tokens.setdefault(t, []).append(p["name"])
        for cand in (p["location"], p["uninstall"], p["icon"]):
            m = _EXE_RE.search((cand or "").replace('"', ""))
            frag = (m.group(1) if m else (cand or "")).lower().rstrip("\\")
            if frag and "\\" in frag:
                paths.append((frag, p["name"]))
    return {
        "tokens": tokens,
        "paths": paths,
        "app_dirs": _app_dir_names(),
        "live": live_paths(),
    }


def _match_dir(name, full_path, idx, allow_appdir=True):
    """返回 (命中的程序名列表, 证据类型)。空列表 = 没有任何东西认领。

    allow_appdir=False 用于 Program Files 自身：那里的目录名天然都在
    idx["app_dirs"] 里，拿它当证据等于自己认领自己，会漏掉安装目录残留。
    """
    hits, kinds = [], set()

    for t in _norm_tokens(name):
        if len(t) < 3:
            continue
        for known, owners in idx["tokens"].items():
            if t == known or (len(t) >= 4 and (known.startswith(t) or t.startswith(known))):
                hits.extend(owners)
                kinds.add("程序名")
                break

    low = name.lower()
    if not hits and len(low) >= 4:
        for loc, owner in idx["paths"]:
            if low in loc:
                hits.append(owner)
                kinds.add("安装路径")
                break

    # 磁盘上同名程序目录（可能是无注册表项的绿色/用户级安装）
    if not hits and allow_appdir and low in idx["app_dirs"]:
        hits.append(f"<{name}>")
        kinds.add("同名程序目录")

    # 活体证据：服务/自启/进程的 exe 落在这个目录下面
    base = os.path.abspath(full_path).lower().rstrip("\\") + "\\"
    for exe in idx["live"]:
        if exe.startswith(base):
            hits.append("运行中组件")
            kinds.add("服务/自启/进程")
            break

    seen, uniq = set(), []
    for h in hits:
        if h.lower() not in seen:
            seen.add(h.lower())
            uniq.append(h)
    return uniq, "+".join(sorted(kinds))


# ───────────────────────── 体积 / 活动时间 / 占用 ─────────────────────────

def dir_size(path, max_files=40000, budget=8.0):
    """返回 (字节数, 文件数, 是否被截断)。超预算即停，避免卡死。"""
    total = files = 0
    truncated = False
    started = time.time()
    stack = [path]
    while stack:
        if files >= max_files or (time.time() - started) > budget:
            truncated = True
            break
        cur = stack.pop()
        try:
            with os.scandir(cur) as it:
                for e in it:
                    try:
                        if e.is_dir(follow_symlinks=False):
                            stack.append(e.path)
                        elif e.is_file(follow_symlinks=False):
                            total += e.stat(follow_symlinks=False).st_size
                            files += 1
                            if files >= max_files:
                                truncated = True
                                break
                    except OSError:
                        continue
        except OSError:
            continue
    return total, files, truncated


def _latest_activity(path, limit=200):
    """目录自身 + 一级子项的最近修改时间（判断"还在被写"）。"""
    newest = 0.0
    try:
        newest = os.stat(path).st_mtime
    except OSError:
        pass
    try:
        n = 0
        with os.scandir(path) as it:
            for e in it:
                try:
                    newest = max(newest, e.stat(follow_symlinks=False).st_mtime)
                except OSError:
                    pass
                n += 1
                if n >= limit:
                    break
    except OSError:
        pass
    return newest


def path_in_use(path):
    """哪些进程的执行文件在这个目录里。返回 ["name(pid)"]。"""
    try:
        import psutil
    except Exception:
        return []
    low = os.path.abspath(path).lower().rstrip("\\") + "\\"
    hits = []
    for p in psutil.process_iter(["pid", "name", "exe"]):
        try:
            if (p.info.get("exe") or "").lower().startswith(low):
                hits.append(f"{p.info.get('name') or '?'}({p.info['pid']})")
        except Exception:
            continue
    return hits[:4]


# ───────────────────────── 主扫描 ─────────────────────────

def scan(min_mb=1.0, older_days=0, roots=None, active_days=45,
         include_matched=False, max_seconds=90):
    """扫描疑似残留。只读，不改动任何文件。

    min_mb         : 只报告不小于该体积的目录
    older_days     : 只报告"最近活动"早于 N 天的目录（0=不限）
    active_days    : 最近 N 天内有写入 → 视为仍在使用，不列为残留
    include_matched: 连"有主"的目录一起列出（默认只列疑似残留/缓存）
    """
    programs = installed_programs()
    idx = _build_index(programs)

    use_roots = roots or [(r, k, d) for r, k, d in CANDIDATE_ROOTS if r and os.path.isdir(r)]

    items, errors = [], []
    scanned = 0
    started = time.time()

    for root, kind, desc in use_roots:
        if not os.path.isdir(root):
            continue
        try:
            entries = sorted(os.scandir(root), key=lambda e: e.name.lower())
        except OSError as exc:
            errors.append(f"{root}: {exc}")
            continue
        for e in entries:
            if time.time() - started > max_seconds:
                errors.append(f"扫描超时（{max_seconds}s），已提前结束")
                break
            try:
                if not e.is_dir(follow_symlinks=False):
                    continue
            except OSError:
                continue
            name = e.name
            low = name.lower()
            if low in SYSTEM_OWNED or low.startswith(("$", ".", "~")):
                continue
            scanned += 1

            matched, evidence = _match_dir(name, e.path, idx, allow_appdir=(kind == "data"))
            # 缓存归类只对数据目录有意义；Program Files 下的同名目录是程序本体
            junk = KNOWN_JUNK.get(low) if kind == "data" else None
            if matched and not include_matched:
                continue

            size, files, truncated = dir_size(e.path)
            if size / 1048576 < min_mb:
                continue

            latest = _latest_activity(e.path)
            idle = int((time.time() - latest) / 86400) if latest else 9999
            if older_days and idle < older_days:
                continue

            if matched:
                category = "matched"
                note = "有程序认领（" + evidence + "）"
            elif junk:
                category = "cache"
                note = junk
            elif idle <= active_days:
                category = "live"
                note = f"{idle} 天内有写入，程序应该还在用"
            else:
                category = "leftover"
                note = "无程序认领，且长期无写入"

            if category == "leftover":
                confidence = "high" if (idle >= 180 and size >= 50 * 1048576) else "medium"
            elif category == "cache":
                confidence = "high"
            else:
                confidence = "low"

            items.append({
                "path": e.path, "name": name, "root": root, "kind": kind,
                "kind_desc": desc, "size": size, "files": files,
                "truncated": truncated, "idle_days": idle,
                "last_active": time.strftime("%Y-%m-%d", time.localtime(latest)) if latest else "-",
                "matched": matched, "evidence": evidence,
                "category": category, "note": note, "confidence": confidence,
            })

    # 注册表幽灵：登记了安装目录但目录不存在
    ghosts, seen_g = [], set()
    for p in programs:
        loc = (p.get("location") or "").strip().strip('"')
        if not loc or len(loc) < 6:
            continue
        key = (p["name"].lower(), loc.lower())
        if key in seen_g:
            continue
        seen_g.add(key)
        try:
            # 有的登记项写的是 %ProgramFiles%\Foo，不展开会误判成「目录不存在」
            if not os.path.exists(os.path.expandvars(loc)):
                ghosts.append({"name": p["name"], "location": loc,
                               "version": p["version"], "key": p["key"],
                               "hive": p.get("hive") or "HKLM",
                               "parent": p.get("parent") or "",
                               "view": p.get("view") or 0})
        except OSError:
            continue

    items.sort(key=lambda x: (-x["size"], x["path"].lower()))
    return {
        "items": items, "ghosts": ghosts,
        "programs": len(programs), "scanned_dirs": scanned,
        "elapsed": round(time.time() - started, 1), "errors": errors,
        "live_paths": len(idx["live"]),
        "roots": [(r, d) for r, _k, d in use_roots],
        "active_days": active_days,
    }


# ───────────────────────── 删除（回收站） ─────────────────────────

_FO_DELETE = 0x0003
_FOF_SILENT = 0x0004
_FOF_NOCONFIRMATION = 0x0010
_FOF_ALLOWUNDO = 0x0040
_FOF_NOERRORUI = 0x0400


class _SHFILEOPSTRUCTW(ctypes.Structure):
    _fields_ = [
        ("hwnd", wt.HWND),
        ("wFunc", wt.UINT),
        ("pFrom", wt.LPCWSTR),
        ("pTo", wt.LPCWSTR),
        ("fFlags", ctypes.c_uint16),
        ("fAnyOperationsAborted", wt.BOOL),
        ("hNameMappings", ctypes.c_void_p),
        ("lpszProgressTitle", wt.LPCWSTR),
    ]


def _recycle_count(path):
    """统计该盘回收站里的 $R 条目数，用于确认"确实进了回收站"。读不到返回 None。"""
    try:
        drive = os.path.splitdrive(os.path.abspath(path))[0] + "\\"
        rb = os.path.join(drive, "$Recycle.Bin")
        n = 0
        for sid in os.listdir(rb):
            try:
                with os.scandir(os.path.join(rb, sid)) as it:
                    for e in it:
                        if e.name.startswith("$R"):
                            n += 1
            except OSError:
                continue
        return n
    except OSError:
        return None


def _shell_delete(paths):
    """一次 SHFileOperation 调用（进回收站）。返回 (ok, 信息)。

    注意：这个 API 的返回码不可靠 —— 实测删除成功后也会返回 2（ERROR_FILE_NOT_FOUND），
    所以成败判断放到调用方用「目录是否还在 + 回收站条目是否增加」来定。
    """
    if not paths:
        return True, ""
    buf = "\0".join(os.path.abspath(p) for p in paths) + "\0\0"
    op = _SHFILEOPSTRUCTW()
    op.hwnd = None
    op.wFunc = _FO_DELETE
    op.pFrom = buf
    op.pTo = None
    op.fFlags = _FOF_ALLOWUNDO | _FOF_NOCONFIRMATION | _FOF_SILENT | _FOF_NOERRORUI
    try:
        res = ctypes.WinDLL("shell32", use_last_error=True).SHFileOperationW(ctypes.byref(op))
    except Exception as exc:
        return False, f"调用失败: {exc}"
    if op.fAnyOperationsAborted:
        return False, "操作被中止"
    if res not in (0, 2):
        return False, f"SHFileOperation 返回 {res} (0x{res:X})"
    return True, ""


def _profile_safe_cache(name_low):
    """这个名字的目录，profile 的规则表已经认定「删了没影响」的缓存。

    为什么要在删除侧再判一次：`SYSTEM_OWNED` 是**按名字全局兜底**的粗名单，
    里面有 `downloaded installations`（InstallShield 把安装源解压到这儿，装完就没人用）、
    `d3dscache`（着色器缓存）、`connecteddevicesplatform` 这类 ——
    而 `profile.APPDATA_RULES` 明确把它们标成 `safe`。
    两边不一致的后果用户已经撞上了：**扫描列出来说「安装包残留（安全）」，
    点删除却回「命中系统目录白名单」**，可他拿资源管理器一删就删掉了。

    判据只留一份（`profile.APPDATA_RULES` 的第三列 == "safe"），这里只转发。
    注意 `temp` / `tmp` / `packages` / `microsoft` 这些在规则表里是 review / keep，
    仍然拦着 —— Temp 目录本身永远不许删。
    """
    try:
        from .profile import APPDATA_RULES
    except Exception:                        # noqa: BLE001  循环导入等，宁可保守
        return False
    ent = APPDATA_RULES.get(name_low)
    return bool(ent and len(ent) >= 3 and ent[2] == "safe")


def trash_paths(paths, max_batch=50, allow_exact=None, allow_system_names=False):
    """把目录移到回收站（可撤销）。返回 (成功[(path, 说明)], 失败[(path, 原因)])。

    allow_exact: 额外允许的精确路径集合（用于用户目录下的缓存目录 ——
    它们不在 CANDIDATE_ROOTS 里，但由 profile 扫描明确点名，必须逐个匹配才放行）。
    allow_system_names: 允许"名字像系统目录"的目标（temp / tmp / packages …）。
    默认 False，因为 SYSTEM_OWNED 是按名字全局兜底的 —— %LOCALAPPDATA% 下的 Temp
    这类真系统目录绝不能被误删。置 True 时也只对 allow_exact 里点过名的路径生效。
    其余三重闸（系统目录黑名单 / 保护关键词 / 在用检测）照样生效。
    """
    ok_list, bad = [], []
    allowed = [r.lower().rstrip("\\") for r, _k, _d in CANDIDATE_ROOTS if r]
    exact = {os.path.abspath(p).lower().rstrip("\\") for p in (allow_exact or [])}

    for p in paths[:max_batch]:
        ap = os.path.abspath(p)
        low = ap.lower().rstrip("\\")
        if not os.path.isdir(ap):
            bad.append((p, "不存在或不是目录"))
            continue
        if low not in exact and not any(low.startswith(r + "\\") for r in allowed):
            bad.append((p, "不在允许清理的根目录内"))
            continue
        name_low = os.path.basename(ap).lower()
        if name_low in SYSTEM_OWNED and not _profile_safe_cache(name_low):
            if not (allow_system_names and low in exact):
                bad.append((p, "命中系统目录白名单"))
                continue
        if any(w in low for w in HARD_BLOCK_WORDS):
            bad.append((p, "命中保护关键词"))
            continue
        busy = path_in_use(ap)
        if busy:
            bad.append((p, f"仍有进程在使用: {', '.join(busy)}"))
            continue

        before = _recycle_count(ap)
        ok, msg = _shell_delete([ap])
        gone = not os.path.exists(ap)
        after = _recycle_count(ap)

        if gone and (before is None or after is None or after > before):
            ok_list.append((p, "已移入回收站（可还原）"))
        elif gone:
            ok_list.append((p, "已删除，但回收站里没找到 —— 可能是永久删除，请注意"))
        elif ok:
            bad.append((p, "调用成功但目录仍在（可能被占用）"))
        else:
            bad.append((p, msg))
    return ok_list, bad


# ─────────────────── 界面点名删除（「空间去哪了」右键） ───────────────────
#
# 第三条删除通道，只有一种调用方：用户在「空间去哪了」里右键某一项、看过确认框、
# 再点「移到回收站」。为什么不能直接复用上面两条：
#   · trash_paths 只认 CANDIDATE_ROOTS（Program Files / ProgramData / AppData），
#     用户在 D:\旧资料 或 C:\临时 上右键会被判「不在允许清理的根目录内」；
#   · slim.trash 只认 ZOMBIE_ROOTS / USER_ROOTS / TEMP_ROOTS，同理。
# 但「用户点名」不等于放开一切。「空间去哪了」能钻到任意位置，所以闸门比上面两条更硬：
# 盘符根、系统目录本身、用户主目录及其标准文件夹、SYSTEM_OWNED 名字、安全/驱动/管控
# 关键词、链接与挂载点、正在被程序使用的目录 —— 一律拒绝。宁可拒绝，也不给
# 「删了才发现不对」的机会（这条是 4.4.0 加的，别把它放宽成通用删除）。

_REPARSE_POINT = 0x400


def _protected_roots():
    """这些路径本身永远不能当「被删对象」（只保护路径自身，不保护其子项）。"""
    home = os.path.expanduser("~")
    roots = {home}
    for name in ("Desktop", "Documents", "Downloads", "Pictures", "Videos",
                 "Music", "Favorites", "OneDrive", "AppData"):
        roots.add(os.path.join(home, name))
    system_drive = os.environ.get("SystemDrive", "C:") + "\\"
    for name in ("Windows", "Program Files", "Program Files (x86)",
                 "ProgramData", "Users", "PerfLogs"):
        roots.add(os.path.join(system_drive, name))
    for r, _kind, _desc in CANDIDATE_ROOTS:
        if r:
            roots.add(r)
    roots.update({LOCAL, ROAMING, os.path.join(LOCAL, "Low") if LOCAL else ""})
    return {os.path.normcase(os.path.abspath(r)).rstrip("\\") for r in roots if r}


def _is_reparse(path):
    """目录是不是链接 / 挂载点（Junction、符号链接）：删它会牵连到目标，不代删。"""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return bool(getattr(st, "st_file_attributes", 0) & _REPARSE_POINT)


def named_block_reason(path):
    """能不能「点名删」。能删返回 None，不能返回一句给用户看的中文原因。"""
    try:
        ap = os.path.abspath(path)
    except (TypeError, ValueError):
        return "路径不合法"
    if not os.path.exists(ap):
        return "已经不在了"

    # 8.3 短名是个真实的洞：%TEMP% 展开就是 C:\Users\ADMINI~1\...，
    # 直接和 %LOCALAPPDATA% 的 C:\Users\Administrator\... 比字符串会漏。
    # 所以两种写法都算一遍，任何一种是保护区就拦（realpath 会还原长名）。
    forms = {os.path.normcase(ap).rstrip("\\")}
    try:
        forms.add(os.path.normcase(os.path.realpath(ap)).rstrip("\\"))
    except OSError:
        pass

    _drive, tail = os.path.splitdrive(ap)
    if not tail.strip("\\/"):
        return "整个磁盘不能这样删"

    if _is_reparse(ap):
        return "这是链接或挂载点，删它会牵连到别的位置"
    roots = _protected_roots()
    if any(f in roots for f in forms):
        return "这是系统目录或你的主目录本身，不能删"

    sysroot = os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows")).rstrip("\\") + "\\"
    if any(f.startswith(sysroot) for f in forms):
        return "Windows 自带的东西，请到「清理空间 → 系统盘瘦身」里处理"

    names = {os.path.basename(f.replace("/", "\\")).lower() for f in forms}
    blocked = {n for n in names if n in SYSTEM_OWNED and not _profile_safe_cache(n)}
    if blocked:
        # 用「」而不是（）—— 这句会被拼进菜单项的括号里，避免括号套括号
        return "系统自带目录「%s」，不能删" % sorted(blocked)[0]
    if any("$recycle.bin" in f for f in forms):
        return "回收站本身不能删"
    if any(any(w in f for w in HARD_BLOCK_WORDS) for f in forms):
        return "属于安全/驱动/管控类，不代删"

    if os.path.isdir(ap):
        busy = path_in_use(ap)
        if busy:
            return "还有程序在用：" + "、".join(busy[:3])
    return None


def trash_by_user(paths, max_batch=10):
    """把用户点名的路径移到回收站（可还原）。返回 (成功[(path, 说明)], 失败[(path, 原因)])。

    一次最多 10 项 —— 界面上是单选右键，给多选留余量，但绝不接受「整批几百个」。
    逐条调用 SHFileOperation（和 slim.trash 同一个教训：批量时一条失败会连坐整批）。
    成败以「原位置是否还在 + 回收站条目是否增加」判定，不信 API 返回码。
    """
    ok_list, bad = [], []
    for p in list(paths or [])[:max_batch]:
        ap = os.path.abspath(p)
        reason = named_block_reason(ap)
        if reason:
            bad.append((p, reason))
            continue

        before = _recycle_count(ap)
        ok, msg = _shell_delete([ap])
        gone = not os.path.exists(ap)
        after = _recycle_count(ap)

        if gone and (before is None or after is None or after > before):
            ok_list.append((p, "已移入回收站（可还原）"))
        elif gone:
            ok_list.append((p, "已删除，但回收站里没找到 —— 可能是永久删除，请注意"))
        elif ok:
            bad.append((p, "调用成功但还在原处（可能被占用）"))
        else:
            bad.append((p, msg))
    return ok_list, bad
