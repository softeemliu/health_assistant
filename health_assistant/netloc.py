"""
health_assistant.netloc — 资源管理器里的网络位置（Windows 自带 FTP / SMB / WebDAV）

为什么需要这一层：
  很多人的"FTP"其实是直接在资源管理器地址栏敲 `\\\\192.168.x.x` 或 `ftp://host`，
  既不装 FileZilla 也没有任何客户端配置文件 —— 但连接和凭据确实留在系统里。
  只查 FTP 客户端会得出"什么都没有"的错误结论。

覆盖的七条通道：
  1. 映射网络驱动器      HKCU\\Network\\<盘符>  （RemotePath / UserName / ProviderName）
  2. 当前网络连接        mpr.dll WNetOpenEnum（含注销后仍存在的连接）
  3. 网络位置快捷方式    %APPDATA%\\Microsoft\\Windows\\Network Shortcuts\\*.lnk
  4. 地址栏输入历史      HKCU\\...\\Explorer\\TypedPaths
  5. 最近访问过的位置    %APPDATA%\\Microsoft\\Windows\\Recent\\*.lnk（含 UNC）
  6. WebDAV / 挂载点     HKCU\\...\\Explorer\\MountPoints2（##host@SSL#DavWWWRoot）
  7. 保存的登录凭据      凭据管理器里目标含主机名的条目（排除 TERMSRV 远程桌面）

全部只读；密码默认解出（reveal=True），需要打码时传 reveal=False / 命令行 --mask。
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os
import re
import time

from .core import IS_WINDOWS

__all__ = [
    "wnet_connections", "mapped_drives", "network_shortcuts", "typed_paths",
    "recent_network_links", "mount_points", "network_locations",
    "scan_targets", "MASK",
]

MASK = "********"

_UNC_RE = re.compile(r"\\\\[A-Za-z0-9._$-]+\\[^\\/:*?\"<>|\r\n\x00-\x1f]{1,120}")
# 注意：不能加 \b —— .lnk 里 URI 前一个字符常是 word 字符（如 "Fftp://"），\b 会失配
_FTP_URL_RE = re.compile(r"(?i)(?:s?ftp|ftps)://[^\s\"'<>\x00-\x1f]{1,120}")
# WebDAV 走的是 http(s)，但不能把普通网址也当网络位置 —— 只在 URL 里出现 dav 特征时收
_DAV_URL_RE = re.compile(r"(?i)https?://[^\s\"'<>\x00-\x1f]{0,120}"
                         r"(?:davwwwroot|/dav|webdav|remote\.php)[^\s\"'<>\x00-\x1f]{0,80}")
# 凭据管理器里的目标名：Domain:target=\\host\share / LegacyGeneric:target=ftp://host
_CRED_TARGET_RE = re.compile(r"(?i)(?:target=)?\\\\?([A-Za-z0-9._$-]+)")


# ───────────────────────────── 1. 映射驱动器 ─────────────────────────────

def mapped_drives():
    """HKCU\\Network\\<盘符> → 持久化的映射盘（重启后仍在）。"""
    if not IS_WINDOWS:
        return []
    import winreg
    out = []
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Network") as key:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(key, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(key, sub) as sk:
                        def g(name):
                            try:
                                v = winreg.QueryValueEx(sk, name)[0]
                                return v if isinstance(v, str) else ""
                            except OSError:
                                return ""
                        remote = g("RemotePath")
                        if not remote:
                            continue
                        out.append({
                            "source": "映射驱动器", "local": f"{sub}:",
                            "remote": remote, "user": g("UserName") or "",
                            "provider": g("ProviderName") or "",
                        })
                except OSError:
                    continue
    except OSError:
        pass
    return out


# ───────────────────────────── 2. 当前网络连接（mpr.dll） ─────────────────────────────

class _NETRESOURCE(ctypes.Structure):
    _fields_ = [
        ("dwScope", wt.DWORD),
        ("dwType", wt.DWORD),
        ("dwDisplayType", wt.DWORD),
        ("dwUsage", wt.DWORD),
        ("lpLocalName", wt.LPWSTR),
        ("lpRemoteName", wt.LPWSTR),
        ("lpComment", wt.LPWSTR),
        ("lpProvider", wt.LPWSTR),
    ]


def wnet_connections():
    """WNetOpenEnumW 枚举"当前已连接"的网络资源（含未映射盘符的 UNC 连接）。"""
    if not IS_WINDOWS:
        return []
    try:
        mpr = ctypes.WinDLL("mpr", use_last_error=True)
    except Exception:
        return []

    mpr.WNetOpenEnumW.argtypes = [wt.DWORD, wt.DWORD, wt.DWORD,
                                  ctypes.POINTER(_NETRESOURCE), ctypes.POINTER(ctypes.c_void_p)]
    mpr.WNetOpenEnumW.restype = wt.DWORD
    mpr.WNetEnumResourceW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.DWORD),
                                      ctypes.c_void_p, ctypes.POINTER(wt.DWORD)]
    mpr.WNetEnumResourceW.restype = wt.DWORD
    mpr.WNetCloseEnum.argtypes = [ctypes.c_void_p]
    mpr.WNetCloseEnum.restype = wt.DWORD

    RESOURCE_CONNECTED = 0x00000001
    RESOURCETYPE_ANY = 0x00000000
    ERROR_NO_MORE_ITEMS = 259

    handle = ctypes.c_void_p()
    if mpr.WNetOpenEnumW(RESOURCE_CONNECTED, RESOURCETYPE_ANY, 0, None,
                         ctypes.byref(handle)) != 0:
        return []

    out = []
    try:
        size = 16384
        while True:
            buf = ctypes.create_string_buffer(size)
            count = wt.DWORD(0xFFFFFFFF)
            bufsize = wt.DWORD(size)
            rc = mpr.WNetEnumResourceW(handle, ctypes.byref(count), buf, ctypes.byref(bufsize))
            if rc == ERROR_NO_MORE_ITEMS or rc != 0:
                break
            if count.value == 0:
                break
            arr = ctypes.cast(buf, ctypes.POINTER(_NETRESOURCE))
            for i in range(count.value):
                nr = arr[i]
                remote = nr.lpRemoteName or ""
                if not remote:
                    continue
                out.append({
                    "source": "当前连接",
                    "local": nr.lpLocalName or "",
                    "remote": remote,
                    "user": "",
                    "provider": nr.lpProvider or "",
                })
    except Exception:
        pass
    finally:
        try:
            mpr.WNetCloseEnum(handle)
        except Exception:
            pass
    return out


# ───────────────────────────── 3~6. 快捷方式 / 历史 ─────────────────────────────

def _lnk_targets(path, limit=4):
    """从 .lnk 里挖出目标路径。

    不解析完整的 Shell Link 二进制结构：UNC 目标在文件里以 UTF-16LE 或 ANSI 明文存着，
    按两种编码各自扫一遍就够了，也不会误伤（只认 \\\\host\\share 与 ftp:// 两种形态）。
    """
    try:
        raw = open(path, "rb").read(262144)
    except OSError:
        return []
    found = []
    for enc in ("utf-16-le", "mbcs", "utf-8"):
        try:
            text = raw.decode(enc, "ignore")
        except Exception:
            continue
        for m in (_UNC_RE.findall(text) + _FTP_URL_RE.findall(text)
                  + _DAV_URL_RE.findall(text)):
            s = m.strip().rstrip("\\")
            if len(s) > 4 and s not in found:
                found.append(s)
        if found:
            break
    return found[:limit]


def _shortcut_dir(extra_label):
    out = []
    base = os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Network Shortcuts")
    if not os.path.isdir(base):
        return out
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return out
    for fn in names:
        if fn.lower() == "desktop.ini":
            continue
        full = os.path.join(base, fn)
        targets = _lnk_targets(full)
        out.append({
            "source": extra_label, "name": os.path.splitext(fn)[0],
            "path": full, "targets": targets,
            "mtime": time.strftime("%Y-%m-%d", time.localtime(_mtime(full))),
        })
    return out


def _mtime(path):
    try:
        return os.path.getmtime(path)
    except OSError:
        return 0.0


def network_shortcuts():
    """网络位置快捷方式（资源管理器左侧"网络位置"那一栏）。"""
    return _shortcut_dir("网络位置快捷方式")


def typed_paths():
    """资源管理器地址栏输入过的路径（含 UNC）。"""
    if not IS_WINDOWS:
        return []
    import winreg
    out = []
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths") as k:
            i = 0
            while True:
                try:
                    name, value, _t = winreg.EnumValue(k, i)
                except OSError:
                    break
                i += 1
                if isinstance(value, str) and (value.startswith("\\\\") or "://" in value):
                    out.append({"source": "地址栏历史", "value": value, "key": name})
    except OSError:
        pass
    return out


def recent_network_links(limit=80):
    """Recent 里指向网络位置的快捷方式 → 曾经访问过哪些 \\\\host\\share。"""
    base = os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Recent")
    if not os.path.isdir(base):
        return []
    out = []
    try:
        names = sorted(os.listdir(base), key=lambda n: -_mtime(os.path.join(base, n)))
    except OSError:
        return []
    for fn in names[:limit]:
        if not fn.lower().endswith(".lnk"):
            continue
        full = os.path.join(base, fn)
        for t in _lnk_targets(full, limit=2):
            if t.startswith("\\\\") or t.lower().startswith("ftp:"):
                out.append({"source": "最近访问", "name": os.path.splitext(fn)[0],
                            "target": t,
                            "mtime": time.strftime("%Y-%m-%d", time.localtime(_mtime(full)))})
                break
    return out


def mount_points():
    """MountPoints2 里的 WebDAV / UNC 挂载点（##host@SSL#DavWWWRoot 这种）。"""
    if not IS_WINDOWS:
        return []
    import winreg
    out = []
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2") as k:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(k, i)
                except OSError:
                    break
                i += 1
                low = sub.lower()
                if "##" in sub and ("dav" in low or "@ssl" in low or "#" in sub):
                    # ##192.168.8.100@8080#DavWWWRoot → 还原成可读形式
                    pretty = sub.lstrip("#").replace("#", "\\").replace("@SSL", ":443").replace("@", ":")
                    out.append({"source": "WebDAV/挂载点", "key": sub, "pretty": pretty})
                elif sub.startswith("\\\\") or "unc" in low:
                    out.append({"source": "挂载点(UNC)", "key": sub, "pretty": sub})
    except OSError:
        pass
    return out


# ───────────────────────────── 汇总 ─────────────────────────────

def _host_of(text):
    """从 UNC / URL / 凭据目标里抠出主机名。"""
    if not text:
        return ""
    s = str(text).strip()
    m = re.search(r"(?i)target=(.+)$", s)
    if m:
        s = m.group(1)
    s = s.lstrip("#\\")
    s = re.sub(r"(?i)^(ftp|ftps|sftp|smb|cifs|dav|https?)://", "", s)
    s = re.split(r"[\\/@#:]", s, maxsplit=1)[0]
    return s.strip()


def _kind_of(remote):
    low = (remote or "").lower()
    if low.startswith("ftp://"):
        return "ftp", "资源管理器 FTP"
    if "@ssl" in low or "davwwwroot" in low or low.startswith("https://"):
        return "webdav", "WebDAV"
    return "smb", "SMB 共享"


def _looks_network(target):
    """凭据目标像不像"网络位置"。

    Windows 存网络登录时目标名形如：
        Domain:target=\\\\192.168.8.100
        LegacyGeneric:target=\\\\nas\\share
        ftp://10.0.0.5
    而 git:https://... / appsecret:cli_xxx / qwenpaw 这类是应用自己的 token，
    不属于网络位置，必须排除 —— 否则"FTP 巡检"会列出一堆无关凭据。
    """
    t = target or ""
    m = re.search(r"(?i)target=(.+)$", t)
    val = (m.group(1) if m else t).strip()
    if val.startswith("\\\\"):
        return True
    if re.match(r"(?i)^(ftp|ftps|smb|cifs|dav|https?)://", val):
        return True
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}(?:[:\\/]|$)", val):
        return True
    return False


def network_locations(reveal=True):
    """把所有网络位置通道汇总成统一结构。返回 (entries, notes)。

    entry: {source, remote, host, user, password, pw_note, kind, kind_desc, detail}
    """
    entries, notes = [], []
    seen = set()

    def add(source, remote, user="", detail=""):
        if not remote:
            return
        kind, kind_desc = _kind_of(remote)
        host = _host_of(remote)
        key = (source, remote.lower(), (user or "").lower())
        if key in seen:
            return
        seen.add(key)
        entries.append({
            "source": source, "remote": remote, "host": host or remote,
            "user": user or "-", "kind": kind, "kind_desc": kind_desc,
            "detail": detail, "password": "", "pw_note": "", "has_password": False,
        })

    # 映射驱动器 + 当前连接
    try:
        for d in mapped_drives():
            add(d["source"], d["remote"], d["user"],
                f"{d['local']} → {d['remote']}" + (f"  提供者 {d['provider']}" if d["provider"] else ""))
    except Exception as exc:
        notes.append(f"映射驱动器读取失败: {type(exc).__name__}")

    try:
        for c in wnet_connections():
            add(c["source"], c["remote"], c["user"],
                (f"{c['local']} → " if c["local"] else "") + c["remote"])
    except Exception as exc:
        notes.append(f"当前网络连接读取失败: {type(exc).__name__}")

    # 网络位置快捷方式
    try:
        for s in network_shortcuts():
            if s["targets"]:
                for t in s["targets"]:
                    add(s["source"], t, "", f"快捷方式「{s['name']}」（{s['mtime']}）")
            else:
                add(s["source"], s["name"], "", f"快捷方式 {s['path']}（未能解析出目标）")
    except Exception as exc:
        notes.append(f"网络位置快捷方式读取失败: {type(exc).__name__}")

    # 地址栏历史 / 最近访问
    try:
        for t in typed_paths():
            add(t["source"], t["value"], "", "资源管理器地址栏输入过")
    except Exception as exc:
        notes.append(f"地址栏历史读取失败: {type(exc).__name__}")

    try:
        for r in recent_network_links():
            add(r["source"], r["target"], "", f"「{r['name']}」（{r['mtime']}）")
    except Exception as exc:
        notes.append(f"最近访问记录读取失败: {type(exc).__name__}")

    # WebDAV 挂载点
    try:
        for mp in mount_points():
            add(mp["source"], mp["pretty"], "", f"注册表键 {mp['key']}")
    except Exception as exc:
        notes.append(f"挂载点读取失败: {type(exc).__name__}")

    # 凭据管理器：把主机名对得上的凭据挂上去
    try:
        from . import credentials as _cred
        creds = _cred.cred_enum(reveal=reveal)
    except Exception as exc:
        creds = []
        notes.append(f"凭据枚举失败: {type(exc).__name__}")

    by_host = {}
    for c in creds:
        target = c.get("target") or ""
        if target.lower().startswith("termsrv"):       # 远程桌面，不是文件共享
            continue
        if not _looks_network(target):                 # git:/appsecret: 这类应用凭据排除
            continue
        host = _host_of(target).lower()
        if host:
            by_host.setdefault(host, []).append(c)

    for e in entries:
        host = (e["host"] or "").lower()
        for cand in (host, host.split(".")[0] if host else ""):
            hits = by_host.get(cand)
            if not hits:
                continue
            c = hits[0]
            e["user"] = c.get("user") or e["user"]
            e["has_password"] = True
            if reveal:
                e["password"] = c.get("password") or ""
                e["pw_note"] = c.get("pw_note") or ""
            else:
                e["password"] = MASK
                e["pw_note"] = c.get("type_name", "")
            e["detail"] = (e["detail"] + f"  凭据 {c['target'][:40]}").strip()
            break

    # 只有凭据、没找到对应连接的位置，也单独列出来（说明曾经连过）
    listed_hosts = {e["host"].lower() for e in entries}
    for host, hits in by_host.items():
        if host in listed_hosts:
            continue
        if not re.match(r"^[0-9a-z._$-]+$", host or ""):
            continue
        c = hits[0]
        entries.append({
            "source": "凭据(网络登录)", "remote": c["target"], "host": host,
            "user": c.get("user") or "-", "kind": "cred",
            "kind_desc": "保存的网络登录凭据",
            "detail": f"凭据类型 {c.get('type_name', '?')}，最后写入 {c.get('last', '')}",
            "password": (c.get("password") or "") if reveal else MASK,
            "pw_note": (c.get("pw_note") or "") if reveal else c.get("type_name", ""),
            "has_password": True,
        })
        listed_hosts.add(host)

    entries.sort(key=lambda e: (e["source"], e["host"].lower()))
    return entries, notes


def scan_targets():
    """本工具检查了哪些网络位置通道 —— 没找到也要说清楚查过哪里。"""
    appdata = os.environ.get("APPDATA", "")
    rows = [
        ("映射驱动器", r"HKCU\Network\<盘符>"),
        ("当前连接", "mpr.dll WNetOpenEnum（已连接的 UNC/网盘）"),
        ("网络位置", os.path.join(appdata, r"Microsoft\Windows\Network Shortcuts")),
        ("地址栏历史", r"HKCU\...\Explorer\TypedPaths"),
        ("最近访问", os.path.join(appdata, r"Microsoft\Windows\Recent") + "  (含 UNC 的 .lnk)"),
        ("挂载点", r"HKCU\...\Explorer\MountPoints2"),
        ("保存的登录", "凭据管理器里目标含主机名的条目（排除 TERMSRV）"),
    ]
    out = []
    import winreg
    for label, path in rows:
        if path.startswith("HKCU"):
            exist = None
            try:
                if "Network" in path:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Network"):
                        exist = True
                elif "TypedPaths" in path:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                        r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"):
                        exist = True
                elif "MountPoints2" in path:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                        r"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"):
                        exist = True
            except OSError:
                exist = False
            out.append((label, path, exist))
        elif path.startswith("mpr.dll") or "凭据管理器" in path:
            out.append((label, path, None))
        else:
            out.append((label, path, os.path.exists(path)))
    return out
