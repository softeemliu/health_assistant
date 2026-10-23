"""
health_assistant.credentials — 凭据 / 浏览器登录 / FTP 站点 访问层

明文显示默认开启（reveal=True，命令行默认明文、加 --mask 遮罩），
只走「本机当前用户本来就能读」的通道，不做提权、不做绕过：
  · Windows 凭据管理器 CredRead —— 取回本账户自己的 CredentialBlob
  · FileZilla 站点密码 —— Base64（本来就不是加密）
  · WinSCP 会话密码 —— DPAPI（当前用户上下文可解）
  · Chrome/Edge 旧格式 —— v10/v11 = AES-256-GCM(密钥在 Local State，DPAPI 保护)；
                          更早的版本 = 裸 DPAPI

Chrome 127+ 起密码改为 v20「应用绑定加密（App-Bound Encryption）」，
该机制的设计目的就是阻止其它进程批量取走浏览器密码。本工具不实现绕过。
需要浏览器密码明文时走系统授权路径：
    chrome://password-manager/settings → 导出密码（需 Windows 登录确认）
    然后  python -m health_assistant import-passwords <导出的.csv>
"""

from __future__ import annotations

import base64
import configparser
import csv
import ctypes
import ctypes.wintypes as wt
import json
import os
import re
import shutil
import sqlite3
import tempfile
import time
import uuid

from .core import IS_WINDOWS, chrome_time, filetime_to_dt

__all__ = [
    "CRED_TYPE", "CRED_PERSIST", "MASK",
    "cred_enum", "cred_delete", "cred_write", "cred_secret", "cred_backup",
    "browser_login_files", "browser_logins", "browser_logins_for",
    "browser_delete", "browser_processes",
    "filezilla_sites", "winscp_sites", "totalcmd_sites", "ftp_sites_all",
    "ftp_scan_targets", "ftp_trace", "import_password_csv", "dpapi_unprotect",
    "BROWSERS", "IMPORT_CACHE", "load_imported", "save_imported", "clear_imported",
    "auto_import_source",
    "find_export_csv", "download_dirs",
]

MASK = "********"

# Chrome 127+ 的应用绑定加密前缀；不复原
_ABE_PREFIXES = (b"v20",)

# v20 的显示标记：不用星号，避免被误当成「本工具在遮罩」
ABE_MARK = "⟨v20加密⟩"

# 浏览器导出 CSV 的落盘缓存（只有 --save 才写）
IMPORT_CACHE = os.path.join(os.environ.get("APPDATA", ""), "health_assistant",
                            "imported-passwords.json")

# DPAPI 密文头；部分软件（如剪映）会在密文前再套一个 ASCII 标记
DPAPI_MAGIC = b"\x01\x00\x00\x00\xd0\x8c\x9d\xdf"


# ───────────────────────────── 通用：DPAPI ─────────────────────────────

class _BLOB(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def dpapi_unprotect(blob: bytes) -> bytes:
    """CryptUnprotectData：当前用户上下文解密。失败抛 OSError。"""
    if not blob:
        return b""
    buf = ctypes.create_string_buffer(blob, len(blob))
    pin = _BLOB(len(blob), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    pout = _BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(pin), None, None, None, None, 0, ctypes.byref(pout)):
        raise OSError(ctypes.get_last_error(), "CryptUnprotectData 失败（可能不是当前用户加密的数据）")
    try:
        return ctypes.string_at(pout.pbData, pout.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(pout.pbData)


def _looks_text(s: str) -> bool:
    if not s:
        return False
    bad = sum(1 for ch in s if not (ch.isprintable() or ch in "\t\r\n"))
    return bad * 10 <= len(s)


def _dpapi_embedded(blob: bytes):
    """有的软件把 DPAPI 密文再包一层：ASCII 标记（如剪映的 'LVDPAPI'）或十六进制。

    命中就就地解密返回明文，否则返回 None。
    """
    cands = [blob]
    try:
        h = blob.decode("ascii")
        if h and len(h) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in h):
            cands.append(bytes.fromhex(h))
    except Exception:
        pass
    for cand in cands:
        idx = cand.find(DPAPI_MAGIC)
        if 0 <= idx <= 8:
            try:
                return dpapi_unprotect(cand[idx:])
            except Exception:
                return None
    return None


def _decode_secret(blob: bytes):
    """把凭据 blob 还原成文本。返回 (文本, 备注)。"""
    if not blob:
        return "", "空"
    raw_dpapi = _dpapi_embedded(blob)
    if raw_dpapi:
        for enc in ("utf-16-le", "utf-8"):
            try:
                s = raw_dpapi.decode(enc).rstrip("\x00")
                if s.strip() and _looks_text(s):
                    return s, "DPAPI 包裹"
            except Exception:
                pass
        return raw_dpapi.hex(), "DPAPI 包裹（内容为二进制，按十六进制显示）"
    raw = blob.rstrip(b"\x00")
    # UTF-16LE 特征：奇数字节大量为 0
    odd = blob[1::2]
    if len(blob) % 2 == 0 and odd and odd.count(0) >= max(1, len(odd) // 2):
        try:
            s = blob.decode("utf-16-le").rstrip("\x00")
            if _looks_text(s):
                return s, ""
        except Exception:
            pass
    try:
        s = raw.decode("utf-8")
        if _looks_text(s):
            return s, ""
    except Exception:
        pass
    try:
        s = blob.decode("utf-16-le", "strict").rstrip("\x00")
        if _looks_text(s):
            return s, ""
    except Exception:
        pass
    return blob.hex(), "二进制（按十六进制显示）"


# ───────────────────────────── Windows 凭据管理器 ─────────────────────────────

class _FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", ctypes.c_ulong), ("dwHighDateTime", ctypes.c_ulong)]


class _CRED_ATTR(ctypes.Structure):
    pass


_CRED_ATTR._fields_ = [
    ("Keyword", ctypes.c_wchar_p),
    ("Flags", ctypes.c_ulong),
    ("ValueSize", ctypes.c_ulong),
    ("Value", ctypes.POINTER(ctypes.c_ubyte)),
]


class CREDENTIAL(ctypes.Structure):
    pass


CREDENTIAL._fields_ = [
    ("Flags", ctypes.c_ulong),
    ("Type", ctypes.c_ulong),
    ("TargetName", ctypes.c_wchar_p),
    ("Comment", ctypes.c_wchar_p),
    ("LastWritten", _FILETIME),
    ("CredentialBlobSize", ctypes.c_ulong),
    ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
    ("Persist", ctypes.c_ulong),
    ("AttributeCount", ctypes.c_ulong),
    ("Attributes", ctypes.POINTER(_CRED_ATTR)),
    ("TargetAlias", ctypes.c_wchar_p),
    ("UserName", ctypes.c_wchar_p),
]

CRED_TYPE = {
    1: "GENERIC", 2: "DOMAIN_PASSWORD", 3: "DOMAIN_CERT", 4: "DOMAIN_VISIBLE",
    5: "GENERIC_CERT", 6: "DOMAIN_EXTENDED",
}
CRED_PERSIST = {1: "SESSION", 2: "LOCAL_MACHINE", 3: "ENTERPRISE"}
CRED_TYPE_GENERIC = 1
CRED_PERSIST_LOCAL_MACHINE = 2

_API = None


def _advapi():
    global _API
    if _API is None:
        d = ctypes.WinDLL("advapi32", use_last_error=True)
        PCRED = ctypes.POINTER(CREDENTIAL)
        PPCRED = ctypes.POINTER(PCRED)
        d.CredEnumerateW.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong,
                                     ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(PPCRED)]
        d.CredEnumerateW.restype = ctypes.c_int
        d.CredReadW.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong,
                                ctypes.POINTER(PCRED)]
        d.CredReadW.restype = ctypes.c_int
        d.CredFree.argtypes = [ctypes.c_void_p]
        d.CredFree.restype = None
        d.CredDeleteW.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong]
        d.CredDeleteW.restype = ctypes.c_int
        d.CredWriteW.argtypes = [ctypes.POINTER(CREDENTIAL), ctypes.c_ulong]
        d.CredWriteW.restype = ctypes.c_int
        _API = (d, PCRED, PPCRED)
    return _API


def cred_secret(target, ctype=None):
    """读取单条凭据的明文。返回 (文本, 备注)；失败返回 (None, 原因)。"""
    if not IS_WINDOWS:
        return None, "仅 Windows"
    d, PCRED, _ = _advapi()
    types = [ctype] if ctype else [1, 2, 4, 3, 6, 5]
    last = "未找到该凭据"
    for t in types:
        if not t:
            continue
        ptr = PCRED()
        if not d.CredReadW(target, t, 0, ctypes.byref(ptr)):
            last = f"CredRead 失败 WinError {ctypes.get_last_error()}"
            continue
        try:
            c = ptr.contents
            size = int(c.CredentialBlobSize)
            blob = ctypes.string_at(c.CredentialBlob, size) if size else b""
            return _decode_secret(blob)
        finally:
            d.CredFree(ptr)
    return None, last


def cred_enum(reveal=True):
    """枚举凭据元数据；reveal=True 时一并取回明文。

    reveal 只读本账户自己的条目（CredRead），不做任何权限绕过。
    """
    if not IS_WINDOWS:
        return []
    d, _PCRED, PPCRED = _advapi()
    count = ctypes.c_ulong()
    arr = PPCRED()
    if not d.CredEnumerateW(None, 0, ctypes.byref(count), ctypes.byref(arr)):
        err = ctypes.get_last_error()
        if err == 1168:                                   # ERROR_NOT_FOUND
            return []
        raise ctypes.WinError(err)
    out = []
    try:
        for i in range(count.value):
            c = arr[i].contents
            item = {
                "target": c.TargetName or "",
                "user": c.UserName or "",
                "type": int(c.Type),
                "type_name": CRED_TYPE.get(int(c.Type), str(c.Type)),
                "persist": CRED_PERSIST.get(int(c.Persist), str(c.Persist)),
                "last": filetime_to_dt(c.LastWritten.dwHighDateTime, c.LastWritten.dwLowDateTime),
                "comment": c.Comment or "",
                "size": int(c.CredentialBlobSize),
            }
            if reveal:
                try:
                    direct = ctypes.string_at(c.CredentialBlob, int(c.CredentialBlobSize)) \
                        if c.CredentialBlobSize else b""
                except Exception:
                    direct = None
                if direct is not None and direct:
                    text, note = _decode_secret(direct)
                    item["password"] = text
                    item["pw_note"] = note
                else:
                    text, note = cred_secret(item["target"], int(c.Type))
                    item["password"] = text if text is not None else ""
                    item["pw_note"] = note
                if item["type"] == 2:
                    item["pw_note"] = "DOMAIN_PASSWORD 里是 NT 单向值，不是可还原明文"
            out.append(item)
    finally:
        try:
            d.CredFree(arr)
        except Exception:
            pass
    out.sort(key=lambda x: (x["target"].lower(), x["user"].lower()))
    return out


def cred_delete(target):
    """删除凭据。返回 (ok, err)。"""
    d, PCRED, PPCRED = _advapi()
    ctype = CRED_TYPE_GENERIC
    exact = target
    for c in cred_enum():
        if c["target"].lower() == target.lower():
            ctype = c["type"]
            exact = c["target"]
            break
    if d.CredDeleteW(exact, ctype, 0):
        return True, ""
    return False, f"WinError {ctypes.get_last_error()}"


def cred_backup(items, directory=None):
    """删除前备份：把条目（目标/用户名/类型/最后写入/备注）写成 JSON。

    Windows 的凭据**密码无法读取回来再备份**（CredRead 能读，但等于明文落盘，
    反而扩大泄露面），所以备份只保证「知道删了什么、怎么重建」，
    文案里必须写清这一点，别让人以为能还原密码。

    返回 (路径, 备注)；失败返回 ("", 错误)。
    """
    if not items:
        return "", "没有要备份的条目"
    base = directory or os.path.join(
        os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"),
        "health_assistant", "cred-backup")
    try:
        os.makedirs(base, exist_ok=True)
        path = os.path.join(base, "creds-%s.json" % time.strftime("%Y%m%d-%H%M%S"))
        payload = {
            "created": time.strftime("%Y-%m-%d %H:%M:%S"),
            "note": "密码无法从系统凭据里还原，本文件只记录被删的目标/用户名，便于重建。",
            "items": [{k: it.get(k) for k in
                       ("target", "user", "type_name", "last", "comment")}
                      for it in items],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        return path, ""
    except OSError as exc:
        return "", f"{type(exc).__name__}: {exc}"


def cred_write(target, user, password, comment="managed by health_assistant"):
    """新增/更新 generic 凭据（blob 按 UTF-16LE，Windows 通用约定）。"""
    d, PCRED, PPCRED = _advapi()
    blob = password.encode("utf-16-le")
    buf = (ctypes.c_ubyte * max(1, len(blob))).from_buffer_copy(blob or b"\x00")

    cred = CREDENTIAL()
    cred.Flags = 0
    cred.Type = CRED_TYPE_GENERIC
    cred.TargetName = target
    cred.Comment = comment
    cred.LastWritten = _FILETIME(0, 0)
    cred.CredentialBlobSize = len(blob)
    cred.CredentialBlob = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE
    cred.AttributeCount = 0
    cred.Attributes = None
    cred.TargetAlias = None
    cred.UserName = user

    if d.CredWriteW(ctypes.byref(cred), 0):
        return True, ""
    return False, f"WinError {ctypes.get_last_error()}"


# ───────────────────────────── 浏览器已保存登录 ─────────────────────────────

BROWSERS = [
    ("Chrome", r"Google\Chrome\User Data"),
    ("Edge", r"Microsoft\Edge\User Data"),
    ("Brave", r"BraveSoftware\Brave-Browser\User Data"),
    ("Chromium", r"Chromium\User Data"),
]

_KEY_CACHE = {}


def browser_login_files():
    """返回 [{'browser','profile','path','root'}]"""
    local = os.environ.get("LOCALAPPDATA", "")
    out = []
    for name, rel in BROWSERS:
        root = os.path.join(local, rel)
        if not os.path.isdir(root):
            continue
        try:
            profs = [d for d in os.listdir(root)
                     if d == "Default" or d.startswith("Profile ") or d == "Guest Profile"]
        except Exception:
            continue
        for prof in sorted(profs):
            ld = os.path.join(root, prof, "Login Data")
            if os.path.isfile(ld):
                out.append({"browser": name, "profile": prof, "path": ld, "root": root})
    return out


def _chrome_master_key(root):
    """从 Local State 取主密钥（DPAPI 解开的 32 字节 AES-256 key）。失败返回 None。"""
    if root in _KEY_CACHE:
        return _KEY_CACHE[root]
    key = None
    try:
        import json
        ls = os.path.join(root, "Local State")
        if os.path.isfile(ls):
            with open(ls, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            enc = (data.get("os_crypt") or {}).get("encrypted_key")
            if enc:
                raw = base64.b64decode(enc)
                if raw[:5] == b"DPAPI":
                    raw = raw[5:]
                key = dpapi_unprotect(raw)
    except Exception:
        key = None
    _KEY_CACHE[root] = key
    return key


def _decrypt_browser_password(blob, key):
    """返回 (明文, 备注)。无法解密时明文为 None。"""
    if not blob:
        return "", "无密码字段"
    pre = blob[:3]
    if pre in _ABE_PREFIXES:
        return None, "v20 应用绑定加密，不解"
    try:
        if pre in (b"v10", b"v11"):
            if not key:
                return None, "取不到浏览器主密钥"
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            body = blob[3:]
            nonce, ct, tag = body[:12], body[12:-16], body[-16:]
            pt = AESGCM(key).decrypt(nonce, ct + tag, None)
            return pt.decode("utf-8", "replace"), ""
        # 更早版本：整段就是 DPAPI
        raw = dpapi_unprotect(blob)
        try:
            return raw.decode("utf-16-le").rstrip("\x00"), ""
        except Exception:
            return raw.decode("utf-8", "replace"), ""
    except Exception as exc:
        return None, f"解密失败: {type(exc).__name__}"


def _read_logins(info, reveal=True):
    """读 Login Data。reveal=True 时尝试解密 password_value。"""
    path, browser, profile = info["path"], info["browser"], info["profile"]
    tmp = os.path.join(tempfile.gettempdir(), f"health_assistant_{uuid.uuid4().hex}.db")
    try:
        shutil.copy2(path, tmp)
        for ext in ("-wal", "-shm"):
            if os.path.exists(path + ext):
                try:
                    shutil.copy2(path + ext, tmp + ext)
                except Exception:
                    pass
        con = sqlite3.connect(tmp)
        try:
            cols = {r[1] for r in con.execute("PRAGMA table_info(logins)")}
            if not cols:
                return []
            sql = "SELECT origin_url, username_value, {}".format(
                "date_last_used" if "date_last_used" in cols else "0")
            sql += ", blacklisted_by_user" if "blacklisted_by_user" in cols else ", 0"
            sql += ", password_value" if (reveal and "password_value" in cols) else ", NULL"
            sql += " FROM logins"
            key = _chrome_master_key(info["root"]) if reveal else None
            rows = []
            for origin, user, last, blacklisted, pw in con.execute(sql):
                if blacklisted or not (origin or user):
                    continue
                item = {
                    "browser": browser, "profile": profile,
                    "origin": origin or "", "user": user or "",
                    "last": chrome_time(last), "file": path,
                    "password": "", "pw_note": "", "pw_state": "masked",
                }
                if reveal:
                    text, note = _decrypt_browser_password(pw, key)
                    item["pw_state"] = ("plain" if text
                                        else ("v20" if (note or "").startswith("v20")
                                              else "fail"))
                    item["password"] = text or ""
                    item["pw_note"] = note
                rows.append(item)
            return rows
        finally:
            con.close()
    except Exception:
        return []
    finally:
        for suffix in ("", "-wal", "-shm"):
            try:
                if os.path.exists(tmp + suffix):
                    os.remove(tmp + suffix)
            except Exception:
                pass


def _import_key(origin, user):
    return f"{(origin or '').strip().lower()}|{(user or '').strip().lower()}"


def load_imported():
    """读浏览器导出 CSV 的落盘缓存（{key: {origin,user,password,source,at}}）。"""
    try:
        with open(IMPORT_CACHE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_imported(rows, source=""):
    """把 CSV 里的明文并入缓存（合并，不覆盖别的条目）。返回 (缓存总数, 本次写入数)。"""
    cache = load_imported()
    stamp = time.strftime("%Y-%m-%d %H:%M")
    n = 0
    for r in rows:
        pw = r.get("password") or ""
        if not pw:
            continue
        cache[_import_key(r.get("url"), r.get("user"))] = {
            "origin": r.get("url", ""), "user": r.get("user", ""),
            "password": pw, "source": os.path.basename(source or ""), "at": stamp,
        }
        n += 1
    try:
        os.makedirs(os.path.dirname(IMPORT_CACHE), exist_ok=True)
        with open(IMPORT_CACHE, "w", encoding="utf-8") as fh:
            json.dump(cache, fh, ensure_ascii=False, indent=1)
        os.chmod(IMPORT_CACHE, 0o600)
    except Exception:
        return len(cache), 0
    return len(cache), n


def clear_imported():
    try:
        os.remove(IMPORT_CACHE)
        return True
    except Exception:
        return False


def browser_logins(reveal=True):
    out = []
    for info in browser_login_files():
        out.extend(_read_logins(info, reveal=reveal))
    if reveal:
        table = _plaintext_table()
        if table:
            for r in out:
                if r.get("pw_state") == "plain":
                    continue
                hit = table.get(_import_key(r["origin"], r["user"]))
                if not hit:
                    hit = table.get(_host_key(r["origin"], r["user"]))
                if hit and hit[0]:
                    r["password"] = hit[0]
                    r["pw_state"] = "plain"
                    r["pw_note"] = f"来自导出CSV {hit[1]}"
    out.sort(key=lambda r: (r["browser"], r["profile"], r["origin"]))
    return out


_AUTO_CSV = {"done": False, "rows": [], "path": ""}


def _origin_host(origin):
    """https://a.b.com:8443/x → a.b.com（去 scheme / path / 端口）。"""
    text = (origin or "").strip().lower()
    for pre in ("https://", "http://"):
        if text.startswith(pre):
            text = text[len(pre):]
            break
    host = text.split("/", 1)[0]
    if host.count(":") == 1:              # 去掉端口（IPv6 会有多个冒号，不管）
        host = host.split(":", 1)[0]
    return host


def _same_site(host, target):
    """同主域判定：jumpadmin.yyxxgame.com 与 yyxxgame.com 算同一个站。"""
    if not host or not target:
        return False
    return ".".join(host.split(".")[-2:]) == ".".join(target.split(".")[-2:])


def browser_logins_for(host, reveal=True):
    """挑出浏览器里为 host 保存的登录信息，按「能直接用的排前面」排序。

    排序：主机完全一致的优先 → 有明文密码的优先 → 最近用过的优先。
    浏览器把密码存成 v20（Chrome 127+ 应用绑定加密）时 password 为空、
    pw_state 为 "v20"，调用方要自己决定「读不出来怎么办」，这里不抛错。
    """
    target = _origin_host(host)
    if not target:
        return []
    out = []
    for row in browser_logins(reveal=reveal):
        host_i = _origin_host(row.get("origin"))
        if not host_i:
            continue
        exact = 1 if host_i == target else 0
        if not exact and not _same_site(host_i, target):
            continue
        item = dict(row)
        item["host_exact"] = exact
        item["usable"] = bool(row.get("password")) and row.get("pw_state") == "plain"
        out.append(item)
    # 先按最近使用倒序，再做稳定排序把「能用 / 主机一致」提到前面
    out.sort(key=lambda r: (r.get("last") or ""), reverse=True)
    out.sort(key=lambda r: (not r["usable"], not r["host_exact"]))
    return out


def _host_key(origin, user):
    """按「主机 + 用户名」兜底匹配，容忍 path 差异。"""
    try:
        host = (origin or "").split("://", 1)[-1].split("/", 1)[0].lower()
    except Exception:
        host = ""
    return f"~{host}|{(user or '').strip().lower()}"


def _plaintext_table():
    """明文对照表：优先用落盘缓存，缓存为空时自动去下载目录找导出的 CSV。

    返回 {key: (password, 日期)}，key 同时包含精确 origin 与主机两种形态。
    """
    table = {}
    for v in (load_imported() or {}).values():
        pw = (v or {}).get("password")
        if not pw:
            continue
        at = str(v.get("at", ""))[:10]
        table[_import_key(v.get("origin"), v.get("user"))] = (pw, at)
        table[_host_key(v.get("origin"), v.get("user"))] = (pw, at)
    if table:
        return table

    if not _AUTO_CSV["done"]:
        _AUTO_CSV["done"] = True
        try:
            path, _age = find_export_csv(max_age_days=60)
        except Exception:
            path = None
        if path:
            try:
                _AUTO_CSV["rows"] = import_password_csv(path)
                _AUTO_CSV["path"] = path
            except Exception:
                _AUTO_CSV["rows"] = []
    rows = _AUTO_CSV["rows"]
    if not rows:
        return table
    today = time.strftime("%Y-%m-%d")
    for r in rows:
        pw = r.get("password")
        if not pw:
            continue
        table[_import_key(r.get("url"), r.get("user"))] = (pw, today)
        table[_host_key(r.get("url"), r.get("user"))] = (pw, today)
    return table


def auto_import_source():
    """自动发现所用的 CSV 路径（没有则为空串）。"""
    if not _AUTO_CSV["done"]:
        _plaintext_table()
    return _AUTO_CSV["path"]


def browser_processes():
    try:
        import psutil
    except Exception:
        return []
    names = {"chrome.exe", "msedge.exe", "brave.exe", "chromium.exe"}
    hits = set()
    for p in psutil.process_iter(["name"]):
        try:
            if (p.info.get("name") or "").lower() in names:
                hits.add(p.info["name"])
        except Exception:
            pass
    return sorted(hits)


def browser_delete(origin, username=None, assume_yes=False, confirm=None):
    """删除浏览器某条已保存登录。需要浏览器全退出；会先备份 Login Data。

    confirm: 可注入的确认函数（CLI 传 input 包装，便于测试）
    """
    running = browser_processes()
    if running:
        return False, f"请先完全退出浏览器：{', '.join(running)}"

    targets = [r for r in browser_logins()
               if r["origin"].lower() == origin.lower()
               and (username is None or r["user"].lower() == username.lower())]
    if not targets:
        return False, "未找到匹配的登录条目"

    if not assume_yes:
        listing = "\n".join(f"    {t['browser']}/{t['profile']}  {t['origin']}  user={t['user']}"
                            for t in targets)
        prompt = f"  将删除 {len(targets)} 条:\n{listing}\n  确认删除? (y/N) "
        ok = confirm(prompt) if confirm else input(prompt)
        if str(ok).strip().lower() not in ("y", "yes"):
            return False, "已取消"

    done = 0
    for t in targets:
        path = t["file"]
        backup = f"{path}.bak_{time.strftime('%Y%m%d_%H%M%S')}"
        try:
            shutil.copy2(path, backup)
        except Exception as exc:
            return False, f"备份失败，未做修改: {exc}"
        try:
            con = sqlite3.connect(path)
            try:
                cur = con.execute("DELETE FROM logins WHERE origin_url=? AND username_value=?",
                                  (t["origin"], t["user"]))
                con.commit()
                done += max(1, cur.rowcount or 0)
            finally:
                con.close()
        except Exception as exc:
            return False, f"删除失败: {exc}（备份仍在: {os.path.basename(backup)}）"
    return True, f"已删除 {done} 条，备份为同目录 *.bak_* 文件"


# ───────────────────────────── FTP 客户端站点 ─────────────────────────────

def _maybe_base64(text):
    text = (text or "").strip()
    if not text:
        return b""
    try:
        return base64.b64decode(text, validate=False)
    except Exception:
        return b""


def _decrypt_stored(enc_text):
    """FileZilla/WinSCP 这类「Base64 → 可能再 DPAPI」的密码字段。"""
    raw = _maybe_base64(enc_text)
    if not raw:
        return "", "无密码"
    if raw.startswith(DPAPI_MAGIC):
        try:
            plain = dpapi_unprotect(raw)
        except Exception as exc:
            return MASK, f"DPAPI 解密失败: {exc}"
        try:
            return plain.decode("utf-16-le").rstrip("\x00"), ""
        except Exception:
            return plain.decode("utf-8", "replace"), ""
    try:
        s = raw.decode("utf-8").rstrip("\x00")
        if _looks_text(s):
            return s, ""
    except Exception:
        pass
    return MASK, "无法识别的密码编码"


def _filezilla_dirs():
    appdata = os.environ.get("APPDATA", "")
    local = os.environ.get("LOCALAPPDATA", "")
    dirs = [os.path.join(appdata, "FileZilla"), os.path.join(appdata, "FileZilla (x86)")]
    # 便携版：常见解压位置
    for base in (local, r"C:\Program Files", r"C:\Program Files (x86)", "D:\\", "E:\\"):
        if not base or not os.path.isdir(base):
            continue
        dirs.append(os.path.join(base, "FileZilla"))
    return dirs


def filezilla_sites(reveal=True):
    """解析 FileZilla 保存的站点。密码字段本身是 Base64（非加密），reveal 时还原。"""
    import xml.etree.ElementTree as ET

    out = []
    seen = set()
    for base in _filezilla_dirs():
        if not os.path.isdir(base):
            continue
        for fn in ("sitemanager.xml", "recentservers.xml", "filezilla.xml"):
            path = os.path.join(base, fn)
            if not os.path.isfile(path) or path in seen:
                continue
            seen.add(path)
            try:
                root = ET.parse(path).getroot()
            except Exception:
                continue
            for srv in root.iter("Server"):
                def g(tag):
                    e = srv.find(tag)
                    return (e.text or "").strip() if e is not None and e.text else ""
                host = g("Host")
                if not host:
                    continue
                pass_node = srv.find("Pass")
                pass_txt = (pass_node.text or "").strip() if pass_node is not None else ""
                item = {
                    "client": "FileZilla",
                    "src": fn,
                    "host": host,
                    "port": g("Port") or "21",
                    "user": g("User") or "(匿名/未保存)",
                    "protocol": g("Protocol") or "ftp",
                    "password": MASK if pass_txt else "",
                    "pw_note": "无保存密码" if not pass_txt else "",
                    "has_password": bool(pass_txt),
                }
                if reveal and pass_txt:
                    item["password"], item["pw_note"] = _decrypt_stored(pass_txt)
                out.append(item)
    return out


def _winscp_ini_paths():
    appdata = os.environ.get("APPDATA", "")
    return [os.path.join(appdata, "WinSCP.ini")]


def winscp_sites(reveal=True):
    """WinSCP：会话既可能在 ini，也可能在注册表。密码是 Base64(+DPAPI)。"""
    out = []

    def add(name, host, user, port, enc):
        if not host:
            return
        item = {
            "client": "WinSCP", "src": name, "host": host, "port": port or "21",
            "user": user or "(匿名/未保存)", "protocol": "ftp/sftp",
            "password": MASK if enc else "", "pw_note": "" if enc else "无保存密码",
            "has_password": bool(enc),
        }
        if reveal and enc:
            item["password"], item["pw_note"] = _decrypt_stored(enc)
        out.append(item)

    # 1) ini
    for path in _winscp_ini_paths():
        if not os.path.isfile(path):
            continue
        cp = configparser.RawConfigParser(strict=False)
        try:
            cp.read(path, encoding="utf-8-sig")
        except Exception:
            try:
                cp.read(path, encoding="mbcs")
            except Exception:
                continue
        for sec in cp.sections():
            if not sec.lower().startswith("sessions"):
                continue
            name = sec.split("\\")[-1]
            add(name, cp.get(sec, "HostName", fallback=""),
                cp.get(sec, "UserName", fallback=""),
                cp.get(sec, "PortNumber", fallback=""), cp.get(sec, "Password", fallback=""))

    # 2) 注册表
    try:
        import winreg
        base = r"Software\Martin Prikryl\WinSCP 2\Sessions"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, base) as k:
            i = 0
            while True:
                try:
                    name = winreg.EnumKey(k, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(k, name) as sk:
                        def gv(n):
                            try:
                                return winreg.QueryValueEx(sk, n)[0] or ""
                            except OSError:
                                return ""
                        add(name, gv("HostName"), gv("UserName"),
                            str(gv("PortNumber") or ""), gv("Password"))
                except OSError:
                    continue
    except Exception:
        pass
    return out


def totalcmd_sites(reveal=True):
    """Total Commander：wcx_ftp.ini。密码用 TC 自有混淆，这里只报存在性。"""
    out = []
    ini = os.path.join(os.environ.get("APPDATA", ""), "GHISLER", "wcx_ftp.ini")
    if not os.path.isfile(ini):
        return out
    cp = configparser.RawConfigParser(strict=False)
    try:
        cp.read(ini, encoding="utf-8-sig")
    except Exception:
        try:
            cp.read(ini, encoding="mbcs")
        except Exception:
            return out
    for sec in cp.sections():
        if sec.lower() in ("connections", "default", "general"):
            continue
        host = cp.get(sec, "host", fallback="")
        if not host:
            continue
        enc = cp.get(sec, "password", fallback="")
        out.append({
            "client": "TotalCmd", "src": "wcx_ftp.ini", "host": host,
            "port": cp.get(sec, "port", fallback="21") or "21",
            "user": cp.get(sec, "username", fallback="(匿名/未保存)"),
            "protocol": "ftp",
            "password": MASK if enc else "",
            "pw_note": "TC 自有混淆，未解码" if enc else "无保存密码",
            "has_password": bool(enc),
        })
    return out


def ftp_scan_targets():
    """本工具会检查哪些 FTP / 网络位置 —— 用于「没找到也要说清楚」。"""
    appdata = os.environ.get("APPDATA", "")
    local = os.environ.get("LOCALAPPDATA", "")
    rows = [
        ("FileZilla", os.path.join(appdata, "FileZilla", "sitemanager.xml")),
        ("FileZilla", os.path.join(appdata, "FileZilla", "recentservers.xml")),
        ("FileZilla", os.path.join(local, r"FileZilla\sitemanager.xml")),
        ("WinSCP(ini)", os.path.join(appdata, "WinSCP.ini")),
        ("WinSCP(reg)", r"HKCU\Software\Martin Prikryl\WinSCP 2\Sessions"),
        ("TotalCmd", os.path.join(appdata, r"GHISLER\wcx_ftp.ini")),
        ("FlashFXP", os.path.join(appdata, "FlashFXP")),
        ("SmartFTP", os.path.join(appdata, "SmartFTP")),
        ("CoreFTP", os.path.join(appdata, "CoreFTP")),
        ("映射驱动器", r"HKCU\Network\<盘符>"),
        ("当前连接", "mpr.dll WNetOpenEnum"),
        ("网络位置", os.path.join(appdata, r"Microsoft\Windows\Network Shortcuts")),
        ("地址栏历史", r"HKCU\...\Explorer\TypedPaths"),
        ("最近访问", os.path.join(appdata, r"Microsoft\Windows\Recent")),
        ("WebDAV挂载", r"HKCU\...\Explorer\MountPoints2"),
        ("凭据管理器", "ftp:// / \\\\host / Domain: 目标"),
    ]
    out = []
    net_counts = None
    for label, path in rows:
        if label in ("映射驱动器", "网络位置", "最近访问", "WebDAV挂载"):
            if net_counts is None:
                try:
                    from . import netloc
                    net_counts = {
                        "映射驱动器": len(netloc.mapped_drives()),
                        "网络位置": len(netloc.network_shortcuts()),
                        "最近访问": len(netloc.recent_network_links()),
                        "WebDAV挂载": len(netloc.mount_points()),
                    }
                except Exception:
                    net_counts = {}
            out.append((label, path, bool(net_counts.get(label))))
            continue
        if path.startswith("HKCU"):
            exist = None
            try:
                import winreg
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                    r"Software\Martin Prikryl\WinSCP 2\Sessions"):
                    exist = True
            except Exception:
                exist = False
        elif path.startswith("mpr.dll") or path.startswith("ftp://") or path.startswith("凭据管理器"):
            exist = None
        else:
            exist = os.path.exists(path)
        out.append((label, path, exist))
    return out


# 各 FTP 客户端的特征数据文件名（用于按名字寻迹，覆盖便携版/改名安装）
_FTP_DATA_FILES = {
    "sitemanager.xml": "FileZilla 站点管理器",
    "recentservers.xml": "FileZilla 最近服务器",
    "filezilla.xml": "FileZilla 配置",
    "winscp.ini": "WinSCP 配置",
    "wcx_ftp.ini": "Total Commander FTP",
    "flashfxp.ini": "FlashFXP 配置",
    "sites.dat": "FTP 客户端站点库",
    "ftp.ini": "通用 FTP 客户端配置",
}


def ftp_trace(depth=3, budget=2.5):
    """按文件名寻迹：在用户目录与程序目录里有界搜索客户端数据文件。

    覆盖「便携版」「装在非标准目录」「客户端名字与数据目录名不一致」这些情况。
    有深度与时间预算，不会长时间卡住。
    """
    roots = [os.environ.get("APPDATA", ""), os.environ.get("LOCALAPPDATA", ""),
             os.path.join(os.environ.get("USERPROFILE", ""), "Documents"),
             os.path.join(os.environ.get("USERPROFILE", ""), "Desktop"),
             r"C:\Program Files", r"C:\Program Files (x86)"]
    skip = {"microsoft", "packages", "windowsapps", "node_modules", ".git",
            "__pycache__", "cache", "code cache", "gpucache", "temp"}
    found = []
    started = time.time()
    for root in roots:
        if not root or not os.path.isdir(root):
            continue
        base_depth = root.rstrip("\\").count("\\")
        for cur, dirs, files in os.walk(root, topdown=True):
            if time.time() - started > budget:
                return found
            if cur.rstrip("\\").count("\\") - base_depth >= depth:
                dirs[:] = []
            dirs[:] = [d for d in dirs if d.lower() not in skip
                       and not d.startswith("$")]
            for f in files:
                label = _FTP_DATA_FILES.get(f.lower())
                if not label:
                    continue
                path = os.path.join(cur, f)
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                found.append({"kind": label, "path": path,
                              "size": st.st_size,
                              "mtime": time.strftime("%Y-%m-%d",
                                                     time.localtime(st.st_mtime))})
    return found


def ftp_sites_all(reveal=True, browser_logins_rows=None):
    """汇总所有渠道的 FTP 连接。返回 (sites, errors)"""
    sites, errors = [], []

    for fn in (filezilla_sites, winscp_sites, totalcmd_sites):
        try:
            sites.extend(fn(reveal=reveal))
        except Exception as exc:
            errors.append(f"{fn.__name__}: {type(exc).__name__}: {exc}")

    # 凭据管理器里的 FTP 条目
    try:
        for c in cred_enum(reveal=reveal):
            t = (c["target"] or "").lower()
            if "ftp" not in t and "filezilla" not in t and "winscp" not in t:
                continue
            sites.append({
                "client": "凭据管理器", "src": "Windows Credential",
                "host": c["target"], "port": "-", "user": c["user"] or "-",
                "protocol": "credential",
                "password": c.get("password", MASK) if reveal else MASK,
                "pw_note": c.get("pw_note", ""),
                "has_password": True,
            })
    except Exception as exc:
        errors.append(f"cred_enum: {exc}")

    # 浏览器里保存的 ftp:// 站点
    try:
        rows = browser_logins_rows if browser_logins_rows is not None else browser_logins(reveal=reveal)
        for r in rows:
            if not r["origin"].lower().startswith("ftp"):
                continue
            sites.append({
                "client": r["browser"], "src": r["origin"], "host": r["origin"],
                "port": "-", "user": r["user"] or "-", "protocol": "ftp-url",
                "password": (ABE_MARK if r.get("pw_state") == "v20"
                             else r.get("password", MASK)),
                "pw_note": r.get("pw_note", ""),
                "has_password": True,
            })
    except Exception as exc:
        errors.append(f"browser: {exc}")

    # 资源管理器里的网络位置（Windows 自带 FTP / SMB 映射 / WebDAV）
    # 这是"没装任何 FTP 客户端但确实连过 \\192.168.x.x"的主通道
    try:
        from . import netloc
        locs, loc_notes = netloc.network_locations(reveal=reveal)
        for e in locs:
            sites.append({
                "client": "资源管理器", "src": e["source"],
                "host": e["remote"], "port": "-",
                "user": e["user"], "protocol": e["kind"],
                "password": (e["password"] or "") if reveal else MASK,
                "pw_note": (e["pw_note"] or e["kind_desc"]) if reveal else e["kind_desc"],
                "has_password": e["has_password"],
                "detail": e["detail"], "kind_desc": e["kind_desc"],
            })
        errors.extend(loc_notes)
    except Exception as exc:
        errors.append(f"netloc: {type(exc).__name__}: {exc}")

    return sites, errors


# 从 `ftp://host:21` / `host` / `host:21` 里认主机名和端口
_HOSTPORT_RE = re.compile(
    r"^(?:(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
    r"|(?P<dom>[A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,}))"
    r"(?::(?P<port>\d{1,5}))?$")


_BARE_HOST_RE = re.compile(r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._\-]*)"
                           r"(?::(?P<port>\d{1,5}))?$")


def split_host_port(text):
    """把凭据/站点里的名字拆成 (host, port)；认不出（比如 UNC 路径）返回 (None, None)。"""
    t = (text or "").strip()
    ftpish = False
    for pre in ("ftps://", "sftp://", "ftp://"):
        if t.lower().startswith(pre):
            t = t[len(pre):]
            ftpish = True
            break
    t = t.split("/")[0].strip()
    if not t:
        return None, None
    m = _HOSTPORT_RE.match(t)
    if m:
        return (m.group("ip") or m.group("dom")), int(m.group("port") or 21)
    if ftpish:                      # 内网里叫 fileserver 这种不带点的主机名也认
        m2 = _BARE_HOST_RE.match(t)
        if m2:
            return m2.group("host"), int(m2.group("port") or 21)
    return None, None


def ftp_account_candidates(reveal=True):
    """本机上「可能能直接拿来登录 FTP」的账号，按可信度排序。

    三档来源：
    1. **凭据管理器里名字带 ftp 的** —— 资源管理器登录时勾了「保存密码」就是这个样子；
    2. **凭据管理器里名字本身就是 IP / 域名的** —— Explorer 存的 FTP 多半是这种；
    3. FileZilla / WinSCP / Total Commander / 浏览器里的 ftp:// 站点。

    只读**当前用户自己**的凭据，和打开「控制面板 → 凭据管理器」看到的是同一批，
    不做任何权限绕过。返回 (rows, notes)。
    """
    rows, notes, seen = [], [], set()

    def add(source, host, port, user, password, note, rank):
        key = (host.lower(), (user or "").lower())
        if key in seen:
            return
        seen.add(key)
        rows.append({"source": source, "host": host, "port": port or 21,
                     "user": user or "", "password": password or "",
                     "note": note or "", "rank": rank,
                     "can_use": bool(password)})

    try:
        for c in cred_enum(reveal=reveal):
            if int(c.get("type") or 0) != CRED_TYPE_GENERIC:
                continue
            host, port = split_host_port(c.get("target"))
            if not host:
                continue                       # TERMSRV/ 、git: 之类一律跳过
            looks_ftp = "ftp" in (c.get("target") or "").lower()
            add("凭据管理器" if looks_ftp else "凭据管理器（主机名）",
                host, port, c.get("user"), c.get("password"),
                c.get("pw_note"), 0 if looks_ftp else 1)
    except Exception as exc:
        notes.append(f"凭据管理器读取失败：{type(exc).__name__}: {exc}")

    try:
        sites, errs = ftp_sites_all(reveal=reveal)
        notes.extend(errs)
        for s in sites:
            if s.get("client") == "凭据管理器":
                continue                       # 上面那一档已经收过了
            host, port = split_host_port(s.get("host"))
            if not host:
                continue
            pw = s.get("password") or ""
            if pw in (MASK, ABE_MARK):
                pw = ""                        # 读不出明文就别当成密码用
            port_i = s.get("port")
            if not isinstance(port_i, int) or not port_i:
                port_i = port
            add(s.get("client") or "FTP 客户端", host, port_i,
                s.get("user"), pw, s.get("pw_note"), 2)
    except Exception as exc:
        notes.append(f"FTP 客户端扫描失败：{type(exc).__name__}: {exc}")

    rows.sort(key=lambda r: (r["rank"], r["host"].lower(), r["user"].lower()))
    return rows, notes


_CSV_HEADERS = {
    "name": ("name", "名称"),
    "url": ("url", "网址", "站点", "链接"),
    "username": ("username", "用户名", "账号"),
    "password": ("password", "密码"),
    "note": ("note", "备注"),
}


def _csv_index(header):
    head = [h.strip().lower() for h in header]
    idx = {}
    for key, aliases in _CSV_HEADERS.items():
        idx[key] = None
        for a in aliases:
            if a.lower() in head:
                idx[key] = head.index(a.lower())
                break
    return idx


def _looks_password_csv(path):
    """粗判一个 CSV 是不是浏览器导出的密码表（只看表头）。"""
    try:
        with open(path, "r", encoding="utf-8-sig", newline="") as fh:
            header = next(csv.reader(fh), None)
        if not header or len(header) < 3:
            return False
        idx = _csv_index(header)
        return idx["url"] is not None and idx["password"] is not None
    except Exception:
        return False


def download_dirs():
    """可能存放导出文件的位置：Chrome 下载目录 + 用户 Downloads/Desktop。"""
    dirs = []
    prefs = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Google", "Chrome",
                         "User Data", "Default", "Preferences")
    try:
        with open(prefs, "r", encoding="utf-8") as fh:
            d = ((json.load(fh).get("download") or {}).get("default_directory") or "")
        if d and os.path.isdir(d):
            dirs.append(d)
    except Exception:
        pass
    home = os.path.expanduser("~")
    for name in ("Downloads", "Desktop"):
        p = os.path.join(home, name)
        if os.path.isdir(p) and p not in dirs:
            dirs.append(p)
    return dirs


def find_export_csv(max_age_days=14, newer_than=0):
    """在下载目录里找最新的浏览器密码导出 CSV。返回 (path, 已存在时长秒) 或 (None, None)。"""
    best = None
    now = time.time()
    for d in download_dirs():
        try:
            names = os.listdir(d)
        except Exception:
            continue
        for n in names:
            if not n.lower().endswith(".csv"):
                continue
            p = os.path.join(d, n)
            try:
                st = os.stat(p)
            except OSError:
                continue
            if st.st_size < 20:
                continue
            age = now - st.st_mtime
            if age > max_age_days * 86400 or st.st_mtime < newer_than:
                continue
            low = n.lower()
            if not any(k in low for k in ("密码", "password", "passwd", "pass")):
                if not _looks_password_csv(p):
                    continue
            elif not _looks_password_csv(p):
                continue
            if best is None or st.st_mtime > best[1]:
                best = (p, st.st_mtime)
    if not best:
        return None, None
    return best[0], now - best[1]


def import_password_csv(path):
    """读取浏览器导出的密码 CSV（Chrome/Edge：name,url,username,password,note）。

    明文不落盘、不缓存：只解析并返回，供终端展示/比对。
    """
    rows = []
    with open(path, "r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.reader(fh)
        header = next(reader, None)
        if not header:
            return rows
        idx = _csv_index(header)
        if idx["url"] is None or idx["password"] is None:
            raise ValueError(f"不是浏览器导出的密码 CSV（缺少 url/password 列）: {header}")
        for rec in reader:
            if not rec:
                continue

            def pick(k):
                i = idx[k]
                return rec[i].strip() if i is not None and i < len(rec) else ""
            rows.append({
                "name": pick("name"), "url": pick("url"),
                "user": pick("username"), "password": pick("password"),
                "note": pick("note"),
            })
    return rows
