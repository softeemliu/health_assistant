"""health_assistant.regclean — 注册表幽灵项清理（先备份成 .reg，再删，可回滚）

「幽灵项」= Windows「已安装程序」登记项（Uninstall 子树）里登记了 InstallLocation，
但那个目录早就不在了。这种条目只是「程序和功能」里的一行死数据，删掉不释放空间，
好处是列表干净、不再误导「这软件还装着」。

**只动 Uninstall 子树，别处一律不碰。** 可删必须同时满足：

1. 父键在白名单里（HKLM/HKCU 的 Uninstall，含 WOW6432Node 视图）；
2. 删除时**重新读一遍注册表**，InstallLocation 展开 %环境变量% 后仍不存在，
   且所在盘符当前在线（盘符离线 = 可能是移动硬盘/U 盘，跳过，否则会误删）；
3. 不是 MSI 托管（WindowsInstaller=1）、不是 SystemComponent=1
   —— 这两种删了会让「程序和功能」与 MSI 数据库/组件登记不一致，收益为零、风险不为零；
4. 当前进程有写权限（HKLM 需要管理员）。

删之前把所有键的值（含子键）导出成 .reg，默认落在
%LOCALAPPDATA%\\health_assistant\\reg-backup\\，双击即可导回。
"""

from __future__ import annotations

import os
import struct
import time

from .core import is_admin

try:
    import winreg
except Exception:                                   # 非 Windows 上 import 失败也不炸
    winreg = None


_HIVES = {
    "HKLM": ("HKEY_LOCAL_MACHINE", None),
    "HKCU": ("HKEY_CURRENT_USER", None),
}

# 唯一允许删除的父键（白名单，宁可少删也不越界）
PARENTS = {
    "HKLM": (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
             r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    "HKCU": (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",),
}


def _roots():
    if winreg is None:
        return {}
    return {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}


def _flag_of(view):
    if winreg is None:
        return 0
    return {64: winreg.KEY_WOW64_64KEY, 32: winreg.KEY_WOW64_32KEY}.get(view, 0)


def display_path(ghost):
    """给人看的完整键路径，例：HKEY_CURRENT_USER\\SOFTWARE\\...\\Uninstall\\Foo"""
    hive = ghost.get("hive") or "HKLM"
    name = _HIVES.get(hive, (hive,))[0]
    return f"{name}\\{ghost.get('parent', '')}\\{ghost.get('key', '')}"


def _open(ghost, write=False):
    root = _roots().get(ghost.get("hive") or "HKLM")
    if root is None:
        raise OSError("当前系统不支持注册表")
    access = winreg.KEY_READ | _flag_of(ghost.get("view"))
    if write:
        access |= winreg.KEY_WRITE
    full = ghost["parent"] + "\\" + ghost["key"]
    return winreg.OpenKey(root, full, 0, access)


def _values(key):
    out = {}
    i = 0
    while True:
        try:
            name, val, typ = winreg.EnumValue(key, i)
        except OSError:
            break
        i += 1
        out[name] = (val, typ)
    return out


def _get_str(vals, name):
    v = vals.get(name)
    if not v:
        return ""
    return v[0].strip() if isinstance(v[0], str) else ""


def _is_flag(vals, name):
    v = vals.get(name)
    if not v:
        return False
    try:
        return int(v[0]) == 1
    except (TypeError, ValueError):
        return str(v[0]).strip() == "1"


def _expanded(loc):
    return os.path.expandvars(loc.strip().strip('"'))


def drive_online(loc):
    """登记目录所在盘符现在在不在。没有盘符（UNC/相对路径）一律当作在线。"""
    drive = os.path.splitdrive(loc)[0]
    if not drive:
        return True
    try:
        return os.path.exists(drive + "\\")
    except OSError:
        return False


def judge(ghost):
    """重新核一遍这个条目现在能不能删。

    返回 {"action": "delete"|"skip", "reason": str, "location": str}。
    """
    res = {"action": "skip", "reason": "", "location": ""}
    hive = ghost.get("hive") or "HKLM"
    parent = ghost.get("parent") or ""
    sub = ghost.get("key") or ""
    if not sub or parent.upper() not in [p.upper() for p in PARENTS.get(hive, ())]:
        res["reason"] = "不在白名单目录下，不动"
        return res

    try:
        with _open(ghost) as k:
            vals = _values(k)
    except FileNotFoundError:
        res["reason"] = "注册表项已经不存在（可能已被别处删掉）"
        return res
    except PermissionError:
        res["reason"] = "读不了这个键（权限不足）"
        return res
    except OSError as exc:
        res["reason"] = f"读注册表失败：{exc}"
        return res

    if not _get_str(vals, "DisplayName"):
        res["reason"] = "没有 DisplayName，不是安装登记项"
        return res

    loc = _expanded(_get_str(vals, "InstallLocation"))
    res["location"] = loc
    if not loc or len(loc) < 6:
        res["reason"] = "没登记安装目录（InstallLocation 为空）"
        return res
    try:
        if os.path.exists(loc):
            res["reason"] = "登记的安装目录现在又存在了"
            return res
    except OSError:
        res["reason"] = "判断目录是否存在时出错"
        return res
    if not drive_online(loc):
        res["reason"] = "盘符当前不在线（可能是移动硬盘 / U 盘），先不删"
        return res
    if _is_flag(vals, "WindowsInstaller"):
        res["reason"] = "MSI 托管项，删了会和 MSI 数据库对不上，建议保留"
        return res
    if _is_flag(vals, "SystemComponent"):
        res["reason"] = "隐藏组件（SystemComponent=1），属于别的产品，建议保留"
        return res
    if hive == "HKLM" and not is_admin():
        res["reason"] = "需要管理员权限（HKLM），请以管理员身份重开"
        return res

    try:
        with _open(ghost, write=True):
            pass
    except PermissionError:
        res["reason"] = "没有写入该键的权限"
        return res
    except OSError as exc:
        res["reason"] = f"写权限检查失败：{exc}"
        return res

    res["action"] = "delete"
    res["reason"] = "目录已不存在，可安全删除这一行登记"
    return res


def values_of(ghost):
    """把某个键的值全读出来（详情窗口 / 导出用），读不到就返回空字典。"""
    try:
        with _open(ghost) as k:
            vals = _values(k)
    except OSError:
        return {}
    return {n: v for n, (v, _t) in vals.items()}


# ───────────────────────── 备份（.reg） ─────────────────────────

def _esc(s):
    return str(s).replace("\\", "\\\\").replace('"', '\\"')


def _hex(b):
    return ",".join(f"{x:02x}" for x in b) + ("," if b else "")


def _utf16(s):
    return s.encode("utf-16-le", "surrogatepass") + b"\x00\x00"


def _fmt_value(name, val, typ):
    key = "@" if name == "" else f'"{_esc(name)}"'
    try:
        if typ == winreg.REG_SZ:
            return f'{key}="{_esc(val)}"'
        if typ == winreg.REG_EXPAND_SZ:
            return f"{key}=hex(2):{_hex(_utf16(val))}"
        if typ in (winreg.REG_DWORD, getattr(winreg, "REG_DWORD_LITTLE_ENDIAN", 4)):
            return f"{key}=dword:{int(val) & 0xFFFFFFFF:08x}"
        if typ == winreg.REG_QWORD:
            return f"{key}=hex(b):{_hex(struct.pack('<Q', int(val)))}"
        if typ == winreg.REG_MULTI_SZ:
            blob = b"".join(_utf16(x) for x in (val or [])) + b"\x00\x00"
            return f"{key}=hex(7):{_hex(blob)}"
        if typ == winreg.REG_BINARY:
            return f"{key}=hex:{_hex(val if isinstance(val, bytes) else b'')}"
    except Exception:
        pass
    blob = val if isinstance(val, bytes) else b""
    return f"{key}=hex({int(typ)}):{_hex(blob)}"


def _dump_key(root, reg_path, shown, access, out):
    """把 reg_path 这一支（含子键）写成 .reg 段落；shown 是带 HKEY_ 前缀的显示路径。"""
    try:
        with winreg.OpenKey(root, reg_path, 0, winreg.KEY_READ | access) as k:
            vals = []
            i = 0
            while True:
                try:
                    n, v, t = winreg.EnumValue(k, i)
                except OSError:
                    break
                i += 1
                vals.append((n, v, t))
            subs = []
            j = 0
            while True:
                try:
                    subs.append(winreg.EnumKey(k, j))
                except OSError:
                    break
                j += 1
    except OSError as exc:
        return f"导出失败：{shown}  {exc}"

    out.append(f"[{shown}]\n")
    for n, v, t in vals:
        out.append(_fmt_value(n, v, t) + "\n")
    out.append("\n")
    for s in subs:
        err = _dump_key(root, reg_path + "\\" + s, shown + "\\" + s, access, out)
        if err:
            return err
    return ""


def dump_reg(ghosts):
    """把若干注册表项导成 .reg 文本。返回 (text, 成功项, 失败说明)。"""
    lines = ["Windows Registry Editor Version 5.00\n\n"]
    ok, bad = [], []
    for g in ghosts:
        hive = g.get("hive") or "HKLM"
        shown = f"{_HIVES.get(hive, (hive,))[0]}\\{g.get('parent', '')}\\{g.get('key', '')}"
        before = len(lines)
        err = _dump_key(_roots().get(hive), f"{g.get('parent')}\\{g.get('key')}", shown,
                        _flag_of(g.get("view")), lines)
        if err:
            del lines[before:]
            bad.append(err)
        else:
            ok.append(g)
    return "".join(lines), ok, bad


def backup_dir():
    base = os.environ.get("LOCALAPPDATA") or os.path.join(
        os.path.expanduser("~"), "AppData", "Local")
    path = os.path.join(base, "health_assistant", "reg-backup")
    os.makedirs(path, exist_ok=True)
    return path


def write_backup(ghosts, stamp=None):
    text, ok, bad = dump_reg(ghosts)
    if not ok:
        raise OSError("没有任何注册表项可以导出，放弃删除：" + ("; ".join(bad) or "未知原因"))
    stamp = stamp or time.strftime("%Y%m%d-%H%M%S")
    path = os.path.join(backup_dir(), f"ghost-{stamp}.reg")
    with open(path, "w", encoding="utf-16", newline="\r\n") as fh:
        fh.write(text)
    return path, ok, bad


# ───────────────────────── 删除 ─────────────────────────

def _subkeys(root, full, access):
    out, i = [], 0
    with winreg.OpenKey(root, full, 0, winreg.KEY_READ | access) as k:
        while True:
            try:
                out.append(winreg.EnumKey(k, i))
            except OSError:
                break
            i += 1
    return out


def _delete_tree(root, full, access):
    for s in _subkeys(root, full, access):
        _delete_tree(root, full + "\\" + s, access)
    if access:
        winreg.DeleteKeyEx(root, full, access, 0)
    else:
        winreg.DeleteKey(root, full)


def delete_ghosts(ghosts, log=None):
    """备份 → 逐条复核 → 删除。返回统计字典，不抛异常。"""
    log = log or (lambda _s: None)
    ghosts = list(ghosts or [])
    out = {"ok": [], "skipped": [], "bad": [], "backup": "", "backup_failed": ""}

    todo = []
    for g in ghosts:
        v = judge(g)
        if v["action"] == "delete":
            todo.append(g)
        else:
            out["skipped"].append({"name": g.get("name", ""), "reason": v["reason"]})
    if not todo:
        return out

    try:
        path, dumped, bad = write_backup(todo)
        out["backup"] = path
        log(f"注册表备份：{path}")
        if bad:
            for b in bad:
                log("备份失败（已跳过该项）：" + b)
        todo = [g for g in todo if any(g is d for d in dumped)]
    except OSError as exc:
        out["backup_failed"] = str(exc)
        for g in todo:
            out["skipped"].append({"name": g.get("name", ""), "reason": "备份失败，未删除"})
        return out

    for g in todo:
        root = _roots().get(g.get("hive") or "HKLM")
        access = _flag_of(g.get("view"))
        full = f"{g['parent']}\\{g['key']}"
        try:
            _delete_tree(root, full, access)
            out["ok"].append({"name": g.get("name", ""), "key": display_path(g)})
            log(f"已删除注册表项：{g.get('name', '')}")
        except PermissionError:
            out["bad"].append({"name": g.get("name", ""), "reason": "权限不足（需要管理员）"})
        except OSError as exc:
            out["bad"].append({"name": g.get("name", ""), "reason": str(exc)})
    return out
