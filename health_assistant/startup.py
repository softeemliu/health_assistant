"""health_assistant.startup — 开机自启项：看清 / 禁用 / 启用

为什么不做「删除」
    删 Run 键是**不可逆**的：删完就不知道原来那条叫什么、指向哪。
    任务管理器那个「禁用」其实是可逆的 —— 它不动 Run 键，只往
    Explorer\\StartupApproved 里写一个启用标志。本模块照做：
      · 禁用 = 往 StartupApproved 写 03（+ 禁用时间）
      · 启用 = 写 02
    想彻底删掉，我们只给命令，让用户自己去 regedit 决定。

三件套（本项目的删除动作硬边界）
    白名单   —— 只碰 StartupApproved 下那 6 个已知键，别的路径一律不写；
    删前复核 —— 写之前重新读一遍当前值，和列表里那份不一致就放弃（程序刚被改过）；
    先备份   —— 每次写之前把「原来的值」追加进 startup-backup.json，
                按记录可以原样写回去（本来没有这条就删掉）。

口径
    · RunOnce 里的项只跑一次，不参与启用/禁用（任务管理器也不列它）；
    · HKLM 下的项属于「所有用户」，改它要管理员；没有权限就给可复制的命令；
    · 目标文件已经不在 = 断链，这类禁用起来最安全（程序都卸了）。
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import struct

__all__ = [
    "items", "summary", "set_enabled", "set_many", "history", "restore_last",
    "delete_commands", "open_location", "SOURCES",
]

IS_WINDOWS = os.name == "nt"

# 启用标志的首字节：偶数 = 启用、奇数 = 禁用。
# 任务管理器写的是 02 / 03；组策略禁用会出现 06 / 07，也按奇偶判。
_ON, _OFF = 0x02, 0x03

# 备份 / 撤销记录
_BACKUP = os.path.join(
    os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"),
    "health_assistant", "startup-backup.json")

_HKCU = "HKCU"
_HKLM = "HKLM"

_EXPLORER = r"Software\Microsoft\Windows\CurrentVersion\Explorer"

# 白名单：允许写的 StartupApproved 键（值名不限）
_APPROVED_KEYS = {
    (_HKCU, _EXPLORER + r"\StartupApproved\Run"),
    (_HKCU, _EXPLORER + r"\StartupApproved\Run32"),
    (_HKCU, _EXPLORER + r"\StartupApproved\StartupFolder"),
    (_HKLM, _EXPLORER + r"\StartupApproved\Run"),
    (_HKLM, _EXPLORER + r"\StartupApproved\Run32"),
    (_HKLM, _EXPLORER + r"\StartupApproved\StartupFolder"),
}

_WIN = r"Software\Microsoft\Windows\CurrentVersion"

# (hive, 键路径, 显示名, 对应的 StartupApproved 键路径, 种类)
SOURCES = [
    (_HKCU, _WIN + r"\Run",
     "当前用户 Run", _EXPLORER + r"\StartupApproved\Run", "run"),
    (_HKCU, _WIN + r"\RunOnce",
     "当前用户 RunOnce", _EXPLORER + r"\StartupApproved\Run", "runonce"),
    (_HKLM, _WIN + r"\Run",
     "所有用户 Run", _EXPLORER + r"\StartupApproved\Run", "run"),
    (_HKLM, _WIN + r"\RunOnce",
     "所有用户 RunOnce", _EXPLORER + r"\StartupApproved\Run", "runonce"),
    (_HKLM, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
     "所有用户 Run(32位)", _EXPLORER + r"\StartupApproved\Run32", "run"),
    (_HKLM, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
     "所有用户 RunOnce(32位)", _EXPLORER + r"\StartupApproved\Run32", "runonce"),
]


def _hive(name):
    import winreg
    return {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}[name]


def _startup_dirs():
    """启动目录（放快捷方式的那个文件夹），按用户范围分。"""
    out = []
    appdata = os.environ.get("APPDATA")
    if appdata:
        out.append((_HKCU, os.path.join(
            appdata, r"Microsoft\Windows\Start Menu\Programs\Startup"), "当前用户 启动文件夹"))
    pd = os.environ.get("ProgramData")
    if pd:
        out.append((_HKLM, os.path.join(
            pd, r"Microsoft\Windows\Start Menu\Programs\Startup"), "所有用户 启动文件夹"))
    return out


# ───────────────────────────── 读 ─────────────────────────────

def _approved_state(hive, key_path, value_name):
    """读 StartupApproved 里的启用标志。

    返回 (enabled, raw_hex)。raw_hex 是 None 表示这条记录**不存在**（默认启用），
    撤销时要按「删掉这个值」处理，不能写成 02。
    """
    import winreg
    try:
        with winreg.OpenKey(_hive(hive), key_path, 0, winreg.KEY_READ) as k:
            data, _t = winreg.QueryValueEx(k, value_name)
    except FileNotFoundError:
        return True, None
    except OSError:
        return True, None
    if not isinstance(data, (bytes, bytearray)) or not data:
        return True, None
    return (int(data[0]) & 1) == 0, bytes(data).hex()


def _exe_from_cmd(cmd):
    """从命令行里抠出可执行文件路径（只为判断「程序还在不在」）。"""
    cmd = (cmd or "").strip()
    if not cmd:
        return ""
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        exe = cmd[1:end] if end > 0 else cmd[1:]
    elif cmd.lower().startswith("\\??\\"):
        exe = cmd[4:].split(",")[0]
    else:
        m = re.match(r"(?i)^(.+?\.(?:exe|com|bat|cmd))(?:\s|,|$)", cmd)
        exe = m.group(1) if m else cmd.split()[0]
    exe = os.path.expandvars(exe).strip().strip('"')
    try:
        return os.path.normpath(exe)
    except (ValueError, OSError):
        return exe


def items():
    """列出所有自启项。

    每项字段：
      id / name / source / kind / hive / key / value / cmd / exe / exists
      enabled / approved_key / approved_value / can_toggle / note
    """
    if not IS_WINDOWS:
        return []
    import winreg

    out = []
    for hive, key_path, label, ap_path, kind in SOURCES:
        try:
            with winreg.OpenKey(_hive(hive), key_path, 0, winreg.KEY_READ) as k:
                i = 0
                while True:
                    try:
                        name, value, _t = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    i += 1
                    cmd = "" if value is None else str(value)
                    exe = _exe_from_cmd(cmd)
                    enabled, raw = _approved_state(hive, ap_path, name)
                    exists = os.path.isfile(exe) if exe else None
                    note = ""
                    if kind == "runonce":
                        note = "只运行一次，不参与禁用"
                    elif exists is False:
                        note = "指向的程序已经不在（断链，禁用最安全）"
                    out.append({
                        "id": f"{hive}\\{key_path}::{name}",
                        "name": name,
                        "source": label,
                        "kind": kind,
                        "hive": hive,
                        "key": key_path,
                        "value": name,
                        "cmd": cmd,
                        "exe": exe,
                        "exists": exists,
                        "enabled": enabled,
                        "approved_key": ap_path,
                        "approved_value": name,
                        "can_toggle": kind != "runonce",
                        "note": note,
                        "_raw": raw,
                    })
        except FileNotFoundError:
            continue
        except OSError:
            continue

    for hive, folder, label in _startup_dirs():
        ap_path = _EXPLORER + r"\StartupApproved\StartupFolder"
        try:
            names = sorted(os.listdir(folder))
        except OSError:
            continue
        for fn in names:
            if fn.lower() == "desktop.ini":
                continue
            full = os.path.join(folder, fn)
            if not os.path.isfile(full):
                continue
            exe = ""
            if fn.lower().endswith(".lnk"):
                try:
                    from .slim import lnk_target
                    exe = lnk_target(full) or ""
                except Exception:
                    exe = ""
            exists = os.path.isfile(exe) if exe else None
            enabled, raw = _approved_state(hive, ap_path, fn)
            note = ""
            if exists is False:
                note = "快捷方式指向的程序已经不在（断链）"
            elif exists is None and fn.lower().endswith(".lnk"):
                note = "快捷方式目标读不出来（不影响正常使用）"
            out.append({
                "id": f"{hive}\\{folder}::{fn}",
                "name": fn,
                "source": label,
                "kind": "startupdir",
                "hive": hive,
                "key": folder,
                "value": fn,
                "cmd": full,
                "exe": exe,
                "exists": exists,
                "enabled": enabled,
                "approved_key": ap_path,
                "approved_value": fn,
                "can_toggle": True,
                "note": note,
                "_raw": raw,
            })

    # 停用的排前面（用户点开就想看「哪些被我关了」），其次断链的
    out.sort(key=lambda it: (it["enabled"], not (it["exists"] is False),
                             it["name"].lower()))
    return out


def summary():
    its = items()
    return {
        "total": len(its),
        "enabled": sum(1 for i in its if i["enabled"] and i["can_toggle"]),
        "disabled": sum(1 for i in its if not i["enabled"]),
        "broken": sum(1 for i in its if i["exists"] is False),
        "third": sum(1 for i in its if not _is_system(i["name"])),
    }


_SYS_NAMES = {"ctfmon", "securityhealth", "onedrive", "application restart",
              "windows security notification icon"}


def _is_system(name):
    n = (name or "").lower()
    if n in _SYS_NAMES:
        return True
    return n.startswith(("delete ", "uninstall ", "microsoftedgeautolaunch"))


# ───────────────────────────── 备份 ─────────────────────────────

def _load_backup():
    try:
        with open(_BACKUP, "r", encoding="utf-8-sig") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _save_backup(records):
    try:
        os.makedirs(os.path.dirname(_BACKUP), exist_ok=True)
        with open(_BACKUP, "w", encoding="utf-8") as fh:
            json.dump(records[-500:], fh, ensure_ascii=False, indent=1)
        return True
    except OSError:
        return False


def _backup(entry):
    """把「改动前是什么」记下来。返回是否备份成功 —— 失败就不许改。"""
    rec = {
        "time": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "item": entry["id"],
        "name": entry["name"],
        "source": entry["source"],
        "hive": entry["hive"],
        "approved_key": entry["approved_key"],
        "approved_value": entry["approved_value"],
        "prev_hex": entry.get("_raw"),      # None = 原来没有这条记录
        "prev_enabled": entry["enabled"],
    }
    recs = _load_backup()
    recs.append(rec)
    return _save_backup(recs)


def history(limit=20):
    return _load_backup()[-limit:][::-1]


def restore_last():
    """把最近一次改动原样写回去。返回 (ok, 说明)。"""
    recs = _load_backup()
    if not recs:
        return False, "没有可撤销的记录"
    rec = recs[-1]
    ok, msg = _write_raw(rec["hive"], rec["approved_key"],
                         rec["approved_value"], rec["prev_hex"])
    if ok:
        _save_backup(recs[:-1])
        return True, f"已恢复「{rec['name']}」到 {rec['time']} 之前的状态"
    return False, msg


# ───────────────────────────── 写 ─────────────────────────────

def _write_raw(hive, key_path, value_name, hex_data):
    """写 StartupApproved 的值；hex_data=None 表示删除这个值。"""
    if not IS_WINDOWS:
        return False, "只有 Windows 支持"
    import winreg

    if (hive, key_path) not in _APPROVED_KEYS:
        return False, f"拒绝写入白名单之外的键：{hive}\\{key_path}"
    try:
        with winreg.OpenKey(_hive(hive), key_path, 0, winreg.KEY_SET_VALUE) as k:
            if hex_data is None:
                winreg.DeleteValue(k, value_name)
            else:
                winreg.SetValueEx(k, value_name, 0, winreg.REG_BINARY,
                                  bytes.fromhex(hex_data))
        return True, ""
    except FileNotFoundError:
        # 键不存在时创建（HKCU 的 StartupApproved\Run 在没禁用过任何东西时确实没有）
        if hex_data is None:
            return True, ""
        try:
            with winreg.CreateKeyEx(_hive(hive), key_path, 0,
                                    winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, value_name, 0, winreg.REG_BINARY,
                                  bytes.fromhex(hex_data))
            return True, ""
        except OSError as exc:
            return False, _perm_hint(exc, hive)
    except OSError as exc:
        return False, _perm_hint(exc, hive)


def _perm_hint(exc, hive):
    if getattr(exc, "winerror", None) == 5:
        if hive == _HKLM:
            return "没有权限改「所有用户」的自启项，需要用管理员身份重开本工具"
        return "没有权限写注册表（可能被安全软件拦住）"
    return f"{type(exc).__name__}: {exc}"


def _blob(on):
    """构造 12 字节的启用标志：首字节状态 + 8 字节时间戳。"""
    flag = _ON if on else _OFF
    if on:
        stamp = b"\x00" * 8
    else:
        # FILETIME：1601-01-01 起的 100ns 计数。任务管理器也是这么写的
        delta = dt.datetime.now() - dt.datetime(1601, 1, 1)
        ticks = int(delta.total_seconds() * 10_000_000)
        stamp = struct.pack("<Q", ticks)
    return (bytes([flag, 0, 0, 0]) + stamp).hex()


def set_enabled(entry, on, check=True):
    """禁用 / 启用一项。返回 (ok, 说明)。

    check=True 时先复核当前状态 —— 和我们列出来的不一致就放弃，
    避免把用户刚在任务管理器里改过的状态又盖回去。
    """
    if not entry.get("can_toggle"):
        return False, entry.get("note") or "这一项不支持禁用"
    on = bool(on)
    if entry["enabled"] == on:
        return True, "已经是这个状态，没有改动"

    if check:
        now_enabled, raw = _approved_state(entry["hive"], entry["approved_key"],
                                           entry["approved_value"])
        if now_enabled != entry["enabled"] or raw != entry.get("_raw"):
            return False, "这一项刚被别处改过（可能你在任务管理器里动过），请点刷新再看"

    if not _backup(entry):
        return False, "备份失败，为了可回滚这次不做改动（检查一下磁盘是否可写）"

    ok, msg = _write_raw(entry["hive"], entry["approved_key"],
                         entry["approved_value"], _blob(on))
    if not ok:
        # 写失败就别留下无效备份记录
        recs = _load_backup()
        if recs and recs[-1].get("item") == entry["id"]:
            _save_backup(recs[:-1])
        return False, msg
    entry["enabled"] = on
    entry["_raw"] = _blob(on)
    return True, "已禁用（随时可以再启用）" if not on else "已启用"


def set_many(entries, on):
    """批量启用 / 禁用。返回 (成功数, [(名称, 原因)])。"""
    ok_n, bad = 0, []
    for e in entries:
        ok, msg = set_enabled(e, on)
        if ok:
            ok_n += 1
        else:
            bad.append((e["name"], msg))
    return ok_n, bad


# ───────────────────────────── 给用户的命令 ─────────────────────────────

def delete_commands(entry):
    """彻底删除这一项的命令（我们不代删，只给命令）。"""
    if entry["kind"] == "startupdir":
        return [f'ren "{entry["key"]}\\{entry["value"]}" '
                f'"{entry["value"]}.bak"']
    hive = "HKCU" if entry["hive"] == _HKCU else "HKLM"
    return [
        f'reg delete "{hive}\\{entry["key"]}" /v "{entry["value"]}" /f',
        f'reg delete "{hive}\\{entry["approved_key"]}" '
        f'/v "{entry["approved_value"]}" /f',
    ]


def open_location(entry):
    """打开它所在的位置（启动目录 = 那个文件夹；注册表项 = 用 regedit 定位）。"""
    if entry["kind"] == "startupdir":
        return entry["key"]
    return None
