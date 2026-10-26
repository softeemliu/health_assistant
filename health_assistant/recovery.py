r"""health_assistant.recovery — 数据恢复：先找回系统留的备份，再从 NTFS 记录里捞已删除的文件

四条路，按「风险从低到高 / 成功率从高到低」排：

1. **卷影副本（「以前的版本」）**：系统若开着还原点/文件历史，格式化前的文件还在那里，
   复制出来即可，零风险。见 `shadow_copies()`。
2. **回收站**：文件根本没被动过，`$I` 小票记着原路径、`$R` 是数据本体 —— 见
   `recycle_items()` / `restore_recycle()`。**最常见、最稳**。
3. **NTFS 已删除文件**：删掉、清空回收站之后，MFT 记录上的文件名、目录、数据簇位置都还在，
   只要那些簇没被新数据盖掉，就能连名字带目录原样捞回来 —— 见 `scan_deleted()` /
   `recover_one()`。
4. **残留元数据扫描**（格式化之后）：新文件系统已经不认识旧记录了，但那些 1024 字节的
   `FILE` 记录还躺在空闲簇里 —— 按签名扫出来、用锚点推回记录编号、再拼回原目录，
   **所以格式化也能带回原名**。见 `metadata_scan()`。它同时读四个来源并按记录号合并：
   MFT 残留记录、`INDX` 目录索引、`$LogFile`/`$MFTMirr` 里的旧记录副本、
   `$UsnJrnl:$J` 变更日志（`usn_records()`，只追加，最抗覆盖）。
5. **按文件类型找（carving）**：连残留记录都被覆盖了（或者根本不是 NTFS），扫描未分配空间，
   靠文件头 + 完整结构走完整个文件 —— 见 `carving.py` / `carve()`。
   现在认 23 类（照片/文档/表格/幻灯片/压缩包/视频/音频/数据库/程序/PSD/RTF…），
   默认扫**整个未分配区**、能跨读块切几十 GB 的大文件。
   代价：**文件名和目录找不回来**，碎片化的文件仍可能只有半截。

另外两件配套的事：

* **整卷镜像**（`image_volume()`）：把盘只读复制成一份镜像文件、支持断点续传，
  之后用 `ImageVolume()` 打开镜像再扫 —— 这就是专业流程的第一步（源盘少读、可反复扫）。
* **清零检测**（`zero_stats()`）：抽样看空闲区是不是全 0x00/0xFF，用来解释
  「为什么一条都没扫到」—— SSD 的 TRIM 真落地到闪存之后，软件只能读到零。

三条铁律（写死的，别改）：

* 扫描对被恢复的卷 **只读**：以 ``\\.\X:``（原始卷）打开、只请求读权限，一个字节都不写；
* 恢复目标 **不许是同一个卷** —— 每写一个字节都可能盖掉还没捞出来的数据。
  这条是硬拒绝，不给「我确定要写」的选项（见 `check_target()`）；
* **不承诺恢复率**。SSD 开了 TRIM、簇已被新文件占用、EFS 加密、NTFS 压缩的，
   都可能捞不回来。界面上只能写「能捞多少算多少」，不许写「一键恢复全部数据」。

用法（开发自测）::

    from health_assistant import recovery
    vol = recovery.NtfsVolume("C:")
    items = recovery.scan_deleted(vol, limit=200)
    recovery.recover_one(vol, items[0], r"E:\\捞出来的")
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import time

from . import carving as _carving

__all__ = [
    "RecoverError", "volumes", "same_volume", "check_target",
    "NtfsVolume", "ImageVolume", "scan_deleted", "recover_one", "carve",
    "shadow_copies", "recycle_items", "restore_recycle", "raw_scan",
    "metadata_scan", "usn_records", "parse_data_full", "verify_recovered",
    "image_volume", "image_info", "zero_stats",
    "image_plan", "smart_preflight", "badmap_path",
    "probe_volume", "boot_kind", "boot_hint", "boot_label", "open_volume",
    "BareVolume",
    "CONFIDENCE", "CARVE_KINDS", "CARVE_LABEL", "CARVE_GROUPS",
]

SECTOR = 512
_ATTR_STANDARD = 0x10
_ATTR_NAME = 0x30
_ATTR_DATA = 0x80
_ATTR_INDEX_ROOT = 0x90
_ATTR_END = 0xFFFFFFFF
_ROOT_RECORD = 5
_EXTEND_RECORD = 11        # $Extend 目录（$UsnJrnl / $ObjId / $Quota 都挂在它下面）

# 可恢复度：给普通使用者看的词，不是概率
CONFIDENCE = {
    "recycle": "还在回收站里，原样可还原",   # 最稳：文件根本没被动过
    # good 现在**必须有证据**：文件头跟扩展名对得上，或者驻留数据非空。
    # 以前是「位图说簇空闲就 good」，格式化之后整盘空闲 → 每条都 good，是假希望。
    "good": "文件头对得上，数据区还有内容",
    "unknown": "看着还在，但无法确认内容",   # 没有文件头判据 → 不吹
    "risky": "所在空间已被新文件占用，可能已损坏",
    "mismatch": "文件头对不上，可能已被覆盖",
    "wiped": "数据区已被清零（多半是 TRIM），内容找不回来",
    "name_only": "只找到名字，内容要靠按类型找",
    "no_data": "没有数据记录",
    "compressed": "NTFS 压缩文件（会自动解压后导出）",
    "encrypted": "EFS 加密文件，本工具不能解密",
    "dir": "文件夹（只恢复目录）",
    # 只做了「不读盘」的初判（记录还在、有数据位置），还没核对内容。
    # 不写成 good：没核过就说能恢复，和 4.12.0 定的规矩冲突。
    "unverified": "还没核对内容（点它就能看）",
}

# 文件头魔数：只用来**校验**「内容像不像这个名字说的东西」，不是用来找文件的。
# 对不上不等于文件一定坏（用户可能自己改过扩展名），所以只说「可能已被覆盖」。
_MAGIC = {
    "jpg": (b"\xff\xd8\xff",), "jpeg": (b"\xff\xd8\xff",),
    "png": (b"\x89PNG\r\n\x1a\n",),
    "gif": (b"GIF87a", b"GIF89a"),
    "bmp": (b"BM",),
    "pdf": (b"%PDF",),
    "zip": (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"),
    "docx": (b"PK\x03\x04",), "xlsx": (b"PK\x03\x04",), "pptx": (b"PK\x03\x04",),
    "rar": (b"Rar!\x1a\x07",),
    "7z": (b"7z\xbc\xaf\x27\x1c",),
    "exe": (b"MZ",), "dll": (b"MZ",), "sys": (b"MZ",), "ocx": (b"MZ",),
    "mp3": (b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"),
    "wav": (b"RIFF",), "avi": (b"RIFF",),
    "doc": (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",),
    "xls": (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",),
    "ppt": (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",),
}
# 纯文本类：没有魔数，只能用「控制字符占比」粗略判断
_TEXT_EXTS = {"txt", "md", "csv", "tsv", "json", "xml", "ini", "log", "py",
              "c", "h", "cpp", "hpp", "cs", "lua", "js", "ts", "html", "css",
              "bat", "cmd", "ps1", "sh", "yml", "yaml", "toml", "sql"}
# 头 4 字节是 size、第 4~8 字节是 ftyp 的容器（MP4/MOV/HEIC…）
_FTYP_EXTS = {"mp4", "mov", "m4a", "m4v", "3gp", "heic"}

# carving 支持的类型：能靠头尾签名切出边界的那几种
CARVE_KINDS = _carving.KIND_IDS
CARVE_LABEL = _carving.KIND_LABEL
CARVE_GROUPS = _carving.GROUPS


class RecoverError(Exception):
    """恢复相关的错误（权限不足、卷不是 NTFS、目标不合法……）。"""


# ───────────────────────── 卷与安全闸 ─────────────────────────

def _letter_norm(letter):
    """'c' / 'C:' / 'C:\\' → 'C:'。"""
    s = str(letter or "").strip()
    m = re.match(r"^([A-Za-z]):?", s)
    if not m:
        raise RecoverError(f"盘符不合法：{letter!r}")
    return m.group(1).upper() + ":"


def volumes():
    """列出本机所有固定/可移动卷（只读查询，不碰磁盘内容）。"""
    out = []
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        mask = k32.GetLogicalDrives()
    except Exception:                       # noqa: BLE001
        return out
    for i in range(26):
        if not (mask >> i) & 1:
            continue
        root = f"{chr(65 + i)}:\\"
        fs = ctypes.create_unicode_buffer(64)
        label = ctypes.create_unicode_buffer(128)
        dtype = ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(root))
        try:
            ok = k32.GetVolumeInformationW(
                ctypes.c_wchar_p(root), label, 129, None, None, None, fs, 64)
        except Exception:                   # noqa: BLE001
            ok = 0
        if not ok:
            continue                        # 光驱/没插卡的空读卡器
        free = ctypes.c_ulonglong(0)
        total = ctypes.c_ulonglong(0)
        k32.GetDiskFreeSpaceExW(ctypes.c_wchar_p(root), ctypes.byref(free),
                                ctypes.byref(total), None)
        out.append({
            "letter": f"{chr(65 + i)}:",
            "label": label.value or "",
            "fs": fs.value or "",
            "is_ntfs": (fs.value or "").upper() == "NTFS",
            "total": total.value,
            "free": free.value,
            "removable": dtype == 2,        # DRIVE_REMOVABLE
        })
    return out


def _volume_of(path):
    """路径落在哪个盘（只认盘符，网络路径返回空）。"""
    try:
        drive = os.path.splitdrive(os.path.abspath(str(path)))[0]
    except Exception:                       # noqa: BLE001
        return ""
    return drive.upper() if drive else ""


def same_volume(letter, path):
    """目标目录是否和要恢复的卷是同一个盘。"""
    return _volume_of(path) == _letter_norm(letter)


def check_target(letter, target_dir):
    """恢复目标能不能用。能用返回 None，否则返回一句给用户看的中文原因。

    这是**硬闸门**：同卷直接拒，不给绕过的开关。理由很直白 —— 往正在被恢复的盘里
    写东西，等于一边捞一边盖，很容易越救越少。真正的恢复流程本来就该准备另一块盘。
    """
    if not target_dir:
        return "先选一个保存位置"
    try:
        drive = _volume_of(target_dir)
    except Exception:                       # noqa: BLE001
        return "这个路径不合法"
    if not drive:
        return "请选本机磁盘或 U 盘上的文件夹（不支持网络位置）"
    if drive == _letter_norm(letter):
        return (f"不能存回 {drive} 本身：每写一个字节都可能盖掉还没捞出来的数据，"
                "请换一个盘（U 盘 / 移动硬盘 / 另一个分区）")
    if not os.path.isdir(target_dir):
        try:
            os.makedirs(target_dir, exist_ok=True)
        except OSError as exc:
            return f"目录建不出来：{exc}"
    # 试写一个空文件，确认真有写权限（不写就别等恢复一半才发现）
    probe = os.path.join(target_dir, ".health_assistant-write-test")
    try:
        with open(probe, "wb") as fh:
            fh.write(b"ok")
        os.remove(probe)
    except OSError as exc:
        return f"这个目录写不进去：{exc}"
    return None


# ───────────────────────── NTFS 结构解析 ─────────────────────────

def _u16(buf, off):
    return struct.unpack_from("<H", buf, off)[0]


def _u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def _u64(buf, off):
    return struct.unpack_from("<Q", buf, off)[0]


def _filetime(value):
    """NTFS 的 FILETIME（100ns since 1601）→ 本地时间字符串。"""
    if not value:
        return ""
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(value / 10_000_000 - 11644473600))
    except (ValueError, OSError, OverflowError):
        return ""


def parse_runs(buf, off):
    """解析 runlist → [(起始簇, 簇数, 是否稀疏)]。

    runlist 是 NTFS 保存「文件数据在磁盘上哪几段」的压缩写法：
    头字节低 4 位是簇数的字节宽度、高 4 位是偏移的字节宽度；偏移按有符号差分累加；
    偏移宽度为 0 表示这一段的簇没有实际位置（稀疏/空洞，读出来按 0 填）。
    """
    runs = []
    p = off
    lcn = 0
    while p < len(buf):
        head = buf[p]
        if head == 0:
            break
        len_sz = head & 0x0F
        off_sz = (head >> 4) & 0x0F
        p += 1
        if len_sz == 0 or p + len_sz > len(buf):
            break
        count = int.from_bytes(buf[p:p + len_sz], "little")
        p += len_sz
        if count <= 0:
            break
        if off_sz == 0:
            runs.append((lcn, count, True))       # 稀疏
            continue
        if p + off_sz > len(buf):
            break
        delta = int.from_bytes(buf[p:p + off_sz], "little", signed=True)
        p += off_sz
        lcn += delta
        if lcn < 0:
            break
        runs.append((lcn, count, False))
    return runs


def _iter_attrs(buf):
    """遍历一条记录里的属性 → (类型, 起始偏移, 长度, 是否非驻留)。"""
    off = _u16(buf, 0x14)
    p = off
    while p + 8 <= len(buf):
        atype = _u32(buf, p)
        if atype == _ATTR_END:
            return
        alen = _u32(buf, p + 4)
        if alen < 16 or p + alen > len(buf):
            return
        yield atype, p, alen, bool(buf[p + 8])
        p += alen


def filename_from_value(val):
    """解析一段 `$FILE_NAME` 的**值**（MFT 属性和 INDX 目录项里是同一种结构）。

    布局：父记录号(8) + 四个时间(各8) + 分配大小(8) + 真实大小(8) + 标志(4)
          + 名字长度(1) + 命名空间(1) + UTF-16 名字
    """
    if len(val) < 0x42:
        return None
    parent = _u64(val, 0x00) & 0x0000FFFFFFFFFFFF       # 低 48 位是记录号
    mtime = _u64(val, 0x10)
    size = _u64(val, 0x30)
    flags = _u32(val, 0x38)
    nlen = val[0x40]
    ns = val[0x41]
    name = val[0x42:0x42 + nlen * 2].decode("utf-16-le", "replace")
    if not name or "\x00" in name:
        return None
    return {"name": name, "parent": parent, "flags": flags,
            "size": size, "mtime": mtime, "ns": ns}


def parse_names(buf):
    """一条记录里所有 $FILE_NAME → [{name, parent, flags, size, mtime, ns}]。"""
    out = []
    for atype, p, alen, nonres in _iter_attrs(buf):
        if atype != _ATTR_NAME or nonres:
            continue
        vlen = _u32(buf, p + 0x10)
        voff = _u16(buf, p + 0x14)
        info = filename_from_value(buf[p + voff:p + voff + vlen])
        if info is not None:
            out.append(info)
    return out


def attr_name(buf, p):
    """属性头里的名字（0 长度表示未命名）。命名数据流靠它区分。"""
    nlen = buf[p + 9]
    if not nlen:
        return ""
    off = _u16(buf, p + 0x0A)
    raw = buf[p + off:p + off + nlen * 2]
    return raw.decode("utf-16-le", "replace")


def parse_data(buf, name=None):
    """$DATA → dict(resident, value, runs, real_size, compressed, encrypted)。

    `name=None` 只取**未命名**流（普通文件内容）；
    传名字则取命名数据流 —— 系统文件的关键数据都挂在命名流上：
      · `$UsnJrnl:$J`    USN 变更日志（能给出「记录号 + 父记录号 + 名字 + 时间」）
      · `$UsnJrnl:$Max`  上面那个流的配额
      · `$Secure:$SDS`   安全描述符、`$Extend\\$ObjId:$O` 对象 ID……
    4.11.0 起支持，就是为了读 `$J`。
    """
    want = name or ""
    for atype, p, alen, nonres in _iter_attrs(buf):
        if atype != _ATTR_DATA:
            continue
        if attr_name(buf, p) != want:
            continue
        flags = _u16(buf, p + 0x0C)
        if not nonres:
            vlen = _u32(buf, p + 0x10)
            voff = _u16(buf, p + 0x14)
            return {"resident": True, "value": bytes(buf[p + voff:p + voff + vlen]),
                    "runs": [], "real_size": vlen,
                    "compressed": bool(flags & 0x0001), "encrypted": bool(flags & 0x4000)}
        run_off = _u16(buf, p + 0x20)
        real = _u64(buf, p + 0x30)
        return {"resident": False, "value": b"", "real_size": real,
                "runs": parse_runs(buf, p + run_off),
                "compressed": bool(flags & 0x0001), "encrypted": bool(flags & 0x4000)}
    return None


def parse_data_full(vol, rec, name=None):
    """取 `$DATA`（含 `$ATTRIBUTE_LIST` 拆到多条扩展记录的情况）→ 合并后的 runs。

    为什么需要它：一个属性的 runlist 太长放不进一条 1KB 记录时，NTFS 会把
    「类型 + 名字 + 起始 VCN + 所在记录号」写进 `$ATTRIBUTE_LIST`，
    真正的 runlist 分散在若干条**扩展记录**里。`$UsnJrnl:$J` 就是典型：
    实测 E: 上基础记录（88523）里只有 `$Max`，`$J` 的 runlist 被拆到
    88640 / 104311 / 25165 / 184213 四条扩展记录里 —— 只读基础记录会得到 None，
    然后误判成「日志被清空了」。
    """
    want = name or ""
    base = parse_data(rec, want)
    entries = []
    for atype, p, alen, nonres in _iter_attrs(rec):
        if atype != 0x20 or nonres:            # $ATTRIBUTE_LIST 一定是驻留的
            continue
        voff = _u16(rec, p + 0x14)
        vlen = _u32(rec, p + 0x10)
        val = rec[p + voff:p + voff + vlen]
        q = 0
        while q + 0x1A <= len(val):
            at = _u32(val, q)
            ln = _u16(val, q + 4)
            nl = val[q + 6]
            if ln < 0x1A or q + ln > len(val):
                break
            nm = (val[q + 0x1A:q + 0x1A + nl * 2].decode("utf-16-le", "replace")
                  if nl else "")
            start_vcn = _u64(val, q + 8)
            ref = _u64(val, q + 0x10) & 0x0000FFFFFFFFFFFF
            if at == _ATTR_DATA and nm == want:
                entries.append((start_vcn, ref))
            q += ln

    if not entries:
        return base

    parts = []
    if base and not base["resident"]:
        parts.append((0, base))
    for start_vcn, ref in sorted(entries):
        try:
            xrec = vol.record(ref)
        except (RecoverError, OSError):
            continue
        if not xrec or xrec[:4] != b"FILE":
            continue
        d = parse_data(xrec, want)
        if d and not d["resident"]:
            parts.append((start_vcn, d))
    if not parts:
        return base

    parts.sort(key=lambda x: x[0])
    runs = []
    real = 0
    seen_vcn = set()
    for vcn, d in parts:
        if vcn in seen_vcn:
            continue
        seen_vcn.add(vcn)
        runs.extend(d["runs"])
        real = max(real, d["real_size"])
    return {"resident": False, "value": b"", "real_size": real, "runs": runs,
            "compressed": any(d["compressed"] for _v, d in parts),
            "encrypted": any(d["encrypted"] for _v, d in parts)}


# NTFS 的压缩单元固定是 2^4 = 16 簇（ntfs-3g 里叫 NTFS_DEFAULT_COMPRESSION_UNIT，
# 驱动不让改，所以不用去属性头里找 —— 那里根本没有这个字段）。
_NTFS_COMP_UNIT = 16


def decompress_compressed(vol, runs, real_size):
    """把 NTFS 压缩文件的数据段解成原始字节。

    压缩文件的 runs 长这样（每 16 簇一个单元，单元之间交替出现）：

        [压缩后的 N 簇] [稀疏 16-N 簇] [下一个单元…]

    稀疏段**不是真的空洞**，它表示「这个单元压缩后省下来的簇」；整单元全零时
    只剩稀疏段。所以不能像普通稀疏文件那样直接填 0，必须按单元把「分配到的簇」
    拼成压缩字节流，再交给 LZNT1 按 4KB chunk 解。

    解不出来（数据被覆盖/记录残缺）时，`lznt1.decompress` 会截断在坏点，
    这里补零到 real_size —— 上层 `verify_recovered()` 会因此判「不完整」，
    不会假装成功。
    """
    from . import lznt1
    cluster = vol.cluster
    unit_bytes = _NTFS_COMP_UNIT * cluster
    todo = [[int(lcn), int(cnt), bool(sp)] for lcn, cnt, sp in runs]
    out = bytearray()
    i = 0
    while len(out) < real_size and i < len(todo):
        # ① 收集本单元「已分配」的簇（压缩后的字节）
        parts = []
        used = 0
        while i < len(todo) and used < _NTFS_COMP_UNIT:
            lcn, cnt, sparse = todo[i]
            if sparse:
                break
            take = min(cnt, _NTFS_COMP_UNIT - used)
            try:
                parts.append(vol.read(lcn * cluster, take * cluster))
            except RecoverError:
                parts.append(bytes(take * cluster))
            used += take
            if take >= cnt:
                i += 1
            else:
                todo[i][0] = lcn + take
                todo[i][1] = cnt - take
        # ② 跳过本单元的稀疏段（压缩省下的簇）
        skipped = 0
        while i < len(todo) and todo[i][2] and skipped < _NTFS_COMP_UNIT - used:
            cnt = todo[i][1]
            take = min(cnt, _NTFS_COMP_UNIT - used - skipped)
            skipped += take
            if take >= cnt:
                i += 1
            else:
                todo[i][1] = cnt - take
        # ③ 解这个单元
        want = min(unit_bytes, real_size - len(out))
        blob = b"".join(parts)
        if not blob:
            out.extend(bytes(want))            # 整个单元都是洞
        else:
            out.extend(lznt1.decompress(blob, expected=unit_bytes)[:want])
        if not parts and not skipped:
            break                              # 数据畸形时别原地打转
    if len(out) < real_size:
        out.extend(bytes(real_size - len(out)))
    return bytes(out[:real_size])


def _compressed_head(vol, item, size=4096):
    """解出压缩文件的**开头**几百~几千字节，用来判文件头。

    只看第一个压缩单元就够判断魔数了；解整个文件来做评级会慢到没法用
    （几万条候选，每条都解一遍）。
    """
    runs = [r for r in (item.get("runs") or []) if not r[2]]
    if not runs:
        return None
    try:
        blob = decompress_compressed(vol, [runs[0]], min(size, vol.cluster))
    except Exception:                          # noqa: BLE001
        return None
    return blob[:size] if blob else None


def parse_named_streams(buf):
    """枚举记录里所有**命名**数据流（ADS）。

    为什么单独列出来：`Zone.Identifier`（「这个文件从网上下载的」标记）、
    缩略图、摘要这类东西都挂在命名流上。只读未命名流的话，这些内容在恢复时
    直接消失，用户得到的文件看起来正常，但系统行为（比如打开时的安全提示）不一样。

    系统文件上的 `$UsnJrnl:$J` 之类也是命名流，但那些不是用户数据 ——
    调用方按 `name.startswith("$")` 过滤掉。
    """
    out = []
    for atype, p, alen, nonres in _iter_attrs(buf):
        if atype != _ATTR_DATA:
            continue
        nm = attr_name(buf, p)
        if not nm:
            continue                        # 未命名流是文件主数据，另行处理
        flags = _u16(buf, p + 0x0C)
        if not nonres:
            vlen = _u32(buf, p + 0x10)
            voff = _u16(buf, p + 0x14)
            out.append({"name": nm, "resident": True,
                        "value": bytes(buf[p + voff:p + voff + vlen]),
                        "runs": [], "real_size": vlen,
                        "compressed": bool(flags & 0x0001),
                        "encrypted": bool(flags & 0x4000)})
        else:
            run_off = _u16(buf, p + 0x20)
            out.append({"name": nm, "resident": False, "value": b"",
                        "runs": parse_runs(buf, p + run_off),
                        "real_size": _u64(buf, p + 0x30),
                        "compressed": bool(flags & 0x0001),
                        "encrypted": bool(flags & 0x4000)})
    return out


def fixup_record(rec):
    """还原 NTFS 记录的「更新序列（USA/fixup）」。

    NTFS 写盘时会把每条记录里**每个 512 字节扇区的最后 2 字节**换成一个序列号，
    原始字节挪到记录头部的 USA 数组里保存，用来检测落盘是否完整。
    所以读原始卷拿到的记录是「被顶掉 2 字节」的：1024 字节的记录里，
    偏移 510~511 和 1022~1023 是序列号，不是文件内容。
    不还原这一步，每个驻留小文件（数据就在记录里）都会坏掉 2~4 个字节 —— 实测
    「这条数据住在 MFT 记录里」重复 8 次的那个 256 字节文本，第 222~223 字节变成了 04 00。
    """
    if len(rec) < SECTOR or rec[0:4] != b"FILE":
        return rec
    usa_off = _u16(rec, 0x04)
    usa_cnt = _u16(rec, 0x06)
    if usa_cnt < 2 or usa_off < 8 or usa_off + usa_cnt * 2 > len(rec):
        return rec
    need = (len(rec) // SECTOR) + 1
    if usa_cnt != need:
        return rec
    buf = bytearray(rec)
    for i in range(1, usa_cnt):
        src = usa_off + i * 2
        dst = i * SECTOR - 2
        if dst < 0 or dst + 2 > len(buf):
            continue
        buf[dst:dst + 2] = rec[src:src + 2]
    return bytes(buf)


class _ClusterBitmap:
    """$Bitmap（记录号 6）—— 哪些簇还被占着。

    只用来判断「已删除文件的簇有没有被新数据覆盖」，决定给不给「可能已被覆盖」的提示；
    不做任何修改。按 1MB 分块读，避免把整张位图读进内存（1TB 盘也才 32MB，其实不大，
    但没必要每个条目都重读）。
    """

    def __init__(self, vol):
        self.vol = vol
        self.runs = []
        self.size = 0
        rec = vol.record(6)
        if rec:
            data = parse_data(rec)
            if data and not data["resident"]:
                self.runs = [r for r in data["runs"] if not r[2]]
                self.size = data["real_size"]
        self._chunk_lcn = -1
        self._chunk = b""

    def _bytes_of(self, want_off, want_len):
        """把位图逻辑偏移映射到物理位置读出来。"""
        pos = 0
        for lcn, count, _sparse in self.runs:
            seg = count * self.vol.cluster
            if want_off < pos + seg:
                skip = want_off - pos
                take = min(want_len, seg - skip)
                return self.vol.read(lcn * self.vol.cluster + skip, take)
            pos += seg
        return b""

    def used(self, lcn):
        """这个簇现在是否被占用（位图里 1 = 已用）。"""
        if not self.runs:
            return None                     # 读不到位图：不知道，别乱判
        off = lcn >> 3
        cached = (self._chunk_lcn >= 0 and self._chunk_lcn <= off
                  and off < self._chunk_lcn + len(self._chunk))
        if not cached:
            self._chunk_lcn = off
            self._chunk = self._bytes_of(off, 1 << 20) or b""
        idx = off - self._chunk_lcn
        if idx >= len(self._chunk):
            return None
        return bool(self._chunk[idx] >> (lcn & 7) & 1)


class _RawVolume:
    r"""无缓冲读原始卷（``\\.\C:``）。

    **为什么不能用 Python 的 open()**：以普通方式读 ``\\.\C:`` 会走系统缓存，
    删除文件后还会读到删除**之前**的旧 MFT —— 实测文件删掉 12 秒后同一句柄、
    新开句柄读到的都是「还没删」的状态，而 ``FILE_FLAG_NO_BUFFERING`` 读出来
    记录已经释放。拿缓存里的旧状态做「已删除文件恢复」，等于对着一份过期快照干活：
    要么找不到刚删的东西，要么把还在用的记录当成可恢复的。

    所以这里用 ctypes 直接 CreateFileW + FILE_FLAG_NO_BUFFERING + ReadFile，
    并把读缓冲区对齐到 512 字节（无缓冲读的硬性要求：偏移、长度、缓冲区地址都要扇区对齐）。
    """

    _GENERIC_READ = 0x80000000
    _SHARE_ALL = 0x00000007                  # READ | WRITE | DELETE
    _OPEN_EXISTING = 3
    _NO_BUFFERING = 0x20000000
    _INVALID = -1

    def __init__(self, letter):
        self.letter = _letter_norm(letter)
        self.path = "\\\\.\\" + self.letter
        try:
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        except Exception as exc:                # noqa: BLE001
            raise RecoverError(f"加载 kernel32 失败：{exc}") from exc
        self._k32 = k32
        k32.CreateFileW.restype = ctypes.c_void_p
        k32.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                                    ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                                    ctypes.c_void_p]
        k32.ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
                                 ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
        k32.ReadFile.restype = ctypes.c_int
        k32.SetFilePointerEx.argtypes = [ctypes.c_void_p, ctypes.c_int64,
                                         ctypes.POINTER(ctypes.c_int64), ctypes.c_uint32]
        k32.SetFilePointerEx.restype = ctypes.c_int
        h = k32.CreateFileW(self.path, self._GENERIC_READ, self._SHARE_ALL, None,
                            self._OPEN_EXISTING, self._NO_BUFFERING, None)
        if not h or h == ctypes.c_void_p(self._INVALID).value:
            err = ctypes.get_last_error()
            if err == 5:                        # ERROR_ACCESS_DENIED
                raise RecoverError(
                    "读不了磁盘原始数据：需要管理员权限。请右键「以管理员身份运行」后再试")
            raise RecoverError(f"打不开 {self.letter}（错误码 {err}）")
        self._h = h

    def close(self):
        if getattr(self, "_h", None):
            try:
                self._k32.CloseHandle(ctypes.c_void_p(self._h))
            finally:
                self._h = None

    def read(self, offset, size):
        """从 offset 读 size 字节（内部按 512 对齐，返回值仍是 offset 起的数据）。"""
        if not getattr(self, "_h", None):
            raise RecoverError("卷已经关了")
        if size <= 0:
            return b""
        start = offset - (offset % SECTOR)
        end = offset + size
        end_al = end + (-end % SECTOR)
        want = end_al - start
        raw = ctypes.create_string_buffer(want + SECTOR)
        addr = ctypes.addressof(raw)
        pad = (-addr) % SECTOR
        pos = ctypes.c_int64(start)
        if not self._k32.SetFilePointerEx(ctypes.c_void_p(self._h), start, None, 0):
            raise RecoverError(f"定位 {self.letter} 偏移 {start} 失败")
        got = ctypes.c_uint32(0)
        ok = self._k32.ReadFile(ctypes.c_void_p(self._h),
                                ctypes.c_void_p(addr + pad), want,
                                ctypes.byref(got), None)
        if not ok:
            err = ctypes.get_last_error()
            raise RecoverError(f"读 {self.letter} 失败（错误码 {err}）")
        data = raw.raw[pad:pad + got.value]
        head = offset - start
        return data[head:head + size]

    def length(self):
        """卷的总字节数。走 `IOCTL_DISK_GET_LENGTH_INFO`（0x7405C），不需要懂文件系统。"""
        if not getattr(self, "_h", None):
            raise RecoverError("卷已经关了")
        out = ctypes.c_int64(0)
        ret = ctypes.c_uint32(0)
        self._k32.DeviceIoControl.argtypes = [
            ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32,
            ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_void_p]
        self._k32.DeviceIoControl.restype = ctypes.c_int
        ok = self._k32.DeviceIoControl(
            ctypes.c_void_p(self._h), 0x0007405C, None, 0,
            ctypes.byref(out), ctypes.sizeof(out), ctypes.byref(ret), None)
        if not ok or ret.value != 8 or out.value <= 0:
            raise RecoverError(f"读不出 {self.letter} 的总大小（错误码 {ctypes.get_last_error()}）")
        return out.value


# ───────────────── 先看清楚这是什么文件系统（别扫半天才发现扫错了）─────────────────

_BOOT_LABEL = {
    "ntfs": "NTFS",
    "exfat": "exFAT",
    "fat32": "FAT32",
    "fat": "FAT",
    "refs": "ReFS",
    "bitlocker": "BitLocker 加密",
    "apfs": "APFS（苹果）",
    "ext": "Linux 的 ext2/3/4",
    "mbr": "分区表（整块硬盘）",
    "zero": "全 0（空白）",
    "unknown": "认不出的格式",
    "denied": "",
}


def boot_kind(head, ext2_magic=b""):
    """看引导扇区的前 512 字节，判断这是哪种文件系统。

    为什么要单独判：以前不分青红皂白按 NTFS 去解析，选到 BitLocker 的盘会扫出
    一堆垃圾条目、选到 exFAT 的 U 盘直接报「不是 NTFS」——用户不知道下一步该干什么。
    现在先认格式，再给针对性的说法（见 `boot_hint()`）。

    判断依据（都是各家的官方布局，不是猜）：
      NTFS/exFAT/ReFS/BitLocker 的 OEM 名在偏移 3、长 8 字节；
      FAT 的偏移 3 是 OEM 厂商名（"MSDOS5.0" 之类），文件系统名在 FAT32 的 0x52、
      FAT12/16 的 0x36；APFS 容器超级块在偏移 32 的 "NXSB"；ext 的魔数 0xEF53
      在偏移 1024（要额外读 2 字节，由调用方传进来）。
    """
    if len(head) < 0x60:
        return "unknown"
    oem = head[3:11]
    if oem == b"NTFS    ":
        return "ntfs"
    if oem == b"EXFAT   ":
        return "exfat"
    if oem == b"ReFS    ":
        return "refs"
    if oem in (b"-FVE-FS-", b"-FVE-FS\x00"):
        return "bitlocker"
    if not any(head[:512]):
        return "zero"
    if head[0x52:0x5A] == b"FAT32   ":
        return "fat32"
    if head[0x36:0x3E] in (b"FAT12   ", b"FAT16   ", b"FAT     "):
        return "fat"
    if head[32:36] == b"NXSB":
        return "apfs"
    if ext2_magic[:2] == b"\x53\xef":
        return "ext"
    # 整块硬盘的最前面是分区表：0x1BE 起四组 16 字节分区项 + 0x55AA 结尾
    if head[510:512] == b"\x55\xaa" and any(head[0x1BE:0x1FE]):
        return "mbr"
    return "unknown"


def boot_label(kind):
    """文件系统的显示名（'exfat' → 'exFAT'）。界面用它，别在界面里再抄一份表。"""
    return _BOOT_LABEL.get(kind or "", kind or "")


def boot_hint(kind, letter=None):
    """把「是什么格式」翻成「现在能做什么、下一步干什么」——不出现听不懂的词。"""
    if kind in ("", "ntfs"):
        return ""
    try:
        lt = _letter_norm(letter) if letter else ""
    except RecoverError:
        lt = ""                         # 打开的是镜像，没有盘符
    where = f"{lt} " if lt else "这块盘"
    if kind == "bitlocker":
        return (f"{where}是 BitLocker 加密的。加密状态下整块盘上存的是密文 —— "
                "任何恢复软件（包括这个）都读不出文件名和内容。这不是工具不行，"
                "是加密本身的设计：没有密钥，数据在数学上就是不可读的。\n\n"
                "先解锁再来：在「此电脑」里双击它、输入密码，或用管理员 PowerShell 执行\n"
                f"manage-bde -unlock {lt or 'X:'} -RecoveryPassword <48 位恢复密钥>\n\n"
                "解锁后不用等它解密完，直接回来重新扫描即可。"
                "恢复密钥在微软账户里（aka.ms/myrecoverykey），公司电脑找 IT。")
    if kind == "exfat":
        return (f"{where}是 exFAT 格式（U 盘、移动硬盘最常见）。\n\n"
                "好消息：exFAT 删文件只是把目录项里的「在用」标记清掉，"
                "文件名、大小、起始位置**全都还在** —— 所以用 ②「已删除的文件」"
                "能连名字带内容找回来。\n\n"
                "用不了的是 ③「格式化后的残留」：那一步扫的是 NTFS 的记录表。"
                "万一这块盘被格式化过，用 ④「按文件类型找」按内容捞。\n\n"
                "如果里面的东西很重要：先别往里写任何东西，也别再插拔 —— "
                "每写一个字节都可能盖掉还没捞出来的数据。")
    if kind in ("fat32", "fat"):
        return (f"{where}是 FAT32/FAT 格式（老 U 盘、存储卡、小容量盘）。\n\n"
                "用 ②「已删除的文件」能找到删掉的东西。但有两件事要先知道：\n\n"
                "· FAT 删文件时会把文件名的**第一个字符**盖掉，所以名字可能显示成 "
                "_xxx.txt（其余字符都在，长文件名是完整的）；\n"
                "· 簇链也被清了，只能假设文件在盘上**连续存放** —— 碎片化过的文件"
                "拼出来会错，这种情况界面会标成「可能已损坏」。\n\n"
                "③「格式化后的残留」只对 NTFS 有效。被格式化过就用 ④「按文件类型找」。"
                "另外 FAT32 单文件上限 4GB，录像类文件常常已经被系统截断过。")
    if kind == "refs":
        return (f"{where}是 ReFS 格式（Windows 服务器/存储池用的）。\n\n"
                "ReFS 的记录结构和 NTFS 完全不同，本工具目前只解析 NTFS。"
                "ReFS 一般自带完整性校验和副本，先检查存储空间是不是还健在，"
                "再从别的副本上取数据，比单盘恢复更靠谱。")
    if kind == "apfs":
        return (f"{where}是苹果的 APFS 格式。Windows 上读不了 APFS，"
                "本工具也不支持。找一台 Mac，或用 Mac 版的恢复软件。")
    if kind == "ext":
        return (f"{where}是 Linux 的 ext2/3/4 格式。本工具只解析 NTFS，"
                "要在 Linux 下用 debugfs / TestDisk / PhotoRec 处理。")
    if kind == "mbr":
        return ("这里读到的是「分区表」，而不是某个分区的内容 —— 说明你选的不是分区的开头，"
                "而是整块硬盘的开头（整盘镜像、或者移动硬盘盒直通整盘）。\n\n"
                "按分区来做：在 Windows 里直接选那个盘符（比如 D:）；"
                "如果是整盘镜像文件，得先按分区表找到分区的起始偏移，单独切出那一段再打开。")
    if kind == "zero":
        return (f"{where}的开头全是 0，一个字节的文件系统信息都没有。通常是这几种情况：\n\n"
                "· 整块盘被做过全盘清零 / 安全擦除（这样连分区表都没了，软件层面没得救）；\n"
                "· 硬盘盒或转接线没把真正的盘暴露出来（换直连 SATA/USB 再试）；\n"
                "· 盘本身已经读不出内容（先看「硬盘健康」那一页）。\n\n"
                "如果这块盘以前有数据、也没主动擦除过，先别再通电折腾，"
                "找专业恢复机构做芯片级检测更稳。")
    return (f"{where}的引导扇区认不出来（既不是 NTFS/exFAT/FAT/ReFS，"
            "也不是 BitLocker 加密）。常见原因：\n\n"
            "· 分区表丢了或被改过（盘还在，只是「目录」没了）；\n"
            "· 是整块硬盘的映像、或者用了特殊的存储池（Storage Spaces / 动态磁盘）；\n"
            "· 文件系统本身损坏。\n\n"
            "这种情况值得试「按文件类型找」：它不依赖文件系统，只按文件头把"
            "照片、视频、PDF、压缩包捞出来。")


def probe_volume(letter):
    """不动数据地看一眼这块盘是什么格式（只读 2 个扇区，几毫秒）。

    界面在用户选盘时就能据此把「不支持的方式」灰掉、把原因写在旁边，
    而不是让人家点了「开始查找」等半分钟才收到一句「不是 NTFS」。
    """
    letter = _letter_norm(letter)
    try:
        raw = _RawVolume(letter)
    except RecoverError as exc:
        return {"kind": "denied", "label": "", "hint": str(exc),
                "readable": False, "letter": letter}
    try:
        head = raw.read(0, SECTOR)
        try:
            ext = raw.read(1024, 2)
        except RecoverError:
            ext = b""
        kind = boot_kind(head, ext)
        return {"kind": kind, "label": _BOOT_LABEL.get(kind, kind),
                "hint": boot_hint(kind, letter), "readable": True, "letter": letter}
    finally:
        raw.close()


class BareVolume:
    r"""只读原始卷的「裸」视图：不解析文件系统，只提供按字节读和卷大小。

    为什么需要它：**「按文件类型找」（carving）本来就不看文件系统** —— 它只按
    文件头尾签名切片。以前它非要一个 NTFS 卷对象，等于把 exFAT / FAT32 /
    引导扇区认不出的盘全挡在门外，而那些盘恰恰最需要按内容捞。

    它不知道哪些簇是空闲的（`cluster_used()` 返回 None），所以从活文件里也可能
    抠出重复的东西 —— 这个代价在界面上会说明，不能假装不知道。
    """

    def __init__(self, letter):
        self.letter = _letter_norm(letter)
        self.path = "\\\\.\\" + self.letter
        self._raw = _RawVolume(self.letter)
        try:
            self.kind = "unknown"
            self.total_bytes = self._raw.length()
            self.bytes_per_sector = SECTOR
            self.cluster = 4096
            boot = self.read(0, SECTOR)
            if len(boot) >= 0x20:
                bps = _u16(boot, 0x0B)
                spc = boot[0x0D]
                if bps in (512, 1024, 2048, 4096) and spc and not (spc & (spc - 1)):
                    self.bytes_per_sector = bps
                    self.cluster = bps * spc
                self.kind = boot_kind(boot)
            self.total_sectors = self.total_bytes // SECTOR
        except Exception:
            self.close()
            raise

    def read(self, offset, size):
        if self._raw is None:
            raise RecoverError("卷已经关了")
        return self._raw.read(offset, size)

    def cluster_used(self, _lcn):
        """不知道哪些簇还在用 —— 返回 None，让调用方知道「这里是盲的」。"""
        return None

    def close(self):
        if self._raw is not None:
            try:
                self._raw.close()
            finally:
                self._raw = None

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()


def _probe_kind_quiet(letter):
    """只读引导扇区看一眼格式；读不到（没权限/盘掉线）返回空串，不抛。"""
    try:
        return probe_volume(letter).get("kind") or ""
    except Exception:                       # noqa: BLE001
        return ""


def open_volume(letter):
    """打开一块卷：NTFS / FAT / exFAT 各返回对应的卷对象，都解析不了才退成裸卷。

    返回 `(vol, kind)`。`kind` 是 "ntfs" / "exfat" / "fat32" / "fat12" / "fat16"，
    或者裸卷的格式名。除裸卷外都能做「找回已删除的文件」。
    """
    letter = _letter_norm(letter)
    kind = _probe_kind_quiet(letter)
    if kind in ("exfat", "fat32", "fat"):
        from . import fatfs
        v = fatfs.open_fat_volume(letter)
        return v, v.fs
    try:
        return NtfsVolume(letter), "ntfs"
    except RecoverError:
        # 不是 NTFS（或者 NTFS 结构坏到读不出 $MFT）→ 退成裸卷，按内容捞还有戏
        bare = BareVolume(letter)      # 权限不足会在这里再抛一次，消息一致
        return bare, bare.kind


def _image_kind_at(path, base=0):
    """看镜像里 `base` 处的卷首是哪种文件系统。"""
    try:
        with open(path, "rb") as fh:
            fh.seek(base)
            head = fh.read(SECTOR)
            fh.seek(base + 1024)
            ext = fh.read(2)
    except OSError as exc:
        raise RecoverError(f"打不开镜像文件：{exc}") from exc
    if len(head) < SECTOR:
        return "unknown"
    return boot_kind(head, ext)


def open_image_volume(path, letter=None, base=0, part=None):
    """打开一份整卷镜像，按里面的引导扇区选解析器（NTFS / FAT / exFAT）。

    以前这里写死 `ImageVolume`，于是 exFAT 或 FAT32 的 U 盘镜像一打开就报
    「不是 NTFS」—— 明明能解析，只是没人去路由。

    `base` 是「卷首在镜像文件里的字节偏移」：整盘镜像（dd 出来的一整块盘）里
    0 偏移放的是**分区表**，真正的卷在某个分区的起点。不给 base 时如果认出是
    分区表，会**自动挑第一个能认出的 Windows 分区**（挑中的信息挂在
    `vol.partition` 上，界面据此告诉用户用的是哪个分区）。
    """
    kind = _image_kind_at(path, base)
    if not base and kind in ("mbr", "zero"):
        from . import partitions
        layout = partitions.list_partitions(path)
        usable = [p for p in layout.get("parts") or []
                  if p.get("fs") in ("ntfs", "exfat", "fat32", "fat")]
        if usable:
            part = usable[0]
            base = int(part["offset"])
            kind = _image_kind_at(path, base)
        elif layout.get("scheme") != "flat":
            raise RecoverError(
                "这个镜像是**整块硬盘**（0 偏移是分区表），但里面没有认得出的"
                "Windows 分区。\n\n"
                + (layout.get("note") or "")
                + "\n\n如果是分区表被删过，可以在「打开已有镜像」里选"
                "「按文件系统签名找分区」，把分区起点找回来再扫。")
    if kind in ("exfat", "fat32", "fat"):
        from . import fatfs
        v = fatfs.open_fat_volume(path, is_image=True, base=base)
    else:
        v = ImageVolume(path, letter=letter, base=base)
    v.partition = part
    return v, getattr(v, "fs", "ntfs")


class NtfsVolume:
    r"""以只读方式打开的 NTFS 卷（``\\.\C:``）。

    为什么不用 ``open("C:\\...")``：普通路径只能看到「活着的文件」，
    已删除的条目在 MFT 里、被覆盖的扇区也不在任何文件里，必须走原始卷。
    """

    def __init__(self, letter):
        self.letter = _letter_norm(letter)
        self.path = "\\\\.\\" + self.letter
        self._raw = None
        self._bitmap = None
        try:
            self._raw = _RawVolume(self.letter)
        except RecoverError:
            raise
        except Exception as exc:                # noqa: BLE001
            raise RecoverError(f"打不开 {self.letter}：{exc}") from exc
        try:
            self._parse_boot()
        except RecoverError:
            self.close()
            raise

    # ---- 生命周期 ----
    def close(self):
        if self._raw is not None:
            try:
                self._raw.close()
            finally:
                self._raw = None

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()

    # ---- 引导扇区 ----
    def _parse_boot(self):
        bs = self.read(0, SECTOR)
        self.kind = "unknown"
        if len(bs) < SECTOR:
            raise RecoverError(f"{self.letter} 连引导扇区都读不出来（盘可能已经掉线，"
                               "或者读这块盘需要管理员权限）")
        try:
            ext_magic = self.read(1024, 2)
        except RecoverError:
            ext_magic = b""
        self.kind = boot_kind(bs, ext_magic)
        if self.kind != "ntfs":
            # 先说清「这是什么格式、为什么扫不了、现在还能做什么」，
            # 而不是甩一句「不是 NTFS」。见 boot_hint()。
            raise RecoverError(boot_hint(self.kind, self.letter))
        self.bytes_per_sector = _u16(bs, 0x0B)
        self.sectors_per_cluster = bs[0x0D]
        if self.bytes_per_sector not in (SECTOR,):
            raise RecoverError(
                f"这块盘的扇区大小是 {self.bytes_per_sector} 字节"
                "（4Kn 模式或非标准扇区），本工具按 512 字节实现，暂不支持。"
                "这种盘很少见，一般出现在新的 NVMe 或磁盘阵列上。")
        if not self.sectors_per_cluster:
            raise RecoverError("这个 NTFS 的簇大小是 0，引导扇区已经损坏，暂不支持")
        self.cluster = self.bytes_per_sector * self.sectors_per_cluster
        self.total_sectors = _u64(bs, 0x28)
        self.mft_lcn = _u64(bs, 0x30)
        cpr = struct.unpack_from("<b", bs, 0x40)[0]
        self.record_size = 1 << (-cpr) if cpr < 0 else cpr * self.cluster
        if not 512 <= self.record_size <= 65536:
            raise RecoverError("MFT 记录大小异常，暂不支持")
        self.serial = _u64(bs, 0x48)
        self._mft_runs = None
        self._mft_size = 0
        self._record_count = None
        self._segments_cache = None

    # ---- 底层读 ----
    def read(self, offset, size):
        """按扇区对齐读原始字节（无缓冲）。返回从 offset 起、长度 ≤ size 的数据。"""
        if self._raw is None:
            raise RecoverError("卷已经关了")
        return self._raw.read(offset, size)

    # ---- MFT ----
    def _mft_data(self):
        """$MFT 自己的 $DATA（记录 0）：拿到 runlist 和数据总长。"""
        if self._mft_runs is None:
            rec = self._read_mft_slot(0)
            data = parse_data(rec) if rec else None
            if not data or data["resident"]:
                raise RecoverError("读不出 $MFT 的位置（卷可能严重损坏）")
            self._mft_runs = [r for r in data["runs"]]
            self._mft_size = data["real_size"]
            self._record_count = max(0, self._mft_size // self.record_size)
        return self._mft_runs

    def _segments(self):
        """把 $MFT 的 runlist 摊成 [(逻辑起, 逻辑止, 物理起或 None)]。"""
        if self._segments_cache is None:
            segs = []
            pos = 0
            for lcn, count, sparse in self._mft_data():
                size = count * self.cluster
                segs.append((pos, pos + size, None if sparse else lcn * self.cluster))
                pos += size
            self._segments_cache = segs
        return self._segments_cache

    def iter_records(self, start=0, stop=None, block=4 << 20):
        """按 MFT 顺序**成块**读记录，产出 (序号, 记录字节)。

        为什么必须成块：一条记录 1KB，整卷 MFT 有近 200 万条。一条一个 read 就是
        200 万次系统调用，实测 121 秒还没扫完；按 4MB 一块读只要几百次，快两个数量级。
        """
        rec = self.record_size
        total = self.record_count
        stop = total if stop is None else min(stop, total)
        idx = 0
        for seg_start, seg_end, phys in self._segments():
            if idx >= stop:
                return
            size = seg_end - seg_start
            if phys is None:                      # 稀疏段：这些记录号不存在
                idx += size // rec
                continue
            pos = phys
            left = size
            carry = b""
            while left > 0 and idx < stop:
                take = min(block, left)
                data = self.read(pos, take)
                if not data:
                    break
                pos += take
                left -= take
                data = carry + data
                whole = len(data) // rec
                for k in range(whole):
                    if idx >= stop:
                        return
                    yield idx, fixup_record(data[k * rec:(k + 1) * rec])
                    idx += 1
                carry = data[whole * rec:]

    def _read_mft_slot(self, index):
        """按 MFT 内序号读一条记录（$MFT 可能是碎片化的，得走 runlist）。"""
        if self._mft_runs is None and index == 0:
            # 记录 0 就在 MFT 起始簇上，直接按物理位置读 —— 不能走 runlist，
            # 否则「读 0 号记录 → 拿 $MFT 的 runlist → 又要读 0 号记录」死循环。
            return fixup_record(self.read(self.mft_lcn * self.cluster, self.record_size))
        self._mft_data()
        offset = index * self.record_size
        pos = 0
        for lcn, count, sparse in self._mft_runs:
            seg = count * self.cluster
            if offset < pos + seg:
                if sparse:
                    return b""
                inner = offset - pos
                return fixup_record(self.read(lcn * self.cluster + inner,
                                              self.record_size))
            pos += seg
        return b""

    @property
    def record_count(self):
        self._mft_data()
        return self._record_count

    def record(self, index):
        return self._read_mft_slot(index)

    # ---- 位图 ----
    @property
    def bitmap(self):
        if self._bitmap is None:
            self._bitmap = _ClusterBitmap(self)
        return self._bitmap

    def cluster_used(self, lcn):
        return self.bitmap.used(lcn)

    # ---- 路径 ----
    def name_of(self, index, cache=None):
        """某条记录的主文件名 + 父记录号 + 是否还在用。"""
        if cache is not None and index in cache:
            return cache[index]
        rec = self.record(index)
        info = None
        if rec and rec[:4] == b"FILE":
            names = parse_names(rec)
            if names:
                best = max(names, key=lambda n: (n["ns"] != 0, len(n["name"])))
                info = {"name": best["name"], "parent": best["parent"],
                        "in_use": bool(_u16(rec, 0x16) & 1)}
        if cache is not None:
            cache[index] = info
        return info

    def path_of(self, index, cache=None, depth=32):
        """拼出原始路径；祖先目录已经不在了就在前面标明。"""
        parts = []
        cur = index
        gone = False
        for _ in range(depth):
            info = self.name_of(cur, cache)
            if not info:
                break
            parts.append(info["name"])
            parent = info["parent"]
            if not parent or parent == _ROOT_RECORD:
                break
            pinfo = self.name_of(parent, cache)
            if not pinfo:
                gone = True
                break
            if not pinfo["in_use"]:
                gone = True
            cur = parent
        parts.reverse()
        return ("（原目录已不在）" if gone else "") + "\\".join(parts)


class _ImageReader:
    """把镜像文件包成「像原始卷一样可读」的对象（只实现 read / close / size）。"""

    def __init__(self, path, base=0):
        self.path = path
        self.base = max(0, int(base or 0))
        self._fh = open(path, "rb", buffering=0)
        self.size = max(0, os.path.getsize(path) - self.base)

    def read(self, offset, size):
        if size <= 0 or offset < 0:
            return b""
        if offset >= self.size:
            return b""
        self._fh.seek(self.base + offset)
        return self._fh.read(min(size, self.size - offset))

    def seek_frame(self, base):
        """换个偏移：整盘镜像里「第 N 个分区」就是从那个分区的第一字节当卷首。"""
        self.base = max(0, int(base or 0))
        self.size = max(0, os.path.getsize(self.path) - self.base)
        return self

    def close(self):
        try:
            if self._fh is not None:
                self._fh.close()
        finally:
            self._fh = None


class BareImageVolume:
    """裸数据镜像的只读视图：没有引导扇区，只按字节读。

    为什么需要：`dd` 出来的镜像、别人给的分区镜像、甚至只是一段被拷出来的数据，
    开头都不是某个文件系统的引导扇区。这种镜像按类型找照样能救东西 ——
    以前这类文件会被当成盘符去扫（`"D://x.img"` → `"D:"`），扫错对象还浑然不觉。
    """

    def __init__(self, path, base=0):
        self.letter = "镜像"
        self.path = path
        self._raw = _ImageReader(path, base=base)
        self.base = self._raw.base
        self.kind = "unknown"
        self.total_bytes = self._raw.size
        self.bytes_per_sector = SECTOR
        self.cluster = 4096
        self.total_sectors = self.total_bytes // SECTOR

    def read(self, offset, size):
        return self._raw.read(offset, size)

    def cluster_used(self, _lcn):
        """看不到位图 —— 返回 None，让调用方知道「这里是盲的」（界面会标出来）。"""
        return None

    def close(self):
        self._raw.close()


class ImageVolume(NtfsVolume):
    """以只读方式打开一份「整卷镜像」（`image_volume()` 写出来的 .pciimg）。

    为什么要它：专业流程的第一步就是镜像 —— 对镜像可以反复扫、扫多久都不碰源盘，
    源盘也不会因为长时间读取而进一步恶化。这里只把底层读换成「读文件」，
    上面所有扫描（MFT / INDX / USN / 按类型找）和恢复导出一行都不用改。
    """

    def __init__(self, path, letter=None, base=0):
        self.letter = letter or "镜像"
        self.path = path
        self._raw = _ImageReader(path, base=base)
        self.base = self._raw.base
        self._bitmap = None
        try:
            self._parse_boot()
        except Exception:
            self.close()
            raise


# ───────────────────────── 扫描已删除文件 ─────────────────────────

def scan_deleted(vol, limit=None, budget=None, progress=None, cancel=None,
                 progress2=None, verify=20000, path_limit=30000):
    """扫 MFT（NTFS）或目录树（FAT/exFAT），列出已删除的文件/文件夹（**只读**）。

    `vol` 可以是盘符（'C:'）也可以是已经打开的卷对象。
    `limit`：返回条数上限（**默认 None = 全部**）。以前默认 2000 / 上限 2 万，
    用户看到的是「只有这么多」，其实盘里有十几万条 —— 上限不该伪装成全部。
    `path_limit`：算「原位置」的条数（每条要随机读祖先目录，实测 15.8 万条要 57 秒），
    默认最近 3 万条；其余留空，点开那一条时再补（那时卷已经打开了，补一条只要几毫秒）。
    `verify`：逐条核对内容（要读盘，每条约 0.3ms）的条数，默认最近 2 万条。
    超出部分标成 `unverified`（记录还在、有数据位置），界面照样列出来，
    点它一下就能看到内容 —— 比「悄悄砍掉」诚实，也比全量核对快得多。
    `budget`：秒数预算（NTFS 默认 90 秒；FAT 走目录树，默认 120 秒）。
    `progress(已扫记录, 总记录)`；`cancel()` 返回 True 就提前收工。
    返回 `(条目列表, 统计 dict)`。

    4.14.0 起按文件系统分流：NTFS 走 MFT，FAT12/16/32 与 exFAT 走
    `fatfs.scan_deleted()`（目录树里的已删除目录项）。**两边的返回结构完全一致**，
    所以界面不用关心这块盘是什么格式。

    顺序上做了一件事：**先按删除/修改时间从新到旧，再按可恢复度**。
    刚删掉的东西才是用户要找的；MFT 里躺着几万条陈年记录，按记录号排等于把新数据埋了。
    """
    if isinstance(vol, str):
        kind = _probe_kind_quiet(vol)
        if kind in ("exfat", "fat32", "fat"):
            from . import fatfs
            return fatfs.scan_deleted(
                vol, limit=max(limit or 200000, 1000),
                budget=budget if budget is not None else 120,
                progress=progress, cancel=cancel)
    try:
        from .fatfs import is_fat
        if is_fat(vol):
            from . import fatfs
            return fatfs.scan_deleted(
                vol, limit=max(limit or 200000, 1000),
                budget=budget if budget is not None else 120,
                progress=progress, cancel=cancel)
    except ImportError:
        pass
    own = not isinstance(vol, NtfsVolume)
    v = NtfsVolume(vol) if own else vol
    try:
        total = v.record_count
        if total <= 0:
            raise RecoverError("读不出 MFT 记录数（卷可能严重损坏）")
        t0 = time.time()
        budget_s = budget if budget is not None else 90
        cands = []
        scanned = 0
        truncated = False
        for idx, rec in v.iter_records():
            scanned = idx + 1
            if idx % 8192 == 0:
                progress and progress(scanned, total)
                if cancel and cancel():
                    truncated = True
                    break
                if time.time() - t0 > budget_s:
                    truncated = True
                    break
            if len(rec) < 0x30 or rec[:4] != b"FILE":
                continue
            flags = _u16(rec, 0x16)
            if flags & 0x01:
                continue                    # 还在用的记录，不是「已删除」
            if idx < 16:
                continue                    # 0~15 是 NTFS 元文件，不能当用户文件恢复
            names = parse_names(rec)
            if not names:
                continue
            best = max(names, key=lambda n: (n["ns"] != 0, len(n["name"])))
            nm = best["name"]
            # 硬链接：同一条 MFT 记录被多个目录引用。ns == 2 是 DOS 短名（跟主名
            # 是同一个文件同一个目录，不算链接），parent 相同也不是链接。
            links = [n["name"] for n in names
                     if n is not best and n.get("ns") != 2
                     and n.get("parent") != best.get("parent")]
            if not nm or nm.startswith("$"):
                continue
            data = parse_data(rec)
            is_dir = bool(flags & 0x02)
            if data is None and not is_dir:
                continue
            size = (data or {}).get("real_size") or best["size"]
            cands.append({
                "idx": idx,
                "name": nm,
                "size": size,
                "mtime": _filetime(best["mtime"]),
                "_t": best["mtime"],         # 排序用的原始 FILETIME
                "is_dir": is_dir,
                "resident": bool(data and data["resident"]),
                "runs": (data or {}).get("runs") or [],
                "compressed": bool(data and data["compressed"]),
                "encrypted": bool(data and data["encrypted"]),
                "data_off": (data or {}).get("value", b"") if (data and data["resident"]) else b"",
                "letter": v.letter,
                "links": links,
            })
            # 命名数据流（ADS）也列出来，名字写成「文件:流名」，导出时 `:` 会被
            # safe_name 换成 `_`，落到盘上是 `文件_流名`，不和主文件撞名。
            for ad in parse_named_streams(rec):
                if ad["name"].startswith("$") or not ad["name"]:
                    continue
                cands.append({
                    "idx": idx,
                    "name": f'{nm}:{ad["name"]}',
                    "size": ad["real_size"],
                    "mtime": _filetime(best["mtime"]),
                    "_t": best["mtime"],
                    "is_dir": False,
                    "resident": bool(ad["resident"]),
                    "runs": ad["runs"],
                    "compressed": bool(ad["compressed"]),
                    "encrypted": bool(ad["encrypted"]),
                    "data_off": ad["value"] if ad["resident"] else b"",
                    "letter": v.letter,
                    "stream": ad["name"],
                })
        progress and progress(scanned, total)

        # 位图判定（「簇是不是已经给别人了」）只对留下的这些做：全量 6 万条 × 每条例行
        # 抽样会把扫描时间翻几倍，而用户真正会勾的就是最近删的那几百条。
        cands.sort(key=lambda c: -c["_t"])
        keep = cands if limit is None else cands[:max(limit, 200)]
        order = {"good": 0, "dir": 1, "risky": 2, "compressed": 3, "encrypted": 4,
                 "no_data": 5, "unverified": 6}
        n_verify = len(keep) if verify is None else min(verify, len(keep))
        # 逐个核对「内容还在不在」要读盘（每条抽 4 段）：2 万条约 20 秒，
        # 15 万条要 3 分钟 —— 这段时间不报进度的话，界面看起来就是卡死了。
        for i, it in enumerate(keep[:n_verify]):
            it["confidence"] = _confidence(v, it)
            if progress2 and i % 256 == 0:
                progress2(i, max(n_verify, 1))
        if progress2:
            progress2(n_verify, max(n_verify, 1))
        # 没核对的照实标出来，不冒充 good，也不从列表里删掉
        for it in keep[n_verify:]:
            it["confidence"] = "unverified"
        keep.sort(key=lambda c: (order.get(c["confidence"], 9), -c["_t"]))
        items = keep if limit is None else keep[:limit]

        # 原路径要随机读祖先目录：15.8 万条实测 57 秒，而界面一次只摆 2000 条。
        # 只给最近 path_limit 条算，其余留空 —— 点开某条时再补（那时卷已经打开，
        # 补一条只要几毫秒）。这里不假装「原目录已不在」，留空就是留空。
        cache = {}
        missing = 0
        for i, it in enumerate(items):
            if path_limit is not None and i >= path_limit:
                it["path"] = ""
                missing += 1
            else:
                it["path"] = v.path_of(it["idx"], cache)
            it["cluster_count"] = sum(c for _l, c, _sp in it["runs"])
            it.pop("_t", None)

        stats = {
            "letter": v.letter,
            "records": total,
            "scanned": scanned,
            "truncated": truncated,
            "elapsed": round(time.time() - t0, 1),
            "found": len(items),
            "candidates": len(cands),
            "unverified": max(0, len(items) - n_verify),
            "path_missing": missing,
            "good": sum(1 for i in items if i["confidence"] == "good"),
            "risky": sum(1 for i in items if i["confidence"] == "risky"),
        }
        return items, stats
    finally:
        if own:
            v.close()


def complete_runs(vol, item):
    """把「runlist 被拆到 `$ATTRIBUTE_LIST` 扩展记录」的碎片文件补全 → True。

    为什么需要：MFT 记录只有 1KB，一条**重度碎片化**的文件（runlist 长到装不下）
    会把后半截 runlist 写进扩展记录。只读主记录的话，恢复出来只有文件的前一段，
    或者被 `_confidence` 判成「段不全」。而这类文件恰恰是用户最想救的那一类。

    **只在「现有 runs 明显装不下」时才去读扩展记录**：全量扫描 15 万条时每条都
    多读几条 MFT 记录，扫描时间会翻倍，而绝大多数文件的 runlist 本来就装得下。

    这个补全是**确定性的**：runlist 就是文件系统自己记的「这段数据在哪儿」，
    拼出来的字节和原件逐字节相同（`_test_fragment.py` 里 MP4 用例验证的就是
    「多段拼接后逐字节一致」这件事）。
    """
    if not item or item.get("is_dir") or item.get("resident"):
        return False
    if item.get("runs_from_attrlist"):
        return True
    runs = item.get("runs") or []
    size = int(item.get("size") or 0)
    cluster = getattr(vol, "cluster", 4096) or 4096
    if not size or not runs or vol is None:
        return False
    have = sum(c for _l, c, _s in runs) * cluster
    if have + cluster >= size:
        return False                        # 装得下，不用折腾
    idx = item.get("idx")
    if not isinstance(idx, int) or idx <= 0 or not hasattr(vol, "record"):
        return False
    try:
        rec = vol.record(idx)
        if not rec:
            return False
        data = parse_data_full(vol, rec)
    except Exception:                       # noqa: BLE001
        return False
    if not data or not data.get("runs"):
        return False
    got = data["runs"]
    if sum(c for _l, c, _s in got) * cluster <= have:
        return False                        # 扩展记录也补不出更多，别自欺欺人
    item["runs"] = got
    item["runs_from_attrlist"] = True
    return True


def fill_path(vol, item, cache=None):
    """给一条结果补上「原位置」（扫描时为了省时间没算的那些）。

    只在卷已经打开的时候调 —— 单独为了一条路径去开卷不值得，
    但恢复和预览本来就要读这块盘，顺手就补了。
    """
    if item.get("path") or vol is None:
        return item.get("path") or ""
    idx = item.get("idx")
    if not isinstance(idx, int) or idx <= 0 or not hasattr(vol, "path_of"):
        return ""
    try:
        item["path"] = vol.path_of(idx, cache if cache is not None else {})
    except Exception:                                   # noqa: BLE001
        return ""
    return item["path"]


def _magic_verdict(name, head):
    """文件头像不像这个名字说的东西 → "good" / "mismatch" / None（没有判据）。

    只认少数常见类型。**没有判据就返回 None，不猜** —— 猜出来的「能恢复」
    是我们这次要消灭的东西。
    """
    if not head:
        return None
    ext = os.path.splitext(name or "")[1].lower().lstrip(".")
    if not ext:
        return None
    if ext in _FTYP_EXTS:
        return "good" if head[4:8] == b"ftyp" else "mismatch"
    sigs = _MAGIC.get(ext)
    if sigs:
        return "good" if head.startswith(sigs) else "mismatch"
    if ext in _TEXT_EXTS:
        sample = head[:512]
        if not sample:
            return None
        ctrl = sum(1 for b in sample if b < 9 or (13 < b < 32))
        # 文本里混几个控制字符正常（换行/制表），超过 5% 就不像文本了
        return "mismatch" if ctrl > len(sample) * 0.05 else "good"
    return None


def _sample_data(vol, item, chunk=4096):
    """从数据区抽样读几块：**开头 2 段 + 结尾 2 段**。返回 (字节, 实际读到多少)。

    为什么头尾都取：只看开头的话，「文件头部本来就是一堆 0」的合法文件会被误判成
    已清零；只看一段又容易撞上稀疏填充。
    """
    runs = [r for r in (item.get("runs") or []) if not r[2] and r[1] > 0]
    if not runs:
        return b"", 0
    picks = runs[:2] + (runs[-2:] if len(runs) > 2 else [])
    out, got = [], 0
    for lcn, count, _sp in picks:
        n = min(chunk, count * vol.cluster)
        try:
            b = vol.read(lcn * vol.cluster, n)
        except (RecoverError, OSError):
            continue
        if b:
            out.append(b)
            got += len(b)
    return b"".join(out), got


def _confidence_quick(vol, item):
    """便宜版评级（只看标记 + `$Bitmap`）—— 全盘扫描时用，因为它要跑几十万次。

    只做「确定性否定」：目录 / 压缩 / 加密 / 没有数据段 / 簇被别人占了。
    剩下的一律先给 "good"，等截断到展示条数后再用 `_confidence()` 严格复核。

    `cluster_used_reliable == False` 的卷（FAT / exFAT）**直接跳过**这一步：
    它们删文件时不清 FAT 链、不清位图（实测），所以「簇标记为占用」根本不能说明
    「被新文件盖了」。拿它当证据会把刚删的文件全判死刑。
    """
    if item.get("is_dir"):
        return "dir"
    if item.get("encrypted"):
        return "encrypted"
    if item.get("compressed"):
        # 压缩文件的真实内容要解压才知道，这里解不起（几十万条）→ 交给严格版复核。
        # 4.15.0 起压缩文件**能解压导出**了，所以不能再打「解不了」的标。
        return None
    if item.get("resident"):
        return "good"
    runs = [r for r in (item.get("runs") or []) if not r[2]]
    if not runs:
        return "no_data"
    if not getattr(vol, "cluster_used_reliable", True):
        return None                    # 这类卷的簇标记没有证据价值，交给数据抽样去判
    checked = used = 0
    for lcn, count, _sparse in runs[:16]:
        for k in range(min(count, 2)):
            flag = vol.cluster_used(lcn + k)
            if flag is None:
                continue
            checked += 1
            if flag:
                used += 1
    if checked == 0:
        return "risky"
    return "risky" if used else "good"


def _confidence(vol, item):
    """这个条目到底能不能完整捞出来 —— **只给证据支持的结论，不吹**。

    判断顺序（从硬到软）：

      1. 目录 / 压缩 / EFS 加密 → 直接标注「解不了」，不给假希望；
      2. 驻留（数据就在 MFT 记录里）：全零 → wiped；否则看文件头；
      3. 非驻留：runlist 容量装不下 real_size → 段不全，必然拼不完整 → risky；
      4. `$Bitmap`：簇已经被别的文件占了 → risky（这条和以前一样，但它只是**否定项**）；
      5. 抽样读数据（头 2 段 + 尾 2 段）：全是 0 → wiped（SSD 的 TRIM 落地就是这样）；
      6. 文件头魔数：对得上 → good（这是唯一的「肯定」证据）；对不上 → mismatch；
      7. 以上都没有 → **unknown**，如实说「看着还在，但确认不了」。

    第 7 条是 4.12.0 的关键改动：以前位图说空闲就报「应该能完整恢复」，
    而格式化之后整盘都是空闲 → 每条都报 good。那是在骗人。
    """
    if item.get("is_dir"):
        return "dir"
    if item.get("encrypted"):
        return "encrypted"

    if item.get("resident"):
        data = item.get("data_off") or b""
        if not data:
            return "no_data"
        if not data.strip(b"\x00"):
            return "wiped"
        return _magic_verdict(item.get("name") or "", data[:4096]) or "good"

    runs = [r for r in (item.get("runs") or []) if not r[2]]
    if not runs:
        return "no_data"

    if item.get("compressed"):
        # NTFS 压缩：盘上是 LZNT1 压过的，直接看文件头一定对不上。
        # 先解第一个单元，用**解压后**的头部判魔数；解不出来才说它坏。
        head = _compressed_head(vol, item)
        if head is None:
            return "risky"
        return _magic_verdict(item.get("name") or "", head) or "unknown"

    size = int(item.get("size") or 0)
    cap = sum(c for _l, c, _s in runs) * vol.cluster
    if size and cap and cap + vol.cluster < size:
        # runlist 装不下真实大小：可能被拆到 $ATTRIBUTE_LIST 里了（重度碎片）。
        # 先试着补全，补得出来就继续按完整的段判，补不出来才说「段不全」。
        if not complete_runs(vol, item):
            return "risky"

    quick = _confidence_quick(vol, item)
    if quick == "risky":
        return "risky"

    head, got = _sample_data(vol, item)
    if got and not head.strip(b"\x00"):
        return "wiped"
    # 判文件头之前必须**按真实大小截断**：一个 16 字节的 txt 文件占了一整簇，
    # 簇尾那 496 个 0x00 是文件系统补齐的，不是文件内容。不截断的话
    # 控制字符率会飙到 90%+，把好文件judge成「文件头对不上」——实测踩过。
    limit = int(item.get("size") or 0)
    if limit and len(head) > limit:
        head = head[:limit]
    verdict = _magic_verdict(item.get("name") or "", head)
    if verdict:
        return verdict
    if got:
        return "unknown"
    return "risky"                     # 一个字节都读不出来，按最坏的说


def _refine_items(vol, items):
    """对最终要展示的条目重算一次严格评级（要读文件头，比较贵）。

    为什么分两步：合并阶段会碰到几十万条记录，每条读 4KB 文件头会让整卷扫多花几十秒；
    而用户真正会看的只有展示出来的那 ≤3000 条。所以「便宜判据过滤 → 截断 → 严格复核」。
    """
    for it in items:
        if it.get("confidence") == "name_only":
            # 只有名字的条目（USN / INDX）本来就没有数据位置，
            # 重算会被判成 no_data，把「只剩名字」这个更准确的说法丢掉。
            continue
        try:
            it["confidence"] = _confidence(vol, it)
        except (RecoverError, OSError):
            continue
    return items


# ───────────────────────── 恢复 ─────────────────────────

_BAD_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
             *(f"LPT{i}" for i in range(1, 10))}


def safe_name(name, fallback="未命名"):
    """把 MFT 里的名字改成 Windows 能落盘的名字（不改变可见字符，只替换非法字符）。"""
    s = _BAD_CHARS.sub("_", str(name or "")).strip().rstrip(". ")
    if not s:
        return fallback
    if s.upper().split(".")[0] in _RESERVED:
        s = "_" + s
    return s[:120]


def _unique_path(path):
    if not os.path.exists(path):
        return path
    stem, ext = os.path.splitext(path)
    for i in range(1, 1000):
        cand = f"{stem}（{i}）{ext}"
        if not os.path.exists(cand):
            return cand
    return f"{stem}（{int(time.time())}）{ext}"


def recover_one(vol, item, target_dir, keep_tree=True, progress=None, cancel=None):
    """把一条已删除条目写到 `target_dir`，返回落盘路径。

    调用方必须先过 `check_target()`：这里**不**再校验目标是不是同一个卷 ——
    但请别绕过，绕过就是拿用户的数据开玩笑。
    """
    # 传盘符时按文件系统自动打开（NTFS / FAT / exFAT 都行）；传卷对象就直接用。
    # 注意：传盘符这条路上打开的卷不会在这里关（和 4.13 之前一致），
    # 界面上永远是先 open 好卷对象再传进来，所以不会泄漏。
    v = open_volume(vol)[0] if isinstance(vol, str) else vol
    os.makedirs(target_dir, exist_ok=True)

    if (not item.get("is_dir") and not item.get("resident")
            and not item.get("runs")):
        # 目录索引里只剩名字的条目（MFT 记录已被覆盖）：有名字没位置，
        # 直接说清楚，别写一个 0 字节的假文件出来。
        raise RecoverError("这条只找到名字，没有数据位置 —— 内容请用「按文件类型找」去捞")

    # 解不了的三种，一律**拒收**而不是「导出一个打不开的文件」。
    # 这一条比任何功能都重要：用户拿到一个坏文件，会误以为「已经恢复了、是我自己的问题」。
    conf_key = item.get("confidence")
    if conf_key == "encrypted":
        raise RecoverError(
            "这是 EFS 加密文件：盘上存的是密文，本工具不能解密。"
            "要在原来那台机器/那个用户账号下用「备份密钥」才能读，或找支持 EFS 的专业工具")
    # 压缩文件不再拒收：4.15.0 起能解 LZNT1（见 decompress_compressed）。
    if conf_key == "wiped":
        raise RecoverError(
            "这条的数据区抽样全是 0：已经被清零了（SSD 的 TRIM 落地后就是这样），"
            "导出只会得到一个空文件")

    if item.get("is_dir"):
        rel = safe_name(item["name"])
        dest = _unique_path(os.path.join(target_dir, rel))
        os.makedirs(dest, exist_ok=True)
        return dest

    # 目录结构：能拼出原目录就照原样建，拼不出就平铺（名字前面已标「原目录已不在」）
    rel_dir = ""
    if keep_tree:
        path = str(item.get("path") or "")
        if "\\" in path and not path.startswith("（原目录已不在）"):
            rel_dir = os.path.join(*[safe_name(p) for p in path.split("\\")[:-1]][-4:])
    folder = os.path.join(target_dir, rel_dir) if rel_dir else target_dir
    os.makedirs(folder, exist_ok=True)
    dest = _unique_path(os.path.join(folder, safe_name(item["name"])))

    if item.get("resident"):
        with open(dest, "wb") as fh:
            fh.write(item.get("data_off") or b"")
        return dest

    total = int(item.get("size") or 0)
    # 重度碎片化的文件，runlist 可能被拆到扩展记录里 —— 只按主记录恢复会少写后半段。
    # complete_runs 只在「现有 runs 明显装不下」时才去读扩展记录，正常文件不受影响。
    complete_runs(v, item)
    runs = [r for r in (item.get("runs") or [])]

    if item.get("compressed"):
        # 压缩文件必须整块解完才能写（LZNT1 的引用跨 chunk，不能流式拼接）。
        # 大文件会占内存，P2-10 的流式改造再做；这里先保证「能恢复出来」。
        data = decompress_compressed(v, runs, total)
        with open(dest, "wb") as fh:
            fh.write(data)
        progress and progress(total, total)
        return dest

    written = 0
    with open(dest, "wb") as fh:
        for lcn, count, sparse in runs:
            if cancel and cancel():
                break
            length = count * v.cluster
            if sparse:
                fh.seek(length, os.SEEK_CUR)          # 空洞按 0 补
                written += length
            else:
                pos = lcn * v.cluster
                left = length
                while left > 0:
                    step = min(left, 1 << 20)
                    chunk = v.read(pos, step)
                    if not chunk:
                        break
                    fh.write(chunk)
                    pos += len(chunk)
                    written += len(chunk)
                    left -= len(chunk)
                    progress and progress(written, total)
            if total and written >= total:
                break
        if total:
            fh.truncate(total)                        # 末尾对齐真实长度，别留尾巴
    return dest



def verify_recovered(dest, item):
    """恢复后自检 → (ok, 说明)。

    只查三件便宜的事：大小对不对、文件头是否像这个扩展名、是不是全零。
    这不是「完整性校验」—— 内容到底能不能打开只能靠用户看，
    但至少能挡住「明明已经坏了、界面还告诉你成功」。
    """
    if item.get("is_dir"):
        return True, "目录已重建"
    try:
        size = os.path.getsize(dest)
    except OSError as exc:
        return False, f"读不到刚写出的文件：{exc}"
    want = int(item.get("size") or 0)
    if want and size != want:
        return False, f"大小不对（写出 {size} 字节，记录里是 {want} 字节）"
    try:
        with open(dest, "rb") as fh:
            head = fh.read(4096)
    except OSError as exc:
        return False, f"读不回刚写出的文件：{exc}"
    if size and not head.strip(b"\x00"):
        return False, "内容是空的（全 0）"
    verdict = _magic_verdict(item.get("name") or "", head)
    if verdict == "mismatch":
        return False, "文件头跟扩展名对不上，可能已经被覆盖"
    return True, "大小和文件头都对得上"


# ───────────────────── 残留元数据扫描（格式化了也能找回名字）─────────────────────

_REC_SIZE = 1024


def _validate_record(rec):
    """校验一段 1024 字节是不是一条完整的 NTFS 记录。

    为什么这么严：整块盘上 `FILE` 这四个字节到处都是（日志、图片里都可能出现）。
    真正的记录有三个硬特征，全中才认：
      1. 头 4 字节是 FILE；
      2. 更新序列号数组（USA）的个数 = 记录里 512 字节扇区数 + 1；
      3. **每个扇区末尾 2 字节都等于 USA 里那个序列号** —— 这是 NTFS 的完整性校验位，
         随机数据几乎不可能满足。
    返回 {name, parent, size, mtime, is_dir, resident, runs, data, flags} 或 None。
    """
    if len(rec) < _REC_SIZE or rec[:4] != b"FILE":
        return None
    usa_off = _u16(rec, 0x04)
    usa_cnt = _u16(rec, 0x06)
    if usa_cnt != (_REC_SIZE // SECTOR) + 1:
        return None
    if usa_off < 8 or usa_off + usa_cnt * 2 > len(rec):
        return None
    seq = rec[usa_off:usa_off + 2]
    for k in range(1, usa_cnt):
        if rec[k * SECTOR - 2:k * SECTOR] != seq:
            return None
    fixed = fixup_record(rec)
    names = parse_names(fixed)
    if not names:
        return None
    best = max(names, key=lambda n: (n["ns"] != 0, len(n["name"])))
    name = best["name"]
    if not name or "\x00" in name:
        return None
    data = parse_data(fixed)
    flags = _u16(fixed, 0x16)
    return {
        "name": name,
        "parent": best["parent"],
        "size": (data or {}).get("real_size") or best["size"],
        "mtime": _filetime(best["mtime"]),
        "_t": best["mtime"],
        "is_dir": bool(flags & 0x02),
        "in_use": bool(flags & 0x01),
        "resident": bool(data and data["resident"]),
        "runs": (data or {}).get("runs") or [],
        "compressed": bool(data and data["compressed"]),
        "encrypted": bool(data and data["encrypted"]),
        "data": (data or {}).get("value", b"") if (data and data["resident"]) else b"",
    }


def _scan_buffer(buf, base, found):
    """在一块内存里找记录候选，把结果塞进 found（(绝对偏移, 记录信息)）。"""
    i = buf.find(b"FILE")
    while i >= 0:
        if i + _REC_SIZE <= len(buf):
            info = _validate_record(buf[i:i + _REC_SIZE])
            if info is not None:
                found.append((base + i, info))
        i = buf.find(b"FILE", i + SECTOR)


def _assign_index(found):
    """给找到的记录推算「原来是 MFT 里的第几号」。

    记录本身**不存自己的编号**，但父目录引用的是编号，没编号就拼不出路径。

    做法不是「一条条接着数」，而是**用锚点算基准、再按偏移做算术**：
      · `$MFT` 恒为 0 号记录，根目录 `.` 恒为 5 号 —— 只要找到它们，就知道
        「偏移 X 对应编号 k」，于是 `起始偏移 = X - k * 1024`；
      · 之后任何一条记录：`编号 = (偏移 - 起始偏移) / 1024`。
    为什么不用「上一条 +1」：中间只要有一条记录校验没过（正常，MFT 里有空记录），
    链子就断了 —— 实测 20 万条只能认出 16 条。算术法不怕中间有洞。
    """
    found.sort(key=lambda x: x[0])
    votes = {}
    for off, info in found:
        if info["name"] == "$MFT" and not info["is_dir"]:
            votes[off] = votes.get(off, 0) + 1
        elif info["name"] == "." and info["is_dir"]:
            origin = off - 5 * _REC_SIZE
            votes[origin] = votes.get(origin, 0) + 1
    if votes:
        origin = max(votes.items(), key=lambda kv: kv[1])[0]
        for off, info in found:
            delta = off - origin
            info["index"] = (delta // _REC_SIZE
                             if delta >= 0 and delta % _REC_SIZE == 0 else None)
        return
    # 一个锚点都没有（旧 MFT 的头几条恰好被覆盖）：退化成相邻连续就接着数，
    # 能认出多少算多少，认不出的编号留空（路径会标「原目录已不在」）。
    prev_off = prev_idx = None
    for off, info in found:
        idx = None
        if prev_off is not None and off == prev_off:
            idx = prev_idx
        elif prev_off is not None and off - prev_off == _REC_SIZE and prev_idx is not None:
            idx = prev_idx + 1
        info["index"] = idx
        prev_off, prev_idx = off, idx


def _path_from_index(idx, by_index, depth=32):
    """用「编号 → 记录」表往上爬，拼回原路径。爬不动就标「原目录已不在」。"""
    if idx is None:
        return "（原目录已不在）"
    parts = []
    cur = idx
    gone = False
    for _ in range(depth):
        it = by_index.get(cur)
        if it is None:
            gone = True
            break
        if it["name"] in (".", ".."):
            break
        parts.append(it["name"])
        parent = it["parent"]
        if not parent or parent == _ROOT_RECORD:
            break
        cur = parent
    parts.reverse()
    return ("（原目录已不在）" if gone else "") + "\\".join(parts)


def _free_extents(vol, min_clusters=1024):
    """按 $Bitmap 找出成片的空闲区域（字节区间）。

    只扫空闲区：活着的簇属于正常文件，扫它们既慢又会把好文件误列进「找回」清单。
    格式化之后整块盘几乎都是空闲，于是原来 MFT 待过的地方自然落在扫描范围里。
    """
    bm = vol.bitmap
    if not bm.runs:
        return None
    total_clusters = (vol.total_sectors * vol.bytes_per_sector) // vol.cluster
    out = []
    off = 0
    need = max(1, min_clusters // 8)          # 位图里 1 字节 = 8 个簇
    while off < bm.size:
        chunk = bm._bytes_of(off, 1 << 20)
        if not chunk:
            break
        for m in re.finditer(b"\x00{%d,}" % need, chunk):
            start_cluster = (off + m.start()) * 8
            end_cluster = (off + m.end()) * 8
            if start_cluster >= total_clusters:
                break
            out.append((start_cluster * vol.cluster,
                        min(end_cluster, total_clusters) * vol.cluster))
        off += len(chunk)
    # 合并相邻区间（跨块的零串会被切两段）
    merged = []
    for start, end in out:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged or None


def raw_scan(letter, budget=None, limit=3000, progress=None, cancel=None,
             only_free=True, block=8 << 20):
    """格式化 / 目录区全丢之后：直接在盘上找**残留的 MFT 记录**。

    和 `scan_deleted()` 的区别：那个只看「现在文件系统还认的那份 MFT」；
    这里不看当前文件系统，而是按 `FILE` 记录签名扫空闲区，找到**新文件系统已经不认识、
    但字节还躺在盘上**的旧记录 —— 所以格式化之后也能把**原来的文件名和目录**带回来。

    这也是商业恢复软件（R-Studio / ReclaiMe / DiskGenius / UFS Explorer）里
    那个「深度扫描 / 查找丢失分区」的核心动作；它们额外做的（USN 日志、$LogFile、
    INDX 目录块、碎片重组）是锦上添花，先把这层做对才有意义。

    返回 (条目列表, 统计 dict)。扫描全程只读。
    """
    v = letter if isinstance(letter, NtfsVolume) else NtfsVolume(letter)
    own = not isinstance(letter, NtfsVolume)
    t0 = time.time()
    budget_s = budget if budget is not None else 180
    try:
        disk_bytes = v.total_sectors * v.bytes_per_sector
        extents = _free_extents(v) if only_free else None
        if not extents:
            extents = [(0, disk_bytes)]          # 位图读不到 / 指定全盘 → 整卷扫
        total_span = sum(e - s for s, e in extents)
        found = []
        scanned = 0
        truncated = False
        for start, end in extents:
            pos = start
            while pos < end:
                if cancel and cancel():
                    truncated = True
                    break
                if time.time() - t0 > budget_s:
                    truncated = True
                    break
                size = min(block, end - pos)
                try:
                    buf = v.read(pos, size)
                except RecoverError:
                    break
                if not buf:
                    break
                _scan_buffer(buf, pos, found)
                scanned += len(buf)
                progress and progress(min(scanned, total_span), total_span, "正在找残留的旧文件记录…")
                pos += max(SECTOR, len(buf) - _REC_SIZE)     # 留一条记录的交叠，别漏跨块的
            if truncated:
                break

        uniq = {}
        for off, info in found:                 # 块交叠会重复，按偏移去重
            uniq.setdefault(off, info)
        found = sorted(uniq.items(), key=lambda x: x[0])
        _assign_index(found)
        by_index = {}
        seen = set()
        items = []
        for off, info in found:
            if info["name"].startswith("$") or info["name"] in (".", ".."):
                continue
            if info["index"] is None:
                continue                              # 编号推不出来，路径没意义
            by_index[info["index"]] = info
        for idx, info in by_index.items():
            if not info["in_use"]:
                continue
            key = (info["name"], info["size"], info["mtime"],
                   tuple((r[0], r[1]) for r in info["runs"][:4]))
            if key in seen:
                continue
            seen.add(key)
            conf = "dir" if info["is_dir"] else _confidence(v, info)
            if conf == "no_data" and not info["is_dir"]:
                continue
            items.append({
                "idx": idx,
                "name": info["name"],
                "path": _path_from_index(idx, by_index),
                "size": info["size"],
                "mtime": info["mtime"],
                "is_dir": info["is_dir"],
                "confidence": conf,
                "resident": info["resident"],
                "runs": info["runs"],
                "data_off": info["data"],
                "cluster_count": sum(c for _l, c, _s in info["runs"]),
                "letter": v.letter,
                "source": "raw",
            })
            if len(items) >= limit:
                truncated = True
                break
        items.sort(key=lambda i: (-(i["size"] or 0)))
        stats = {
            "letter": v.letter,
            "records": len(found),
            "anchored": sum(1 for _o, i in found if i.get("index") is not None),
            "found": len(items),
            "good": sum(1 for i in items if i["confidence"] == "good"),
            "risky": sum(1 for i in items if i["confidence"] == "risky"),
            "scanned": scanned,
            "span": total_span,
            "truncated": truncated,
            "elapsed": round(time.time() - t0, 1),
        }
        return items, stats
    finally:
        if own:
            v.close()



# ───────────── INDX 目录索引（MFT 记录被覆盖后，名字还在这里）─────────────

def _validate_indx(buf):
    """校验一段 `INDX` 目录索引块，返回去掉 fixup 后的块；不是就返回 None。

    INDX 是 NTFS 目录的 B+ 树叶子块（通常 4KB），里面一条条塞着
    「文件名 + 父目录记录号 + 时间 + 大小」。它比 MFT 记录**更抗覆盖**：
    MFT 记录被复用了，目录索引块常常还躺在空闲簇里 —— 这就是「格式化后只剩名字」的来源。
    校验方式和 MFT 记录一样靠 USA：每个 512 字节扇区尾 2 字节必须等于序列号。
    """
    if len(buf) < 0x30 or buf[:4] != b"INDX":
        return None
    usa_off = _u16(buf, 0x04)
    usa_cnt = _u16(buf, 0x06)
    if usa_cnt < 2:
        return None
    size = SECTOR * (usa_cnt - 1)
    if size < SECTOR or size > len(buf):
        return None
    if usa_off + usa_cnt * 2 > size:
        return None
    seq = buf[usa_off:usa_off + 2]
    for k in range(1, usa_cnt):
        if buf[k * SECTOR - 2:k * SECTOR] != seq:
            return None
    fixed = bytearray(buf[:size])
    for k in range(1, usa_cnt):
        src = usa_off + k * 2
        fixed[k * SECTOR - 2:k * SECTOR] = buf[src:src + 2]
    return bytes(fixed)


def _parse_indx(block, out):
    """把一块 INDX 里的目录项拆出来，塞进 out：[{ref, name, parent, size, mtime}]。

    块头：0x18 是「目录项区起点相对 0x18 的偏移」，0x1C 是这块目录项区的总长。
    每个目录项：文件引用(8，低 48 位是记录号) + 长度(2) + 键长(2) + 标志(2) + 键(就是 $FILE_NAME 的值)。
    标志 0x02 表示这是最后一条，后面是填充。
    """
    ent_off = _u32(block, 0x18)
    ent_size = _u32(block, 0x1C)
    p = 0x18 + ent_off
    end = min(len(block), p + ent_size)
    while p + 0x10 <= end:
        ref = _u64(block, p) & 0x0000FFFFFFFFFFFF
        elen = _u16(block, p + 0x08)
        klen = _u16(block, p + 0x0A)
        flags = _u16(block, p + 0x0C)
        if elen < 0x10 or p + elen > end:
            break
        if klen >= 0x42:
            info = filename_from_value(block[p + 0x10:p + 0x10 + klen])
            if (info and info["name"] not in (".", "..")
                    and not info["name"].startswith("$")):
                out.append({"ref": ref, "name": info["name"],
                            "parent": info["parent"], "size": info["size"],
                            "mtime": info["mtime"]})
        if flags & 0x02:
            break
        p += elen


def _path_from_map(ref, names, depth=32):
    """按「记录号 → 名字/父目录」表往上爬，拼回原路径。"""
    parts = []
    cur = ref
    gone = False
    for _ in range(depth):
        it = names.get(cur)
        if it is None:
            gone = True
            break
        parts.append(it["name"])
        parent = it.get("parent") or 0
        if not parent or parent == _ROOT_RECORD:
            break
        cur = parent
    parts.reverse()
    return ("（原目录已不在）" if gone else "") + "\\".join(parts)




# ───────────── USN 变更日志（$UsnJrnl:$J —— 名字最后还能留下来的地方）─────────────

# 删除类事件的 reason 位。注意真删的时候通常还带 CLOSE(0x8000)，所以只判「包含」。
USN_DELETE = 0x00000200
USN_RENAME_OLD = 0x00001000
USN_RENAME_NEW = 0x00002000

USN_REASON_CN = {
    0x00000001: "数据被覆盖", 0x00000002: "数据追加", 0x00000004: "数据截断",
    0x00000100: "新建", 0x00000200: "删除", 0x00000400: "扩展",
    0x00001000: "改名（原名）", 0x00002000: "改名（新名）",
    0x00004000: "属性变更", 0x00008000: "关闭",
}


def _parse_usn(buf, p):
    """解析一条 USN 记录。返回 (状态, dict)。

    状态：`ok` 解析成功；`more` 这条记录跨过缓冲区尾部（要留到下一块）；
          `bad` 不是记录（跳过）。
    V2 用 8 字节文件引用；V3 用 16 字节（我们只取低 8 字节里的低 48 位记录号，
    高位是序列号，和 MFT 的用法一致）。V4 少见，按 bad 跳过。
    """
    if p + 8 > len(buf):
        return "more", None
    rlen = _u32(buf, p)
    major = _u16(buf, p + 4)
    if major not in (2, 3) or rlen < 0x3C or rlen % 4:
        return "bad", None
    if p + rlen > len(buf):
        return "more", None
    if major == 2:
        ref = _u64(buf, p + 8)
        parent = _u64(buf, p + 16)
        ts = _u64(buf, p + 32)
        reason = _u32(buf, p + 40)
        nlen = _u16(buf, p + 56)
        noff = _u16(buf, p + 58)
    else:
        ref = _u64(buf, p + 8)
        parent = _u64(buf, p + 24)
        ts = _u64(buf, p + 48)
        reason = _u32(buf, p + 56)
        nlen = _u16(buf, p + 72)
        noff = _u16(buf, p + 74)
    if nlen > 1024 or noff + nlen > rlen:
        return "bad", None
    name = buf[p + noff:p + noff + nlen].decode("utf-16-le", "replace")
    if not name or "\x00" in name:
        return "bad", None
    return "ok", {
        "ref": ref & 0x0000FFFFFFFFFFFF,
        "parent": parent & 0x0000FFFFFFFFFFFF,
        "usn_time": ts,
        "reason": reason,
        "name": name,
        "length": rlen,
    }


def _index_root_entries(rec, stream="$I30"):
    """`$INDEX_ROOT` 里的目录项 → [{ref, name, parent}]。

    小目录的全部目录项都在这里（resident）；目录大了才会溢出到 `$INDEX_ALLOCATION`。
    `$Extend` 只有几个子项，永远在根里，所以查 `$UsnJrnl` 走这条路最稳。
    """
    out = []
    for atype, p, alen, nonres in _iter_attrs(rec):
        if atype != _ATTR_INDEX_ROOT or nonres or attr_name(rec, p) != stream:
            continue
        voff = _u16(rec, p + 0x14)
        vlen = _u32(rec, p + 0x10)
        val = rec[p + voff:p + voff + vlen]
        if len(val) < 0x20:
            continue
        ent_off = _u32(val, 0x10)          # INDEX_HEADER 相对 0x10
        ent_size = _u32(val, 0x14)
        q = 0x10 + ent_off
        end = min(len(val), q + ent_size)
        while q + 0x10 <= end:
            ref = _u64(val, q) & 0x0000FFFFFFFFFFFF
            elen = _u16(val, q + 8)
            klen = _u16(val, q + 0x0A)
            flags = _u16(val, q + 0x0C)
            if elen < 0x10 or q + elen > end:
                break
            if klen >= 0x42:
                info = filename_from_value(val[q + 0x10:q + 0x10 + klen])
                if info is not None:
                    out.append({"ref": ref, "name": info["name"],
                                "parent": info["parent"]})
            if flags & 0x02:               # 最后一条
                break
            q += elen
    return out


def _find_child_record(vol, parent_rec, target):
    """在目录记录 `parent_rec` 的索引里按名字找子项 → 返回子记录号。

    为什么不能按固定号找：`$UsnJrnl` **不是** 9 号（9 号是 `$Secure`），
    它挂在 `$Extend`（11 号）下面，实测本机 E: 上是 88523 号 —— 号是由系统分配的，
    换台机器就不一样，只能顺着目录索引查。
    """
    rec = vol.record(parent_rec)
    if not rec or rec[:4] != b"FILE":
        return None
    for e in _index_root_entries(rec):
        if e["name"] == target:
            return e["ref"]
    return None


def usn_records(vol, budget=None, limit=200000, progress=None, cancel=None,
                block=1 << 20):
    """扫 `$UsnJrnl:$J`，把「谁曾经被删过 / 改过名」捞出来。

    为什么值得做：MFT 记录会被复用、INDX 目录块会被覆盖，但 **USN 变更日志是只追加的**，
    里面逐条记着「哪个记录号、在哪个父目录下、叫什么名字、什么时候、干了什么」。
    这是「记录和目录都被覆盖了，只剩日志还记得名字」那最后一层。
    商业工具（R-Studio / ReclaiMe / UFS Explorer）都会读它，我们之前的差距就在这里。

    `$J` 是稀疏流：前面一大段是洞（读出来全是 0），真正的记录在后面，
    所以必须**按 runlist 跳过稀疏段**，否则会把大把时间花在读洞上。

    返回 (条目列表, 统计)。条目只带名字/父记录号/时间，**没有数据位置** ——
    内容还得靠 MFT 恢复或按类型找。全程只读。
    """
    v = vol if isinstance(vol, NtfsVolume) else NtfsVolume(vol)
    own = not isinstance(vol, NtfsVolume)
    t0 = time.time()
    budget_s = budget if budget is not None else 120
    try:
        rec_no = _find_child_record(v, _EXTEND_RECORD, "$UsnJrnl")
        rec = v.record(rec_no) if rec_no is not None else None
        if not rec or rec[:4] != b"FILE":
            raise RecoverError("这块盘上没有 $UsnJrnl（系统关掉了 USN 变更日志）")
        data = parse_data_full(v, rec, "$J")
        if data is None:
            raise RecoverError("读不出 $UsnJrnl:$J 的位置（日志可能被清空过）")
        if data["resident"]:
            raise RecoverError("$UsnJrnl:$J 太小（日志刚被清空），没有可用的历史记录")

        best = {}
        scanned = 0
        total_bytes = 0
        records = 0
        truncated = False
        for lcn, count, sparse in data["runs"]:
            if sparse or count <= 0:            # 洞：跳过，不浪费时间
                continue
            total_bytes += count * v.cluster
        for lcn, count, sparse in data["runs"]:
            if sparse or count <= 0:
                continue
            seg_start = lcn * v.cluster
            seg_len = count * v.cluster
            pos = 0
            carry = b""
            while pos < seg_len:
                if cancel and cancel():
                    truncated = True
                    break
                if time.time() - t0 > budget_s:
                    truncated = True
                    break
                chunk = v.read(seg_start + pos, min(block, seg_len - pos))
                if not chunk:
                    break
                buf = carry + chunk
                pos += len(chunk)
                scanned += len(chunk)
                i = 0
                while True:
                    state, r = _parse_usn(buf, i)
                    if state == "more":
                        break                   # 尾部不完整，留到下一块
                    if state == "bad":
                        i += 8                  # 记录是 8 字节对齐的，挪一格再试
                        if i + 8 > len(buf):
                            break
                        continue
                    records += 1
                    if r["reason"] & (USN_DELETE | USN_RENAME_OLD):
                        old = best.get(r["ref"])
                        if old is None or r["usn_time"] >= old["usn_time"]:
                            best[r["ref"]] = r
                    i += r["length"]
                    if i + 8 > len(buf):
                        break
                carry = buf[i:] if i < len(buf) else b""
                progress and progress(min(scanned, total_bytes), total_bytes,
                                      "正在读变更日志（谁被删过）…")
                if len(best) >= limit:
                    truncated = True
                    break
            if truncated:
                break

        items = []
        for ref, r in best.items():
            items.append({
                "idx": ref,
                "name": r["name"],
                "parent": r["parent"],
                "size": 0,
                "mtime": _filetime(r["usn_time"]),
                "_t": r["usn_time"],
                "is_dir": False,
                "confidence": "name_only",
                "resident": False,
                "runs": [],
                "data_off": b"",
                "cluster_count": 0,
                "letter": v.letter,
                "source": "usn",
            })
        items.sort(key=lambda i: -(i["_t"] or 0))
        stats = {
            "letter": v.letter,
            "records": records,
            "deleted": len(items),
            "bytes": total_bytes,
            "scanned": scanned,
            "truncated": truncated,
            "elapsed": round(time.time() - t0, 1),
        }
        return items, stats
    finally:
        if own:
            v.close()


def _meta_extents(vol):
    """系统元数据文件占的簇区间 → [(起, 止, 名字)]。

    `$MFTMirr`（1 号，MFT 前 4 条记录的备份）和 `$LogFile`（2 号，NTFS 事务日志）
    这两处**经常留着旧 MFT 记录的完整副本**：NTFS 改记录前先把「改后的记录字节」
    写进日志（redo），所以日志里能翻到 FILE 签名 + 合法 USA 的记录镜像。
    只扫空闲区的话这些地方会被跳过 —— 它们明明是「已分配」的，
    但里面的内容可能是几周前的旧文件。

    `$UsnJrnl` 故意**不**放进来：它的数据是 USN 记录流，不是 MFT 记录镜像，
    由 `usn_records()` 按格式解析（比在这里碰运气找 FILE 签名准得多），
    放进来只会白读一遍几个 GB。
    """
    out = []
    for rec_no, label, stream in ((1, "$MFTMirr", None),
                                  (2, "$LogFile", None)):
        try:
            rec = vol.record(rec_no)
            if not rec or rec[:4] != b"FILE":
                continue
            data = parse_data(rec, stream)
            if not data or data["resident"]:
                continue
            for lcn, count, sparse in data["runs"]:
                if sparse or count <= 0:
                    continue
                out.append((lcn * vol.cluster, (lcn + count) * vol.cluster, label))
        except (RecoverError, OSError):
            continue
    return out


def _drop_live_records(vol, items):
    """整卷扫描（连已分配的簇也扫）时，把「现在还活着的文件」的原始记录剔掉。

    为什么要剔：全盘扫必然扫到当前 $MFT 里的记录，那些文件好好的躺在那儿，
    列进「恢复清单」只会让人以为找回了东西，还会和真正的残留混在一起。
    判据很简单：拿记录编号去读**当前** MFT 的同号记录 —— 还在用、名字和大小都对得上，
    就是活文件；记录已经释放（in-use=0）或内容对不上，才是残留。
    返回 (保留的条目, 剔掉的条数)。
    """
    keep = []
    dropped = 0
    try:
        count = vol.record_count
    except RecoverError:
        return items, 0
    for it in items:
        idx = it.get("idx")
        if it.get("source") != "mft" or idx is None or idx >= count:
            keep.append(it)
            continue
        rec = vol.record(idx)
        if not rec or rec[:4] != b"FILE" or not (_u16(rec, 0x16) & 0x01):
            keep.append(it)                       # 记录已释放 → 真是残留
            continue
        names = parse_names(rec)
        live = max(names, key=lambda n: (n["ns"] != 0, len(n["name"]))) if names else None
        data = parse_data(rec)
        size = (data or {}).get("real_size") or (live or {}).get("size") or 0
        if live and live["name"] == it["name"] and size == (it.get("size") or 0):
            dropped += 1
            continue
        keep.append(it)
    return keep, dropped


_RECYCLE_NAME_RE = re.compile(r"^\$[IR][A-Z0-9]{6}(\.[A-Za-z0-9]{1,6})?$")


def _is_noise_name(name):
    """回收站内部名（$R123ABC.txt / $I123ABC.txt）和 NTFS 元文件不算「用户文件」。"""
    if not name:
        return True
    if name.startswith("$") and not _RECYCLE_NAME_RE.match(name):
        return True
    return bool(_RECYCLE_NAME_RE.match(name))


def _merge_items(recs, indx, vol, limit=None, usn=None):
    """把「MFT 残留记录」「INDX 目录项」「USN 变更日志」按记录号合并成一份清单。

    规则（和 ReclaiMe/R-Studio 的做法一致）：
      · MFT 记录是权威：它带着数据位置，能直接导出，优先放进去；
      · INDX 只补那些「已经没有 MFT 记录」的：只剩名字、目录、时间和大小；
      · USN 再补 INDX 也没了的：同样是只有名字，但它是**只追加的日志**，
        记录和目录块都被覆盖之后，往往只剩它还记得「这个记录号当时叫什么」；
      · 三边的名字表拼在一起用，所以即使某一级目录的记录被覆盖了，
        只要它的目录项 / 日志项还在，路径照样能拼出来。
    返回 (条目列表, MFT 覆盖到的记录号集合)。
    """
    names = {}
    for _off, info in recs:
        if info.get("index") is not None:
            names[info["index"]] = info
    by_index = dict(names)
    indx_map = {}
    for e in indx:
        indx_map.setdefault(e["ref"], e)
        names.setdefault(e["ref"], e)

    items = []
    seen = set()
    mft_refs = set()
    for idx, info in by_index.items():
        if not info["in_use"]:
            continue
        if _is_noise_name(info["name"]):
            # NTFS 自己的元文件（$MFT / $LogFile / $Volume / $MFTMirr…）和
            # 回收站内部条目（$R123ABC.txt）。扫 $MFTMirr 和 $LogFile 时必然翻到，
            # 列出来纯属噪音 —— 它们不是用户文件，也没有「恢复」的意义。
            continue
        key = (info["name"], info["size"], info["mtime"],
               tuple((r[0], r[1]) for r in info["runs"][:4]))
        if key in seen:
            continue
        seen.add(key)
        # 合并阶段会跑几十万次，只能用便宜判据；严格评级留到截断之后（见 _refine_items）
        conf = "dir" if info["is_dir"] else _confidence_quick(vol, info)
        if conf == "no_data" and not info["is_dir"]:
            continue
        mft_refs.add(idx)
        items.append({
            "idx": idx,
            "name": info["name"],
            "path": _path_from_map(idx, names),
            "size": info["size"],
            "mtime": info["mtime"],
            "is_dir": info["is_dir"],
            "confidence": conf,
            "resident": info["resident"],
            "runs": info["runs"],
            "data_off": info["data"],
            "cluster_count": sum(c for _l, c, _s in info["runs"]),
            "letter": vol.letter,
            "source": "mft",
        })

    for ref, e in indx_map.items():
        if ref in mft_refs:
            continue
        items.append({
            "idx": ref,
            "name": e["name"],
            "path": _path_from_map(ref, names),
            "size": e["size"],
            "mtime": _filetime(e["mtime"]),
            "is_dir": False,
            "confidence": "name_only",
            "resident": False,
            "runs": [],
            "data_off": b"",
            "cluster_count": 0,
            "letter": vol.letter,
            "source": "indx",
        })

    rank = {"good": 0, "dir": 1, "unknown": 2, "risky": 3, "mismatch": 4,
            "wiped": 5, "name_only": 6, "no_data": 7, "compressed": 8,
            "encrypted": 9}

    def _order(rows):
        """先按时间新→旧排，再按「可恢复度」稳定排序。

        顺序有讲究：同一档里（尤其「只有名字」这一大堆）用户先要看**最近删的**，
        而不是按大小排出来的随机顺序。两步排序靠 Python 的稳定排序实现：
        第二步只比较等级，同等级内部保持第一步的时间顺序。
        """
        rows.sort(key=lambda i: i.get("mtime") or "", reverse=True)
        rows.sort(key=lambda i: (rank.get(i["confidence"], 9), -(i["size"] or 0)))
        return rows

    _order(items)

    if usn:
        # USN 兜底：只有前面三路都没覆盖到、而且名字不同的才加进来。
        # 同一个记录号可能已经被新文件复用，所以「已经有这个 ref 的条目」一律以那边为准。
        have_ref = mft_refs | set(indx_map)
        have_name = {(i["idx"], i["name"]) for i in items}
        for e in usn:
            ref = e.get("ref", e.get("idx"))
            if ref is None or ref in have_ref or (ref, e["name"]) in have_name:
                continue
            if _is_noise_name(e["name"]):
                continue
            have_name.add((ref, e["name"]))
            # 把 USN 的「父记录号」也塞进名字表：这样 _path_from_map 至少能把
            # 已知的上级目录拼出来（USN 里带 parent，之前没用上是浪费）。
            # 找不到上级就还是「（原目录已不在）」，不假装知道。
            names.setdefault(ref, {"name": e["name"],
                                   "parent": e.get("parent") or 0,
                                   "size": e.get("size") or 0,
                                   "mtime": e.get("mtime") or ""})
            items.append({
                "idx": ref,
                "name": e["name"],
                "path": _path_from_map(ref, names),
                "size": e.get("size") or 0,
                "mtime": e.get("mtime") or "",
                "is_dir": False,
                "confidence": "name_only",
                "resident": False,
                "runs": [],
                "data_off": b"",
                "cluster_count": 0,
                "letter": vol.letter,
                "source": "usn",
            })
        _order(items)

    if limit is not None and len(items) > limit:
        items = items[:limit]
    return items, mft_refs


def metadata_scan(letter, budget=None, limit=3000, progress=None, cancel=None,
                  only_free=True, block=8 << 20, with_index=True,
                  with_usn=True, with_meta=True):
    """格式化恢复的完整版：**MFT 残留记录 + INDX 目录索引 + USN 变更日志**，三路合并。

    商业软件（ReclaiMe / R-Studio / DiskGenius / UFS Explorer）在格式化场景就是
    多路并行再按记录号合并，我们的顺序也一致：

      · MFT 残留记录（`_scan_buffer`）       → 带数据位置，能直接导出；
      · INDX 目录索引（`_parse_indx`）        → 只剩名字/目录/时间/大小；
      · $LogFile / $MFTMirr 里的旧记录副本   → 带数据位置（NTFS 日志的 redo 数据）；
      · $UsnJrnl:$J 变更日志（`usn_records`）→ 只剩名字（只追加，最抗覆盖）。

    合并的钥匙是 NTFS 的「记录号」：四处都带着它，所以名字和内容能对上同一个文件。
    扫描全程只读。
    """
    v = letter if isinstance(letter, NtfsVolume) else NtfsVolume(letter)
    own = not isinstance(letter, NtfsVolume)
    t0 = time.time()
    budget_s = budget if budget is not None else 180
    try:
        disk_bytes = v.total_sectors * v.bytes_per_sector
        core = (_free_extents(v) if only_free else None) or [(0, disk_bytes)]
        meta = _meta_extents(v) if with_meta else []
        if only_free:
            # 系统日志区排最前面：它小，而且里面是「旧记录的副本」，命中率最高。
            # 空闲区按定义不含已分配的日志簇，所以不存在重叠。
            ranges = [(s, e, lbl) for s, e, lbl in meta]
            ranges += [(s, e, "") for s, e in core]
        else:
            ranges = [(0, disk_bytes, "整卷")]
        span = sum(e - s for s, e, _t in ranges)
        recs, indx = [], []
        scanned = 0
        meta_scanned = 0
        truncated = False

        # USN 先跑：它只要几秒（实测 283MB 日志 5 秒），而且「名字」信息最难得。
        # 如果放在后面，整卷扫一旦吃满预算就轮不到它了 —— 这是第一次实现的顺序错误，
        # 实测「整卷扫 25 秒」时 usn_records 直接是 0。
        usn_items, usn_stats = [], {}
        if with_usn:
            share = max(15, min(60, int(budget_s * 0.3)))
            try:
                usn_items, usn_stats = usn_records(
                    v, budget=share, progress=progress, cancel=cancel)
            except RecoverError as exc:
                usn_stats = {"error": str(exc)}

        for start, end, tag in ranges:
            pos = start
            while pos < end:
                if cancel and cancel():
                    truncated = True
                    break
                if time.time() - t0 > budget_s:
                    truncated = True
                    break
                buf = v.read(pos, min(block, end - pos))
                if not buf:
                    break
                _scan_buffer(buf, pos, recs)
                if with_index:
                    j = buf.find(b"INDX")
                    while j >= 0:
                        blk = _validate_indx(buf[j:j + 4096 + SECTOR])
                        if blk:
                            _parse_indx(blk, indx)
                        j = buf.find(b"INDX", j + SECTOR)
                scanned += len(buf)
                if tag:
                    meta_scanned += len(buf)
                progress and progress(
                    min(scanned, span), span,
                    f"正在翻系统日志区（{tag}）…" if tag
                    else "正在找残留的文件记录和目录索引…")
                pos += max(SECTOR, len(buf) - _REC_SIZE)
            if truncated:
                break

        uniq = {}
        for off, info in recs:
            uniq.setdefault(off, info)
        recs = sorted(uniq.items(), key=lambda x: x[0])
        _assign_index(recs)

        # USN 已经在前面的扫描之前跑完了
        merged, mft_refs = _merge_items(recs, indx, v, limit=None, usn=usn_items)
        live_dropped = 0
        if not only_free:
            # 整卷扫会连活文件一起扫到，先剔掉，剩下的才是「格式化前的东西」
            merged, live_dropped = _drop_live_records(v, merged)
        # 统计要在截断前取：USN 条目排在 name_only 末尾，一截断就数不到了
        usn_merged = sum(1 for i in merged if i.get("source") == "usn")
        if len(merged) > limit:
            merged = merged[:limit]
            truncated = True
        items = merged
        # 截断之后再算严格评级：读文件头比较贵，只对要展示的这 ≤limit 条做。
        # 这一步是 4.12.0 的核心 —— 「能恢复」必须有证据，不能靠位图猜。
        _refine_items(v, items)
        # 一条都没找到时，顺手抽样看空闲区是不是已经被清零/擦除（TRIM 已落地）
        zero = None
        if not items:
            try:
                zero = zero_stats(v)
            except (RecoverError, OSError):
                zero = None
        stats = {
            "letter": v.letter,
            "records": len(recs),
            "anchored": sum(1 for _o, i in recs if i.get("index") is not None),
            "indx_entries": len(indx),
            "indx_refs": len({e["ref"] for e in indx}),
            "meta_ranges": len(meta),
            "meta_scanned": meta_scanned,
            "usn_records": usn_stats.get("records", 0),
            "usn_deleted": usn_stats.get("deleted", 0),
            "usn_error": usn_stats.get("error", ""),
            "from_usn": usn_merged,
            "with_data": sum(1 for i in items if i["confidence"] != "name_only"),
            "name_only": sum(1 for i in items if i["confidence"] == "name_only"),
            "good": sum(1 for i in items if i["confidence"] == "good"),
            "risky": sum(1 for i in items if i["confidence"] == "risky"),
            "found": len(items),
            "zero": zero,
            "live_dropped": live_dropped,
            "whole_disk": not only_free,
            "scanned": scanned,
            "span": span,
            "truncated": truncated,
            "elapsed": round(time.time() - t0, 1),
        }
        return items, stats
    finally:
        if own:
            v.close()


# ───────────────────────── 按文件类型找（carving） ─────────────────────────

# ───────────────────────── 按文件类型找（carving）─────────────────────────
# 真正的实现在 `carving.py`：23 类签名 / 结构校验 / 跨块切片 / 全盘扫描。
# 这里只留一层兼容包装 —— 老的调用方式（kinds / budget_bytes / max_file / max_files）
# 继续有效，但默认值全改了：以前默认只扫前 512MB、只写 120 个文件，等于没扫。
_KIND_ALIAS = {"jpg": "jpeg", "jpe": "jpeg", "tif": "tiff", "doc": "cfb", "xls": "cfb",
               "ppt": "cfb", "msi": "cfb", "docx": "zip", "xlsx": "zip", "pptx": "zip",
               "mov": "mp4", "heic": "mp4", "avi": "riff", "wav": "riff", "webp": "riff",
               "gz": "gzip", "db": "sqlite", "exe": "exe", "dll": "exe"}


def carve(vol, out_dir, kinds=None, budget_bytes=None, max_file=None,
          max_files=5000, progress=None, cancel=None, groups=None, min_size=None,
          image_base=0):
    """在未分配空间里按文件类型找（carving），直接写到 `out_dir`。

    **只在目录区也没了的时候用**：格式化、分区表坏、MFT 被清、甚至根本不是 NTFS。
    找回的是「文件内容」，原文件名和目录找不回来。

    和 4.17 以前的区别（都是实测出来的差距）：
    * 从 5 种格式扩到 23 类 / 30 多种扩展名，而且**按结构走到文件尾**，
      不再「看到文件头就当找到、切出来一半」；
    * 默认扫**整个未分配区**（不是前 512MB），可以随时停，进度条按字节走；
    * 结果默认最多 5000 个（以前 120 个），同内容只留一份；
    * 每个结果都带 verdict：结构完整走到尾的算 ok，只能走到「结构不再自洽」的算 weak，
      **文件在盘上被拆成几段的算 fragment**（4.19.0 起：MP4 的 moov 被切到后面时
      会去把它捞回来，中间缺的按空白补齐，交出来的文件能打开、只有缺的那段是花的）。

    `groups` 可按大类缩小范围：photo/doc/media/archive/other（只扫需要的类更快）。
    `vol` 除了盘符和卷对象，也可以直接给**镜像文件路径**（会按镜像打开）。
    """
    from . import carving
    from .fatfs import is_fat
    if isinstance(vol, str) and os.path.isfile(vol):
        # 传进来的是镜像文件，不是盘符。这里必须自己识别 ——
        # 以前会把它当盘符处理，"D:\x\disk.img" 被截成 "D:"，
        # 于是**悄悄扫了整个 D 盘**（实测 12MB 的镜像扫了十分钟还没完，
        # 而且进度条上写着 706GB）。这种错误用户根本看不出来。
        try:
            v, _kind = open_image_volume(vol, base=image_base)
        except Exception:                   # noqa: BLE001
            # 没有引导扇区的裸数据镜像（dd 出来的、只拷了一段数据的）也能扫。
            # 这里故意连「不是 NTFS」一起接住：按类型找本来就不看文件系统，
            # 能读到字节就够了。
            v = BareImageVolume(vol, base=image_base)
        own = True
    else:
        own = not isinstance(vol, (NtfsVolume, BareVolume)) and not is_fat(vol)
        v = open_volume(vol)[0] if own else vol
    ids = None
    if kinds:
        ids = []
        for k in kinds:
            k = _KIND_ALIAS.get(str(k).lower().lstrip("."), str(k).lower().lstrip("."))
            if k in carving.KINDS and k not in ids:
                ids.append(k)
    try:
        return carving.carve(v, out_dir, kinds=ids, groups=groups,
                             budget_bytes=budget_bytes, max_file=max_file,
                             max_files=max_files, min_size=min_size,
                             progress=progress, cancel=cancel)
    finally:
        if own:
            v.close()


# ───────────────────────── 卷影副本（「以前的版本」）─────────────────────────

def shadow_copies(volume=None):
    """列出可用卷影副本（系统还原点 / 文件历史留下的「以前的版本」）。

    这是**最省事、最安全**的一条路：文件根本没被删，只是卷上还有一份旧快照。
    有的话优先用资源管理器「属性 → 以前的版本」直接还原，比任何工具都稳。
    需要管理员权限；没有就返回空列表（不报错，属于正常情况）。
    """
    args = ["vssadmin", "list", "shadows"]
    if volume:
        args += ["/for=" + _letter_norm(volume) + "\\"]
    try:
        p = subprocess.run(args, capture_output=True,
                           creationflags=0x08000000, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return []
    raw = p.stdout or b""
    text = ""
    for enc in ("gbk", "utf-8"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    if not text:
        return []
    out = []
    for block in re.split(r"卷影副本 ID|Shadow Copy ID", text)[1:]:
        dev = re.search(r"卷影副本卷|Shadow Copy Volume\s*[:：]\s*(\S+)", block)
        when = re.search(r"创建时间|creation time\s*[:：]\s*(.+)", block)
        vol = re.search(r"原始卷|Original Volume\s*[:：]\s*(\S+)", block)
        if not dev:
            continue
        out.append({
            "device": dev.group(1).strip(),
            "created": (when.group(1).strip() if when else ""),
            "volume": (vol.group(1).strip() if vol else ""),
        })
    return out


# ───────────────── 整卷镜像（先镜像，再对镜像慢慢扫）─────────────────

_IMAGE_MAGIC = "health_assistant-image-1"
_BADMAP_MAGIC = "health_assistant-badmap-1"
_BAD_MARGIN = 64 << 20           # 镜像前要求的额外余量（进度文件 + 文件系统元数据）
_BAD_MIN_FIRST = 16 << 10        # 第一遍撞上坏块时，二分到 16KB 就认命（别一格一格死磕）


def _size_text(n):
    """给用户看的体积（镜像里不要出现裸字节数）。"""
    n = float(n or 0)
    if n >= 1 << 40:
        return f"{n / (1 << 40):.2f} TB"
    if n >= 1 << 30:
        return f"{n / (1 << 30):.1f} GB"
    if n >= 1 << 20:
        return f"{n / (1 << 20):.1f} MB"
    if n >= 1 << 10:
        return f"{n / (1 << 10):.0f} KB"
    return f"{n:.0f} B"


def badmap_path(dest):
    """坏区清单跟着镜像走：`<镜像>.badmap`。"""
    return str(dest) + ".badmap"


def _merge_extents(exts):
    """把重叠/相邻的坏区合并成有序、不重叠的区间。"""
    out = []
    for pair in sorted((int(a), int(b)) for a, b in exts if int(b) > int(a)):
        if out and pair[0] <= out[-1][1]:
            if pair[1] > out[-1][1]:
                out[-1][1] = pair[1]
        else:
            out.append([pair[0], pair[1]])
    return out


def _save_badmap(dest, letter, extents):
    payload = {"magic": _BADMAP_MAGIC, "letter": letter,
               "extents": [[int(s), int(e)] for s, e in _merge_extents(extents)],
               "updated": _now_text()}
    tmp = badmap_path(dest) + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        os.replace(tmp, badmap_path(dest))
    except OSError:
        pass


def _load_badmap(dest):
    """读上次留下的坏区清单（续传时接着用，别把上一次的坏区当好消息）。"""
    try:
        with open(badmap_path(dest), "r", encoding="utf-8") as fh:
            info = json.load(fh)
    except (OSError, ValueError):
        return []
    if not isinstance(info, dict) or info.get("magic") != _BADMAP_MAGIC:
        return []
    out = []
    for pair in info.get("extents") or []:
        try:
            s, e = int(pair[0]), int(pair[1])
        except (TypeError, ValueError, IndexError):
            continue
        if e > s:
            out.append([s, e])
    return _merge_extents(out)


def _free_bytes(path):
    """目标目录所在的卷还剩多少字节（查不到返回 None，不要用 0 冒充）。"""
    try:
        return shutil.disk_usage(path).free
    except OSError:
        return None


def image_plan(letter, dest):
    """镜像之前的核算：要写多大、目标盘还剩多少、能不能接着上次写。

    为什么先算：一整块 1T 的盘做镜像要 1T 空间，选错位置会在写了几百 GB 之后
    才失败 —— 那才是最难受的。这里几十毫秒就能提前说「放不下」。

    不在这里查 SMART：那要跑 PowerShell，几百毫秒到几秒，属于后台线程的活
    （见 `smart_preflight()`）。
    """
    letter = _letter_norm(letter)
    raw = _RawVolume(letter)
    try:
        declared = raw.length()
        total = _probe_length(raw, declared)
    finally:
        raw.close()
    done = 0
    info = image_info(dest)
    if os.path.isfile(dest) and info:
        done = min(int(info.get("done") or 0), total)
        done -= done % SECTOR
    need = max(0, total - done)
    folder = os.path.dirname(os.path.abspath(dest)) or "."
    free = _free_bytes(folder)
    ok = free is None or free >= need + _BAD_MARGIN
    why = ""
    if not ok:
        why = (f"这个位置放不下：镜像还要写 {_size_text(need)}，"
               f"而它所在的分区只剩 {_size_text(free)}。\n\n"
               f"至少要留出 {_size_text(need + _BAD_MARGIN)}"
               f"（多留 64 MB 给进度记录和文件系统本身）。\n\n"
               "换一块空间够的别的盘 —— 不要选正在恢复的这块盘本身。"
               "空间实在不够时，可以先用别的工具按分区做镜像，"
               "或者只做「按文件类型找」。")
    return {"total": total, "declared": declared, "done": done, "need": need,
            "free": free, "ok": ok, "why": why}


def smart_preflight(letter):
    """镜像前看一眼源盘的健康状态。**只报告，不阻断**。

    为什么要查：盘已经出问题时，每一次上电读取都在加重它的负担。如果 SMART 已经
    预测即将故障，用户该做的是「尽快做镜像 / 换盘」，而不是「反复扫三天」。
    但也不能因为健康状态差就不让做 —— 恰恰是坏盘才最需要先镜像。

    读不到（没有权限、虚拟盘、外置盒不报 SMART）时返回 None，不当作错误。
    """
    try:
        from . import smart
        lt = _letter_norm(letter)
        for d in smart.disks():
            if lt in (d.get("letters") or []):
                level, text = smart.verdict(d)
                return {"level": level, "text": text,
                        "disk": d.get("name") or "", "media": d.get("media") or "",
                        "wear": d.get("wear"), "temp": d.get("temp"),
                        "predict": bool(d.get("predict_fail"))}
    except Exception:                       # noqa: BLE001
        return None
    return None


def image_info(dest):
    """读镜像旁边的进度文件 → dict；没有或者不是我们的格式就返回 None。"""
    meta_path = dest + ".json"
    if not os.path.isfile(meta_path):
        return None
    try:
        with open(meta_path, "r", encoding="utf-8") as fh:
            info = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(info, dict) or info.get("magic") != _IMAGE_MAGIC:
        return None
    return info


def _save_image_info(dest, letter, total, done, head_hash, declared=None, **extra):
    payload = {"magic": _IMAGE_MAGIC, "letter": letter, "total": total,
               "done": done, "head": head_hash, "declared": declared,
               "updated": _now_text()}
    payload.update({k: v for k, v in extra.items() if v is not None})
    tmp = dest + ".json.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False)
        os.replace(tmp, dest + ".json")
    except OSError:
        pass


def _now_text():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _probe_length(raw, declared):
    """找出**真正能读到**的卷尾位置（≤ declared）。

    为什么不能直接信 `IOCTL_DISK_GET_LENGTH_INFO`：实测这块 64MB 虚拟盘报 128896 扇区，
    但读到 128888 扇区之后 ReadFile 就返回 0 字节了（NTFS 引导扇区自己算的是 128895）。
    如果按报出来的长度做镜像，最后几 KB 永远写不进去 →
    镜像永远「没完成」、断点续传每次都从同一个位置重试，看起来像卡死。
    做法：从尾部二分，找「最后一个能完整读出一个扇区」的偏移，最多 17 次读，几十毫秒。
    """
    def readable(end):
        if end <= 0:
            return True
        try:
            return len(raw.read(end - SECTOR, SECTOR)) == SECTOR
        except RecoverError:
            return False

    if readable(declared):
        return declared
    lo, hi = 0, declared            # 不变式：readable(lo) 真、readable(hi) 假
    while hi - lo > SECTOR:
        mid = ((lo + hi) // 2) // SECTOR * SECTOR
        if mid <= lo or mid >= hi:
            break
        if readable(mid):
            lo = mid
        else:
            hi = mid
    return lo


def _read_retry(raw, off, size, retries):
    """同一块重试几次 —— 偶发读错很常见，重试一次往往就过了。全失败返回 None。"""
    for _ in range(max(1, int(retries))):
        try:
            buf = raw.read(off, size)
        except RecoverError:
            continue
        if buf and len(buf) == size:
            return buf
    return None


def _read_rescue(raw, off, size, retries, bad, min_unit=_BAD_MIN_FIRST):
    """尽量把 [off, off+size) 读出来；读不出的最小单元填 0 并记进 `bad`。

    为什么不能「读失败就整次结束」：一盘只要有几个坏道，8MB 一块的整卷拷贝就会
    反复撞上、每次从头再来，等于永远做不完（这就是「坏道卡死」）。
    ddrescue 的做法是撞上坏块就二分缩小范围，把坏区定位到扇区级 ——
    好扇区照样保住，只有真正读不出来的那几 KB 才留空。这里就是那个二分。

    返回的字节数**恒等于 size**（坏的地方是 0），镜像长度和原盘一致、偏移不错位；
    填零的位置记在 `.badmap` 里，不假装读到了。
    """
    if size <= 0:
        return b""
    buf = _read_retry(raw, off, size, retries)
    if buf is not None:
        return buf
    if size <= min_unit:
        bad.append([off, off + size])
        return bytes(size)
    half = (size // 2) // SECTOR * SECTOR
    if half < min_unit:
        half = min_unit
    if half >= size:
        half = (size // 2) // SECTOR * SECTOR
    if half <= 0 or half >= size:
        bad.append([off, off + size])
        return bytes(size)
    head = _read_rescue(raw, off, half, retries, bad, min_unit)
    tail = _read_rescue(raw, off + half, size - half, retries, bad, min_unit)
    return head + tail


def image_volume(letter, dest, block=8 << 20, progress=None, cancel=None,
                 passes=3, retries=2, smart_check=True, space_check=True):
    """把整块卷**只读**复制成一个镜像文件：断点续传 + **坏道跳过** + **多遍重读**。

    为什么专业流程第一步都是镜像：
      · 源盘只读一遍，慢扫、反复扫都在镜像上做，减少二次损伤；
      · 源盘读取中途失败/掉线不会让整次分析白费；
      · 镜像留着，以后可以换工具交叉验证。

    坏道怎么办（4.13.0）：盘已经有坏道时，「读到坏块就抛异常」等于整次镜像白做 ——
    一块 1T 的盘上往往就只有几十个扇区读不出来。所以这里学 ddrescue：
      1. 整块（8MB）快读，正常路径零开销；
      2. 撞上坏块就二分，把坏区压到 16KB；
      3. 全卷跑完之后**再来两遍**，只重读坏区，粒度降到 512B、重试次数翻倍；
         某一遍一个字节都没救回来就停，不无止境地耗；
      4. 读不出来的位置填 0 保证长度对齐，但**逐个记进 `<镜像>.badmap`**，
         进度文件和界面上都写明「哪些位置没读到」—— 不假装成功。

    断点续传：镜像旁边有个 `<镜像>.json`，记着「源盘指纹（头 512 字节的 sha1）+
    总长 + 已写到哪」。同一个路径再调一次就从断点接着写；指纹跟当前盘对不上则
    **直接拒绝** —— 把两块盘的数据拼进一个文件是最糟的错。

    返回 dict：dest / total / done / resumed / complete / elapsed / letter
                / bad_bytes / bad_count / passes / smart / notes。
    """
    letter = _letter_norm(letter)
    notes = []
    pre = None
    if smart_check:
        pre = smart_preflight(letter)
        if pre and pre.get("level") == "error":
            notes.append(f"源盘健康状态不好（{pre.get('text')}）。"
                         "别再反复插拔、别再通电折腾，先把镜像做完再谈怎么捞。")

    raw = _RawVolume(letter)
    try:
        declared = raw.length()
        total = _probe_length(raw, declared)
        if total <= 0:
            raise RecoverError(f"{letter} 一个扇区都读不出来，先确认盘还活着")
        head = raw.read(0, SECTOR)
        head_hash = hashlib.sha1(head).hexdigest()
        info = image_info(dest)
        done = 0
        resumed = False
        bad = []
        if os.path.isfile(dest) and info:
            same_disk = (info.get("head") == head_hash
                         and info.get("total") in (total, declared))
            if not same_disk:
                raise RecoverError(
                    "这个镜像文件不是这块盘的（记录的盘指纹不一致）。"
                    "换一个文件名重新做，别把两块盘的字节拼在一起")
            done = min(int(info.get("done") or 0), total)
            done -= done % SECTOR
            resumed = done > 0
            # 上次没收完的坏区接着重读 —— 不能因为「这次是新一遍」就当它们没坏过
            bad = _load_badmap(dest)

        if space_check:
            free = _free_bytes(os.path.dirname(os.path.abspath(dest)) or ".")
            need = max(0, total - done)
            if free is not None and free < need + _BAD_MARGIN:
                raise RecoverError(
                    f"放不下：镜像还要写 {_size_text(need)}，"
                    f"所选位置只剩 {_size_text(free)}。\n\n"
                    f"至少要留出 {_size_text(need + _BAD_MARGIN)}，"
                    "换一块够大的别的盘。")

        t0 = time.time()
        mode = "r+b" if os.path.isfile(dest) else "wb"
        passes_done = 1
        with open(dest, mode, buffering=0) as fh:
            fh.seek(done)
            fh.truncate(done)         # 丢掉上次中断留下的半截块
            last_save = 0.0
            while done < total:
                if cancel and cancel():
                    break
                want = min(block, total - done)
                buf = _read_retry(raw, done, want, retries)
                if buf is None:
                    # 撞上坏块：二分定位，好扇区照样保下来（见 _read_rescue）
                    buf = _read_rescue(raw, done, want, retries, bad, _BAD_MIN_FIRST)
                fh.write(buf)
                done += len(buf)
                if progress:
                    merged = _merge_extents(bad)
                    extra = (f"，已跳过 {len(merged)} 处读不出来的位置"
                             if merged else "")
                    progress(done, total, f"正在做镜像…{extra}")
                now = time.time()
                if now - last_save > 2:
                    fh.flush()
                    merged = _merge_extents(bad)
                    _save_image_info(dest, letter, total, done, head_hash, declared,
                                     bad=sum(e - s for s, e in merged) or None,
                                     bad_count=len(merged) or None)
                    _save_badmap(dest, letter, merged)
                    last_save = now
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass

        # 第二、三遍：只重读坏区。粒度从 16KB 降到 512B，重试次数翻倍。
        todo = _merge_extents(bad)
        for p in range(2, max(1, int(passes)) + 1):
            if not todo or (cancel and cancel()):
                break
            still = []
            before = sum(e - s for s, e in todo)
            with open(dest, "r+b", buffering=0) as fh:
                for i, (s, e) in enumerate(todo, 1):
                    if cancel and cancel():
                        still.extend(todo[i - 1:])
                        break
                    buf = _read_rescue(raw, s, e - s, retries * (2 + p), still, SECTOR)
                    fh.seek(s)
                    fh.write(buf)
                    if progress:
                        progress(done, total,
                                 f"第 {p} 遍：正在重读读不出来的位置（{i}/{len(todo)}）…")
                fh.flush()
                try:
                    os.fsync(fh.fileno())
                except OSError:
                    pass
            todo = _merge_extents(still)
            passes_done = p
            if sum(e - s for s, e in todo) >= before:
                break                     # 一个字节都没救回来，别再无止境地耗

        bad = todo
        bad_bytes = sum(e - s for s, e in bad)
        complete = done >= total
        _save_image_info(dest, letter, total, done, head_hash, declared,
                         bad=bad_bytes or None, bad_count=len(bad) or None,
                         passes=passes_done)
        _save_badmap(dest, letter, bad)
        if bad_bytes:
            notes.append(f"有 {len(bad)} 处读不出来（共 {_size_text(bad_bytes)}），"
                         "这些位置在镜像里是空的，清单在 "
                         f"{os.path.basename(badmap_path(dest))}。"
                         "盘已经出现读不出的扇区，别再往这块盘上写东西。")
        return {"dest": dest, "letter": letter, "total": total, "done": done,
                "declared": declared, "resumed": resumed, "complete": complete,
                "elapsed": round(time.time() - t0, 1),
                "bad_bytes": bad_bytes, "bad_count": len(bad),
                "passes": passes_done, "smart": pre, "notes": notes}
    finally:
        raw.close()


def zero_stats(vol, regions=24, per=1 << 20):
    """抽样看「空闲区是不是已经被清零 / 擦除」—— 用来解释「为什么什么都扫不到」。

    SSD 开了 TRIM 之后再格式化，主控会把闪存块擦掉，软件按逻辑地址读出来就是
    全 0x00 或全 0xFF。这已经超出软件恢复的范围（物理层被清了），
    但必须**如实告诉用户**，而不是让他以为「再扫久一点就有了」。

    只抽空闲区：活文件区当然有数据，抽它没有意义。

    返回 {regions, sampled, zero_ratio, ff_ratio, verdict}；
    verdict: `zeros`（大片 0x00）/ `erased`（大片 0xFF）/ `data`（还有数据）/ `unknown`。
    """
    v = vol if isinstance(vol, NtfsVolume) else NtfsVolume(vol)
    own = not isinstance(vol, NtfsVolume)
    try:
        extents = _free_extents(v) or []
        if not extents:
            return {"regions": 0, "sampled": 0, "zero_ratio": 0.0,
                    "ff_ratio": 0.0, "verdict": "unknown"}
        # 均匀挑几个点：从每个区间取中点，区间多了就隔几个取一个
        step = max(1, len(extents) // regions)
        picks = [extents[i] for i in range(0, len(extents), step)][:regions]
        zeros = ff = sampled = 0
        for start, end in picks:
            span = end - start
            if span <= 0:
                continue
            take = min(per, span)
            pos = start + (span - take) // 2
            buf = v.read(pos, take)
            if not buf:
                continue
            sampled += len(buf)
            zeros += buf.count(0)
            ff += buf.count(0xFF)
        if not sampled:
            return {"regions": len(picks), "sampled": 0, "zero_ratio": 0.0,
                    "ff_ratio": 0.0, "verdict": "unknown"}
        zr = zeros / sampled
        fr = ff / sampled
        # 阈值怎么定的：真·清零是 100%（读多少都是 0），但盘上空闲区里偶尔会夹着
        # 未清理的老数据（实测 C: 是 93% 零 + 少量残留），所以分三档说，
        # 不把「大部分是零」硬说成「全被擦掉了」。
        if zr >= 0.995:
            verdict = "zeros"
        elif fr >= 0.995:
            verdict = "erased"
        elif zr >= 0.90:
            verdict = "mostly_zeros"
        else:
            verdict = "data"
        return {"regions": len(picks), "sampled": sampled, "zero_ratio": round(zr, 4),
                "ff_ratio": round(fr, 4), "verdict": verdict}
    finally:
        if own:
            v.close()


# ───────────────────────── 回收站（最省事的一条路）─────────────────────────

def _recycle_dirs(letter=None):
    """找出回收站目录（每个卷一个，里面再按用户 SID 分子目录）。"""
    out = []
    letters = [_letter_norm(letter)] if letter else [v["letter"] for v in volumes()]
    for lt in letters:
        base = f"{lt}\\$Recycle.Bin"
        try:
            if not os.path.isdir(base):
                continue
            for entry in os.scandir(base):
                if entry.is_dir(follow_symlinks=False):
                    out.append((lt, entry.path))
        except OSError:
            continue
    return out


def _parse_i(path):
    """读 $I 文件：原路径、原大小、删除时间。

    $I 是回收站的「小票」：8 字节版本 + 8 字节原大小 + 8 字节删除时间 +
    4 字节名字长度 + UTF-16 的原路径。版本 2（Vista 之后）才有名字长度字段。
    """
    try:
        with open(path, "rb") as fh:
            raw = fh.read(4096)
    except OSError:
        return None
    if len(raw) < 28:
        return None
    version = struct.unpack_from("<Q", raw, 0)[0]
    size = struct.unpack_from("<Q", raw, 8)[0]
    when = struct.unpack_from("<Q", raw, 16)[0]
    nlen = struct.unpack_from("<I", raw, 24)[0]
    if version == 1:
        name = raw[28:28 + 520].decode("utf-16-le", "replace").split("\x00")[0]
    else:
        name = raw[28:28 + nlen * 2].decode("utf-16-le", "replace").strip("\x00")
    return {"version": version, "size": size, "deleted": _filetime(when),
            "orig_path": name}


def recycle_items(letter=None):
    """列出回收站里还能**原样还原**的条目（$I 记原名，$R 是数据本体）。

    为什么先看这里：删到回收站的文件根本没被动过，还原是 100% 准确的，零风险。
    只有回收站被清空了，才需要往下面「扫 MFT」「按类型找」走。
    `letter` 传盘符就只看那个卷，不传就看所有卷。
    """
    items = []
    for lt, folder in _recycle_dirs(letter):
        try:
            names = os.listdir(folder)
        except OSError:
            continue
        for n in names:
            if not n.startswith("$I") or len(n) < 4:
                continue
            i_path = os.path.join(folder, n)
            r_path = os.path.join(folder, "$R" + n[2:])
            meta = _parse_i(i_path)
            if not meta or not os.path.exists(r_path):
                continue
            orig = meta["orig_path"]
            if not orig:
                continue
            is_dir = os.path.isdir(r_path)
            items.append({
                "letter": lt,
                "name": os.path.basename(orig.rstrip("\\")) or os.path.basename(r_path),
                "path": orig,
                "size": meta["size"] if not is_dir else 0,
                "mtime": meta["deleted"],
                "deleted": meta["deleted"],
                "is_dir": is_dir,
                "confidence": "recycle",
                "resident": False,
                "runs": [],
                "i_path": i_path,
                "r_path": r_path,
            })
    items.sort(key=lambda i: i.get("deleted") or "", reverse=True)
    return items


def restore_recycle(item, target_dir, keep_tree=True):
    """把回收站里的这一项复制到 `target_dir`（**不**动回收站里的原件）。

    直接复制而不是「还原到原位置」：原位置可能已经被新文件占了，而且用户要的通常是
    「先拿出来看看」。想放回原处，Windows 资源管理器右键「还原」才是最稳的。
    """
    src = item.get("r_path")
    if not src or not os.path.exists(src):
        raise RecoverError("回收站里这个条目的数据文件已经不在了（可能刚被清空）")
    os.makedirs(target_dir, exist_ok=True)
    base = safe_name(item.get("name") or os.path.basename(src))
    if item.get("is_dir"):
        dest = _unique_path(os.path.join(target_dir, base))
        os.makedirs(dest, exist_ok=True)
        for root, dirs, files in os.walk(src):
            rel = os.path.relpath(root, src)
            sub = dest if rel == "." else os.path.join(dest, rel)
            os.makedirs(sub, exist_ok=True)
            for f in files:
                shutil.copy2(os.path.join(root, f), os.path.join(sub, f))
        return dest

    rel_dir = ""
    if keep_tree:
        parent = os.path.dirname(str(item.get("path") or ""))
        # 只保留原路径最后 3 层，够看又不至于在目标盘堆一长串目录
        parts = [p for p in re.split(r"[\\/]+", parent) if p][-3:]
        parts = [safe_name(p) for p in parts if not re.fullmatch(r"[A-Za-z]:", p)]
        rel_dir = os.path.join(*parts) if parts else ""
    folder = os.path.join(target_dir, rel_dir) if rel_dir else target_dir
    os.makedirs(folder, exist_ok=True)
    dest = _unique_path(os.path.join(folder, base))
    shutil.copy2(src, dest)
    return dest
