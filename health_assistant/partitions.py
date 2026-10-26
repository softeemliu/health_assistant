r"""health_assistant.partitions — 分区表解析、整盘镜像里找分区（**只读**）

为什么需要它
    专业恢复流程里，「拿到一个整盘镜像（dd / E01 / 移动硬盘盒直通）」是最常见的开局：
    0 偏移放的是**分区表**，不是某个文件系统。而本工具的入口一直是「盘符」，
    对着整盘镜像按 NTFS 解析会得到「这是分区表」的提示，然后就卡住了。

    这个模块补上两件事：
      1. 读 MBR / GPT，把「这个整盘里有哪几个分区、各自从哪开始、是什么文件系统」列出来；
      2. 分区表坏掉/被删掉时，**靠文件系统引导扇区的签名**把分区起点找回来。

硬边界（和 recovery 一致）
    **只读**。找到的分区不给"写回分区表"这种操作 —— 那等于替用户改盘，
    一次误判就可能把整盘搞得更乱。这里只负责「找到，然后从那个偏移开始扫」。

    找回来的分区，`start` 是绝对字节偏移，配合 `recovery.ImageVolume(path, base=start)`
    就能当成一个普通卷来扫（同一套 MFT / 目录项解析，一行都不用改）。
"""

from __future__ import annotations

import struct

__all__ = ["parse_mbr", "parse_gpt", "list_partitions", "find_boot_sectors",
           "PART_TYPES", "describe"]

SECTOR = 512

# MBR 分区类型里值得认的几个（其余显示成十六进制）
PART_TYPES = {
    0x01: "FAT12", 0x04: "FAT16 <32M", 0x05: "扩展分区", 0x06: "FAT16",
    0x07: "NTFS / exFAT", 0x0B: "FAT32", 0x0C: "FAT32 (LBA)", 0x0E: "FAT16 (LBA)",
    0x0F: "扩展分区 (LBA)", 0x82: "Linux swap", 0x83: "Linux",
    0xEE: "GPT 保护分区", 0xEF: "EFI 系统分区",
}

_FS_SIGS = ((b"NTFS    ", "ntfs"), (b"EXFAT   ", "exfat"),
            (b"ReFS    ", "refs"), (b"-FVE-FS-", "bitlocker"),
            (b"MSDOS5.0", "fat"), (b"MSWIN4.1", "fat"),
            (b"FAT32   ", "fat32"), (b"FAT16   ", "fat"))


def looks_like_boot(sec):
    """一个 512 字节扇区像不像**文件系统引导扇区**？返回格式名或空串。

    这是「按签名找分区」的最终判据 —— 光靠 find 命中某个字符串太容易误报
    （数据区里恰好有 "NTFS    " 的字节序列太正常了）。必须同时满足
    「有 0x55AA 结束标志」+「签名在它该在的位置上」才算数。
    """
    if len(sec) < 512 or sec[510:512] != b"\x55\xaa":
        return ""
    oem = sec[3:11]
    if oem == b"NTFS    ":
        return "ntfs"
    if oem == b"EXFAT   ":
        return "exfat"
    if oem == b"ReFS    ":
        return "refs"
    if oem == b"-FVE-FS-":
        return "bitlocker"
    if sec[0x52:0x5A] == b"FAT32   ":
        return "fat32"
    if sec[0x36:0x3E] in (b"FAT12   ", b"FAT16   ", b"FAT     "):
        return "fat"
    if sec[32:36] == b"NXSB":
        return "apfs"
    return ""


def find_boot_sectors(path, limit_bytes=64 << 30, progress=None, cancel=None):
    """分区表没了，靠**引导扇区签名**把分区起点找回来。

    为什么不能逐扇区扫：1TB = 20 亿个扇区，就算每次都秒回也要几小时。
    这里按 1MB 块顺序读，用 `bytes.find` 粗筛签名，命中位置再取整个扇区喂给
    `looks_like_boot()` 做严格判定（签名位置 + 0x55AA 结束标志都要对）。
    实测 1TB 只要 100 万次字符串比较 + 一千次 I/O，十几秒量级。
    """
    out = []
    chunk = 1 << 20
    from . import vdisk

    disk = vdisk.open_path(path)
    try:
        total = disk.size
        end = min(total, limit_bytes)
        pos = 0
        while pos < end:
            if cancel and cancel():
                break
            buf = disk.read(pos, min(chunk, end - pos))
            if not buf:
                break
            for sig, _hint in _FS_SIGS:
                i = buf.find(sig)
                while i >= 0:
                    sec = pos + i
                    sec -= (sec % SECTOR)              # 退到扇区首
                    rel = sec - pos
                    if 0 <= rel and rel + SECTOR <= len(buf):
                        kind = looks_like_boot(buf[rel:rel + SECTOR])
                        if kind and not any(abs(sec - e["offset"]) < SECTOR
                                            for e in out):
                            out.append({"offset": sec, "fs": kind,
                                        "scheme": "found", "index": len(out),
                                        "type": kind,
                                        "name": "（分区表丢失，按签名找到）"})
                    i = buf.find(sig, i + 1)
            # 交叠一个扇区：签名可能正好跨在块边界上
            pos += max(1, len(buf) - SECTOR)
            if progress:
                progress(min(pos, end), end)
    finally:
        disk.close()
    out.sort(key=lambda p: p["offset"])
    # FAT32 在第 6 个扇区存了一份**备份引导扇区**，内容和主引导扇区几乎一模一样，
    # 所以按签名扫必然二次命中（实测：主 1048576、备份 1051648，正好差 6 个扇区）。
    # 规则：相距不到 1MB 的候选只留第一个 —— 恢复场景里没人关心小于 1MB 的「分区」。
    dedup = []
    for p in out:
        if dedup and p["offset"] - dedup[-1]["offset"] < (1 << 20):
            continue
        dedup.append(p)
    out = dedup
    for i, p in enumerate(out):
        p["index"] = i
        # 分区的实际长度只能靠下一个分区的起点推（分区表没了，没人告诉我们长度）
        nxt = out[i + 1]["offset"] if i + 1 < len(out) else None
        p["size"] = (nxt - p["offset"]) if nxt else None
    return out


def describe(kind):
    """分区类型 → 给用户看的名字。"""
    if isinstance(kind, int):
        return PART_TYPES.get(kind, f"类型 0x{kind:02X}")
    return str(kind)


def parse_mbr(head):
    """解析 MBR 分区表（0x1BE 起 4 项）。返回 (分区列表, 方案)。

    每项：{index, type, offset, size, scheme}。`type == 0xEE` 说明这是
    GPT 的保护性 MBR —— 真正的分区表在 512 字节之后的 GPT header 里。
    """
    if len(head) < 512:
        return [], "none"
    parts = []
    for i in range(4):
        e = head[0x1BE + i * 16: 0x1BE + (i + 1) * 16]
        if len(e) < 16:
            break
        typ = e[4]
        lba = struct.unpack_from("<I", e, 8)[0]
        cnt = struct.unpack_from("<I", e, 12)[0]
        if typ == 0 or cnt == 0:
            continue
        parts.append({"index": i, "type": typ, "scheme": "mbr",
                      "offset": lba * SECTOR, "size": cnt * SECTOR})
    scheme = "gpt" if any(p["type"] == 0xEE for p in parts) else ("mbr" if parts else "none")
    return parts, scheme


def parse_gpt(read_at):
    """解析 GPT 分区表。`read_at(offset, size) -> bytes` 由调用方提供。"""
    hdr = read_at(SECTOR, SECTOR)
    if len(hdr) < 92 or hdr[:8] != b"EFI PART":
        return []
    ent_lba = struct.unpack_from("<Q", hdr, 0x48)[0]
    count = struct.unpack_from("<I", hdr, 0x50)[0]
    esz = struct.unpack_from("<I", hdr, 0x54)[0]
    if esz not in (128, 256) or not count or count > 512:
        esz = 128
        count = min(count or 128, 128)
    data = read_at(ent_lba * SECTOR, count * esz)
    out = []
    for i in range(count):
        e = data[i * esz:(i + 1) * esz]
        if len(e) < esz or e[:16] == b"\x00" * 16:
            continue
        first = struct.unpack_from("<Q", e, 32)[0]
        last = struct.unpack_from("<Q", e, 40)[0]
        if last < first:
            continue
        name = e[56:128].decode("utf-16-le", "replace").replace("\x00", "").strip()
        out.append({"index": i, "type": e[:16].hex(), "scheme": "gpt",
                    "offset": first * SECTOR, "size": (last - first + 1) * SECTOR,
                    "name": name})
    return out


def _probe_fs(read_at, offset):
    """读分区起点一个扇区，看是什么文件系统（认不出返回空串）。

    必须走 `looks_like_boot()`：FAT32 引导扇区的 OEM 名字段是 "MSDOS5.0"，
    光看偏移 3 会把它当成 FAT16（FAT12/16/32 的区别在 0x52 / 0x36 那两处）。
    """
    try:
        head = read_at(offset, SECTOR)
    except Exception:                      # noqa: BLE001
        return ""
    if len(head) < SECTOR:
        return ""
    kind = looks_like_boot(head)
    if kind:
        return kind
    return "zero" if not any(head) else ""


def list_partitions(path):
    """列出整盘（镜像文件或物理盘设备）里的分区。

    返回 `{"scheme", "parts": [...], "note"}`。每个分区带 `fs`（探测到的文件系统）。
    支持 MBR、GPT，以及「两者都没有但 0 偏移直接是 NTFS」的单分区镜像。

    镜像可能是虚拟盘（VHD / VHDX / VMDK），统一交给 `vdisk` 解成扁平字节流 ——
    否则读到的是映射表而不是分区表。
    """
    from . import vdisk

    disk = vdisk.open_path(path)
    try:
        head = disk.read(0, SECTOR)

        def read_at(off, size):
            return disk.read(off, size)

        if len(head) < SECTOR:
            return {"scheme": "none", "parts": [], "note": "这个文件连 512 字节都不到"}
        parts, scheme = parse_mbr(head)
        note = ""
        if scheme == "gpt":
            gpt = parse_gpt(read_at)
            if gpt:
                parts = gpt
            else:
                note = "有 GPT 保护分区，但 GPT 头读不出来（可能被覆盖）"
        if not parts:
            # 没分区表：也许 0 偏移直接就是文件系统（有的人只 dd 了一个分区）
            fs = _probe_fs(read_at, 0)
            if fs and fs != "zero":
                total = disk.size
                return {"scheme": "flat", "parts": [{
                    "index": 0, "type": fs, "scheme": "flat", "offset": 0,
                    "size": total, "fs": fs, "name": "整个文件"}],
                    "note": "这个文件的开头直接就是文件系统（不是整盘，是单个分区）"}
            return {"scheme": "none", "parts": [],
                    "note": "0 偏移既不是分区表，也不是能认出的文件系统"}
        for p in parts:
            p["fs"] = _probe_fs(read_at, p["offset"])
        return {"scheme": scheme, "parts": parts, "note": note}
    finally:
        disk.close()

