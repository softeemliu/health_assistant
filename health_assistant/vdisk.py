"""虚拟磁盘读取：把 VHD / VHDX / VMDK 当成一块「扁平的、能按字节读」的盘。

为什么要这一层：用户手上的镜像很少是 `dd` 出来的裸数据。Windows 自己的
「磁盘管理 / Hyper-V / 系统映像备份」产出的是 VHD / VHDX，VMware 的是 VMDK，
专业取证交付的是 E01。这些格式内部都是「稀疏块 + 映射表」，直接按文件偏移读
读到的是映射表，不是一个盘 —— 于是工具会告诉你「引导扇区认不出来」，
而真正的原因是「这根本不是裸镜像」。

这一层只做一件事：**认得出来 + 解得开**，让它和裸镜像走完全相同的后续流程
（分区表、NTFS/FAT 解析、按类型找、恢复导出都不用改）。

支持的格式与依据：
  · VHD  fixed / dynamic      （微软 Virtual PC / diskpart `create vdisk`）
  · VHDX fixed / dynamic      （Hyper-V、Windows 系统映像备份）
  · VMDK monolithicSparse     （VMware）
  · dd 裸镜像 / 任意扁平字节流（原样透传）

不支持的（识别出来就给明确指引，不假装是坏镜像）：
  · E01 / Ex01（EWF 取证格式）、QCOW2、差分盘（VHD differencing）、压缩 VMDK

全程只读。所有多字节字段：VHD 是**大端**，VHDX / VMDK 是**小端**。
"""
from __future__ import annotations

import os
import struct
import threading

SECTOR = 512

# ───────────────────────── 用户能看懂的错误 ─────────────────────────

_E01_HINT = (
    "这是一份 **E01 取证镜像**（EWF 格式，专业取证/实验室交付常用），"
    "不是普通的整盘镜像。\n\n"
    "现在还不直接支持这种格式。可以这样转成裸镜像后再打开：\n"
    "· 用 FTK Imager（免费）：「File → Create Disk Image」反过来不行，"
    "要用「Export Disk Image」，或者先挂载 E01（FTK Imager 可以直接挂）再按盘读；\n"
    "· 命令行工具 ewfexport（libewf）：`ewfexport -t out image.E01` 会得到 out.raw；\n"
    "· 转出来的 .raw/.dd/.img 直接在这里打开就行。")

_QCOW_HINT = (
    "这是一份 **QCOW2 镜像**（QEMU/KVM 虚拟机的磁盘格式）。\n\n"
    "现在还不直接支持。可以先用 `qemu-img convert -f qcow2 -O raw 镜像.qcow2 盘.raw` "
    "转成裸镜像，再在这里打开。")

_VHD_DIFF_HINT = (
    "这是一个 **差分 VHD**（differencing）—— 它只存了「相对父盘改动过的块」，"
    "单独一份不构成完整的盘。\n\n"
    "要读它得先找到它的父盘（.vhd 链里的第一层），把整条链合并成一个："
    "`diskpart` 里 attach 父盘、再 attach 这一份，或者用 Hyper-V 的"
    "「合并磁盘」功能。合并出来的完整 VHD 就能直接打开。")

_VMDK_COMPRESSED_HINT = (
    "这是一个**压缩过的 VMDK**（宿主机的「压缩磁盘」选项），块内容是压缩流，"
    "读出来必须先解压。目前不直接支持。\n\n"
    "可以先用 `qemu-img convert -f vmdk -O raw 磁盘.vmdk 盘.raw` 转成裸镜像，"
    "再在这里打开。")

_VMDK_DESCRIPTOR_HINT = (
    "这是 VMDK 的**描述文件**（几 KB 的文本 .vmdk），真正存数据的是同一目录下的 "
    "`xxx-flat.vmdk` / `xxx-s001.vmdk` 那些文件。\n\n"
    "把那个存数据的分片文件（或者 VMware 的「单一文件」.vmdk）拖进来打开。")


class VDiskError(Exception):
    """虚拟盘读不了 —— 消息本身就是给用户看的。"""


# ───────────────────────── 每线程一个句柄 ─────────────────────────

class _Handles:
    """包一层「每线程独立句柄」的只读文件。

    和 `recovery._ImageReader` 同一个理由：Python 的文件对象带读写位置，
    两个线程共用一个对象时 seek/read 会交错。扫描是并行的，所以这里必须拆开。
    """

    def __init__(self, path):
        self.path = path
        self._local = threading.local()
        self._lock = threading.Lock()
        self._all = []

    def fh(self):
        f = getattr(self._local, "f", None)
        if f is None:
            f = open(self.path, "rb", buffering=0)
            self._local.f = f
            with self._lock:
                self._all.append(f)
        return f

    def pread(self, off, n):
        if n <= 0 or off < 0:
            return b""
        try:
            f = self.fh()
            f.seek(off)
            return f.read(n)
        except (OSError, ValueError):
            return b""

    def close(self):
        with self._lock:
            allf, self._all = self._all, []
        for f in allf:
            try:
                f.close()
            except OSError:
                pass
        self._local = threading.local()


# ───────────────────────── 基类 ─────────────────────────

class VDisk:
    """一块「可以按字节读」的盘。"""

    kind = "raw"
    label = "整盘镜像"
    note = ""
    size = 0                             # 虚拟盘总字节数（不含格式开销）

    def read(self, off, n):
        raise NotImplementedError

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()


class _FlatDisk(VDisk):
    """扁平字节流：dd 镜像、以及固定 VHD 的数据区都走这里。"""

    kind = "raw"
    label = "整盘镜像"

    def __init__(self, path, base=0, size=None):
        self._h = _Handles(path)
        self._base = max(0, int(base or 0))
        total = os.path.getsize(path)
        self.size = max(0, (total - self._base) if size is None else int(size))

    def read(self, off, n):
        if off < 0 or off >= self.size:
            return b""
        return self._h.pread(self._base + off, min(n, self.size - off))

    def close(self):
        self._h.close()


# ───────────────────────── VHD（大端）─────────────────────────

_VHD_COOKIE = b"conectix"
_VHD_DYN_COOKIE = b"cxsparse"

_VHD_DISK_FIXED = 2
_VHD_DISK_DYNAMIC = 3
_VHD_DISK_DIFF = 4


def _be(b, off, n):
    return int.from_bytes(b[off:off + n], "big")


class _VhdDisk(VDisk):
    """VHD：文件末尾 512 字节是 footer（固定盘数据也从 0 偏移开始）。

    footer 关键字段（全部大端）：
      0x10 data_offset  —— 指向动态盘头（固定盘是 0xFFFFFFFFFFFFFFFF）
      0x30 current_size —— 虚拟盘大小
      0x3C disk_type    —— 2 固定 / 3 动态 / 4 差分

    动态盘头（cookie "cxsparse"）：
      0x10 table_offset     —— BAT 在文件里的偏移
      0x1C max_table_entries—— 一共多少块
      0x20 block_size       —— 每块多少字节（默认 2MB）
    BAT 每项 4 字节，是**扇区号**（0xFFFFFFFF = 这块没分配，读出来是全 0）；
    每块数据前面还有一个 512 字节的位图扇区，真正的数据从「块扇区号×512+512」开始。
    """

    kind = "vhd"

    def __init__(self, path):
        self._h = _Handles(path)
        self._path = path
        total = os.path.getsize(path)
        foot = self._h.pread(total - SECTOR, SECTOR)
        if len(foot) < SECTOR or foot[:8] != _VHD_COOKIE:
            raise VDiskError("这个文件的结尾没有 VHD 标记（不是一个完整的 VHD）")
        self._dtype = _be(foot, 0x3C, 4)
        self._dyn_off = _be(foot, 0x10, 8)
        cur = _be(foot, 0x30, 8)
        self._cur_size = cur or _be(foot, 0x28, 8)
        self.size = self._cur_size
        if self._dtype == _VHD_DISK_FIXED:
            self.kind = "vhd-fixed"
            self.label = "VHD 固定盘"
            self._base = 0                       # 固定盘：数据就在 0 偏移
            return
        if self._dtype == _VHD_DISK_DIFF:
            raise VDiskError(_VHD_DIFF_HINT)
        if self._dtype != _VHD_DISK_DYNAMIC:
            raise VDiskError(f"这是一个不认识的 VHD 类型（disk_type={self._dtype}）")
        self.kind = "vhd-dynamic"
        self.label = "VHD 动态盘"
        head = self._h.pread(self._dyn_off, 1024)
        if head[:8] != _VHD_DYN_COOKIE:
            raise VDiskError("VHD 的动态盘头损坏（cxsparse 标记对不上）")
        table_off = _be(head, 0x10, 8)
        entries = _be(head, 0x1C, 4)
        block_size = _be(head, 0x20, 4)
        if not (0 < entries < (1 << 24)) or block_size < SECTOR or block_size % SECTOR:
            raise VDiskError("VHD 的块表参数不合理（文件可能被截断）")
        self._block = block_size
        raw = self._h.pread(table_off, entries * 4)
        self._bat = list(struct.unpack(">%dI" % entries, raw)) if len(raw) == entries * 4 else []
        if not self._bat:
            raise VDiskError("VHD 的块表读不出来（文件可能被截断）")

    def read(self, off, n):
        if off < 0 or off >= self.size:
            return b""
        n = min(n, self.size - off)
        out = bytearray()
        left = n
        pos = off
        if self._dtype == _VHD_DISK_FIXED:
            return self._h.pread(pos, left)
        blk_size = self._block
        while left > 0:
            blk = pos // blk_size
            inner = pos % blk_size
            take = min(left, blk_size - inner)
            sec = self._bat[blk] if blk < len(self._bat) else 0xFFFFFFFF
            if sec == 0xFFFFFFFF:               # 没分配：这块本来就是全 0
                out += bytes(take)
            else:
                chunk = self._h.pread(sec * SECTOR + SECTOR + inner, take)
                out += chunk if len(chunk) == take else chunk + bytes(take - len(chunk))
            pos += take
            left -= take
        return bytes(out)

    def close(self):
        self._h.close()


# ───────────────────────── VHDX（小端）─────────────────────────

_VHDX_SIG = b"vhdxfile"


def _guid(text):
    """'2DC27766-F623-4200-9D64-115E9BFD4A08' → 磁盘上的 16 字节。

    GUID 的前三段是**小端**存的（Windows 的 GUID 结构体就是三个整数 + 8 字节），
    手写十六进制极容易错位 —— 这里统一从文本生成，别写裸 hex。
    """
    a, b, c, d, e = text.split("-")
    return (struct.pack("<I", int(a, 16)) + struct.pack("<H", int(b, 16))
            + struct.pack("<H", int(c, 16))
            + bytes.fromhex(d) + bytes.fromhex(e))


_VHDX_REGION_BAT = _guid("2DC27766-F623-4200-9D64-115E9BFD4A08")
_VHDX_REGION_META = _guid("8B7CA206-4790-4B9A-B8FE-575F050F886E")
_VHDX_META_FILE_PARAMS = _guid("CAA16737-FA36-4D43-B3B6-33F0AA44E76B")
_VHDX_META_DISK_SIZE = _guid("2FA54224-CD1B-4876-B211-5DBED83BF4B8")


class _VhdxDisk(VDisk):
    """VHDX：文件头 + 两个头 + 两份区域表 + BAT + Metadata。

    关键字段：
      · 区域表在 64KB / 128KB 之后（192KB、256KB 各一份，互为备份），签名为 "regi"；
        每项 32 字节：GUID(16) + FileOffset(8) + Length(4) + Required(4)。
      · Metadata 区域里能查到「块大小」和「虚拟盘大小」。
      · BAT 每项 8 字节：低 3 位是状态，高 61 位是「文件偏移，单位 1MB」。
        状态 6/7 才算「有数据」，0~3 一律当全 0。
    """

    kind = "vhdx"

    def __init__(self, path):
        self._h = _Handles(path)
        head = self._h.pread(0, 16)
        if head[:8] != _VHDX_SIG:
            raise VDiskError("这不是 VHDX（文件头标记对不上）")
        layout = None
        for off in (192 << 10, 256 << 10):       # 两份区域表，前一份坏就读后一份
            raw = self._h.pread(off, 64 << 10)
            if len(raw) >= 16 and raw[:4] == b"regi":
                layout = self._parse_regions(raw)
                if layout.get("bat") and layout.get("meta"):
                    break
        if not layout or not layout.get("bat") or not layout.get("meta"):
            raise VDiskError("VHDX 的区域表读不出来（文件可能被截断或损坏）")
        bat_off, bat_len = layout["bat"]
        meta_off, meta_len = layout["meta"]
        info = self._parse_metadata(self._h.pread(meta_off, meta_len))
        self._block = int(info.get("block_size") or (2 << 20))
        self.size = int(info.get("disk_size") or 0)
        if info.get("has_parent"):
            raise VDiskError(_VHD_DIFF_HINT.replace("VHD", "VHDX"))
        if self._block < (1 << 20) or self._block & (self._block - 1):
            raise VDiskError("VHDX 的块大小不合理（文件可能损坏）")
        if not self.size:
            raise VDiskError("VHDX 里读不出虚拟盘大小（Metadata 损坏）")
        count = (self.size + self._block - 1) // self._block
        self._bat_off = bat_off
        self._bat_len = bat_len
        self._count = count
        raw = self._h.pread(bat_off, count * 8)
        if len(raw) == count * 8:
            self._bat = list(struct.unpack("<%dQ" % count, raw))
        else:                                   # 太大的 BAT：按需读
            self._bat = None
        self.kind = "vhdx"
        self.label = "VHDX 虚拟盘"

    def _parse_regions(self, raw):
        out = {}
        count = struct.unpack_from("<I", raw, 8)[0]
        if count > 2048:
            return out
        for i in range(count):
            p = 16 + i * 32
            if p + 32 > len(raw):
                break
            guid = raw[p:p + 16]
            foff, flen = struct.unpack_from("<QI", raw, p + 16)
            if guid == _VHDX_REGION_BAT:
                out["bat"] = (foff, flen)
            elif guid == _VHDX_REGION_META:
                out["meta"] = (foff, flen)
        return out

    def _parse_metadata(self, raw):
        out = {}
        if len(raw) < 32 or raw[:8] != b"metadata":
            return out
        count = struct.unpack_from("<H", raw, 10)[0]
        for i in range(min(count, 2048)):
            p = 32 + i * 32
            if p + 32 > len(raw):
                break
            guid = raw[p:p + 16]
            voff, vlen = struct.unpack_from("<II", raw, p + 16)
            if voff + vlen > len(raw):
                continue
            val = raw[voff:voff + vlen]
            if guid == _VHDX_META_FILE_PARAMS and len(val) >= 8:
                block, flags = struct.unpack_from("<II", val, 0)
                out["block_size"] = block
                out["has_parent"] = bool(flags & 2)
            elif guid == _VHDX_META_DISK_SIZE and len(val) >= 8:
                out["disk_size"] = struct.unpack_from("<Q", val, 0)[0]
        return out

    def _item(self, blk):
        if self._bat is not None:
            return self._bat[blk] if blk < len(self._bat) else 0
        raw = self._h.pread(self._bat_off + blk * 8, 8)
        return struct.unpack("<Q", raw)[0] if len(raw) == 8 else 0

    def read(self, off, n):
        if off < 0 or off >= self.size:
            return b""
        n = min(n, self.size - off)
        out = bytearray()
        left = n
        pos = off
        while left > 0:
            blk = pos // self._block
            inner = pos % self._block
            take = min(left, self._block - inner)
            item = self._item(blk)
            state = item & 0x7
            mb = (item >> 20) & 0xFFFFFFFFFFF
            if state in (0, 1, 2, 3) or not mb:   # 未分配 / 全零 / 未映射
                out += bytes(take)
            else:
                chunk = self._h.pread((mb << 20) + inner, take)
                out += chunk if len(chunk) == take else chunk + bytes(take - len(chunk))
            pos += take
            left -= take
        return bytes(out)

    def close(self):
        self._h.close()


# ───────────────────────── VMDK（小端）─────────────────────────

_VMDK_MAGIC = b"KDMV"


class _VmdkDisk(VDisk):
    """VMDK 单文件稀疏盘（monolithicSparse）。

    头 512 字节，小端：
      0x0C capacity         —— 总扇区数
      0x14 grainSize        —— 每个 grain 多少扇区（默认 128 = 64KB）
      0x2C numGTEsPerGT     —— 每张 grain 表多少项
      0x38 gdOffset         —— grain 目录（GD）在文件里的扇区号
      0x40 overhead         —— 数据区起始扇区
      0x4C compressAlgorithm—— 0 表示不压缩（非 0 就是压缩流，读不了）

    GD 每项 4 字节 = 对应 grain 表的扇区号；grain 表每项 4 字节 = 该 grain
    在文件里的扇区号，0 表示「没分配，读出来全 0」。
    """

    kind = "vmdk"

    def __init__(self, path):
        self._h = _Handles(path)
        head = self._h.pread(0, SECTOR)
        if head[:4] != _VMDK_MAGIC:
            if head[:4] == b"# Di":
                raise VDiskError(_VMDK_DESCRIPTOR_HINT)
            raise VDiskError("这不是 VMDK（文件头标记对不上）")
        magic, _ver, _flags = struct.unpack_from("<III", head, 0)
        if magic != 0x564D444B:
            raise VDiskError("VMDK 文件头损坏")
        self._capacity = struct.unpack_from("<Q", head, 0x0C)[0]
        self._grain_sectors = struct.unpack_from("<Q", head, 0x14)[0]
        self._gtes = struct.unpack_from("<I", head, 0x2C)[0]
        self._gd = struct.unpack_from("<Q", head, 0x38)[0]
        self._compress = struct.unpack_from("<H", head, 0x4C)[0]
        self.size = self._capacity * SECTOR
        if self._compress:
            raise VDiskError(_VMDK_COMPRESSED_HINT)
        if not self._grain_sectors or not self._gtes or not self._gd:
            raise VDiskError("这是 VMDK 的描述文件，不是存数据的那份（见下）")
        self._grain_bytes = self._grain_sectors * SECTOR
        self._grains = (self.size + self._grain_bytes - 1) // self._grain_bytes
        self._gd_count = (self._grains + self._gtes - 1) // self._gtes
        raw = self._h.pread(self._gd * SECTOR, self._gd_count * 4)
        self._gd_tab = list(struct.unpack("<%dI" % self._gd_count, raw)) \
            if len(raw) == self._gd_count * 4 else []
        self._gt_cache = {}
        self.label = "VMDK 虚拟盘"

    def _grain_sector(self, gid):
        gd_idx = gid // self._gtes
        gt_idx = gid % self._gtes
        if gd_idx >= len(self._gd_tab):
            return 0
        gt_sec = self._gd_tab[gd_idx]
        if not gt_sec or gt_sec == 0xFFFFFFFF:
            return 0
        tab = self._gt_cache.get(gt_sec)
        if tab is None:
            raw = self._h.pread(gt_sec * SECTOR, self._gtes * 4)
            tab = struct.unpack("<%dI" % self._gtes, raw) if len(raw) == self._gtes * 4 else None
            if tab is None:
                return 0
            if len(self._gt_cache) > 4096:        # 别让缓存无限长
                self._gt_cache.clear()
            self._gt_cache[gt_sec] = tab
        return tab[gt_idx] if gt_idx < len(tab) else 0

    def read(self, off, n):
        if off < 0 or off >= self.size:
            return b""
        n = min(n, self.size - off)
        out = bytearray()
        left = n
        pos = off
        gb = self._grain_bytes
        while left > 0:
            gid = pos // gb
            inner = pos % gb
            take = min(left, gb - inner)
            sec = self._grain_sector(gid)
            if not sec:
                out += bytes(take)
            else:
                chunk = self._h.pread(sec * SECTOR + inner, take)
                out += chunk if len(chunk) == take else chunk + bytes(take - len(chunk))
            pos += take
            left -= take
        return bytes(out)

    def close(self):
        self._h.close()


# ───────────────────────── 识别 + 打开 ─────────────────────────

_E01_SIGS = (b"EVF\x09\x0d\x0a\xff\x00", b"EVF2\r\n\x81\x00")
_QCOW_SIG = b"QFI\xfb"


def probe(path):
    """看一眼这是什么格式，返回 (kind, label)。不打开、不解析。

    kind 为 `raw` 表示「就是一段扁平字节流」（dd 镜像、任意数据）。
    已知但**不支持**的格式也会如实返回（e01 / qcow2 / vhd-differencing），
    这样调用方能给出「为什么读不了、怎么转」而不是「这不是文件系统」。
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(512)
            fh.seek(0, 2)
            total = fh.tell()
            tail = b""
            if total >= SECTOR:
                fh.seek(total - SECTOR)
                tail = fh.read(SECTOR)
    except OSError:
        return "missing", "文件读不了"
    if head[:8] == _VHDX_SIG:
        return "vhdx", "VHDX 虚拟盘"
    if head[:4] == _VMDK_MAGIC:
        return "vmdk", "VMDK 虚拟盘"
    if head[:4] == b"# Di":
        return "vmdk-descriptor", "VMDK 描述文件"
    for sig in _E01_SIGS:
        if head.startswith(sig):
            return "e01", "E01 取证镜像"
    if head[:4] == _QCOW_SIG:
        return "qcow2", "QCOW2 镜像"
    if tail[:8] == _VHD_COOKIE:
        dtype = _be(tail, 0x3C, 4)
        if dtype == _VHD_DISK_FIXED:
            return "vhd-fixed", "VHD 固定盘"
        if dtype == _VHD_DISK_DYNAMIC:
            return "vhd-dynamic", "VHD 动态盘"
        if dtype == _VHD_DISK_DIFF:
            return "vhd-diff", "VHD 差分盘"
        return "vhd", "VHD 虚拟盘"
    return "raw", "整盘镜像"


def open_path(path):
    """打开一份镜像，返回能按字节读的盘对象。

    普通镜像（dd / 裸数据）也会返回对象 —— 调用方不用区分「虚拟盘」和「文件」。
    已知但不支持的格式抛 `VDiskError`，消息里带转换办法。
    """
    kind, _label = probe(path)
    if kind == "missing":
        raise VDiskError(f"打不开这个文件：{path}")
    if kind == "vhdx":
        return _VhdxDisk(path)
    if kind == "vmdk":
        return _VmdkDisk(path)
    if kind == "vmdk-descriptor":
        raise VDiskError(_VMDK_DESCRIPTOR_HINT)
    if kind == "e01":
        raise VDiskError(_E01_HINT)
    if kind == "qcow2":
        raise VDiskError(_QCOW_HINT)
    if kind == "vhd-diff":
        raise VDiskError(_VHD_DIFF_HINT)
    if kind in ("vhd-fixed", "vhd-dynamic"):
        return _VhdDisk(path)
    return _FlatDisk(path)
