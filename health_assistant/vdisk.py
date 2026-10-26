"""虚拟磁盘读取：把 VHD / VHDX / VMDK / QCOW2 当成一块「扁平的、能按字节读」的盘。

为什么要这一层：用户手上的镜像很少是 `dd` 出来的裸数据。Windows 自己的
「磁盘管理 / Hyper-V / 系统映像备份」产出的是 VHD / VHDX，VMware 的是 VMDK，
QEMU / KVM / Proxmox / 云厂商的是 QCOW2，专业取证交付的是 E01。这些格式内部都是
「稀疏块 + 映射表」，直接按文件偏移读读到的是映射表，不是一个盘 —— 于是工具会
告诉你「引导扇区认不出来」，而真正的原因是「这根本不是裸镜像」。

这一层只做一件事：**认得出来 + 解得开**，让它和裸镜像走完全相同的后续流程
（分区表、NTFS/FAT 解析、按类型找、恢复导出都不用改）。

支持的格式与依据：
  · VHD  fixed / dynamic      （微软 Virtual PC / diskpart `create vdisk`）
  · VHDX fixed / dynamic      （Hyper-V、Windows 系统映像备份）
  · VMDK monolithicSparse     （VMware）
  · QCOW2 v2 / v3             （QEMU / KVM / Proxmox；含压缩簇、零簇、差分链）
  · dd 裸镜像 / 任意扁平字节流（原样透传）

  · E01（EWF 第一版，EnCase 1~6 / FTK Imager / linen 都产出这种）
  · Ex01（EWF 第二版，EnCase 7 之后）

不支持的（识别出来就给明确指引，不假装是坏镜像）：
  · L01 / Lx01（逻辑取证文件，里面是挑出来的文件、不是盘）
  · 加密的 QCOW2 / Ex01、QCOW2 的 external data file 与 extended L2、
    差分盘（VHD differencing）

全程只读。所有多字节字段：VHD 是**大端**，QCOW2 是**大端**，
VHDX / VMDK / E01 / Ex01 是**小端**。
"""
from __future__ import annotations

import array
import bz2
import os
import re
import struct
import sys
import threading
import zlib

# zstd 压缩的 QCOW2 簇只有极少数镜像会用；没装这个库就如实说读不了，
# 不学「拿错数据凑数」。放在顶层 try 里是为了打包时能被静态分析看到。
try:
    import zstandard as _zstd
except Exception:                        # noqa: BLE001  没装 / 装了但加载不了
    _zstd = None

SECTOR = 512

# ───────────────────────── 用户能看懂的错误 ─────────────────────────

_L01_HINT = (
    "这是一个 **逻辑取证文件（.L01）**，不是磁盘镜像。\n\n"
    "L01 里存的是取证时**挑出来的那些文件**（连同目录结构和元数据），"
    "没有分区表、没有文件系统、也没有空闲空间 —— 所以按盘恢复的那套办法"
    "（找删除记录、按内容扫描）在这里没有意义。\n\n"
    "要看里面的文件，用 FTK Imager 或 EnCase 直接打开这个 L01 就行；"
    "如果你要恢复的是那块盘上被删的东西，需要那块盘的 E01/raw 整盘镜像。")

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


# ───────────────────────── QCOW2（QEMU / KVM）─────────────────────────

_QCOW_SIG = b"QFI\xfb"

_QCOW_OFLAG_ZERO = 1 << 0
_QCOW_OFLAG_COMPRESSED = 1 << 62
_QCOW_OFFSET_MASK = 0x00FFFFFFFFFFFE00      # host 偏移占 bit 9~55

# incompatible_features（v3）：未知位不许猜，必须拒绝 —— 猜了就是错位的数据
_QCOW_IN_EXTERNAL_DATA = 1 << 2
_QCOW_IN_COMPRESSION_TYPE = 1 << 3
_QCOW_IN_EXTENDED_L2 = 1 << 4
_QCOW_IN_KNOWN = 0x1F


def _u32be(b, off):
    return struct.unpack_from(">I", b, off)[0] if len(b) >= off + 4 else 0


def _u64be(b, off):
    return struct.unpack_from(">Q", b, off)[0] if len(b) >= off + 8 else 0


_QCOW_CRYPT_HINT = (
    "这是一份**加了密的 QCOW2 镜像**（AES 或 LUKS 加密）。\n\n"
    "没有口令读不出里面的数据，本工具也不猜口令、不尝试破解。\n\n"
    "要读它得先解密：用 `qemu-img convert` 配合 `--object secret` 把口令交给 qemu，"
    "转成裸镜像（.raw）再在这里打开。")

_QCOW_BACKING_HINT = (
    "这是一份 **QCOW2 差分盘**（快照的增量层）—— 它只存了「相对底层改动过的块」，"
    "单独一份不构成完整的盘。\n\n"
    "它要读的底层盘是：\n    {name}\n\n"
    "把这个文件按上面的路径放好（通常是同一目录）再打开，本工具会把两层叠起来读；"
    "也可以用 `qemu-img convert -O raw` 把整条链合并成一份裸镜像。")

_QCOW_EXTERNAL_DATA_HINT = (
    "这是一份**数据放在外部文件里的 QCOW2**（external data file）——"
    "元数据在这个文件里，真正的扇区数据在同目录的另一个 .raw 文件里。\n\n"
    "目前不直接支持这种拆开放法。用 `qemu-img convert -O raw` 合并成一份裸镜像再打开。")

_QCOW_EXTENDED_L2_HINT = (
    "这份 QCOW2 用了 **extended L2（子簇分配）**，是比较新的写法，"
    "目前还不支持。\n\n"
    "用 `qemu-img convert -O raw` 转成裸镜像再打开。")

_QCOW_ZSTD_HINT = (
    "这份 QCOW2 的压缩簇用的是 **zstd**，本机没装解压它的库，"
    "所以现在读不出来（不会拿错数据凑数）。\n\n"
    "用 `qemu-img convert -O raw` 转成裸镜像再打开，或者装上 `zstandard` 后重开本工具。")


class _Qcow2Disk(VDisk):
    """QCOW2：QEMU / KVM / Proxmox / 云厂商导出的默认磁盘格式。

    头部 72 字节（v3 起 104+），**所有字段大端**，偏移：
      4  version          20 cluster_bits     36 l1_size
      8  backing 名字偏移  24 虚拟盘字节数     40 l1 表偏移
      16 backing 名字长度  32 crypt_method     72 incompatible_features（v3）
                                              104 compression_type（v3，0 deflate / 1 zstd）

    L1 表：l1_size 个 8 字节项 → 每项指向一张 L2 表所在的簇（偏移在 bit 9~55），
    为 0 表示这张 L2 整个没分配。
    L2 表：每项 8 字节描述一个 guest 簇：
      bit 62   压缩簇（内容是一段**裸 deflate 流**，没有 zlib 头）
      bit 0    读出来全是 0（不再往下找底层盘）
      bit 9~55 数据在文件里的偏移；为 0 = 没分配 → 读底层盘（没有就全 0）

    压缩簇把「偏移」和「长度」挤在最低的 x = 62-(cluster_bits-8) 位里：
      偏移 = 低 x 位，**不是簇或扇区对齐的**；
      长度 = 再往上 (62-x) 位加 1，按 512 字节扇区算，再减去偏移落在扇区内的那截。
    这两个式子照 qcow2 规范写；错了就解不开（实测拿 qemu 产出的镜像验过）。
    """

    kind = "qcow2"

    def __init__(self, path, _seen=None):
        path = os.path.abspath(path)
        self._path = path
        self._h = _Handles(path)
        self._l2_cache = {}
        self._backing = None
        self.bad_clusters = 0
        self._comp = 0
        head = self._h.pread(0, 512)
        if head[:4] != _QCOW_SIG:
            raise VDiskError("这不是 QCOW2（文件头标记对不上）")
        if len(head) < 72:
            raise VDiskError("这份 QCOW2 文件太小，连头部都不完整（可能没拷完）。")
        self._version = _u32be(head, 4)
        if self._version not in (2, 3):
            raise VDiskError(f"这份 QCOW2 的版本号是 {self._version}，只认得 2 和 3。")
        cb = _u32be(head, 20)
        if cb < 9 or cb > 21:
            raise VDiskError("这份 QCOW2 的头部坏了（簇大小字段不合理）。")
        self._cluster_bits = cb
        self._cluster = 1 << cb
        self.size = _u64be(head, 24)
        if _u32be(head, 32):
            raise VDiskError(_QCOW_CRYPT_HINT)
        l1_size = _u32be(head, 36)
        l1_off = _u64be(head, 40)
        if not l1_size or not l1_off or l1_size > (1 << 22):
            raise VDiskError("这份 QCOW2 的头部坏了（L1 表字段不合理）。")
        if self._version >= 3:
            feats = _u64be(head, 72)
            if feats & _QCOW_IN_EXTERNAL_DATA:
                raise VDiskError(_QCOW_EXTERNAL_DATA_HINT)
            if feats & _QCOW_IN_EXTENDED_L2:
                raise VDiskError(_QCOW_EXTENDED_L2_HINT)
            if feats & ~_QCOW_IN_KNOWN:
                raise VDiskError("这份 QCOW2 用了本工具不认识的新特性，为了不给错数据，"
                                 "先不打开。用 `qemu-img convert -O raw` 转成裸镜像再试。")
            if feats & _QCOW_IN_COMPRESSION_TYPE:
                self._comp = head[104] if len(head) > 104 else 0
                if self._comp == 1:
                    if _zstd is None:
                        raise VDiskError(_QCOW_ZSTD_HINT)
                elif self._comp != 0:
                    raise VDiskError(f"这份 QCOW2 的压缩方式是 {self._comp}，"
                                     f"本工具只认得 deflate 和 zstd。")
        raw = self._h.pread(l1_off, l1_size * 8)
        if len(raw) != l1_size * 8:
            raise VDiskError("这份 QCOW2 的 L1 表读不全（文件可能被截断了）。")
        self._l1 = struct.unpack(">%dQ" % l1_size, raw)
        self._l2_count = self._cluster // 8
        self._l2_bytes = self._cluster
        self._l2_shift = cb - 3                 # 一个 L2 表管 2^(cb-3) 个 guest 簇
        self.label = "QCOW2 镜像"
        seen = set(_seen or ())
        seen.add(path)
        self._open_backing(head, seen)

    def _open_backing(self, head, seen):
        off = _u64be(head, 8)
        size = _u32be(head, 16)
        if not off or not size or size > 1023:
            return
        raw = self._h.pread(off, size)
        name = raw.decode("utf-8", "replace").strip("\x00").strip()
        if not name:
            return
        if not os.path.isabs(name):
            name = os.path.join(os.path.dirname(self._path), name)
        name = os.path.abspath(name)
        if not os.path.isfile(name):
            raise VDiskError(_QCOW_BACKING_HINT.format(name=name))
        if name in seen:
            raise VDiskError("这份 QCOW2 的差分链指向了自己（底层盘绕成环），没法读。")
        seen.add(name)
        parent = open_path(name, seen)          # 底层盘也可能是 raw / vmdk / 另一份 qcow2
        self._backing = parent
        self.label = "QCOW2 镜像（含差分层）"
        self.note = (f"这是一份差分盘，已经把底层「{os.path.basename(name)}」"
                     f"叠上来一起读（看到的是合并后的样子）；单独交出去的这一份不完整。")

    def _l2_entry(self, cid):
        idx = cid >> self._l2_shift
        if idx >= len(self._l1):
            return 0
        tab = self._l2_cache.get(idx)
        if tab is None:
            base = self._l1[idx] & _QCOW_OFFSET_MASK
            if not base:
                return 0
            raw = self._h.pread(base, self._l2_bytes)
            if len(raw) != self._l2_bytes:
                return 0
            tab = struct.unpack(">%dQ" % self._l2_count, raw)
            if len(self._l2_cache) > 4096:
                self._l2_cache.clear()
            self._l2_cache[idx] = tab
        return tab[cid & (self._l2_count - 1)]

    def _decompress(self, entry):
        x = 62 - (self._cluster_bits - 8)
        coff = entry & ((1 << x) - 1)
        nb = ((entry >> x) & ((1 << (62 - x)) - 1)) + 1
        want = nb * SECTOR - (coff % SECTOR)
        if coff <= 0 or want <= 0:
            self.bad_clusters += 1
            return b""
        raw = self._h.pread(coff, want)
        if not raw:
            self.bad_clusters += 1
            return b""
        try:
            if self._comp == 1:
                out = _zstd.ZstdDecompressor().decompress(
                    raw, max_output_size=self._cluster)
            else:
                d = zlib.decompressobj(-15)     # 裸 deflate：qemu 不写 zlib 头
                out = b""
                buf = raw
                while buf and len(out) < self._cluster:
                    out += d.decompress(buf, self._cluster - len(out))
                    buf = d.unconsumed_tail
                    if d.eof:
                        break
        except Exception:
            self.bad_clusters += 1
            return b""
        if len(out) < self._cluster:
            self.bad_clusters += 1               # 解出来不够一簇 = 这段是坏的
        return out

    def _part(self, cid, inner, take):
        entry = self._l2_entry(cid)
        if entry & _QCOW_OFLAG_COMPRESSED:
            data = self._decompress(entry)
            if not data:
                return bytes(take)
            return data[inner:inner + take].ljust(take, b"\x00")
        if entry & _QCOW_OFLAG_ZERO:
            return bytes(take)
        host = entry & _QCOW_OFFSET_MASK
        if host:
            chunk = self._h.pread(host + inner, take)
            return chunk if len(chunk) == take else chunk + bytes(take - len(chunk))
        return self._from_backing(cid * self._cluster + inner, take)

    def _from_backing(self, off, n):
        b = self._backing
        if b is None or off >= b.size:
            return bytes(n)
        take = min(n, b.size - off)
        data = b.read(off, take)
        return data.ljust(n, b"\x00")

    def read(self, off, n):
        if off < 0 or off >= self.size:
            return b""
        n = min(n, self.size - off)
        csize = self._cluster
        out = bytearray()
        pos, left = off, n
        while left > 0:
            inner = pos & (csize - 1)
            take = min(left, csize - inner)
            out += self._part(pos >> self._cluster_bits, inner, take)
            pos += take
            left -= take
        return bytes(out)

    def close(self):
        if self._backing is not None:
            self._backing.close()
        self._h.close()


def _qcow2_backing(path):
    """只看头部，返回这份 QCOW2 的底层盘路径（没有 / 读不了 → None）。"""
    try:
        with open(path, "rb") as fh:
            head = fh.read(64)
            if head[:4] != _QCOW_SIG:
                return None
            off = _u64be(head, 8)
            size = _u32be(head, 16)
            if not off or not size or size > 1023:
                return None
            fh.seek(off)
            name = fh.read(size).decode("utf-8", "replace").strip("\x00").strip()
    except OSError:
        return None
    if not name:
        return None
    if not os.path.isabs(name):
        name = os.path.join(os.path.dirname(os.path.abspath(path)), name)
    return os.path.abspath(name)


# ───────────────────────── E01 / EWF（取证格式）─────────────────────────

_EWF_SIG = b"EVF\x09\x0d\x0a\xff\x00"          # E01 / S01 的段文件头
_EWF2_SIG = b"EVF2\r\n\x81\x00"                # Ex01（EWF 第二版）
_EWF_L01_SIG = b"LVF\x09\x0d\x0a\xff\x00"      # L01 逻辑取证文件
_EWF_EXT_RE = re.compile(r"^\.(?:e|ex|l|s)(?:[0-9]{2}|[a-z]{2})$", re.I)

_SEC_DESC = 76          # section 描述符长度，所有 section 都一样
_SEC_PAD = 72           # 校验和覆盖描述符前 72 字节（Adler-32）


def _u16(b, off):
    return struct.unpack_from("<H", b, off)[0] if len(b) >= off + 2 else 0


def _u32(b, off):
    return struct.unpack_from("<I", b, off)[0] if len(b) >= off + 4 else 0


def _u64(b, off):
    return struct.unpack_from("<Q", b, off)[0] if len(b) >= off + 8 else 0


def _adler(b):
    return zlib.adler32(b) & 0xFFFFFFFF


def _ewf_segments(path):
    """找回同一套镜像的**所有分卷**（xxx.E01 / .E02 / …），按段号排序。

    分卷是按大小切开的，少一段后面的数据就全错位 —— 所以这里不猜扩展名顺序，
    而是把同目录下同样前缀、同样 EWF 签名的文件全找出来，按**文件头里记的段号**
    （偏移 9，2 字节）排序。段号缺失时用扩展名顺序兜底。

    段号从 1 开始；某一段的段号重复/为 0，就当它是「未知」，排在后面。
    """
    path = os.path.abspath(path)
    folder, name = os.path.split(path)
    stem, ext = os.path.splitext(name)
    try:
        names = os.listdir(folder)
    except OSError:
        names = []
    found = []
    for fn in names:
        s2, e2 = os.path.splitext(fn)
        if s2.lower() != stem.lower() or not _EWF_EXT_RE.match(e2 or ""):
            continue
        found.append(os.path.join(folder, fn))
    if path not in found:                    # 扩展名不规范的也照开
        found.append(path)
    segs = []
    for p in found:
        try:
            with open(p, "rb") as fh:
                head = fh.read(13)
        except OSError:
            continue
        if not (head.startswith(_EWF_SIG) or head.startswith(_EWF_L01_SIG)
                or head.startswith(_EWF2_SIG)):
            continue
        num = int.from_bytes(head[9:11], "little") if len(head) >= 11 else 0
        segs.append((num or (1 << 20), p))
    segs.sort()
    return [p for _n, p in segs]


def _ewf_sections(h, total):
    """走一遍段文件里的 section 链 → [(类型, 描述符偏移, 段大小)]。

    section 是**单向链表**：每个描述符里的「下一段偏移」指到下一个描述符。
    到 "next"/"done" 就停（"next" 指向自己，如果不判会原地打转）。
    """
    out = []
    off = 13                                  # 文件头 13 字节之后就全是 section
    seen = set()
    while 0 < off and off + _SEC_DESC <= total:
        if off in seen:
            break
        seen.add(off)
        desc = h.pread(off, _SEC_DESC)
        if len(desc) < _SEC_DESC:
            break
        typ = desc[:16].split(b"\x00", 1)[0].decode("latin-1", "replace").strip()
        nxt = _u64(desc, 16)
        size = _u64(desc, 24)
        out.append((typ, off, size))
        if typ in ("next", "done") or nxt <= off or nxt >= total:
            break
        off = nxt
    return out


class _EwfDisk(VDisk):
    """E01：把「分卷 + 一堆压缩块」还原成一块能按字节读的盘。

    结构（依据 libewf 的 EWF 规范，字段偏移用真实样本核对过）：
      · 段文件头 13 字节：签名 "EVF\\x09\\x0d\\x0a\\xff\\x00"(8) + 0x01(1) +
        段号(2, 小端) + 0x0000(2)。
      · 之后是 section 链表，每个 section 头 76 字节：
        [0:16] 类型（"volume"/"sectors"/"table"/"next"/"done"…）、
        [16:24] 下一段偏移、[24:32] 本段大小、[72:76] 描述符的 Adler-32。
      · volume 段（1052 字节）：[4] 总块数、[8] 每块多少扇区（默认 64）、
        [12] 每扇区多少字节（默认 512）、[16] 总扇区数（8 字节）。
      · 数据都在 sectors 段里，一块一块紧挨着：要么是**一整段 zlib 流**
        （自带 Adler-32），要么是**原始数据 + 4 字节 Adler-32**。
      · 每块在哪由随后的 table 段给出：24 字节表头（[0] 条目数、[8] 基准偏移，
        只有 EnCase 6+ 有这一栏）+ N 个 4 字节偏移。偏移最高位是「压没压」的标志，
        所以真正的偏移要 `& 0x7FFFFFFF`。table2 是 table 的镜像，不用重复读。

    读的时候不信任「最高位标志」也不信任「基准偏移」—— 这两个东西各家实现
    有出入（EnCase 6.7.1 甚至会把 31 位用满）。做法是：拿到候选偏移后
    **真的去解一次第一块**，解出来的字节数正好等于块大小才算数。解不开就换
    另一种解释。这样「能不能读」永远有实证，不是猜。
    """

    kind = "e01"
    label = "E01 取证镜像"

    def __init__(self, path):
        self._path = path
        self._segs = []
        self._tables = []          # [(起始块号, 块数, 段下标, 基准偏移, 偏移表, 结束位置)]
        self._firsts = []          # 每张表的起始块号，给 bisect 用
        self._chunk_n = 0          # 已收到的块数
        self._chunk_size = 0
        self._sectors = 0
        self._bps = 0
        self._chunk_n_want = 0     # volume 段里自称有多少块
        self._bad = 0              # 有块解不出来（坏块）的次数
        self._tl = threading.local()
        self.note = ""
        paths = _ewf_segments(path)
        if not paths:
            raise VDiskError("这不是 E01 镜像（文件头标记对不上）")
        for p in paths:
            self._segs.append(_Handles(p))
        try:
            self._load()
        except Exception:
            self.close()
            raise
        if not self._chunk_size or not self.size:
            self.close()
            raise VDiskError("这份 E01 读不出「块大小 / 盘有多大」，"
                             "文件可能被截断或者根本不是 E01")

    # ── 打开时的解析 ──────────────────────────────────────────────

    def _load(self):
        vol = None
        plan = []                              # [(段下标, table 段偏移, 前一个 sectors 偏移)]
        for si, h in enumerate(self._segs):
            try:
                total = os.path.getsize(h.path)
            except OSError:
                continue
            prev_sect = 0
            for typ, off, _size in _ewf_sections(h, total):
                if typ in ("volume", "disk"):
                    if vol is None:
                        vol = h.pread(off + _SEC_DESC, 1052)
                elif typ == "sectors":
                    prev_sect = off
                elif typ == "table" and prev_sect:
                    plan.append((si, off, prev_sect))
        if vol:
            self._read_volume(vol)
        if not self._chunk_size:
            self._guess_chunk_size(plan)
        for si, off, sect in plan:
            self._add_table(si, off, sect)
        if not self._chunk_n:
            raise VDiskError("这份 E01 里一块数据都没找到 —— 文件可能被截断，"
                             "也可能分卷不齐（只给了一部分 .E01/.E02…），或者块表坏了")
        want = self._sectors * self._bps if (self._sectors and self._bps) else 0
        total = self._chunk_n * self._chunk_size
        self.size = min(want, total) if want else total
        miss = self._chunk_n_want - self._chunk_n
        if miss > 0:
            self.note = (f"块表里只有 {self._chunk_n} 块，镜像自称 {self._chunk_n_want} 块"
                         f"（少 {miss} 块，分卷可能不齐），缺的部分按 0 读")
        elif want and total < want:
            self.note = (f"数据比镜像自称的少 {want - total} 字节，缺的部分按 0 读")
        elif len(self._segs) > 1:
            # 分卷个数写进 label（界面那行「已解开：…」直接用它），note 留给出问题的情况
            self.label = f"E01 取证镜像（{len(self._segs)} 个分卷）"

    def _read_volume(self, raw):
        if len(raw) < 20:
            return
        n = _u32(raw, 4)
        spc = _u32(raw, 8)
        bps = _u32(raw, 12)
        secs = _u64(raw, 16)
        # 三个值必须自洽：块 = 每块扇区数 × 每扇区字节数，且都是 2 的幂/整数倍
        if (0 < spc <= 1 << 20 and 128 <= bps <= 1 << 16
                and (bps & (bps - 1)) == 0 and SECTOR <= spc * bps <= 64 << 20):
            self._chunk_size = spc * bps
            self._bps = bps
        if 0 < secs < (1 << 48):
            self._sectors = secs
        if 0 < n < (1 << 32):
            self._chunk_n_want = n
        else:
            self._chunk_n_want = 0

    def _guess_chunk_size(self, plan):
        """volume 段读不出来时，直接从第一块解出来的长度反推块大小。"""
        for si, off, sect in plan:
            h = self._segs[si]
            hdr = h.pread(off + _SEC_DESC, 24)
            n = _u32(hdr, 0)
            if not 0 < n < (1 << 23):
                continue
            entries = h.pread(off + _SEC_DESC + 24, min(n, 2) * 4)
            if len(entries) < 8:
                continue
            a = _u32(entries, 0) & 0x7FFFFFFF
            b = _u32(entries, 4) & 0x7FFFFFFF
            for base in (_u64(hdr, 8), 0):
                if b <= a or not (sect < base + a < off):
                    continue
                raw = h.pread(base + a, b - a)
                try:
                    d = zlib.decompressobj().decompress(raw, 64 << 20)
                except zlib.error:
                    continue
                if d:
                    self._chunk_size = len(d)
                    self._bps = SECTOR
                    return

    def _add_table(self, si, table_off, sect_off):
        """读一张块表，把「块偏移」按哪种解释读得通这件事**当场验证**掉。"""
        h = self._segs[si]
        hdr = h.pread(table_off + _SEC_DESC, 24)
        n = _u32(hdr, 0)
        if not 0 < n < (1 << 23):
            return
        base_off = _u64(hdr, 8)                # EnCase 6+ 才有这一栏，老版本是 0
        raw = h.pread(table_off + _SEC_DESC + 24, n * 4)
        n = min(n, len(raw) // 4)
        if n <= 0:
            return
        arr = array.array("I")
        arr.frombytes(raw[:n * 4])
        if sys.byteorder != "little":
            arr.byteswap()
        vals = [v & 0x7FFFFFFF for v in arr]    # 最高位是「压没压」的标志，不是偏移
        end = table_off                        # 块都在 table 之前，到这儿为止
        chosen = None
        for base in ([base_off, 0] if base_off else [0]):
            if self._verify(h, vals, base, end, sect_off):
                chosen = (base, vals)
                break
        if chosen is None and any(v & 0x80000000 for v in arr):
            # 极少数（EnCase 6.7.1 的 bug）会把 31 位用满，那时不能剥最高位
            raw_vals = list(arr)
            for base in ([base_off, 0] if base_off else [0]):
                if self._verify(h, raw_vals, base, end, sect_off):
                    chosen = (base, raw_vals)
                    break
        base, vals = chosen if chosen else (base_off, vals)   # 都不通也先收下
        self._firsts.append(self._chunk_n)
        self._tables.append((self._chunk_n, n, si, base, vals, end))
        self._chunk_n += n

    def _verify(self, h, vals, base, end, sect_off):
        """按这种解释读第一块：能解出东西才算解释对。

        不强求「正好一整块」—— 只有一个残块的镜像（盘比块小）第一块本来就是
        短的。判据是「zlib 解得开」或者「Adler-32 对得上」，这两个撞对的概率
        可以忽略，所以这是实证而不是猜。
        """
        a = base + vals[0]
        b = base + (vals[1] if len(vals) > 1 else 0)
        if len(vals) == 1:
            b = end
        if b <= a or not (sect_off < a < end):
            return False
        data, ok = self._load_chunk(h, a, b - a)
        return bool(ok and data)

    # ── 按块取数据 ────────────────────────────────────────────────

    def _decode(self, raw, limit):
        """一块的原始字节 → (数据, 是否可信)。

        先按 zlib 解；解不出来再按「原始数据 + 4 字节 Adler-32」验一遍。
        两条都不成立就是坏块 —— **不返回猜的内容**（宁可如实算 0）。
        """
        if len(raw) < 8:
            return None, False
        try:
            d = zlib.decompressobj().decompress(raw, limit + 1)
        except zlib.error:
            d = b""
        if 0 < len(d) <= limit:
            return d, True
        for blen in (limit, len(raw) - 4):
            if 8 < blen <= len(raw) - 4 and _adler(raw[:blen]) == _u32(raw, blen):
                return raw[:blen], True
        return None, False

    def _load_chunk(self, h, off, length):
        if length <= 0:
            return None, False
        limit = self._chunk_size or (1 << 23)
        # 压缩块比原始略大是正常的（压不动的数据），留足余量但不给无限空间
        if length > limit * 2 + (1 << 16):
            return None, False
        return self._decode(h.pread(off, length), limit)

    def _load_index(self, idx):
        i = _bsearch(self._firsts, idx)
        if i < 0:
            return None
        first, n, si, base, vals, end = self._tables[i]
        j = idx - first
        a = base + vals[j]
        b = base + vals[j + 1] if j + 1 < n else end
        data, ok = self._load_chunk(self._segs[si], a, b - a)
        if not ok:
            self._bad += 1
        return data

    def _chunk_at(self, idx):
        """每线程一个小缓存：扫描是「顺序读 + 少量回头」，块比页大得多。"""
        local = self._tl
        cache = getattr(local, "cache", None)
        if cache is None:
            cache = local.cache = {}
        data = cache.get(idx)
        if data is None and idx not in cache:
            data = self._load_index(idx)
            if len(cache) >= 8:
                cache.pop(next(iter(cache)))
            cache[idx] = data
        return data

    # ── 对外 ──────────────────────────────────────────────────────

    def read(self, off, n):
        if off < 0 or off >= self.size or n <= 0:
            return b""
        n = min(n, self.size - off)
        cs = self._chunk_size
        out = bytearray()
        pos = off
        left = n
        while left > 0:
            idx = pos // cs
            inner = pos % cs
            take = min(left, cs - inner)
            data = self._chunk_at(idx)
            if data and len(data) >= inner + take:
                out += data[inner:inner + take]
            elif data:
                piece = data[inner:inner + take]
                out += piece + bytes(take - len(piece))
            else:                              # 坏块 / 缺块：按 0 读，不编内容
                out += bytes(take)
            pos += take
            left -= take
        return bytes(out)

    def close(self):
        for h in self._segs:
            h.close()
        self._segs = []
        self._tables = []
        self._tl = threading.local()


def _bsearch(firsts, idx):
    """在「每张表的起始块号」里找 idx 落在哪张表（表是按块号递增排的）。"""
    lo, hi = 0, len(firsts)
    while lo < hi:
        mid = (lo + hi) // 2
        if firsts[mid] <= idx:
            lo = mid + 1
        else:
            hi = mid
    return lo - 1 if lo > 0 else -1


# ─────────────────── EWF 第二版（Ex01 / EnCase 7+）───────────────────
#
# 和 E01 长得像但**不能照搬**，四处是反的：
#   · section 描述符在**段的末尾**，而且是**从后往前走**（描述符里记的是「上一段在哪」）；
#   · 描述符 64 字节（E01 是 76），字段全是定长二进制（E01 用 "volume"/"sectors" 字符串）；
#   · 块表项 16 字节、块偏移 **8 字节且是段内绝对偏移**（E01 是 4 字节相对基准偏移，
#     最高位还兼作压缩标志）；
#   · 每块扇区数 / 每扇区字节数 不在「volume 段」里，而在**设备信息段 + 案件信息段**
#     的「序列化对象字符串」里（UTF-16 的 `1\nmain\n标签行\n值行\n`）。
#
# 依据：libewf 的 EWF2 规范 + libewf 参考实现（libewf_section_descriptor.c 里
# `start_offset = previous_offset + 64`、`size = end_offset - start_offset`，
# `libewf_segment_file.c` 里 `segment_file_offset -= section_descriptor->size`）。
# 这两处只看规范是读不出确切含义的，所以对着实现核过。

_EX01_LX_SIG = b"LEF2\r\n\x81\x00"      # Lx01（EWF2 逻辑取证）的段文件头

_EX01_LX01_HINT = (
    "这是一份 **Lx01 逻辑取证文件**（EWF 第二版的逻辑取证格式，只装挑出来的文件，"
    "不是整块盘）。\n\n"
    "它不是盘，所以没法按「已删除记录 / 格式化残留」去扫。要恢复文件内容的话：\n"
    "· 用 FTK Imager（免费）打开它，把里面的文件导出到本地磁盘再处理；\n"
    "· 或者用 ewfexport（libewf）：`ewfexport -t out image.Lx01`。")

_EX01_ENCRYPTED_HINT = (
    "这份 Ex01 是**加密**的（段文件头里声明了加密，或者出现了加密密钥段）。\n"
    "加密镜像必须用原来的口令解开，工具不会去猜口令。\n\n"
    "可以在采集软件（EnCase / FTK Imager）里用口令解密后导出成裸镜像，再打开这里。")

_EX01_TYPE_DEVICE_INFO = 0x00000001
_EX01_TYPE_CASE_DATA = 0x00000002
_EX01_TYPE_SECTOR_DATA = 0x00000003
_EX01_TYPE_SECTOR_TABLE = 0x00000004
_EX01_TYPE_ENCRYPTION = 0x0000000b
_EX01_TYPE_NEXT = 0x0000000d
_EX01_TYPE_DONE = 0x0000000f
_EX01_DESC = 64                      # 描述符长度（含自身）
_EX01_HDR = 32                       # 段文件头长度

_EX01_COMP_NONE = 0
_EX01_COMP_DEFLATE = 1
_EX01_COMP_BZIP2 = 2

_FLAG_COMPRESSED = 0x00000001
_FLAG_CHECKSUMED = 0x00000002
_FLAG_PATTERN = 0x00000004


def _ex01_segments(path):
    """同一套 Ex01 的所有分卷，按**文件头里的段号**（偏移 12，4 字节）排序。

    不能按扩展名排：EnCase 过了 .Ex99 会接着写 .ExAA、.ExZZ、.EyAA…，扩展名的
    字典序和实际顺序一致但极易踩坑（.Ex1A vs .Ex01），而段号是文件自己写的，
    不会骗人。所以这里跟 E01 一样，认文件头，不认文件名。
    """
    path = os.path.abspath(path)
    folder, name = os.path.split(path)
    stem, _ext = os.path.splitext(name)
    try:
        names = os.listdir(folder)
    except OSError:
        names = []
    found = []
    for fn in names:
        s2, e2 = os.path.splitext(fn)
        if s2.lower() != stem.lower() or not _EWF_EXT_RE.match(e2 or ""):
            continue
        found.append(os.path.join(folder, fn))
    if path not in found:
        found.append(path)
    segs = []
    for p in found:
        try:
            with open(p, "rb") as fh:
                head = fh.read(_EX01_HDR)
        except OSError:
            continue
        if not head.startswith(_EWF2_SIG):
            continue
        num = _u32(head, 12) if len(head) >= 16 else 0
        segs.append((num or (1 << 30), p))
    segs.sort()
    return [p for _n, p in segs]


def _ex01_sections(h, total):
    """走一遍 Ex01 段文件里的 section 链，按**物理顺序**返回。

    和 E01 相反：描述符在末尾，链是「后 → 前」。做法是从文件末尾 64 字节处读
    描述符，然后 `偏移 -= 本段总长`（总长 = 数据 + 补位 + 描述符自身 64 字节）
    跳到上一段的描述符。所以最后拿到的是倒序，返回前 reverse 一下。

    每段的实际数据范围 = [上一段描述符偏移 + 64, 本描述符偏移)；第一段的起点
    是段文件头之后（32 字节）。描述符自带的 Adler-32 对不上就说明链坏了，
    直接停 —— 宁可少解析几段，也不拿错位的字节冒充数据。
    """
    out = []
    off = total - _EX01_DESC
    guard = 0
    while off > _EX01_HDR and guard < 1 << 20:
        guard += 1
        raw = h.pread(off, _EX01_DESC)
        if len(raw) < _EX01_DESC:
            break
        if (_adler(raw[:60]) & 0xFFFFFFFF) != _u32(raw, 60):
            break                        # 描述符校验不过：链到这里就断了
        typ = _u32(raw, 0)
        flags = _u32(raw, 4)
        prev = _u64(raw, 8)
        data_size = _u64(raw, 16)
        pad = _u32(raw, 28)
        start = (prev + _EX01_DESC) if prev else _EX01_HDR
        if not (_EX01_HDR <= start <= off):
            break
        out.append({
            "type": typ, "flags": flags, "start": start, "end": off,
            "data_size": data_size, "padding": pad, "desc": off,
        })
        if typ in (_EX01_TYPE_NEXT, _EX01_TYPE_DONE) and len(out) > 1:
            # next/done 是段的最后一段，继续往前也没有意义（但保留它，里面没数据）
            pass
        off = start - _EX01_DESC
    out.reverse()
    return out


def _object_values(raw):
    """把「序列化对象字符串」拆成 {标签: 值}。

    真实格式（拿 libewf 里从真实镜像摘出来的 device_information 核对过）：
    `BOM + "1\\nmain\\n<标签1>\\t<标签2>…\\n<值1>\\t<值2>…\\n\\n"`，UTF-16LE。
    值和标签**按位置对应**，空值就是两个制表符挨着。所以不能按 `=` 或 `:` 去猜，
    也不能假设值里有几个空格就切开 —— 型号名里有空格（"Flash Disk"）。
    """
    if not raw:
        return {}
    if raw[:2] == b"\xff\xfe":
        text = raw.decode("utf-16-le", "ignore")
    elif raw[:2] == b"\xfe\xff":
        text = raw.decode("utf-16-be", "ignore")
    else:                                # 少数实现直接写单字节文本
        text = raw.decode("utf-8", "ignore")
    text = text.replace("\ufeff", "").replace("\x00", "")
    lines = text.split("\n")
    if len(lines) < 4:
        return {}
    tags = [t.strip() for t in lines[2].split("\t")]
    vals = lines[3].split("\t")
    out = {}
    for i, tag in enumerate(tags):
        if not tag:
            continue
        val = vals[i].strip() if i < len(vals) else ""
        # 有的采集软件会在第一个值前面塞一个控制字符（实测 EnCase 的 sn 就是），
        # 只留可打印内容，免得把垃圾字节当成型号/容量
        val = "".join(ch for ch in val if ch.isprintable())
        out[tag] = val
    return out


class _Ex01Disk(VDisk):
    """Ex01（EWF 第二版）：分卷 + 压缩块 → 一块能按字节读的盘。

    读盘路径和 E01 一样：`read(off, n)` → 落在第几块 → 解那块 → 切片。
    每线程一个块缓存（扫描是顺序读 + 少量回头）。

    不信任的两处（都有实证兜底，不猜）：
      · 块表项里的偏移是「段内绝对偏移」，理论上无需基准；但真出现对不上的镜像时，
        依次试「绝对」和「相对本段数据段起点」，**拿第一块真解一遍**，解得开才算；
      · 块大小以设备信息（每扇区字节数）/ 案件信息（每块扇区数）为准，读不到时
        才从第一块反推（未压缩块 = 长度 - 4 字节校验和；压缩块 = 解出来的长度）。
    """

    kind = "ex01"
    label = "Ex01 取证镜像"

    def __init__(self, path):
        self._path = path
        self._segs = []
        self._comp = []            # 每段的压缩方法（0 不压 / 1 deflate / 2 bzip2）
        self._tables = []          # [(起始块号, 块数, 段下标, 基准偏移, 条目列表)]
        self._firsts = []          # 每张表的起始块号，给 bisect 用
        self._chunk_n = 0
        self._chunk_size = 0
        self._sectors = 0
        self._bps = 0
        self._chunk_n_want = 0
        self._bad = 0
        self._tl = threading.local()
        self.note = ""
        self.encrypted = False
        paths = _ex01_segments(path)
        if not paths:
            raise VDiskError("这不是 Ex01 镜像（文件头标记对不上）")
        for p in paths:
            self._segs.append(_Handles(p))
        try:
            self._load()
        except Exception:
            self.close()
            raise
        if self.encrypted:
            self.close()
            raise VDiskError(_EX01_ENCRYPTED_HINT)
        if not self._chunk_size or not self.size:
            self.close()
            raise VDiskError("这份 Ex01 读不出「块大小 / 盘有多大」，"
                             "文件可能被截断、分卷不齐，或者块表坏了")

    # ── 打开时的解析 ──────────────────────────────────────────────

    def _headers(self):
        """读每段的文件头：压缩方法 + 是否声明了加密。"""
        for h in self._segs:
            head = h.pread(0, _EX01_HDR)
            if len(head) < _EX01_HDR:
                self._comp.append(_EX01_COMP_DEFLATE)
                continue
            self._comp.append(_u16(head, 10))
            # 段文件头的第 2 位没有公开的「加密」标志，加密只体现在加密密钥段上，
            # 所以这儿不做判断，留给 _load() 里看有没有 0x0b 段。

    def _load(self):
        self._headers()
        dev = {}
        case = {}
        tables = []            # [(段下标, 表格子, 段数据起点)]
        for si, h in enumerate(self._segs):
            try:
                total = os.path.getsize(h.path)
            except OSError:
                continue
            if total < _EX01_HDR + _EX01_DESC:
                continue
            sect_start = 0
            for sec in _ex01_sections(h, total):
                typ = sec["type"]
                if typ == _EX01_TYPE_DEVICE_INFO and not dev:
                    dev = _object_values(h.pread(sec["start"], min(sec["end"] - sec["start"], 1 << 16)))
                elif typ == _EX01_TYPE_CASE_DATA and not case:
                    case = _object_values(h.pread(sec["start"], min(sec["end"] - sec["start"], 1 << 16)))
                elif typ == _EX01_TYPE_SECTOR_DATA:
                    sect_start = sec["start"]
                elif typ == _EX01_TYPE_SECTOR_TABLE:
                    tables.append((si, sec, sect_start))
                elif typ == _EX01_TYPE_ENCRYPTION:
                    self.encrypted = True
        self._from_values(dev, case)
        for si, sec, sect_start in tables:
            self._add_table(si, sec, sect_start)
        if not self._chunk_size:
            self._guess_chunk_size(tables)
        if not self._chunk_n:
            raise VDiskError("这份 Ex01 里一块数据都没找到 —— 文件可能被截断，"
                             "也可能分卷不齐（只给了一部分 .Ex01/.Ex02…），或者块表坏了")
        want = self._sectors * self._bps if (self._sectors and self._bps) else 0
        total = self._chunk_n * self._chunk_size
        self.size = min(want, total) if want else total
        miss = self._chunk_n_want - self._chunk_n
        if miss > 0:
            self.note = (f"块表里只有 {self._chunk_n} 块，镜像自称 {self._chunk_n_want} 块"
                         f"（少 {miss} 块，分卷可能不齐），缺的部分按 0 读")
        elif want and total < want:
            self.note = (f"数据比镜像自称的少 {want - total} 字节，缺的部分按 0 读")
        elif len(self._segs) > 1:
            self.label = f"Ex01 取证镜像（{len(self._segs)} 个分卷）"

    def _from_values(self, dev, case):
        """从设备信息 / 案件信息里取容量和块大小。取不到就留空，后面再反推。"""
        bps = _as_int(dev.get("bp"))
        secs = _as_int(dev.get("ts"))
        spc = _as_int(case.get("sb"))
        nchunk = _as_int(case.get("tb"))
        if bps and 128 <= bps <= 1 << 16 and (bps & (bps - 1)) == 0:
            self._bps = bps
        if secs and 0 < secs < (1 << 48):
            self._sectors = secs
        if spc and self._bps and 0 < spc <= 1 << 20 and SECTOR <= spc * self._bps <= 64 << 20:
            self._chunk_size = spc * self._bps
        if nchunk and 0 < nchunk < (1 << 40):
            self._chunk_n_want = nchunk

    def _add_table(self, si, sec, sect_start):
        """读一张块表：20 字节头 + 12 字节补位 + 16 字节 × N 条目 + 16 字节尾。

        条目里 [0:8] 偏移、[8:12] 长度、[12:16] 标志。偏移按「段内绝对」解释；
        对不上就把本段数据段起点当基准再试一次，两次都拿**第一块真去解**来验。
        """
        h = self._segs[si]
        start = sec["start"]
        hdr = h.pread(start, 32)
        if len(hdr) < 32:
            return
        first_chunk = _u64(hdr, 0)
        n = _u32(hdr, 8)
        if not 0 < n < (1 << 24):
            return
        raw = h.pread(start + 32, n * 16)
        n = min(n, len(raw) // 16)
        if n <= 0:
            return
        entries = []
        for i in range(n):
            base = i * 16
            entries.append((_u64(raw, base), _u32(raw, base + 8), _u32(raw, base + 12)))
        limit = sec["desc"]                  # 本段数据不会跑到自己的描述符之后
        chosen = None
        for base in ([0, sect_start] if sect_start else [0]):
            if self._verify(h, entries, base, limit, self._comp[si]):
                chosen = base
                break
        if chosen is None:
            chosen = 0                       # 都不通也先收下，坏块会按 0 读并计数
        self._firsts.append(self._chunk_n)
        self._tables.append((self._chunk_n, n, si, chosen, entries))
        self._chunk_n += n

    def _verify(self, h, entries, base, limit, comp):
        """按这种解释读前几块：**真能解出来**才算解释对，解不出来就不算。

        两处刻意避开：
          · 填充块不参与判断 —— 它的偏移字段里装的是 8 字节图案（常常就是 0），
            拿去算位置会得到 offset=0、被判成「基准不对」，于是白白换错基准；
          · 未压缩且没有校验和的块也**不能**用来判断 —— 随便一段字节它都「成功」，
            等于没验。只认「压缩解得开」和「Adler-32 对得上」这两件强证据。
        """
        strong = 0
        for off, size, flags in entries[:8]:
            if flags & _FLAG_PATTERN and flags & _FLAG_COMPRESSED:
                continue
            if size <= 0 or size > (64 << 20):
                return False
            pos = base + off
            if not (0 < pos < limit):
                return False
            data, ok = self._decode(h.pread(pos, size), size, flags, comp, strict=True)
            if ok and data:
                strong += 1
        return strong > 0

    def _guess_chunk_size(self, tables):
        """设备/案件信息都读不到时，从第一块反推块大小。"""
        for si, sec, _ss in tables:
            h = self._segs[si]
            hdr = h.pread(sec["start"], 32)
            n = _u32(hdr, 8) if len(hdr) >= 12 else 0
            if not 0 < n:
                continue
            raw = h.pread(sec["start"] + 32, 16)
            if len(raw) < 16:
                continue
            off, size, flags = _u64(raw, 0), _u32(raw, 8), _u32(raw, 12)
            if flags & _FLAG_PATTERN:
                continue
            data, ok = self._decode(h.pread(off, size), size, flags, self._comp[si])
            if ok and data:
                self._chunk_size = len(data)
                self._bps = SECTOR
                return

    # ── 按块取数据 ────────────────────────────────────────────────

    def _decode(self, raw, size, flags, comp, strict=False):
        """一块的原始字节 → (数据, 是否可信)。

        四种情况（全按规范，不按「看起来像」猜）：
          · 压缩 + 填充：读盘无意义，偏移字段就是 8 字节填充图案，重复铺满；
          · 压缩：deflate 或 bzip2，解出来的长度必须 ≤ 块大小；
          · 未压缩 + 校验和：末尾 4 字节是 Adler-32，对得上才认；
          · 未压缩：原样。
        解不开 / 校验不过 → 返回 (None, False)，由调用方按 0 读，绝不编内容。
        """
        if not raw:
            return None, False
        if flags & _FLAG_COMPRESSED:
            try:
                if comp == _EX01_COMP_BZIP2:
                    d = bz2.BZ2Decompressor().decompress(raw, max_length=self._chunk_size + 1)
                else:
                    d = zlib.decompressobj().decompress(raw, self._chunk_size + 1)
            except (zlib.error, OSError, ValueError):
                return None, False
            if not d:
                return None, False
            if self._chunk_size and len(d) > self._chunk_size:
                return None, False
            return d, True
        if flags & _FLAG_CHECKSUMED and len(raw) >= 4:
            body = raw[:len(raw) - 4]
            if (_adler(body) & 0xFFFFFFFF) == _u32(raw, len(raw) - 4):
                return body, True
            return None, False                     # 校验和对不上 = 这块不可信，按 0 读
        if strict:
            # 判断「基准对不对」时，没有校验和的块等于没有证据，不能算通过
            return None, False
        return raw, True

    def _load_index(self, idx):
        i = _bsearch(self._firsts, idx)
        if i < 0:
            return None
        first, n, si, base, entries = self._tables[i]
        j = idx - first
        if not 0 <= j < n:
            return None
        off, size, flags = entries[j]
        if flags & _FLAG_PATTERN and flags & _FLAG_COMPRESSED:
            # 填充块：偏移字段里装的是 8 字节图案（按小端原样），重复铺满一块
            pat = struct.pack("<Q", off)
            return (pat * (self._chunk_size // 8 + 1))[:self._chunk_size]
        data, ok = self._decode(self._segs[si].pread(base + off, size), size,
                               flags, self._comp[si])
        if not ok:
            self._bad += 1
        return data

    def _chunk_at(self, idx):
        local = self._tl
        cache = getattr(local, "cache", None)
        if cache is None:
            cache = local.cache = {}
        data = cache.get(idx)
        if data is None and idx not in cache:
            data = self._load_index(idx)
            if len(cache) >= 8:
                cache.pop(next(iter(cache)))
            cache[idx] = data
        return data

    # ── 对外 ──────────────────────────────────────────────────────

    def read(self, off, n):
        if off < 0 or off >= self.size or n <= 0:
            return b""
        n = min(n, self.size - off)
        cs = self._chunk_size
        out = bytearray()
        pos = off
        left = n
        while left > 0:
            idx = pos // cs
            inner = pos % cs
            take = min(left, cs - inner)
            data = self._chunk_at(idx)
            if data and len(data) >= inner + take:
                out += data[inner:inner + take]
            elif data:
                piece = data[inner:inner + take]
                out += piece + bytes(take - len(piece))
            else:                              # 坏块 / 缺块：按 0 读，不编内容
                out += bytes(take)
            pos += take
            left -= take
        return bytes(out)

    def close(self):
        for h in self._segs:
            h.close()
        self._segs = []
        self._tables = []
        self._tl = threading.local()


def _as_int(text):
    """把序列化对象字符串里的数值读成 int。空值 / 带引号 / 带单位的都容错。"""
    if not text:
        return 0
    buf = []
    for ch in str(text):
        if ch.isdigit():
            buf.append(ch)
        elif ch in "+-" and not buf:
            continue
        elif buf:
            break
    try:
        return int("".join(buf)) if buf else 0
    except ValueError:
        return 0



# ───────────────────────── 识别 + 打开 ─────────────────────────


def probe(path):
    """看一眼这是什么格式，返回 (kind, label)。不打开、不解析。

    kind 为 `raw` 表示「就是一段扁平字节流」（dd 镜像、任意数据）。
    已知但**不支持**的格式也会如实返回（lx01 / l01 / qcow2-crypt / vhd-differencing），
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
    if head.startswith(_EWF_SIG):
        return "e01", "E01 取证镜像"
    if head.startswith(_EWF_L01_SIG):
        return "l01", "L01 逻辑取证文件"
    if head.startswith(_EWF2_SIG):
        return "ex01", "Ex01 取证镜像"
    if head.startswith(_EX01_LX_SIG):
        return "lx01", "Lx01 逻辑取证文件"
    if head[:4] == _QCOW_SIG:
        if _u32be(head, 32):
            return "qcow2-crypt", "QCOW2 镜像（加密）"
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


def source_size(path):
    """这份镜像在磁盘上占多少字节。

    E01 是多分卷，只看用户点的那一段会少算（实测 8 段各 2MB，界面显示「0 MB」）。
    QCOW2 差分盘同理：只算最上面一层会少算底层的量。这里把这套文件全加起来；
    其它格式就是文件本身的大小。
    """
    try:
        kind, _label = probe(path)
        if kind in ("e01", "ex01"):
            total = 0
            finder = _ewf_segments if kind == "e01" else _ex01_segments
            for p in finder(path):
                try:
                    total += os.path.getsize(p)
                except OSError:
                    pass
            if total:
                return total
        if kind in ("qcow2", "qcow2-crypt"):
            total = 0
            seen = set()
            cur = os.path.abspath(path)
            while cur and cur not in seen:
                seen.add(cur)
                try:
                    total += os.path.getsize(cur)
                except OSError:
                    break
                cur = _qcow2_backing(cur)
            if total:
                return total
        return os.path.getsize(path)
    except OSError:
        return 0


def open_path(path, _seen=None):
    """打开一份镜像，返回能按字节读的盘对象。

    普通镜像（dd / 裸数据）也会返回对象 —— 调用方不用区分「虚拟盘」和「文件」。
    已知但不支持的格式抛 `VDiskError`，消息里带转换办法。
    `_seen` 是内部用的：QCOW2 差分链要防环，别在调用方传。
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
        return _EwfDisk(path)
    if kind == "ex01":
        return _Ex01Disk(path)
    if kind == "lx01":
        raise VDiskError(_EX01_LX01_HINT)
    if kind == "l01":
        raise VDiskError(_L01_HINT)
    if kind == "qcow2":
        return _Qcow2Disk(path, _seen)
    if kind == "qcow2-crypt":
        raise VDiskError(_QCOW_CRYPT_HINT)
    if kind == "vhd-diff":
        raise VDiskError(_VHD_DIFF_HINT)
    if kind in ("vhd-fixed", "vhd-dynamic"):
        return _VhdDisk(path)
    return _FlatDisk(path)
