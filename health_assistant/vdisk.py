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

  · E01（EWF 取证格式，EnCase 1~7 / FTK Imager / linen 都产出这种）

不支持的（识别出来就给明确指引，不假装是坏镜像）：
  · Ex01 / L01（EWF 第二版、逻辑取证文件）、QCOW2、差分盘、压缩 VMDK

全程只读。所有多字节字段：VHD 是**大端**，VHDX / VMDK / E01 是**小端**。
"""
from __future__ import annotations

import array
import os
import re
import struct
import sys
import threading
import zlib

SECTOR = 512

# ───────────────────────── 用户能看懂的错误 ─────────────────────────

_E01_HINT = (
    "这是一份 **E01 取证镜像**（EWF 格式，专业取证/实验室交付常用），"
    "不是普通的整盘镜像。\n\n"
    "这个版本暂时读不了这个文件：**E01 第二版（.Ex01）** 是 EnCase 7 之后的新格式，"
    "文件结构跟老 E01 不一样。\n\n"
    "可以这样转成裸镜像后再打开：\n"
    "· FTK Imager（免费）：打开这个 Ex01，用「Export Disk Image」导出 raw；\n"
    "· 命令行 ewfexport（libewf）：`ewfexport -f raw -t out image.Ex01`；\n"
    "· 转出来的 .raw/.dd/.img 直接在这里打开就行。")

_L01_HINT = (
    "这是一个 **逻辑取证文件（.L01）**，不是磁盘镜像。\n\n"
    "L01 里存的是取证时**挑出来的那些文件**（连同目录结构和元数据），"
    "没有分区表、没有文件系统、也没有空闲空间 —— 所以按盘恢复的那套办法"
    "（找删除记录、按内容扫描）在这里没有意义。\n\n"
    "要看里面的文件，用 FTK Imager 或 EnCase 直接打开这个 L01 就行；"
    "如果你要恢复的是那块盘上被删的东西，需要那块盘的 E01/raw 整盘镜像。")

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


# ───────────────────────── E01 / EWF（取证格式）─────────────────────────

_EWF_SIG = b"EVF\x09\x0d\x0a\xff\x00"          # E01 / S01 的段文件头
_EWF2_SIG = b"EVF2\r\n\x81\x00"                # Ex01（EWF 第二版）
_EWF_L01_SIG = b"LVF\x09\x0d\x0a\xff\x00"      # L01 逻辑取证文件
_EWF_EXT_RE = re.compile(r"^\.(?:e|ex|l|s)(?:[0-9]{2}|[a-z]{2})$", re.I)

_SEC_DESC = 76          # section 描述符长度，所有 section 都一样
_SEC_PAD = 72           # 校验和覆盖描述符前 72 字节（Adler-32）


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


# ───────────────────────── 识别 + 打开 ─────────────────────────

_QCOW_SIG = b"QFI\xfb"


def probe(path):
    """看一眼这是什么格式，返回 (kind, label)。不打开、不解析。

    kind 为 `raw` 表示「就是一段扁平字节流」（dd 镜像、任意数据）。
    已知但**不支持**的格式也会如实返回（ex01 / l01 / qcow2 / vhd-differencing），
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
        return "ex01", "E01 第二版（Ex01）"
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
        return _EwfDisk(path)
    if kind == "ex01":
        raise VDiskError(_E01_HINT)
    if kind == "l01":
        raise VDiskError(_L01_HINT)
    if kind == "qcow2":
        raise VDiskError(_QCOW_HINT)
    if kind == "vhd-diff":
        raise VDiskError(_VHD_DIFF_HINT)
    if kind in ("vhd-fixed", "vhd-dynamic"):
        return _VhdDisk(path)
    return _FlatDisk(path)
