r"""health_assistant.carving — 按内容找文件（file carving），不依赖任何文件系统

## 为什么要单独一个模块

以前「按类型找」只有 5 种签名（jpg/png/pdf/zip/mp4）、每块只在 4MB 窗口里找文件尾、
默认只扫前 512MB、最多写 120 个文件。拿一张真实脏盘量：**27 个格式各异的真文件只捞回 4 个**，
另外还写出 11 个「切了一半」的残片 —— 用户拿到打不开的文件，比什么也不给更糟。

这份实现按市面工具（PhotoRec / Disk Drill / R-Studio）的做法重写了三件事：

1. **认得出多少种**：23 类签名覆盖 30 多种常见扩展名（照片/文档/表格/幻灯片/压缩包/
   视频/音频/数据库/可执行文件/PSD/RTF…），并且**按结构走完整个文件**，
   不是「看到文件头就算找到」。
2. **能跨读块**：文件尾在 4MB 之外也照走（MP4 的 box 链、ZIP 的 EOCD、PDF 的 %%EOF）。
   大文件不再被切一半。
3. **结构校验**：PNG 走 chunk 链、ZIP 校验中央目录偏移、7z 校验 StartHeader 的 CRC、
   CFB 走 FAT 表、EXE 走节表、TIFF 走 IFD 和 strip 表 …… 签名之后必须**结构自洽**
   才认，随机数据里「碰巧有几个字节像 jpg」的垃圾因此进不来。

## 碎片（4.19.0 起的做法，边界写清楚）

文件在盘上被拆成几段时，能做什么完全取决于**这种格式有没有断点标记**：

* **MP4 / MOV**：`mdat` 的体积写在 box 头里，「moov 该在哪」算得出来；moov 被推后
  了就去后面把它找回来，中间缺的那段**按 0 补**（不能跳过 —— stco 记的是绝对偏移，
  挤掉缺口会让索引表全部错位）。结果标 `fragment`：能播，缺的那几个簇是花的。
* **ZIP / Office**：目录区（EOCD，就 22 字节）被覆盖时不再整包丢弃，按本地文件头
  逐条走、把内容照样交出来（标 weak）。
* **JPEG**：熵编码区没有长度字段，**中间断掉就数学上无法接回去**。这里能做的只有
  「识别出来别谎报」：熵数据里出现连续 2KB 可打印文本 = 那里是别人的文件（真实
  熵数据出现这种排列的概率 ≈ 0），切在缺口之前、补 EOI 交出上半截，标 `fragment`。
  以前这种情况会一路穿过缺口找到原图后半段的 FFD9，切出「长度正确、中间塞着别人
  文件内容」的东西还报 ok。
* **PNG / 压缩流（zlib、deflate、7z、rar）**：断在中间就解不出来，拼不回来。

## 边界（如实说，不装）

* 只认内容，**原文件名和目录找不回来**；每个结果都带 `verdict`
  （ok / weak / fragment），界面要能说清。
* 不认加密内容（BitLocker / EFS）和清零区（TRIM 已落地）：读出来全是 0，找不到签名。
* 扫描全程只读。
"""

from __future__ import annotations

import hashlib
import os
import struct
import time
import zlib

__all__ = ["carve", "KIND_IDS", "KIND_LABEL", "KIND_GROUPS", "GROUPS"]

MIB = 1 << 20
_READ_CHUNK = 8 << 20          # 顺序扫描的读块；越大越省系统调用，8MB 实测最稳
_MAX_CANDIDATES = 4 << 20      # 单块里最多认多少个候选（防病态数据把内存撑爆）
_UNKNOWN = 0xFFFFFFFFFFFFFFFF


# ───────────────────────────── 读取器 ─────────────────────────────
class _Ctx:
    """给解析器的只读视图：按绝对偏移取字节，带一个「当前窗口」缓存。

    为什么要有窗口缓存：扫描时手里已经有这一块的 8MB 字节，解析器要文件头的
    那几十个字节如果还去发一次系统调用，随机数据里成千上万个假候选会把扫描拖垮。
    """

    def __init__(self, read, end, win_base=0, win=b""):
        self._read = read
        self.end = end
        self.base = win_base
        self._win = win

    def set_window(self, base, buf):
        self.base = base
        self._win = buf

    def get(self, off, n):
        if off < 0 or n <= 0 or off >= self.end:
            return b""
        n = min(n, self.end - off)
        rel = off - self.base
        if 0 <= rel and rel + n <= len(self._win):
            return self._win[rel:rel + n]
        return self._read(off, n)

    def byte(self, off):
        b = self.get(off, 1)
        return b[0] if b else -1

    def u16(self, off, bo="<"):
        b = self.get(off, 2)
        return struct.unpack(bo + "H", b)[0] if len(b) == 2 else -1

    def u32(self, off, bo="<"):
        b = self.get(off, 4)
        return struct.unpack(bo + "I", b)[0] if len(b) == 4 else -1

    def u64(self, off, bo="<"):
        b = self.get(off, 8)
        return struct.unpack(bo + "Q", b)[0] if len(b) == 8 else -1


def _find_forward(ctx, needle, off, cap, chunk=1 << 20):
    """在 [off, cap) 里找 needle，跨块读；找不到返回 -1。"""
    n = len(needle)
    pos = off
    while pos < cap:
        buf = ctx.get(pos, min(chunk + n, cap - pos))
        if not buf:
            return -1
        i = buf.find(needle)
        if i >= 0:
            return pos + i
        if len(buf) < chunk:
            return -1
        pos += len(buf) - (n - 1)
    return -1


_TEXT_BYTES = bytes(range(0x20, 0x7F)) + b"\t\n\r"


def _is_text_block(raw):
    """这一段是不是纯文本（可打印 ASCII + 制表/换行/回车）。

    为什么需要：文件碎片化时，中间那几簇是别人的数据。JPEG 的熵编码区没有长度
    字段，扫描会**一路穿过缺口**，遇到原图后半段的 FFD9 就收工 —— 于是切出一个
    「长度正确、中间塞着别人文件内容」的东西，还报「完整」。

    真实 JPEG 熵数据里连着 2048 字节全是可打印 ASCII 的概率 ≈ (0.4)^2048 ≈ 0
    （Huffman 编码的字节分布接近均匀，还大量夹着 0x00-0x1F）。反过来说，文本
    文件被当成缺口填充时几乎 100% 命中。

    **不能**改用「无 FF 段太长」当判据：实测一条纯色 JPEG 里最长的无 FF 段有
    67KB，那样会把正常照片判成碎片。
    """
    if not raw:
        return False
    return not raw.translate(None, _TEXT_BYTES)      # 删掉全部文本字符后为空


def _text_start(ctx, end, floor, limit=1 << 16):
    """从 `end` 往回走，找到这段文本真正的起点（最多回退 limit 字节）。"""
    pos = end
    stop = max(floor, end - limit)
    while pos > stop:
        b = ctx.byte(pos - 1)
        if b < 0 or (b not in (0x09, 0x0A, 0x0D) and not (0x20 <= b <= 0x7E)):
            break
        pos -= 1
    return pos


def _find_text(ctx, lo, hi, window=1024, limit=1 << 17):
    """在 [lo, hi) 这段「无 FF」区里从后往前找一个**整块都是文本**的窗口。

    返回这段外来的文本的起点（切图就切在这儿），没有就返回 None。

    为什么不能只看「紧挨着 FF 之前的那 2048 字节」：原图的后半段往往在缺口的
    后面几百个字节内就出现 FF，那 2048 字节里既有文本又有图像数据，判不出来
    —— 实测就是这么漏过去的。
    """
    end = hi
    stop = max(lo, hi - limit)
    while end - window >= stop:
        if _is_text_block(ctx.get(end - window, window)):
            return _text_start(ctx, end - window, lo)
        end -= window
    return None


def _scan_entropy(ctx, pos, cap):
    """走 JPEG 熵编码区，返回 (位置, 结局)。

    结局：'eoi'（正常结束）/ 'marker'（下一个标记段，渐进式 JPEG 每段扫描都这样）/
    'bad'（这里已经不是这张图的数据）/ 'foreign'（这里塞着别的文件的内容）/
    'end'（走到头，文件被截断）。

    JPEG 熵编码里 0xFF 只能后跟：00（字节填充）、D0-D7（RST 重启标记）、
    D9（结束），或者 0xC0-0xFE（新标记段）。出现别的组合就说明数据到这儿为止了。
    """
    run = pos                               # 这一轮「无 FF」段的起点
    while pos + 2 <= cap:
        buf = ctx.get(pos, min(1 << 16, cap - pos))
        if not buf:
            return pos, "end"
        i = buf.find(b"\xff")
        if i < 0:
            pos += max(1, len(buf) - 1)     # 留 1 字节，别把跨块的 FF 漏掉
            continue
        if i + 1 >= len(buf):
            pos += i                        # 下一轮从 FF 开始读
            continue
        if pos + i - run >= 2048:
            cut = _find_text(ctx, run, pos + i)
            if cut is not None:
                return cut, "foreign"
        m = buf[i + 1]
        if m == 0x00 or 0xD0 <= m <= 0xD7:
            pos += i + 2
            run = pos
            continue
        if m == 0xD9:
            return pos + i, "eoi"
        if 0xC0 <= m <= 0xFE:
            return pos + i, "marker"        # 下一个标记段 / 下一张图
        return pos + i, "bad"               # FF 后面跟了个不可能的字节
    if cap - run >= 2048:
        cut = _find_text(ctx, run, cap)
        if cut is not None:
            return cut, "foreign"
    return pos, "end"


def _u32be(buf, off):
    return struct.unpack_from(">I", buf, off)[0]


def _u32le(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


# ───────────────────────────── 各类型的解析器 ─────────────────────────────
# 统一契约：p_xxx(ctx, start, cap) -> None（不是这个格式）
#                             或 (长度, "ok"/"weak")
#                             或 (长度, verdict, 扩展名)   # 同一种容器分出子类型
#
# "ok"   = 结构完整走到文件尾（有明确的结束标记/表项）
# "weak" = 只能走到「结构不再自洽」为止（这类文件本来就没有结束标记）

def p_jpeg(ctx, start, cap):
    """JPEG：段链 + 熵编码区，走到 EOI(FFD9) 收尾。

    三道防线，缺一个就会出错：

    1. **必须见过 SOF（帧头）和 SOS（扫描开始）**。只靠「能走到 FFD9」的话，
       随机数据里的 FF D8 FF 加上一串碰巧连连看的段长，也能拼出几 MB 的假照片。
    2. **段长必须和组件数对得上**（SOFn = 8+3×Nf，SOS = 6+2×Ns）。这条是防
       假阳性的主力：实测用 `(i*37)&0xFF` 这种周期数据填充时，不做这条校验
       能从 12MB 里抠出 10 张「照片」，全都打不开。
    3. **熵编码区必须自洽**：0xFF 后面只能跟 00 / D0-D7 / 新标记。
       走到头还没 EOI 就是被截断 —— 这时**不丢**，补个 EOI 交出去（见下）。
    """
    # 先看一眼 SOI 后面是不是合法的段标记（FF C0..FF FE）
    nxt = ctx.byte(start + 3)
    if nxt < 0 or not (0xC0 <= nxt <= 0xFE):
        return None
    pos = start + 2
    saw_sof = saw_sos = False
    while pos + 2 <= cap:
        if ctx.byte(pos) != 0xFF:
            return None                     # SOS 之前不该出现非标记字节
        m = ctx.byte(pos + 1)
        if m < 0:
            return None
        if m == 0xFF:
            pos += 1
            continue
        if m == 0x00 or 0xD0 <= m <= 0xD7:
            pos += 2
            continue
        if m == 0xD9:                       # 还没 SOS 就到 EOI → 不是完整文件
            if not (saw_sof and saw_sos):
                return None
            n = pos + 2 - start
            return (n, "ok") if n >= 128 else None
        if m in (0x01, 0xD8):
            pos += 2
            continue
        ln = ctx.u16(pos + 2, ">")
        if ln < 2 or pos + 2 + ln > cap:
            return None
        head2 = ctx.get(pos + 4, 2)
        if len(head2) < 2:
            return None
        if m == 0xDA:                       # SOS：段长 6 + 2×分量数
            if ln != 6 + 2 * head2[0]:
                return None
            saw_sos = True
        elif 0xC0 <= m <= 0xCF and m not in (0xC4, 0xC8, 0xCC):
            # SOF 负载是「精度(1) 高(2) 宽(2) Nf(1) 分量×3」，Nf 在第 6 个字节。
            # 别顺手用 head2[1] —— 那是高度高字节，读完得到的 Nf 永远是 0 或离谱值，
            # 段长校验必然过不去（真照片全被判「不是 jpeg」）。
            sof = ctx.get(pos + 4, 6)
            if len(sof) < 6:
                return None
            nf = sof[5]
            if not (1 <= nf <= 4) or ln != 8 + 3 * nf:   # SOF 段长 = 8 + 3×Nf
                return None
            saw_sof = True
        pos += 2 + ln
        if not saw_sof and pos - start > (4 << 20):
            return None                     # 头部超过 4MB 还没帧头 → 假货
        if m != 0xDA:
            continue
        # 进了熵编码区：一直走到「结束」或「下一个标记段」（渐进式 JPEG 有多段扫描）
        end, kind = _scan_entropy(ctx, pos, cap)
        if kind == "eoi":
            n = end + 2 - start
            return (n, "ok") if n >= 128 else None
        if kind == "marker":
            pos = end
            continue
        # 'bad'（数据不自洽）/ 'end'（走到头）/ 'foreign'（中间塞着别的文件）：
        # 这张图被截断或碎片化了。以前这里 return None —— 整张照片直接没了，
        # 用户眼里就是「工具什么都没找到」。上半截能看的照片远比「零件」有用：
        # 按自洽范围切出来，补上 EOI 交出去。
        if saw_sof and saw_sos and (end - start) >= 4096:
            verdict = "fragment" if kind == "foreign" else "weak"
            return (end - start, verdict, None, b"\xff\xd9")
        return None
    return None


_PNG_IEND = b"\x00\x00\x00\x00IEND\xaeB`\x82"      # 长度 0 + "IEND" + 固定 CRC


def p_png(ctx, start, cap):
    """PNG：chunk 链；第一块必须是 IHDR，走到 IEND 结束。"""
    pos = start + 8
    first = True
    last_good = 0
    while pos + 12 <= cap:
        head = ctx.get(pos, 8)
        if len(head) < 8:
            break
        ln = _u32be(head, 0)
        typ = head[4:8]
        if ln > 0x7FFFFFFF:
            break
        nxt = pos + 12 + ln
        if nxt > cap:
            break                           # 头里写了 ln 字节，后面没有了 → 截断
        if first:
            if typ != b"IHDR":
                return None
            ihdr = ctx.get(pos + 8, 13)
            if len(ihdr) < 13 or _u32be(ihdr, 0) == 0 or _u32be(ihdr, 4) == 0:
                return None
            first = False
        last_good = nxt
        if typ == b"IEND":
            return (nxt - start, "ok")
        pos = nxt
    # 链断了（碎片化 / 尾部被覆盖）。有 IHDR + 至少一个完整数据块的话，
    # 这张图的上半截还能显示，补个 IEND 就能打开 —— 丢掉才是最差的选择。
    if not first and last_good and (last_good - start) >= 1024:
        # 只有「IDAT 的压缩流是完整的、单纯缺尾块」时补 IEND 才有意义（补上就能打开）。
        # 数据本身被截断的话，补 IEND 只是假装完整，照样打不开 —— 那种就只标 weak，
        # 交给专门的修复工具（或者用户自己认领上半截）。
        if _png_idat_complete(ctx, start, last_good):
            return (last_good - start, "weak", None, _PNG_IEND)
        return (last_good - start, "weak")
    return None


def _png_idat_complete(ctx, start, end):
    """PNG 的像素数据（IDAT）能不能完整解压出来。"""
    pos = start + 8
    dec = zlib.decompressobj()
    seen = False
    try:
        while pos + 12 <= end:
            head = ctx.get(pos, 8)
            if len(head) < 8:
                return False
            ln = _u32be(head, 0)
            typ = head[4:8]
            nxt = pos + 12 + ln
            if nxt > end:
                return False
            if typ == b"IDAT":
                seen = True
                left = ln
                p = pos + 8
                while left > 0:
                    buf = ctx.get(p, min(left, 1 << 20))
                    if not buf:
                        return False
                    dec.decompress(buf)
                    p += len(buf)
                    left -= len(buf)
                if dec.eof:
                    return True
            elif typ == b"IEND":
                break
            pos = nxt
    except zlib.error:
        return False
    return bool(seen) and dec.eof


def p_gif(ctx, start, cap):
    head = ctx.get(start, 13)
    if len(head) < 13 or head[:6] not in (b"GIF87a", b"GIF89a"):
        return None
    flags = head[10]
    pos = start + 13
    if flags & 0x80:
        pos += 3 * (2 ** ((flags & 0x07) + 1))
    while pos < cap:
        tag = ctx.byte(pos)
        if tag < 0:
            return None
        if tag == 0x3B:
            return (pos + 1 - start, "ok")
        if tag == 0x21:                                  # 扩展块
            pos += 2
            while True:
                ln = ctx.byte(pos)
                if ln < 0:
                    return None
                pos += 1 + ln
                if ln == 0:
                    break
        elif tag == 0x2C:                                # 图像描述块
            desc = ctx.get(pos, 10)
            if len(desc) < 10:
                return None
            lf = desc[9]
            pos += 10
            if lf & 0x80:
                pos += 3 * (2 ** ((lf & 0x07) + 1))
            pos += 1                                     # LZW 最小码长
            while True:
                ln = ctx.byte(pos)
                if ln < 0:
                    return None
                pos += 1 + ln
                if ln == 0:
                    break
        else:
            return None
    return None


def p_bmp(ctx, start, cap):
    head = ctx.get(start, 30)
    if len(head) < 30 or head[6:8] != b"\x00\x00":
        return None
    size = _u32le(head, 2)
    pix = _u32le(head, 10)
    dib = _u32le(head, 14)
    if dib not in (12, 40, 52, 56, 64, 108, 124) or size < 26:
        return None
    if pix < 14 + dib or size < pix or start + size > cap:
        return None
    return (size, "ok")


_RIFf = {b"WAVE": ".wav", b"AVI ": ".avi", b"WEBP": ".webp"}


def p_riff(ctx, start, cap):
    head = ctx.get(start, 12)
    if len(head) < 12 or head[8:12] not in _RIFf:
        return None
    size = _u32le(head, 4)
    end = 8 + size + (size & 1)
    if size < 16 or start + end > cap:
        return None
    return (end, "ok", _RIFf[head[8:12]])


_TIFF_TYPE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}


def p_tiff(ctx, start, cap):
    """TIFF/CR2/NEF：走 IFD 链，按 strip 表算真实结尾（PIL 写的 TIFF 也能精确切出）。"""
    head = ctx.get(start, 8)
    if len(head) < 8 or head[:2] not in (b"II", b"MM"):
        return None
    bo = "<" if head[:2] == b"II" else ">"
    if ctx.u16(start + 2, bo) != 42:
        return None
    off = ctx.u32(start + 4, bo)
    maxend = 8
    strips = []
    seen = set()
    for _ in range(24):
        if off in seen or off < 8 or start + off + 2 > cap:
            break
        seen.add(off)
        cnt = ctx.u16(start + off, bo)
        if cnt <= 0 or cnt > 1024:
            break
        tag_off = tag_cnt = None
        for i in range(cnt):
            e = start + off + 2 + i * 12
            if e + 12 > cap:
                break
            tag = ctx.u16(e, bo)
            typ = ctx.u16(e + 2, bo)
            num = ctx.u32(e + 4, bo)
            size = num * _TIFF_TYPE.get(typ, 1)
            if size > 4:
                voff = ctx.u32(e + 8, bo)
                maxend = max(maxend, voff + size)
            if tag == 0x111:
                tag_off = (typ, num, e + 8)
            elif tag == 0x117:
                tag_cnt = (typ, num, e + 8)
        if tag_off and tag_cnt:
            strips.append((tag_off, tag_cnt, bo))
        nxt = ctx.u32(start + off + 2 + cnt * 12, bo)
        if not nxt or nxt <= off:
            break
        off = nxt
    if maxend <= 8:
        return None
    for (ot, on, oo), (ct, cn, co), bo2 in strips:
        offs = _tiff_array(ctx, start, ot, on, oo, bo2)
        cnts = _tiff_array(ctx, start, ct, cn, co, bo2)
        for o, c in zip(offs, cnts):
            maxend = max(maxend, o + c)
    if start + maxend > cap:
        return None
    ext = ".cr2" if ctx.get(start + 8, 2) == b"CR" else ".tif"
    return (maxend, "ok", ext)


def _tiff_array(ctx, start, typ, num, field_off, bo):
    size = num * _TIFF_TYPE.get(typ, 1)
    base = field_off if size <= 4 else start + ctx.u32(field_off, bo)
    raw = ctx.get(base, size)
    if len(raw) < size or typ not in (3, 4):
        return []
    fmt = {3: "H", 4: "I"}[typ]
    step = struct.calcsize(fmt)
    return [struct.unpack_from(bo + fmt, raw, i * step)[0]
            for i in range(min(num, 65536))]


_MP4_EXT = {b"heic": ".heic", b"heix": ".heic", b"hevc": ".heic", b"mif1": ".heic",
            b"msf1": ".heic", b"avif": ".avif", b"qt  ": ".mov", b"3gp4": ".3gp",
            b"3gp5": ".3gp", b"M4A ": ".m4a", b"m4a ": ".m4a"}


_MOV_RESUME_WINDOW = 8 << 20        # moov 被切到后面时，最多往后找这么远


def _box_head(ctx, pos):
    """读一个 box 头 → (类型, 大小) 或 None。"""
    bh = ctx.get(pos, 16)
    if len(bh) < 8:
        return None
    size = _u32be(bh, 0)
    typ = bh[4:8]
    if size == 1:
        if len(bh) < 16:
            return None
        size = struct.unpack_from(">Q", bh, 8)[0]
    if size < 8 or not all(32 <= c < 127 for c in typ):
        return None
    return typ, size


def _mp4_resume(ctx, start, bpos, cap, ext):
    """moov 被切到后面去了 —— 找它，中间那一截按 0 补。

    **为什么「补零」而不是「跳过缺口把两截粘起来」**：`stco`/`co64` 里记的是
    从文件开头算的**绝对偏移**，一旦把中间的洞挤掉，索引表全部错位，文件直接
    打不开。补零保住偏移，视频只是那几个簇花屏。

    **为什么知道该补多长**：`mdat` 的体积写在 box 头里，「moov 逻辑上在哪」
    是算得出来的（就是 box 链断掉的位置 bpos）。物理上它被推后了多少，得靠找：
    在簇边界上找 `moov`（带 `mvhd`），找到就知道尾部从哪儿开始。

    断点往前对齐到簇边界再补零：文件系统的碎片一定是整簇整簇分开的，
    最后那个不满一簇的尾巴之外的部分，盘上已经是别的文件了，读出来也不能用。
    """
    if bpos <= start + 8:
        return None
    end = min(cap, bpos + _MOV_RESUME_WINDOW)
    pos = bpos
    while pos < end:
        buf = ctx.get(pos, min(1 << 20, end - pos))
        if not buf:
            return None
        i = buf.find(b"moov")
        while i >= 0:
            box = pos + i - 4
            if box >= bpos:                 # 只看断点之后的（前面是 mdat 自己的数据）
                got = _box_head(ctx, box)
                if got and got[0] == b"moov" and box + got[1] <= cap:
                    # 内容里必须有 mvhd（媒体头），否则只是碰巧四个字节像 moov。
                    # 注意**不能**要求 box 按簇对齐：mdat 的尾巴往往不满一簇，
                    # moov 因此会落在簇中间（实测就是这么漏的）。
                    if b"mvhd" in ctx.get(box + 8, 512):
                        gap_start = bpos - (bpos % 4096)
                        if gap_start < start:
                            gap_start = start
                        parts = [(start, gap_start - start)]
                        if bpos > gap_start:
                            parts.append((None, bpos - gap_start))
                        parts.append((box, got[1]))
                        return (parts, "fragment", ext)
            i = buf.find(b"moov", i + 1)
        pos += max(len(buf) - 3, 1)     # 留 3 字节防跨块漏掉；必须 ≥1 否则原地死循环
    return None


def p_mp4(ctx, start, cap):
    """MP4/MOV/HEIC：走 box 链（size+type），跨多少块都行。

    `moov` 在文件尾（没用 faststart 的相机/录屏文件全是这样）。这类文件一旦
    中间被别的文件占了几个簇，box 链就在 mdat 之后断掉 —— 以前直接 return None，
    一整段录像彻底找不到；现在去后面把 moov 捞回来、中间补零交出（见 `_mp4_resume`）。
    """
    head = ctx.get(start, 16)
    if len(head) < 12 or head[4:8] != b"ftyp":
        return None
    ext = _MP4_EXT.get(head[8:12], ".mp4")
    pos = start
    boxes = 0
    saw_moov = saw_mdat = False
    broke = False
    while pos + 8 <= cap and boxes < 8192:
        bh = ctx.get(pos, 16)
        if len(bh) < 8:
            broke = True
            break
        size = _u32be(bh, 0)
        typ = bh[4:8]
        if size == 1:
            if len(bh) < 16:
                broke = True
                break
            size = struct.unpack_from(">Q", bh, 8)[0]
        elif size == 0:
            broke = True                    # 到文件尾（或后面的填充），正常收尾
            break
        if size < 8 or not all(32 <= c < 127 for c in typ):
            broke = True
            break
        if pos + size > cap:
            if not boxes:
                return None                 # 第一个 box 就大到读不下 → 不是我们能处理的
            # 后面的 box 越过 cap：多半是链已经走进了别人的数据（碎片）。
            # 以前这里直接 return None，等于把整段录像扔了。
            broke = True
            break
        if typ == b"moov":
            saw_moov = True
        elif typ == b"mdat":
            saw_mdat = True
        pos += size
        boxes += 1
    if boxes < 1 or pos <= start + 8:
        return None
    if not broke:                           # box 链一路走到头，就是完整文件
        return (pos - start, "ok" if boxes >= 2 else "weak", ext)
    # 只有「真走过 ftyp + mdat、头部已经有好几十 KB」才值得去找 moov。
    # 不加这几道闸，脏盘上成千上万个碰巧像 box 的候选每个都去翻 8MB，扫描直接瘫掉
    # （实测 220MB 的镜像从 2.6 秒变成几分钟都跑不完）。
    if (not saw_moov) and saw_mdat and boxes >= 2 and (pos - start) >= (64 << 10):
        stitched = _mp4_resume(ctx, start, pos, cap, ext)
        if stitched:
            return stitched
    # 走完整 box 链、停在 box 边界上，本身就是证据（mdat 声明的体积已经满足了）。
    # 这里不能因为「没见到 moov」就降级：不少录屏/相机的 MP4 只有 ftyp + mdat，
    # 引擎按 max_len 之外去读当然读不到 moov，那不叫缺失。
    return (pos - start, "ok" if boxes >= 2 else "weak", ext)


def p_pdf(ctx, start, cap):
    # 便宜的前置校验：%PDF-1.x 之后必须是行尾/空白。否则随机数据里的「%PDF-」会把
    # 后面的 %%EOF 搜索一路拖到卷尾（实测这是扫描慢的主因之一）。
    ver = ctx.get(start + 5, 3)
    if len(ver) < 3 or not ver[0:1].isdigit() or ver[1:2] != b"." or not ver[2:3].isdigit():
        return None
    i = _find_forward(ctx, b"%%EOF", start + 8, cap)
    if i < 0:
        return None
    end = i + 5
    while end < cap and ctx.byte(end) in (0x0D, 0x0A):
        end += 1
    tail = ctx.get(max(start, i - 1024), i - max(start, i - 1024))
    return (end - start, "ok" if b"startxref" in tail else "weak")


def p_zip(ctx, start, cap):
    """ZIP / Office：找 EOCD 并校验「中央目录偏移 + 大小」落在文件内，再把子类型认出来。"""
    # 前置校验：本地文件头（PK\x03\x04）的字段得说得通，否则随机数据里的 4 字节签名
    # 会让 EOCD 搜索一路扫到卷尾。
    if ctx.get(start, 4) == b"PK\x03\x04":
        h = ctx.get(start + 4, 26)
        if len(h) < 26:
            return None
        method = struct.unpack_from("<H", h, 4)[0]
        nlen = struct.unpack_from("<H", h, 22)[0]
        elen = struct.unpack_from("<H", h, 24)[0]
        if method not in (0, 1, 6, 8, 9, 12, 14, 93, 95, 98, 99):
            return None
        if not (0 < nlen <= 1024) or elen > 4096:
            return None
        name = ctx.get(start + 30, nlen)
        if len(name) < nlen or any(c < 0x20 or c == 0x7F for c in name):
            return None
    pos = start + 4
    while True:
        i = _find_forward(ctx, b"PK\x05\x06", pos, cap, chunk=256 << 10)
        if i < 0:
            break
        tail = ctx.get(i, 22)
        if len(tail) < 22:
            break
        clen = struct.unpack_from("<H", tail, 20)[0]
        cd_size = _u32le(tail, 12)
        cd_off = _u32le(tail, 16)
        end = i + 22 + clen
        ok = cd_off == 0xFFFFFFFF or (cd_off + cd_size) <= (i - start) + 16
        if ok and end <= cap:
            return (end - start, "ok", _zip_ext(ctx, start, min(256 << 10, end - start)))
        pos = i + 4
    # 找不到完好的 EOCD：目录区（就 22 字节 + 变长的注释）是最容易被覆盖的部分。
    # 以前这里直接丢弃整包 —— 但压缩包的文件内容都自带本地头，7-Zip / WinRAR
    # 照样能按本地头把文件取出来。所以退一步交「内容还在、目录没了」的包。
    data_len = _zip_local_len(ctx, start, cap)
    if data_len:
        return (data_len, "weak", _zip_ext(ctx, start, min(256 << 10, data_len)))
    return None


def _zip_local_len(ctx, start, cap, limit=1 << 20):
    """只走本地文件头链，不依赖中央目录，返回数据区长度（认不出返回 0）。

    每个本地头自带 compressed size，所以链是能逐条推下去的；只有「数据描述符」
    模式（flags bit3，长度写在数据**后面**）拿不到长度，这时退化成往后找下一个
    本地头签名。整条链一旦不自洽就停，绝不硬猜长度 —— 猜长了会把后面别的文件
    也拼进来。
    """
    pos = start
    n = 0
    while n < 200000:
        sig = ctx.get(pos, 4)
        if sig == b"PK\x03\x04":
            h = ctx.get(pos + 4, 26)
            if len(h) < 26:
                break
            flags = struct.unpack_from("<H", h, 2)[0]
            method = struct.unpack_from("<H", h, 4)[0]
            csize = struct.unpack_from("<I", h, 14)[0]
            nlen = struct.unpack_from("<H", h, 22)[0]
            elen = struct.unpack_from("<H", h, 24)[0]
            if method not in (0, 1, 6, 8, 9, 12, 14, 93, 95, 98, 99):
                break
            if not (0 < nlen <= 1024) or elen > 4096:
                break
            body = pos + 30 + nlen + elen
            if body > cap:
                break
            if (flags & 0x08) and csize == 0:
                j = _find_forward(ctx, b"PK\x03\x04", body,
                                  min(cap, body + (1 << 20)))
                if j < 0:
                    pos = body
                    break
                pos = j
            else:
                if body + csize > cap:
                    break
                pos = body + csize
            n += 1
            continue
        break                       # 中央目录 / EOCD / 数据完了
    if n == 0:
        return 0
    return pos - start


def _zip_ext(ctx, start, span):
    head = ctx.get(start, span)
    if b"word/document.xml" in head:
        return ".docx"
    if b"xl/workbook.xml" in head:
        return ".xlsx"
    if b"ppt/presentation.xml" in head:
        return ".pptx"
    return ".zip"


def p_rar(ctx, start, cap):
    head = ctx.get(start, 8)
    if head[:7] == b"Rar!\x1a\x07\x00":
        pos = start + 7
        while pos + 7 <= cap:
            h = ctx.get(pos, 7)
            if len(h) < 7:
                return None
            typ = h[2]
            flags = struct.unpack_from("<H", h, 3)[0]
            size = struct.unpack_from("<H", h, 5)[0]
            if typ == 0x7B:
                return (pos + 7 - start, "ok", ".rar")
            if size < 7:
                return None
            pos += size
            if flags & 0x8000:
                pos += _u32le(ctx.get(pos, 4) or b"\x00\x00\x00\x00", 0)
        return None
    if head[:8] == b"Rar!\x1a\x07\x01\x00":
        pos = start + 8
        while pos + 5 <= cap:
            n, used = _rar5_vint(ctx, pos + 4)
            if n is None or n <= 0:
                return None
            end = pos + 4 + n
            if end > cap:
                return None
            if ctx.byte(pos + 4 + used) in (2, 3):       # HEAD_TYPE 2/3 = 结束块
                return (end - start, "ok", ".rar")
            pos = end
        return None
    return None


def _rar5_vint(ctx, off):
    b = ctx.get(off, 10)
    if not b:
        return None, 0
    mask = 0x80
    length = 1
    while length <= len(b) and not (b[0] & mask):
        mask >>= 1
        length += 1
    if length > len(b):
        return None, 0
    val = b[0] & (mask - 1)
    for i in range(1, length):
        val = (val << 8) | b[i]
    return val, length


def p_7z(ctx, start, cap):
    head = ctx.get(start, 32)
    if len(head) < 32 or head[:6] != b"7z\xbc\xaf\x27\x1c":
        return None
    if zlib.crc32(head[12:32]) & 0xFFFFFFFF != _u32le(head, 8):
        return None                                  # StartHeader 的 CRC 不对 → 假货
    next_off = struct.unpack_from("<Q", head, 12)[0]
    next_size = struct.unpack_from("<Q", head, 20)[0]
    end = 32 + next_off + next_size
    if next_size == 0 or end > cap or next_off > (64 << 20):
        return None
    return (end, "ok", ".7z")


def p_gzip(ctx, start, cap):
    head = ctx.get(start, 10)
    if len(head) < 10 or head[:3] != b"\x1f\x8b\x08":
        return None
    flags = head[3]
    pos = start + 10
    if flags & 0x04:                                  # FEXTRA
        ln = ctx.u16(pos, "<")
        if ln < 0:
            return None
        pos += 2 + ln
    for bit in (0x08, 0x10):                          # FNAME / FCOMMENT
        if flags & bit:
            while pos < cap and ctx.byte(pos) not in (0, -1):
                pos += 1
            pos += 1
    if flags & 0x02:                                  # FHCRC
        pos += 2
    body = pos                                  # deflate 流从这里开始
    obj = zlib.decompressobj(-15)
    out_total = 0
    while pos < cap:
        buf = ctx.get(pos, 1 << 20)
        if not buf:
            return None
        try:
            out_total += len(obj.decompress(buf))
        except zlib.error:
            return None
        pos += len(buf)
        if out_total > (2 << 30):
            return None
        if obj.eof:
            end = pos - len(obj.unused_data)
            # gzip 的尾部还有 8 字节（CRC32 + 原始长度），deflate 流结束时它们还没被吃掉
            if end + 8 <= cap:
                end += 8
            return (end - start, "ok", ".gz")
    return None


def p_tar(ctx, start, cap):
    pos = start
    files = 0
    while pos + 512 <= cap and files < 200000:
        head = ctx.get(pos, 512)
        if len(head) < 512:
            return None
        if head[:100].strip(b"\x00") == b"":
            if files:
                return (pos + 512 - start, "ok", ".tar")
            return None
        if head[257:262] != b"ustar":
            return None
        try:
            size = int(head[124:136].strip(b"\x00 ") or b"0", 8)
        except ValueError:
            return None
        pos += 512 + ((size + 511) // 512) * 512
        files += 1
    return None


def p_flv(ctx, start, cap):
    head = ctx.get(start, 13)
    if len(head) < 13 or head[:3] != b"FLV":
        return None
    pos = start + 13
    tags = 0
    while pos + 11 <= cap:
        h = ctx.get(pos, 11)
        if len(h) < 11 or h[0] not in (8, 9, 18):
            break
        size = (h[1] << 16) | (h[2] << 8) | h[3]
        pos += 11 + size + 4
        tags += 1
    if tags < 1 or pos > cap:
        return None
    return (pos - start, "ok", ".flv")


_MP3_BR = {                                  # (版本,层) → 码率表(kbps)
    (3, 1): (0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320),
    (3, 2): (0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384),
    (3, 3): (0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320),
    (2, 1): (0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256),
    (2, 2): (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160),
    (2, 3): (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160),
}
_MP3_SR = {3: (44100, 48000, 32000), 2: (22050, 24000, 16000), 0: (11025, 12000, 8000)}


def p_mp3(ctx, start, cap):
    """MP3：跳 ID3v2 头，然后按帧头连续校验（至少 3 帧同参数才算真）。"""
    pos = start
    head = ctx.get(start, 10)
    if head[:3] == b"ID3":
        size = 0
        for b in head[6:10]:
            if b & 0x80:
                return None
            size = (size << 7) | b
        pos = start + 10 + size + (10 if head[5] & 0x10 else 0)
    frames = 0
    first = None
    while pos + 4 <= cap and frames < 2_000_000:
        h = ctx.get(pos, 4)
        if len(h) < 4 or h[0] != 0xFF or (h[1] & 0xE0) != 0xE0:
            break
        ver = (h[1] >> 3) & 0x03
        layer = (h[1] >> 1) & 0x03
        br_i = (h[2] >> 4) & 0x0F
        sr_i = (h[2] >> 2) & 0x03
        pad = (h[2] >> 1) & 0x01
        if ver == 1 or layer == 0 or br_i in (0, 15) or sr_i == 3:
            break
        layer_no = 4 - layer
        table = _MP3_BR.get((ver, layer_no))
        if not table:
            break
        br = table[br_i] * 1000
        sr = _MP3_SR[ver][sr_i]
        if layer_no == 1:
            flen = (12 * br // sr + pad) * 4
        else:
            flen = (144 if ver == 3 else 72) * br // sr + pad
        if flen < 24 or pos + flen > cap:
            break
        key = (ver, layer_no, sr)
        if first is None:
            first = key
        elif key != first:
            break
        pos += flen
        frames += 1
    if frames < 3:
        return None
    return (pos - start, "ok" if frames >= 10 else "weak", ".mp3")


def p_ogg(ctx, start, cap):
    first = ctx.get(start, 5)
    if len(first) < 5 or first[:4] != b"OggS" or first[4] != 0:
        return None
    pos = start
    pages = 0
    while pos + 27 <= cap:
        head = ctx.get(pos, 27)
        if len(head) < 27 or head[:4] != b"OggS":
            break
        nseg = head[26]
        seg = ctx.get(pos + 27, nseg)
        if len(seg) < nseg:
            return None
        pos += 27 + nseg + sum(seg)
        pages += 1
    if pages < 1:
        return None
    return (pos - start, "ok", ".ogg")


def p_cfb(ctx, start, cap):
    """OLE 容器（doc/xls/ppt/msi）：走 FAT 表找最后一个扇区。"""
    head = ctx.get(start, 512)
    if len(head) < 512 or head[:8] != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return None
    ssz = 1 << struct.unpack_from("<H", head, 30)[0]
    if ssz not in (512, 4096):
        return None
    n_fat = _u32le(head, 44)
    if n_fat <= 0 or n_fat > 4096:
        return None
    first_difat = _u32le(head, 68)
    fat_secs = [_u32le(head, 76 + 4 * i) for i in range(109)]
    fat_secs = [s for s in fat_secs if s < 0xFFFFFFFA]
    sec = first_difat
    guard = 0
    while sec < 0xFFFFFFFA and guard < 1024:
        d = ctx.get(start + (sec + 1) * ssz, ssz)
        if len(d) < ssz:
            break
        for i in range(ssz // 4 - 1):
            v = _u32le(d, 4 * i)
            if v < 0xFFFFFFFA:
                fat_secs.append(v)
        sec = _u32le(d, ssz - 4)
        guard += 1
    fat_secs = fat_secs[:n_fat] or fat_secs
    # FAT 扇区自己不在任何 FAT 链里（由 DIFAT / 头部指向），只扫链上引用会少算开头那几 MB
    max_idx = max(fat_secs) if fat_secs else 0
    for s in fat_secs[:512]:
        fat = ctx.get(start + (s + 1) * ssz, ssz)
        if len(fat) < ssz:
            continue
        for i in range(0, ssz, 4):
            v = _u32le(fat, i)
            if v < 0xFFFFFFFA:
                max_idx = max(max_idx, v)
    # 扇区 N 的起点是 (N+1)*ssz（前面还有一个 512 字节头），所以结尾要再 +1 个扇区
    end = (max_idx + 2) * ssz
    if end < 512 or start + end > cap:
        return None
    return (end, "ok", _cfb_ext(ctx, start, end, ssz, _u32le(head, 48)))


_CFB_CLSID = {
    bytes.fromhex("84100c0000000000c000000000000046"): ".msi",   # Windows Installer
    bytes.fromhex("0609020000000000c000000000000046"): ".doc",   # Word.Document.8
    bytes.fromhex("2008020000000000c000000000000046"): ".xls",   # Excel.Sheet.8
    bytes.fromhex("108d81644f9b11cf86ea00aa00b929e8"): ".ppt",   # PowerPoint 97
}


def _cfb_ext(ctx, start, end, ssz, dir_start):
    """OLE 容器里认子类型。

    两条判据，先硬后软：
    1. **根目录项的 CLSID**（目录流第一个扇区 +0x50）—— MSI / Word / Excel / PPT 各有固定值，
       实测 5 个真 MSI 全是 `84100c00-…-46`，这条最准；
    2. 流名字（UTF-16）—— 名字常在文件**末尾**的目录里，所以头尾都要看。
       只查开头会把 MSI 认成 .doc（这一步踩过）。
    """
    if dir_start < 0xFFFFFFFA:
        root = ctx.get(start + (dir_start + 1) * ssz, 0x70)
        if len(root) >= 0x70:
            ext = _CFB_CLSID.get(root[0x50:0x60])
            if ext:
                return ext
    body = ctx.get(start, min(end, 4 << 20))
    tail_len = min(end, 96 << 10)
    body += ctx.get(start + end - tail_len, tail_len)
    for needle, ext in ((b"W\x00o\x00r\x00d\x00D\x00o\x00c\x00u\x00m\x00e\x00n\x00t", ".doc"),
                        (b"W\x00o\x00r\x00k\x00b\x00o\x00o\x00k", ".xls"),
                        (b"P\x00o\x00w\x00e\x00r\x00P\x00o\x00i\x00n\x00t", ".ppt"),
                        (b"!\x00_\x00S\x00t\x00r\x00i\x00n\x00g\x00D\x00a\x00t\x00a", ".msi")):
        if needle in body:
            return ext
    return ".doc"


def p_sqlite(ctx, start, cap):
    head = ctx.get(start, 100)
    if len(head) < 100 or head[:16] != b"SQLite format 3\x00":
        return None
    psize = struct.unpack_from(">H", head, 16)[0]
    if psize == 1:
        psize = 65536
    if psize < 512 or psize & (psize - 1):
        return None
    pages = struct.unpack_from(">I", head, 28)[0]
    if pages <= 0:
        return None
    end = psize * pages
    if start + end > cap:
        return None
    return (end, "ok", ".sqlite")


def p_exe(ctx, start, cap):
    """EXE/DLL：只认 PE 结构（节表定长度）。

    以前还有个「纯 DOS 老 exe 按页数算大小」的兜底 —— 实测那是假阳性的主要来源：
    8MB 随机噪声里就能捞出一个「5MB 的 exe」，还会把后面互不相干的数据整片吞掉。
    DOS 时代的 exe 现在可以认为不存在，宁可漏它。
    """
    head = ctx.get(start, 0x40)
    if len(head) < 0x40 or head[:2] != b"MZ":
        return None
    lfanew = _u32le(head, 0x3C)
    if not (0 < lfanew < 0x4000000):
        return None
    nt = ctx.get(start + lfanew, 24)
    if len(nt) < 24 or nt[:4] != b"PE\x00\x00":
        return None
    nsect = struct.unpack_from("<H", nt, 6)[0]
    opt = struct.unpack_from("<H", nt, 20)[0]
    if not (1 <= nsect <= 96) or opt < 60 or opt > 4096:
        return None
    base = start + lfanew + 24 + opt
    end = 0
    for i in range(nsect):
        sh = ctx.get(base + 40 * i, 40)
        if len(sh) < 40:
            return None
        raw_size = _u32le(sh, 16)
        raw_ptr = _u32le(sh, 20)
        end = max(end, raw_ptr + raw_size)
    if end < 512 or start + end > cap:
        return None
    return (end, "ok", ".exe")


def p_ico(ctx, start, cap):
    """ICO/CUR：目录项必须**自洽**（图标都很小，图片区通常是紧挨着顺序放的）。

    这条以前只校验「offset >= 目录末尾」，结果在真实盘上从随机数据里认出了
    **4GB 的图标**，一路把磁盘写满 —— 4 字节签名太常见了，必须靠结构说话。
    """
    head = ctx.get(start, 6)
    if len(head) < 6 or struct.unpack_from("<H", head, 0)[0] not in (0, 1, 2):
        return None
    count = struct.unpack_from("<H", head, 4)[0]
    if not (1 <= count <= 64):
        return None
    floor = 6 + 16 * count
    end = 0
    prev = floor
    for i in range(count):
        e = ctx.get(start + 6 + 16 * i, 16)
        if len(e) < 16:
            return None
        w, h = e[0], e[1]
        size = _u32le(e, 8)
        off = _u32le(e, 12)
        if size <= 0 or size > (16 << 20):          # 单个图标 > 16MB 不可能
            return None
        if off < floor or off > (64 << 20):         # 图片区起始不可能超过 64MB
            return None
        if i and off < prev:                        # 正常 ICO 是顺序排列的
            return None
        prev = off
        end = max(end, off + size)
    if not end or start + end > cap or end > (128 << 20):
        return None
    return (end, "ok", ".ico")


def p_psd(ctx, start, cap):
    head = ctx.get(start, 26)
    if len(head) < 26 or head[:4] != b"8BPS" or struct.unpack_from(">H", head, 4)[0] != 1:
        return None
    ch = struct.unpack_from(">H", head, 12)[0]
    hh = struct.unpack_from(">I", head, 14)[0]
    ww = struct.unpack_from(">I", head, 18)[0]
    depth = struct.unpack_from(">H", head, 22)[0]
    if not (1 <= ch <= 56 and 0 < hh <= 300000 and 0 < ww <= 300000
            and depth in (1, 8, 16, 32)):
        return None
    pos = start + 26
    for _ in range(3):
        ln = ctx.u32(pos, ">")
        if ln < 0 or pos + 4 + ln > cap:
            return None
        pos += 4 + ln
    comp = ctx.u16(pos, ">")
    pos += 2
    if comp == 0:
        end = pos + ww * hh * ch * (depth // 8) - start
    elif comp == 1:
        rows = hh * ch
        raw = ctx.get(pos, rows * 2)
        if len(raw) < rows * 2:
            return None
        total = sum(struct.unpack_from(">" + "H" * rows, raw, 0))
        end = pos + rows * 2 + total - start
    else:
        return None
    if end <= 26 or start + end > cap:
        return None
    return (end, "ok", ".psd")


def p_rtf(ctx, start, cap):
    head = ctx.get(start, 7)
    if head[:5] != b"{\\rtf" or not (0x30 <= head[5] <= 0x39):
        return None
    pos = start
    depth = 0
    while pos < cap:
        buf = ctx.get(pos, 1 << 16)
        if not buf:
            return None
        i = 0
        n = len(buf)
        while i < n:
            c = buf[i]
            if c == 0x5C:                              # 反斜杠：跳过下一个字符
                i += 2
                continue
            if c == 0x7B:
                depth += 1
            elif c == 0x7D:
                depth -= 1
                if depth == 0:
                    return (pos + i + 1 - start, "ok", ".rtf")
            i += 1
        pos += n
    return None


_EBML_MASTER = {0x18538067, 0x1F43B675, 0x1549A966, 0x1654AE6B, 0x1C53BB6B, 0x1254C367}


def p_mkv(ctx, start, cap):
    """MKV/WebM：EBML 元素链。Segment 常写「未知长度」，所以要能下钻。"""
    head = ctx.get(start, 4)
    if len(head) < 4 or head[:4] != b"\x1a\x45\xdf\xa3":
        return None
    # 前置校验：EBML 头里必须能找到 DocType（matroska / webm）。
    # 不做这一步，随机数据里的 4 字节签名会让元素链一路走到底，白读几个 GB。
    probe = ctx.get(start, 256)
    if b"matroska" not in probe and b"webm" not in probe:
        return None
    # EBML 头自己是「ID + size + 内容」，先把它整段跳过去，别把它的 size 当成下一个 ID
    sz, used = _rar5_vint(ctx, start + 4)          # 同一个变长整数读法，EBML 也适用
    if sz is None:
        return None
    pos = start + 4 + used + sz
    elems = 0
    has_cluster = False
    clean = False                           # 结构主动拒绝（不是数据读没了）
    while pos < cap and elems < 100000:
        b = ctx.get(pos, 1)
        if not b:
            break
        mask = 0x80
        ilen = 1
        while ilen <= 4 and not (b[0] & mask):
            mask >>= 1
            ilen += 1
        if ilen > 4:
            clean = True                    # 下一个字节不是合法的 EBML ID → 文件到头了
            break
        eid = int.from_bytes(ctx.get(pos, ilen), "big")
        pos += ilen
        sb = ctx.get(pos, 1)
        if not sb:
            break
        mask = 0x80
        slen = 1
        while slen <= 8 and not (sb[0] & mask):
            mask >>= 1
            slen += 1
        if slen > 8:
            clean = True
            break
        raw = ctx.get(pos, slen)
        if len(raw) < slen:
            break
        val = raw[0] & (mask - 1)
        for k in range(1, slen):
            val = (val << 8) | raw[k]
        unknown = val == (1 << (7 * slen)) - 1
        pos += slen
        if unknown or eid in _EBML_MASTER:
            if eid == 0x1F43B675:           # Cluster：真的有媒体数据，不只是个头
                has_cluster = True
            elems += 1
            continue
        pos += val
        elems += 1
    if pos <= start + 8:
        return None
    if pos > cap:
        pos = cap
        clean = False                       # 声明的体积超出实有数据 → 被截断，别报 ok
    ext = ".webm" if ctx.get(start, 64).find(b"webm") >= 0 else ".mkv"
    # MKV 的 Segment 多半写「未知长度」，正常文件也是走到「下一个字节不是合法 EBML」
    # 才算完 —— 那本身就是结构证据，可以报 ok；只有「数据读没了」才算半截。
    verdict = "ok" if (clean and has_cluster) else "weak"
    return (pos - start, verdict, ext)


# ───────────────────────────── 类型注册表 ─────────────────────────────
# group：界面上的分组（photo/doc/media/archive/other），也是「只找某一类」的依据
KINDS = {}


def _kind(kid, label, group, exts, sigs, parse, min_len=256, max_len=None):
    KINDS[kid] = {"id": kid, "label": label, "group": group, "exts": exts,
                  "sigs": sigs, "parse": parse, "min_len": min_len,
                  "max_len": max_len or (4 << 30)}


_kind("jpeg", "照片 JPEG", "photo", (".jpg", ".jpeg"),
      ((b"\xff\xd8\xff", 0),), p_jpeg, 512, max_len=512 << 20)
_kind("png", "图片 PNG", "photo", (".png",),
      ((b"\x89PNG\r\n\x1a\n", 0),), p_png, 128, max_len=1 << 30)
_kind("gif", "动图 GIF", "photo", (".gif",),
      ((b"GIF87a", 0), (b"GIF89a", 0)), p_gif, 64, max_len=256 << 20)
_kind("bmp", "位图 BMP", "photo", (".bmp",),
      ((b"BM", 0),), p_bmp, 128, max_len=512 << 20)
_kind("tiff", "照片 TIFF/CR2/NEF", "photo", (".tif", ".tiff", ".cr2", ".nef"),
      ((b"II*\x00", 0), (b"MM\x00*", 0)), p_tiff, 512, max_len=2 << 30)
_kind("riff", "波形/视频/网页图 RIFF", "media", (".wav", ".avi", ".webp"),
      ((b"RIFF", 0),), p_riff, 128, max_len=4 << 30)
_kind("mp4", "视频 MP4/MOV/HEIC", "media", (".mp4", ".mov", ".heic", ".3gp", ".m4a"),
      ((b"ftyp", 4),), p_mp4, 512, max_len=16 << 30)
_kind("mkv", "视频 MKV/WebM", "media", (".mkv", ".webm"),
      ((b"\x1a\x45\xdf\xa3", 0),), p_mkv, 512, max_len=16 << 30)
_kind("flv", "视频 FLV", "media", (".flv",),
      ((b"FLV\x01", 0),), p_flv, 1024, max_len=4 << 30)
_kind("mp3", "音频 MP3", "media", (".mp3",),
      ((b"ID3", 0), (b"\xff\xfb", 0), (b"\xff\xf3", 0), (b"\xff\xf2", 0)),
      p_mp3, 1024, max_len=512 << 20)
_kind("ogg", "音频 OGG", "media", (".ogg", ".opus"),
      ((b"OggS", 0),), p_ogg, 512, max_len=512 << 20)
_kind("pdf", "文档 PDF", "doc", (".pdf",),
      ((b"%PDF-", 0),), p_pdf, 512, max_len=1 << 30)
_kind("zip", "压缩包 / Office 新格式", "archive", (".zip", ".docx", ".xlsx", ".pptx"),
      ((b"PK\x03\x04", 0), (b"PK\x05\x06", 0)), p_zip, 128, max_len=1 << 30)
_kind("cfb", "文档 DOC/XLS/PPT（旧格式）", "doc", (".doc", ".xls", ".ppt", ".msi"),
      ((b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0),), p_cfb, 512, max_len=2 << 30)
_kind("rtf", "文档 RTF", "doc", (".rtf",),
      ((b"{\\rtf", 0),), p_rtf, 64, max_len=256 << 20)
_kind("rar", "压缩包 RAR", "archive", (".rar",),
      ((b"Rar!\x1a\x07", 0),), p_rar, 64, max_len=4 << 30)
_kind("7z", "压缩包 7Z", "archive", (".7z",),
      ((b"7z\xbc\xaf\x27\x1c", 0),), p_7z, 64, max_len=4 << 30)
_kind("gzip", "压缩包 GZ", "archive", (".gz",),
      ((b"\x1f\x8b\x08", 0),), p_gzip, 32, max_len=4 << 30)
_kind("tar", "压缩包 TAR", "archive", (".tar",),
      ((b"ustar", 257),), p_tar, 1024, max_len=4 << 30)
_kind("sqlite", "数据库 SQLite", "other", (".sqlite", ".db"),
      ((b"SQLite format 3\x00", 0),), p_sqlite, 512, max_len=8 << 30)
_kind("exe", "程序 EXE/DLL", "other", (".exe", ".dll"),
      ((b"MZ", 0),), p_exe, 512, max_len=1 << 30)
_kind("ico", "图标 ICO", "photo", (".ico",),
      ((b"\x00\x00\x01\x00", 0), (b"\x00\x00\x02\x00", 0)), p_ico, 128,
      max_len=8 << 20)
_kind("psd", "设计稿 PSD", "photo", (".psd",),
      ((b"8BPS", 0),), p_psd, 512, max_len=1 << 30)

KIND_IDS = tuple(KINDS)
KIND_LABEL = {k: v["label"] for k, v in KINDS.items()}
GROUPS = {
    "all": "全部类型",
    "photo": "照片 / 图片",
    "doc": "文档 / 表格 / 幻灯片",
    "media": "视频 / 音频",
    "archive": "压缩包",
    "other": "数据库 / 程序 / 其它",
}
KIND_GROUPS = KIND_LABEL                     # 兼容旧名字

# 展开成「签名 → 类型」的查找表（按 needle 长度倒序：长签名更特异，先判）
_SIG_TABLE = []
for _k, _v in KINDS.items():
    for _sig, _delta in _v["sigs"]:
        _SIG_TABLE.append((_sig, _delta, _k))
_SIG_TABLE.sort(key=lambda t: -len(t[0]))


# ───────────────────────────── 扫描范围 ─────────────────────────────
def _free_ranges(vol, max_gap=4 << 20):
    """NTFS 上按 $Bitmap 找出空闲区；小洞合并（多读几 MB 比多几百次寻道便宜）。

    返回 None 表示「不知道哪些是空闲的」（裸卷 / 不认识的卷），调用方按全卷扫并标 blind。
    """
    bm = getattr(vol, "bitmap", None)
    if bm is None or not getattr(bm, "runs", None):
        return None
    cluster = vol.cluster
    total = getattr(vol, "total_bytes", 0) or (vol.total_sectors * vol.bytes_per_sector)
    total_clusters = total // cluster
    ranges = []
    off = 0
    need = 1
    while off < bm.size:
        chunk = bm._bytes_of(off, 1 << 20)
        if not chunk:
            break
        start = None
        for i in range(len(chunk)):
            byte = chunk[i]
            if start is None:
                if byte != 0xFF:
                    start = i
            elif byte == 0xFF:
                s_cluster = (off + start) * 8
                e_cluster = min((off + i) * 8, total_clusters)
                if e_cluster > s_cluster:
                    ranges.append((s_cluster * cluster, e_cluster * cluster))
                start = None
        if start is not None:
            s_cluster = (off + start) * 8
            e_cluster = min((off + len(chunk)) * 8, total_clusters)
            if e_cluster > s_cluster:
                ranges.append((s_cluster * cluster, e_cluster * cluster))
        off += len(chunk)
    if not ranges:
        return []
    merged = [ranges[0]]
    for s, e in ranges[1:]:
        if s - merged[-1][1] <= max_gap:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
        else:
            merged.append((s, e))
    _ = need
    return merged


# ───────────────────────────── 主流程 ─────────────────────────────
def carve(vol, out_dir, kinds=None, groups=None, budget_bytes=None, max_file=None,
          max_files=5000, min_size=None, progress=None, cancel=None, dedupe=True):
    r"""在卷的未分配空间里按内容找文件，直接写到 `out_dir`。

    vol        : 卷对象（有 read(off,size) / cluster / total_bytes 即可）
    kinds      : 只找这些类型（KINDS 的 id）；None = 全部
    groups     : 只找这些分组（photo/doc/media/archive/other）；None = 全部
    budget_bytes: 最多扫多少字节；**None = 扫完整个目标范围**（默认；可随时 cancel）
    max_files  : 最多写出多少个文件（默认 5000；到了就停，不是悄悄丢）
    min_size   : 小于这个字节数的结果不写（默认按类型各自的 min_len）

    返回 (写出的路径列表, 统计 dict)。统计里有 by_kind / verdict / 速度 / blind。
    """
    ids = set(KINDS)
    if kinds:
        ids &= set(kinds)
    if groups and "all" not in groups:
        ids &= {k for k, v in KINDS.items() if v["group"] in set(groups)}
    if not ids:
        raise ValueError("没有选中任何类型")

    sigs = [t for t in _SIG_TABLE if t[2] in ids]
    os.makedirs(out_dir, exist_ok=True)
    cluster = getattr(vol, "cluster", 4096) or 4096
    total_bytes = getattr(vol, "total_bytes", 0) or (
        getattr(vol, "total_sectors", 0) * getattr(vol, "bytes_per_sector", 512))
    end_of_volume = total_bytes

    ranges = _free_ranges(vol)
    blind = ranges is None
    if blind:
        ranges = [(0, end_of_volume)]
    if not ranges:
        return [], {"scanned": 0, "found": 0, "by_kind": {}, "blind": blind,
                    "empty": True, "elapsed": 0.0, "speed": 0.0,
                    "total": 0, "kinds": sorted(ids)}
    # 尾部留一个读块：解析器可能要读到卷尾
    total_target = sum(e - s for s, e in ranges)
    if budget_bytes is not None:
        total_target = min(total_target, budget_bytes)

    def used(offset):
        if blind:
            return False
        fn = getattr(vol, "cluster_used", None)
        if fn is None:
            return False
        try:
            return bool(fn(offset // cluster))
        except Exception:                             # noqa: BLE001
            return False

    t0 = time.time()
    found = []
    scanned = 0
    truncated = False
    hit_used = 0
    seen_hash = set()
    made = []
    by_kind = {}
    dup = 0

    def _dest(kind, ext, n):
        name = f"{ext.lstrip('.')}_{n:05d}{ext}"
        k = 1
        while os.path.exists(os.path.join(out_dir, name)):
            k += 1
            name = f"{ext.lstrip('.')}_{n:05d}_{k}{ext}"
        return os.path.join(out_dir, name)

    def _record(kind, verdict, dest):
        made.append(dest)
        st = by_kind.setdefault(kind, {"n": 0, "ok": 0, "weak": 0})
        st["n"] += 1
        st[verdict] = st.get(verdict, 0) + 1

    def _pieces(amount, start):
        """把「长度」或「分段列表」统一成 [(偏移 或 None, 长度), …]。

        `None` 表示这一段盘上已经没有原数据了（碎片缺口），按 0 补齐 ——
        为什么补零而不是「跳过缺口把两截粘起来」：ZIP 的中央目录、MP4 的 stco
        记的都是**从文件开头算的绝对偏移**，一旦把中间的洞挤掉，后面所有偏移
        全部错位，粘出来反而打不开。补零能保住偏移，视频只是那一段花屏、
        WAV 只是那一段静音，比「文件彻底打不开」好得多。
        """
        if isinstance(amount, (int, float)):
            return [(start, int(amount))]
        return [(off, int(n)) for off, n in amount]

    def flush():
        """把候选落到 out_dir。

        小文件（≤24MB）读进内存 → 算 sha1 → 同内容的只留第一份；大文件边读边写，
        不占内存（以前一律 join 成一个大 bytes，碰到一个 4GB 的假文件就直接吃光内存）。
        """
        nonlocal dup
        while found and len(made) < max_files:
            row = found.pop(0)
            kind, start, amount, verdict, ext = row[:5]
            # 截断的图要补一个结束标记才打得开（JPEG 补 EOI、PNG 补 IEND）
            trailer = row[5] if len(row) > 5 else b""
            parts = _pieces(amount, start)
            length = sum(n for _o, n in parts)
            dest = _dest(kind, ext, len(made) + 1)
            if length <= (24 << 20):
                blob = bytearray()
                for off, n in parts:
                    if off is None:
                        blob += bytes(n)
                        continue
                    chunk = vol.read(off, n)
                    if len(chunk) < n:
                        break
                    blob += chunk
                if len(blob) < 8 or len(blob) < length:
                    continue
                if dedupe:
                    h = hashlib.sha1(bytes(blob)).digest()
                    if h in seen_hash:
                        dup += 1
                        continue
                    seen_hash.add(h)
                try:
                    with open(dest, "wb") as fh:
                        fh.write(blob)
                        if trailer:
                            fh.write(trailer)
                except OSError:
                    continue
                _record(kind, verdict, dest)
                continue
            written = 0
            short = False
            try:
                with open(dest, "wb") as fh:
                    for off, n in parts:
                        if off is None:
                            step = 4 << 20
                            while n > 0:                 # 缺口按 0 补齐
                                k = min(n, step)
                                fh.write(b"\x00" * k)
                                written += k
                                n -= k
                            continue
                        p, left = off, n
                        while left > 0:
                            buf = vol.read(p, min(left, 4 << 20))
                            if not buf:
                                short = True
                                break
                            fh.write(buf)
                            p += len(buf)
                            left -= len(buf)
                            written += len(buf)
                        if short:
                            break
                    if not short and trailer:
                        fh.write(trailer)
            except OSError:
                try:
                    os.remove(dest)
                except OSError:
                    pass
                continue
            if short or written < max(length - (1 << 20), 8):
                # 读不全（坏道 / 卷尾）→ 不留半截文件
                try:
                    os.remove(dest)
                except OSError:
                    pass
                continue
            _record(kind, verdict, dest)

    for r_start, r_end in ranges:
        if scanned >= total_target:
            truncated = True
            break
        pos = r_start
        while pos < r_end:
            if cancel and cancel():
                truncated = True
                break
            want = min(_READ_CHUNK, r_end - pos, total_target - scanned)
            if want <= 0:
                truncated = True
                break
            buf = vol.read(pos, want)
            if not buf:
                break
            ctx = _Ctx(vol.read, end_of_volume, pos, buf)
            cands = []
            for needle, delta, kid in sigs:
                i = buf.find(needle)
                while i >= 0:
                    s = i - delta
                    if s >= 0:
                        cands.append((pos + s, kid))
                        if len(cands) > _MAX_CANDIDATES:
                            break
                    i = buf.find(needle, i + 1)
            if cands:
                cands.sort()
                last_end = pos
                for start, kid in cands:
                    if start < last_end:
                        continue                      # 落在已认出的文件里，跳过
                    spec = KINDS[kid]
                    cap = min(end_of_volume, start + (max_file or spec["max_len"]))
                    if start + spec["min_len"] > cap:
                        continue
                    if used(start):
                        hit_used += 1
                        continue
                    try:
                        res = spec["parse"](ctx, start, cap)
                    except (struct.error, IndexError, ValueError, zlib.error):
                        res = None
                    if not res:
                        last_end = start + 1
                        continue
                    length, verdict = res[0], res[1]
                    ext = (res[2] if len(res) > 2 else None) or spec["exts"][0]
                    trailer = res[3] if len(res) > 3 else b""
                    # 分段结果（碎片补齐）：长度按各段之和算，min/max 的闸门照样生效
                    total_len = length if isinstance(length, (int, float)) else sum(
                        n for _o, n in length)
                    if total_len < max(spec["min_len"], min_size or 0):
                        last_end = start + 1
                        continue
                    if total_len > (max_file or spec["max_len"]):
                        last_end = start + 1
                        continue
                    found.append((kid, start, length, verdict, ext, trailer))
                    last_end = start + max(total_len, 1)
                    if len(found) >= 64:
                        flush()
                    if len(made) >= max_files:
                        truncated = True
                        break
                if len(made) >= max_files:
                    break
            scanned += len(buf)
            pos += len(buf)
            if progress:
                progress(min(scanned, total_target), total_target, len(made))
        if len(made) >= max_files or (cancel and cancel()):
            break
    flush()

    elapsed = max(time.time() - t0, 1e-6)
    stats = {
        "scanned": scanned,
        "total": total_target,
        "found": len(made),
        "dup_skipped": dup,
        "hit_used": hit_used,
        "by_kind": by_kind,
        "kinds": sorted(ids),
        "blind": blind,
        "elapsed": round(elapsed, 1),
        "speed": round(scanned / MIB / elapsed, 1),
        "truncated": truncated,
        "fs": getattr(vol, "kind", "ntfs"),
        "files": [{"name": os.path.basename(p),
                   "size": os.path.getsize(p) if os.path.exists(p) else 0}
                  for p in made],
    }
    return made, stats
