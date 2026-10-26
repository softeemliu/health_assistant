"""health_assistant.preview — 恢复结果「先看一眼再决定」

为什么需要这个：按文件类型找出来的东西名字是程序起的（`jpg_00017.jpg`），
用户不看内容根本没法挑。「跟市面产品比效果不达标」里最直观的一条差距就是这里 ——
别人选中就能看缩略图，我们要先恢复出来再用别的软件打开。

这里的做法全部**只读**，而且只读**开头一段**（缩略图不需要整张原图）：

* 按「这条记录现在还指向哪里」取字节：回收站原件 / 驻留数据 / 数据簇 runs / 已导出文件；
* 认出真实类型（签名 + 结构），并回答那个最关键的问题：**文件头跟扩展名对不对得上**；
* 图片给出尺寸并把字节交给界面解码；视频/音频给出时长和分辨率（不解码，没带 ffmpeg）；
* 文本给出前几行；Office/压缩包给出里面的文件名。

一次最多读 24MB：手机照片 4032×3024 也只有几 MB，缩略到 240px 更不需要全图。
"""

from __future__ import annotations

import os
import struct

from . import carving

HEAD_MAX = 24 << 20        # 图片缩略图/元数据最多读这么多
TAIL_KB = 96 << 10         # ZIP 的中央目录、CFB 的目录项常在尾部
TEXT_SHOW = 1200           # 文本预览显示多少字符

# 文本类扩展名（判「像不像文本」用控制字符率，和 recovery._magic_verdict 一个口径）
TEXT_EXTS = {"txt", "log", "ini", "cfg", "conf", "csv", "tsv", "md", "json",
             "xml", "html", "htm", "css", "js", "py", "bat", "cmd", "ps1",
             "sql", "yml", "yaml", "reg", "cs", "cpp", "h", "hpp", "java",
             "lua", "go", "sh", "srt", "ass", "vtt", "eml"}

IMAGE_KINDS = {"jpeg", "png", "gif", "bmp", "tiff", "ico", "psd"}
MEDIA_KINDS = {"mp4", "mkv", "riff", "flv", "mp3", "ogg"}

KIND_LABEL = {
    "jpeg": "JPEG 照片", "png": "PNG 图片", "gif": "GIF 动图", "bmp": "BMP 位图",
    "tiff": "TIFF 照片", "ico": "图标", "psd": "PSD 设计稿",
    "mp4": "视频 MP4/MOV", "mkv": "视频 MKV/WebM", "riff": "波形/视频 RIFF",
    "flv": "视频 FLV", "mp3": "音频 MP3", "ogg": "音频 OGG",
    "pdf": "PDF 文档", "zip": "压缩包 ZIP", "cfb": "Office 旧格式文档",
    "rtf": "RTF 文档", "rar": "压缩包 RAR", "7z": "压缩包 7Z",
    "gzip": "压缩包 GZ", "tar": "压缩包 TAR", "sqlite": "SQLite 数据库",
    "exe": "程序 EXE/DLL", "text": "文本文件",
}


# ────────────────────────── 取字节（全部只读）──────────────────────────

def _read_runs(vol, item, limit):
    """按数据簇 runs 读开头 limit 字节；稀疏段按 0 补。"""
    if vol is None:
        return b""
    out, left = [], limit
    for run in (item.get("runs") or []):
        lcn, count, sparse = run[0], run[1], run[2]
        if left <= 0:
            break
        length = count * vol.cluster
        if sparse:
            take = min(length, left)
            out.append(b"\x00" * take)
            left -= take
            continue
        pos = lcn * vol.cluster
        want = min(length, left)
        while want > 0:
            chunk = vol.read(pos, min(want, 1 << 20))
            if not chunk:
                break
            out.append(chunk)
            pos += len(chunk)
            want -= len(chunk)
            left -= len(chunk)
    return b"".join(out)


def _open_path(item):
    """这条记录在磁盘上的真实文件（回收站原件 / 已导出的 carve 结果）。"""
    rp = item.get("r_path")
    if rp and os.path.isfile(str(rp)):
        return str(rp)
    path = item.get("path")
    # MFT 记录的 path 是**原路径**（早就没了），只有不靠 runs 的条目才是真文件
    if path and not item.get("runs") and not item.get("resident") \
            and os.path.isfile(str(path)):
        return str(path)
    return ""


def needs_volume(item):
    """这条要不要开卷才能看？

    回收站里的原件、已经导出到磁盘上的文件都能直接读，**不该因为「开不了卷」而看不了**
    —— 没管理员权限、盘被占用、U 盘拔了这些情况，恰好是用户最需要先看一眼的时候。
    """
    if _open_path(item):
        return False
    if isinstance(item.get("data_off"), (bytes, bytearray)):
        return False
    return bool(item.get("runs"))


def read_head(vol, item, limit=HEAD_MAX):
    """按「这条记录现在还指向哪里」取开头一段。取不到就返回空字节，不抛。"""
    path = _open_path(item)
    if path:
        try:
            with open(path, "rb") as fh:
                return fh.read(limit)
        except OSError:
            return b""
    data = item.get("data_off")
    if isinstance(data, (bytes, bytearray)):        # 驻留小文件：内容就在记录里
        return bytes(data[:limit])
    return _read_runs(vol, item, limit)


def read_tail(vol, item, length=TAIL_KB, size=None):
    """读文件末尾一段（ZIP 中央目录、CFB 目录项都在后面）。"""
    total = int(size if size is not None else (item.get("size") or 0))
    if total <= 0:
        return b""
    start = max(0, total - length)
    path = _open_path(item)
    if path:
        try:
            with open(path, "rb") as fh:
                fh.seek(start)
                return fh.read(length)
        except OSError:
            return b""
    if vol is None or not item.get("runs"):
        return b""
    out, seen = [], 0
    for run in (item.get("runs") or []):
        lcn, count, sparse = run[0], run[1], run[2]
        run_start, run_len = seen, count * vol.cluster
        if run_start + run_len <= start:            # 整段在取样点之前
            seen += run_len
            continue
        if sparse:
            out.append(b"\x00" * run_len)
            seen += run_len
            continue
        pos = lcn * vol.cluster + max(0, start - run_start)
        want = run_len - max(0, start - run_start)
        while want > 0:
            chunk = vol.read(pos, min(want, 1 << 20))
            if not chunk:
                break
            out.append(chunk)
            pos += len(chunk)
            want -= len(chunk)
        seen += run_len
    blob = b"".join(out)
    return blob[-length:] if len(blob) > length else blob


# ────────────────────────── 认类型 ──────────────────────────

def sniff(head):
    """按签名认出真实类型 → (kind_id, 主扩展名, 中文标签)，认不出返回 None。

    签名表直接用 carving 的（23 类），别在这里再抄一份 —— 抄两份迟早不一致。
    """
    if not head:
        return None
    for kid, spec in carving.KINDS.items():
        for sig, off in spec["sigs"]:
            if off + len(sig) <= len(head) and head[off:off + len(sig)] == sig:
                return kid, spec["exts"][0], spec["label"]
    return None


def _looks_text(head):
    sample = head[:512]
    if not sample:
        return False
    ctrl = sum(1 for b in sample if b < 9 or (13 < b < 32))
    return ctrl <= len(sample) * 0.05


def image_size(head, kind):
    """从文件头解析像素尺寸（不解码）。返回 (宽, 高) 或 None。"""
    try:
        if kind == "png" and head[:8] == b"\x89PNG\r\n\x1a\n":
            return struct.unpack_from(">II", head, 16)
        if kind == "gif":
            return struct.unpack_from("<HH", head, 6)
        if kind == "bmp":
            w, h = struct.unpack_from("<ii", head, 18)
            return abs(w), abs(h)
        if kind == "jpeg":
            pos = 2
            while pos + 9 < len(head):
                if head[pos] != 0xFF:
                    pos += 1
                    continue
                m = head[pos + 1]
                if m in (0xD8, 0x01, 0xFF) or 0xD0 <= m <= 0xD7:
                    pos += 2
                    continue
                ln = struct.unpack_from(">H", head, pos + 2)[0]
                if 0xC0 <= m <= 0xCF and m not in (0xC4, 0xC8, 0xCC):
                    h_, w_ = struct.unpack_from(">HH", head, pos + 5)
                    return w_, h_
                pos += 2 + max(ln, 2)
        if kind == "ico" and len(head) >= 6:
            count = struct.unpack_from("<H", head, 4)[0]
            if count >= 1:
                w, h = head[6], head[7]
                return (w or 256), (h or 256)
        if kind == "psd" and len(head) >= 26:
            h_, w_ = struct.unpack_from(">II", head, 14)   # height@14、width@18
            return w_, h_
        if kind == "tiff" and len(head) >= 8:
            return _tiff_size(head)
    except (struct.error, IndexError):
        return None
    return None


def _tiff_size(head):
    """TIFF 的尺寸在 IFD 里：顺序读 tag，ImageWidth(0x100)/ImageLength(0x101)。"""
    le = head[:2] == b"II"
    fmt = "<" if le else ">"
    try:
        off = struct.unpack_from(fmt + "I", head, 4)[0]
        if not (8 <= off < len(head) - 2):
            return None
        n = struct.unpack_from(fmt + "H", head, off)[0]
        w = h = 0
        for i in range(min(n, 512)):
            p = off + 2 + i * 12
            if p + 12 > len(head):
                break
            tag, typ = struct.unpack_from(fmt + "HH", head, p)
            if typ == 3:                      # SHORT
                val = struct.unpack_from(fmt + "H", head, p + 8)[0]
            elif typ == 4:                     # LONG
                val = struct.unpack_from(fmt + "I", head, p + 8)[0]
            else:
                continue
            if tag == 0x100:
                w = val
            elif tag == 0x101:
                h = val
            if w and h:
                return w, h
    except (struct.error, IndexError):
        return None
    return None


def media_meta(head, tail, kind, size):
    """视频/音频的时长与分辨率。不解码，只看容器头（头里没有就去尾部找）。

    为什么要看尾部：手机的 MP4、重新封装过的 MKV 常把 moov / Info 放在文件**末尾**，
    只看开头会得到一个「没有时长」的视频，用户没法判断这是不是他要的那段。
    """
    out = {}
    try:
        if kind == "mp4":
            _mp4_meta(head, out)
            if "seconds" not in out and tail:
                _mvhd_from_blob(tail, out)
                _tkhd_from_blob(tail, out)
        elif kind == "riff":
            _riff_meta(head, out, size)
        elif kind == "mkv":
            for blob in (head, tail):
                i = blob.find(b"\x44\x89\x88")      # Duration（float64，单位 ms）
                if 0 <= i < len(blob) - 11:
                    out["seconds"] = struct.unpack_from(">d", blob, i + 3)[0] / 1000.0
                    break
        elif kind == "flv" and len(head) > 40:
            out["seconds"] = struct.unpack_from(">I", head, 32)[0] / 1000.0
        elif kind == "mp3":
            _mp3_meta(head, size, out)
    except (struct.error, IndexError, ZeroDivisionError):
        pass
    return out


def _mvhd_from_blob(blob, out):
    """在任意一段字节里找 mvhd（moov 在文件尾部时用）。"""
    i = blob.find(b"mvhd")
    if i < 0 or i + 30 > len(blob):
        return
    body = i + 4
    try:
        ver = blob[body]
        if ver == 1:
            ts = struct.unpack_from(">I", blob, body + 20)[0]
            du = struct.unpack_from(">Q", blob, body + 24)[0]
        else:
            ts = struct.unpack_from(">I", blob, body + 12)[0]
            du = struct.unpack_from(">I", blob, body + 16)[0]
        if ts:
            out["seconds"] = du / ts
    except (struct.error, IndexError):
        pass


def _tkhd_from_blob(blob, out):
    """在任意一段字节里找 tkhd 的分辨率（16.16 定点）。"""
    i = blob.find(b"tkhd")
    if i < 0 or i + 92 > len(blob):
        return
    body = i + 4
    try:
        ver = blob[body]
        base = body + (96 if ver == 1 else 84)
        if base + 8 > len(blob):
            return
        w = struct.unpack_from(">I", blob, base - 8)[0] >> 16
        h = struct.unpack_from(">I", blob, base - 4)[0] >> 16
        if w and h:
            out.setdefault("size_px", (w, h))
    except (struct.error, IndexError):
        pass


_MP3_BITRATES = {
    1: (0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320),
    2: (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160),
}


def _mp3_meta(head, size, out):
    """MP3 的时长按码率估：CBR 的 (总字节 × 8) / kbps 就是秒数，够判断「是不是那首歌」。"""
    start = 0
    if head[:3] == b"ID3" and len(head) >= 10:
        sz = head[6:10]
        start = 10 + ((sz[0] & 0x7F) << 21 | (sz[1] & 0x7F) << 14
                      | (sz[2] & 0x7F) << 7 | (sz[3] & 0x7F))
    # 找第一个帧头（FF Ex/Fx）
    pos = start
    while pos + 4 <= len(head) and pos < start + (1 << 20):
        if head[pos] == 0xFF and (head[pos + 1] & 0xE0) == 0xE0:
            break
        pos += 1
    else:
        return
    if pos + 4 > len(head):
        return
    b2 = head[pos + 2]
    layer = (head[pos + 1] >> 1) & 0x03
    br_idx = b2 >> 4
    table = _MP3_BITRATES.get(1 if layer == 3 else 2)
    if not table or br_idx >= len(table) or not table[br_idx]:
        return
    kbps = table[br_idx]
    if size > pos:
        out["seconds"] = size * 8 / (kbps * 1000.0)
        out["audio"] = f"{kbps}kbps"


def _boxes(buf, start=0, end=None, depth=0):
    """遍历 MP4 的 box 链，产出 (类型, 内容起点, 内容终点)。"""
    end = len(buf) if end is None else end
    pos = start
    while pos + 8 <= end:
        size = struct.unpack_from(">I", buf, pos)[0]
        typ = buf[pos + 4:pos + 8]
        if size == 1:
            if pos + 16 > end:
                return
            size = struct.unpack_from(">Q", buf, pos + 8)[0]
            body = pos + 16
        elif size == 0:
            size, body = end - pos, pos + 8
        else:
            body = pos + 8
        if size < 8 or pos + size > end:
            return
        yield typ, body, pos + size, depth
        pos += size


def _mp4_meta(head, out):
    for typ, body, end, _d in _boxes(head):
        if typ == b"moov":
            for typ2, b2, e2, _d2 in _boxes(head, body, end):
                if typ2 == b"mvhd" and b2 + 20 <= e2:
                    ver = head[b2]
                    if ver == 1:
                        ts = struct.unpack_from(">I", head, b2 + 20)[0]
                        du = struct.unpack_from(">Q", head, b2 + 24)[0]
                    else:
                        ts = struct.unpack_from(">I", head, b2 + 12)[0]
                        du = struct.unpack_from(">I", head, b2 + 16)[0]
                    if ts:
                        out["seconds"] = du / ts
                elif typ2 == b"trak":
                    for typ3, b3, e3, _d3 in _boxes(head, b2, e2):
                        if typ3 == b"tkhd" and b3 + 84 <= e3:
                            w = struct.unpack_from(">I", head, b3 + 76)[0] >> 16
                            h = struct.unpack_from(">I", head, b3 + 80)[0] >> 16
                            if w and h:
                                out.setdefault("size_px", (w, h))
            return


def _riff_meta(head, out, size):
    kind = head[8:12]
    if kind == b"WAVE":
        i = head.find(b"fmt ")
        if 0 <= i < len(head) - 20:
            ch = struct.unpack_from("<H", head, i + 10)[0]
            rate = struct.unpack_from("<I", head, i + 12)[0]
            bits = struct.unpack_from("<H", head, i + 22)[0]
            if ch and rate and bits:
                kbps = rate * ch * bits / 1000.0
                out["audio"] = f"{rate}Hz {ch}声道 {bits}bit"
                if size:
                    out["seconds"] = size / (rate * ch * bits / 8)
    elif kind == b"AVI ":
        i = head.find(b"avih")
        if 0 <= i < len(head) - 40:
            usec = struct.unpack_from("<I", head, i + 8)[0]
            frames = struct.unpack_from("<I", head, i + 24)[0]
            if usec:
                out["seconds"] = usec * frames / 1e6
            w = struct.unpack_from("<I", head, i + 40)[0] if i + 44 <= len(head) else 0
            h = struct.unpack_from("<I", head, i + 44)[0] if i + 48 <= len(head) else 0
            if w and h:
                out["size_px"] = (w, h)



# ────────────────────────── 内容摘要 ──────────────────────────

def _zip_names(head, tail, limit=8):
    """从 ZIP 里挑几个文件名（新格式 Office 靠这个认子类型）。"""
    names = []
    for blob in (head, tail):
        pos = 0
        while len(names) < limit:
            i = blob.find(b"PK\x03\x04", pos)
            if i < 0 or i + 30 > len(blob):
                break
            n_len = struct.unpack_from("<H", blob, i + 26)[0]
            if 0 < n_len < 512 and i + 30 + n_len <= len(blob):
                raw = blob[i + 30:i + 30 + n_len]
                try:
                    names.append(raw.decode("utf-8", "replace"))
                except Exception:                   # noqa: BLE001
                    pass
            pos = i + 4
        if names:
            break
    return names


def zip_subtype(names):
    """docx / xlsx / pptx / 普通 zip。"""
    for n in names:
        low = n.lower()
        if low.startswith("word/"):
            return ".docx", "Word 文档"
        if low.startswith("xl/"):
            return ".xlsx", "Excel 表格"
        if low.startswith("ppt/"):
            return ".pptx", "PowerPoint 幻灯片"
    return ".zip", "压缩包"


_CFB_CLSID_LABEL = {
    bytes.fromhex("84100c0000000000c000000000000046"): ("Windows 安装包 MSI", ".msi"),
    bytes.fromhex("0609020000000000c000000000000046"): ("Word 文档", ".doc"),
    bytes.fromhex("2008020000000000c000000000000046"): ("Excel 表格", ".xls"),
    bytes.fromhex("108d81644f9b11cf86ea00aa00b929e8"): ("PowerPoint 幻灯片", ".ppt"),
}


def _cfb_clsid(head):
    """根目录项的 CLSID —— 比流名字靠谱（名字可能在文件末尾，CLSID 始终在目录流第一项）。"""
    try:
        ssz = 1 << struct.unpack_from("<H", head, 30)[0]
        dir_start = struct.unpack_from("<I", head, 48)[0]
        if ssz not in (512, 4096) or dir_start >= 0xFFFFFFFA:
            return None
        off = (dir_start + 1) * ssz + 0x50
        if off + 16 > len(head):
            return None
        return _CFB_CLSID_LABEL.get(head[off:off + 16])
    except (struct.error, IndexError):
        return None


def _webp_size(head):
    """WebP 的尺寸：VP8X 是显式的 24 位，VP8/VP8L 要按各自格式取。"""
    if head[:4] != b"RIFF" or head[8:12] != b"WEBP":
        return None
    chunk = head[12:16]
    try:
        if chunk == b"VP8X":
            w = int.from_bytes(head[24:27], "little") + 1
            h = int.from_bytes(head[27:30], "little") + 1
            return w, h
        if chunk == b"VP8 ":
            i = head.find(b"\x9d\x01\x2a", 12)
            if i > 0 and i + 7 <= len(head):
                w = struct.unpack_from("<H", head, i + 3)[0] & 0x3FFF
                h = struct.unpack_from("<H", head, i + 5)[0] & 0x3FFF
                return w, h
        if chunk == b"VP8L" and len(head) >= 25:
            bits = int.from_bytes(head[21:25], "little")
            return (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
    except (struct.error, IndexError):
        return None
    return None


def _cfb_streams(head, tail, limit=6):
    """CFB 里的流名（UTF-16LE）。够用来认 doc/xls/ppt/msi，不做完整目录解析。"""
    out = []
    for blob in (head[-TAIL_KB:] if len(head) > TAIL_KB else head, tail):
        for needle in ("WordDocument", "Workbook", "PowerPoint Document",
                       "!_StringData", "!_Tables", "VisioDocument"):
            wide = needle.encode("utf-16-le")
            if wide in blob:
                out.append(needle)
    return out


def _text_preview(head):
    for enc in ("utf-8", "gb18030", "utf-16"):
        try:
            text = head.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        return ""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [ln.rstrip() for ln in text.split("\n")]
    while lines and not lines[-1].strip():
        lines.pop()
    body = "\n".join(lines[:14])
    return body[:TEXT_SHOW]


# ────────────────────────── 对外入口 ──────────────────────────

def describe(vol, item):
    """给一条恢复结果做「预览描述」。**只读**，任何异常都不往外抛。

    返回 dict：
      kind        真实类型 id（image/media/text/archive/doc/unknown/empty/dir/name_only）
      label       人话类型（"JPEG 照片"）
      match       True 文件头与扩展名一致 / False 不一致 / None 没有判据
      match_text  这句话直接显示在界面上
      detail      尺寸、时长、编码这类附加信息
      image       bytes（图片时给界面解码用），否则 b""
      text        文本预览（前几行），否则 None
      names       容器里的文件名列表（Office/压缩包）
      size        字节数
    """
    size = int(item.get("size") or 0)
    name = str(item.get("name") or "")
    ext = os.path.splitext(name)[1].lower().lstrip(".")

    res = {"kind": "unknown", "label": "", "match": None, "match_text": "",
           "detail": "", "image": b"", "text": None, "names": [], "size": size,
           "suggest_ext": ""}

    if item.get("is_dir"):
        res.update(kind="dir", label="文件夹", match=None,
                   match_text="文件夹只恢复目录结构，里面的文件要单独勾")
        return res
    if item.get("confidence") == "name_only":
        res.update(kind="name_only", label="只有名字",
                   match=None,
                   match_text="只从残留记录里找到名字，数据位置已经没了 —— 看不了内容")
        return res

    try:
        head = read_head(vol, item)
    except Exception:                               # noqa: BLE001
        head = b""
    if not head:
        res.update(kind="empty", label="读不出内容",
                   match=False,
                   match_text="读不到任何字节：数据区可能已经被覆盖，或者这块盘读不动")
        return res
    if not head.strip(b"\x00"):
        res.update(kind="empty", label="空的",
                   match=False,
                   match_text="开头这段全是 0：大概率已被清零（SSD 的 TRIM 落地后就是这样）")
        return res

    hit = sniff(head)
    kind = hit[0] if hit else ("text" if _looks_text(head) else "unknown")
    real_ext = hit[1] if hit else (".txt" if kind == "text" else "")
    label = KIND_LABEL.get(kind) or (hit[2] if hit else "认不出的类型")

    # 判据：文件头跟扩展名对不对得上（这是用户最想知道的「这个能打开吗」）
    # 文本类要先判 —— .py/.bat/.log 这些本来就是文本，别一张嘴就劝人改成 .txt
    if kind == "text":
        if ext:
            res["match"] = True if _looks_text(head) else False
            res["match_text"] = "是文本内容，用记事本就能打开"
        else:
            res["match"] = None
            res["suggest_ext"] = ".txt"
            res["match_text"] = "这个文件没有扩展名，内容是文本 —— 加上 .txt 就能打开"
    elif not ext and real_ext:
        # 没有扩展名太常见了：FAT 短名丢了首字符、残留记录里只剩名字、carving 输出。
        # 这时候「没有判据」是一句废话 —— 有用的做法是直接告诉他该加什么后缀。
        res["suggest_ext"] = real_ext
        res["match"] = None
        res["match_text"] = (f"这个文件没有扩展名，内容是 {label} "
                             f"—— 恢复后加上 {real_ext} 就能打开")
    elif ext and real_ext:
        alts = {e.lstrip(".").lower()
                for e in carving.KINDS.get(kind, {}).get("exts", ())}
        alts.add(real_ext.lstrip(".").lower())
        if ext in alts:
            res["match"] = True
            res["match_text"] = f"文件头是真正的 {label}，和扩展名一致"
        else:
            res["match"] = False
            res["suggest_ext"] = real_ext
            res["match_text"] = (f"扩展名写的是 .{ext}，实际内容是 {label} "
                                 f"—— 改成 {real_ext} 才能正常打开")
    else:
        res["match"] = None
        res["match_text"] = "没有判据，只能说读到了内容"

    res.update(kind=kind, label=label)

    # 尾部只读一次（Office 的中央目录、MP4/MKV 的 moov/Info、CFB 目录项都可能在后面）
    tail = b""
    if size > len(head):
        try:
            tail = read_tail(vol, item, TAIL_KB, size)
        except Exception:                           # noqa: BLE001
            tail = b""

    # 先细化子类型（RIFF 的 wav/avi/webp、CFB 的 msi/doc/xls/ppt、ZIP 的 Office），
    # 因为「是哪种文件」决定了后面怎么取尺寸和时长。
    refined = False
    if kind == "riff":
        sub = head[8:12]
        if sub == b"WAVE":
            res["label"] = "WAV 音频"
            refined = True
        elif sub == b"AVI ":
            res["label"] = "AVI 视频"
            refined = True
        elif sub == b"WEBP":
            res["label"] = "网页图片 WebP"
            refined = True
            res["suggest_ext"] = res["suggest_ext"] or ".webp"
            wh = _webp_size(head)
            if wh:
                res["wh"] = wh
    elif kind == "cfb":
        streams = _cfb_streams(head, tail)
        if streams:
            res["names"] = streams[:6]
        by_clsid = _cfb_clsid(head)
        by_name = {"!_StringData": ("Windows 安装包 MSI", ".msi"),
                   "!_Tables": ("Windows 安装包 MSI", ".msi"),
                   "WordDocument": ("Word 文档", ".doc"),
                   "Workbook": ("Excel 表格", ".xls"),
                   "PowerPoint Document": ("PowerPoint 幻灯片", ".ppt")}
        hit_label = by_clsid or by_name.get(streams[0] if streams else "")
        if hit_label:
            res["label"] = hit_label[0]
            refined = True
            res["suggest_ext"] = res["suggest_ext"] or hit_label[1]
    elif kind == "zip":
        names = _zip_names(head, tail)
        if names:
            res["names"] = names[:8]
            sub_ext, sub_label = zip_subtype(names)
            if sub_ext != ".zip":
                res["label"] = sub_label
                refined = True
                res["suggest_ext"] = res["suggest_ext"] or sub_ext
    elif kind == "pdf":
        res["label"] = "PDF 文档"
        refined = True

    # 标签被细化过 → 判据文案跟着更新（否则会出现「Word 文档」配「压缩包 ZIP」）
    if refined and res["match"] is True:
        res["match_text"] = f"文件头是真正的 {res['label']}，和扩展名一致"
    elif refined and res["match"] is False and res.get("suggest_ext"):
        res["match_text"] = (f"扩展名写的是 .{ext}，实际内容是 {res['label']} "
                             f"—— 改成 {res['suggest_ext']} 才能正常打开")

    # 尺寸 / 时长
    bits = []
    if kind in IMAGE_KINDS:
        wh = image_size(head, kind)
        if wh:
            bits.append(f"{wh[0]}×{wh[1]}")
        res["image"] = head
    elif res.get("wh"):
        bits.append(f"{res['wh'][0]}×{res['wh'][1]}")
        res["image"] = head                     # Qt 也能解 webp，给界面试试
    elif kind in MEDIA_KINDS:
        meta = media_meta(head, tail, kind, size)
        secs = meta.get("seconds")
        if secs and 0 < secs < 86400 * 3:
            m, s = divmod(int(round(secs)), 60)
            h, m = divmod(m, 60)
            bits.append(f"时长 {h}:{m:02d}:{s:02d}" if h else f"时长 {m}:{s:02d}")
        if meta.get("size_px"):
            bits.append(f"{meta['size_px'][0]}×{meta['size_px'][1]}")
        if meta.get("audio"):
            bits.append(meta["audio"])
        if meta.get("note"):
            bits.append(meta["note"])
    elif kind == "text":
        res["text"] = _text_preview(head)
        n = res["text"].count("\n") + 1 if res["text"] else 0
        bits.append(f"预览 {n} 行")
    elif kind == "sqlite":
        try:
            page = struct.unpack_from(">H", head, 16)[0]
            pages = struct.unpack_from(">I", head, 28)[0]
            if page and pages:
                bits.append(f"约 {pages} 页 × {page} 字节")
        except struct.error:
            pass

    if bits:
        res["detail"] = "，".join(bits)
    return res


def summary_line(info):
    """一行式摘要（表格里的提示 / 状态栏用）。"""
    parts = [info.get("label") or "认不出的类型"]
    if info.get("detail"):
        parts.append(info["detail"])
    if info.get("match") is False:
        parts.append("⚠ 内容与扩展名不符")
    return "　".join(parts)
