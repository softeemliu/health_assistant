r"""health_assistant.fatfs — FAT12/16/32 与 exFAT 的已删除文件扫描（**只读**）

为什么要单独一个模块
    `recovery.py` 那 3000 行几乎全是 NTFS 的记录表知识（MFT / INDX / USN / $Bitmap）。
    把第二套文件系统塞进去，两边都会变成难改的一锅。这里只做三件事：

      1. 认出卷结构（BPB / 簇大小 / 数据区起点 / 根目录）；
      2. 走目录树，把**已删除的目录项**翻出来；
      3. 给每个条目算出 `runs`（簇号 + 连续段数），格式和 NTFS 那边**完全一致** ——
         这样 `recovery._confidence()` / `recover_one()` 一行都不用改。

两种「已删除」长什么样（这是本模块存在的全部理由）
    · FAT：删文件时把目录项**首字节改成 0xE5**。
      - 短名还在（8.3 名原样保留）；
      - **长文件名（LFN）的 13 字符内容也还在**，只有所在项的首字节变成 0xE5，
        序号丢了 —— 所以要靠「紧挨短名项往前推」把序号补回来（见 `_parse_dir_block`）；
      - FAT 表里的簇链会被清零，所以数据段只能**假设连续存放**（`_runs_for`）：
        这是 FAT 恢复的物理上限，不是偷懒。
    · exFAT：删文件时把 entry set 里各项的 **in-use 位（bit7）清掉**（0x85→0x05、
      0xC0→0x40、0xC1→0x41），`SecondaryCount` 和名字、大小、首簇**全都保留**。
      所以 exFAT 的已删除扫描比 FAT 可靠得多，FAT 链通常也还在（不必假设连续）。

界面那边怎么用
    `recovery.open_volume()` 认到 exfat/fat 会返回这里的卷对象；
    `recovery.scan_deleted()` 在不是 NTFS 时自动转到这里。GUI 不用关心是哪一套。
"""

from __future__ import annotations

import time

__all__ = ["FatVolume", "ExfatVolume", "FatImageVolume", "ExfatImageVolume",
           "open_fat_volume", "scan_deleted", "fs_label", "is_fat"]


# ───────────────────────── 目录项解析 ─────────────────────────

def _dos_dt(date, tim):
    """DOS 日期/时间 → (epoch 秒, 显示文本)。解析不了就给 (0, "")。"""
    if not date:
        return 0, ""
    y = 1980 + ((date >> 9) & 0x7F)
    mo = (date >> 5) & 0x0F
    d = date & 0x1F
    hh = (tim >> 11) & 0x1F
    mm = (tim >> 5) & 0x3F
    ss = (tim & 0x1F) * 2
    if not (1 <= mo <= 12 and 1 <= d <= 31):
        return 0, ""
    try:
        t = time.mktime((y, mo, d, hh, mm, ss, 0, 0, -1))
    except (OverflowError, ValueError):
        return 0, ""
    return int(t), time.strftime("%Y-%m-%d %H:%M", time.localtime(t))


def _fat_name(entry, deleted=False):
    """FAT 短名（8.3）→ 字符串。

    两个坑：
      · 首字节 0x05 表示「真名以 0xE5 开头」（转义，这是微软的规矩）；
      · **已删除项的首字节是 0xE5**（删除标记），原来那个字符**被覆盖掉了**，
        谁也读不回来 —— 所以用 `_` 占位，别把它当成真字符（cp437 的 0xE5 是 σ，
        直接解码会得到「σB.TXT」这种鬼东西）。
    """
    raw = bytearray(entry[0:11])
    if deleted and raw[0] == 0xE5:
        raw[0] = ord("_")
    elif raw[0] == 0x05:
        raw[0] = 0xE5
    base = bytes(raw[:8]).decode("cp437", "replace").rstrip(" ")
    ext = bytes(raw[8:11]).decode("cp437", "replace").rstrip(" ")
    # Windows 用 0x0F / 0xE5 之类的小写标记把名字「压扁」成大写；0x0F 是 LFN 项，
    # 真·小写标记在 0x0C（bit3 = 小写 base，bit4 = 小写 ext）
    flags = entry[0x0C]
    if flags & 0x08:
        base = base.lower()
    if flags & 0x10:
        ext = ext.lower()
    if base == "" and ext == "":
        return ""
    return f"{base}.{ext}" if ext else base


def _lfn_chars(entry):
    """从一条 LFN 项里取 13 个 UTF-16 字符（遇到 0x0000 就截断）。"""
    out = []
    for seg in (entry[1:11], entry[14:26], entry[28:32]):
        for i in range(0, len(seg) - 1, 2):
            code = seg[i] | (seg[i + 1] << 8)
            if code == 0x0000:
                return "".join(out)
            if code == 0xFFFF:
                continue
            out.append(chr(code))
    return "".join(out)


def _lfn_from_pending(pending):
    """把一串 LFN 项拼成完整长文件名。

    **两个都必须做对，缺一个名字就全乱**：

      1. 按 **倒序** 拼。目录里的物理布局是「最后一段在前、第 1 段紧挨短名项」:
             [段3 (seq|=0x40)] [段2] [段1] [短名项]
         所以 `pending` 收到的是 [段3, 段2, 段1]，必须 reversed 之后再拼。
      2. 已删除的 LFN 项首字节被改成 0xE5，序号没了，**但物理顺序没变** ——
         这正是长文件名能完整恢复的原因：不靠序号，靠位置。
    """
    if not pending:
        return ""
    parts = [_lfn_chars(e) for e in reversed(pending)]
    return "".join(parts).replace("\x00", "").strip()


# ───────────────────────── FAT12/16/32 ─────────────────────────

class _FatBase:
    """两种 FAT 的共同接口。子类负责把簇号换算成「卷内绝对偏移」。

    `cluster_used_reliable = False` 是个**实测结论**，不是保守起见：
      · FAT：删文件**不清 FAT 链**（实测删掉 3 个文件后，链 5→6→7→8 完好无损）；
      · exFAT：删文件**不清位图**（实测位图 `ff3f` 里簇 5 仍然标记为占用）。
    也就是说这两种卷的「簇标记」只回答「有没有被登记过」，回答不了
    「有没有被新文件盖掉」。拿它当评级依据，会把**刚删掉、最想恢复**的文件
    一律判成「所在空间已被占用」，等于把用户最需要的结论说反。
    所以评级改走「读数据 + 看文件头」（见 `recovery._confidence`）。
    """

    letter = ""
    kind = "fat"
    cluster = 4096
    bytes_per_sector = 512
    data_start = 0
    cluster_count = 0
    fs = "fat"
    cluster_used_reliable = False

    def read(self, offset, size):
        if self._raw is None:
            raise RuntimeError("卷已经关了")
        return self._raw.read(offset, size)

    def close(self):
        if getattr(self, "_raw", None) is not None:
            try:
                self._raw.close()
            finally:
                self._raw = None

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()

    def _abs_lcn(self, n):
        """FAT/exFAT 的簇号 n（从 2 开始）→ 卷内「绝对簇索引」。

        为什么要换算而不是直接存 n：`recover_one()` / `_sample_data()` 都是用
        `lcn * vol.cluster` 算字节偏移的（NTFS 里 LCN 0 就是卷首）。
        把 n 换算成「数据区起点 + (n-2) 个簇」，上面那些函数就完全不用改。
        data_start 一定是簇大小的整数倍，所以这个换算是精确的。
        """
        return self.data_start // self.cluster + (n - 2)

    def cluster_used(self, lcn):
        """这个绝对簇索引现在是否被占用。不知道就 None（**不能拿 False 冒充空闲**）。"""
        raise NotImplementedError


class FatVolume(_FatBase):
    """FAT12 / FAT16 / FAT32 卷（只读）。

    字段来源全部是 BPB（引导扇区 0x0B 起），不是猜的：
      0x0B 扇区大小 / 0x0D 每簇扇区 / 0x0E 保留扇区 / 0x10 FAT 份数 /
      0x11 根目录项数（FAT12/16）/ 0x13 总扇区 16 位 / 0x16 FAT 大小 16 位 /
      0x20 总扇区 32 位 / 0x24 FAT 大小 32 位 / 0x2C 根目录起始簇（FAT32）。
    """

    def __init__(self, letter):
        from .recovery import _RawVolume, _letter_norm
        self.letter = _letter_norm(letter)
        self.path = "\\\\.\\" + self.letter
        self._raw = _RawVolume(self.letter)
        try:
            self._parse_boot()
        except Exception:
            self.close()
            raise

    def _parse_boot(self):
        from .recovery import RecoverError, boot_kind, _u16, _u32
        bs = self.read(0, 512)
        if len(bs) < 512:
            raise RecoverError(f"{self.letter} 连引导扇区都读不出来")
        kind = boot_kind(bs)
        if kind not in ("fat32", "fat"):
            raise RecoverError(f"{self.letter} 不是 FAT（识别为 {kind}）")
        self.kind = kind
        self.fs = kind
        self.bytes_per_sector = _u16(bs, 0x0B)
        spc = bs[0x0D]
        reserved = _u16(bs, 0x0E)
        nfats = bs[0x10] or 1
        root_entries = _u16(bs, 0x11)
        total16 = _u16(bs, 0x13)
        fat16 = _u16(bs, 0x16)
        total32 = _u32(bs, 0x20)
        fat32 = _u32(bs, 0x24)
        if self.bytes_per_sector not in (512, 1024, 2048, 4096) or not spc:
            raise RecoverError("这个 FAT 的扇区/簇大小不常见，暂不支持")
        self.cluster = self.bytes_per_sector * spc
        self.total_sectors = total16 or total32
        fat_size = fat16 or fat32
        if not self.total_sectors or not fat_size:
            raise RecoverError("FAT 引导扇区里的容量/表大小是 0，卷结构已损坏")
        self.fat_start = reserved * self.bytes_per_sector
        self.fat_bytes = fat_size * self.bytes_per_sector
        if fat16:
            # FAT12/16：根目录是一段固定区域，不在数据区里
            self.kind = "fat16"
            self.root_start = (reserved + nfats * fat_size) * self.bytes_per_sector
            root_secs = (root_entries * 32 + self.bytes_per_sector - 1) // self.bytes_per_sector
            self.root_bytes = root_secs * self.bytes_per_sector
            self.data_start = self.root_start + self.root_bytes
            self.root_cluster = 0
        else:
            # FAT32：根目录是普通簇链
            self.kind = "fat32"
            self.root_cluster = _u32(bs, 0x2C)
            self.root_start = 0
            self.root_bytes = 0
            self.data_start = (reserved + nfats * fat_size) * self.bytes_per_sector
        data_sectors = max(0, self.total_sectors - self.data_start // self.bytes_per_sector)
        self.cluster_count = data_sectors // spc
        if fat16 and self.cluster_count < 4085:
            # FAT 规范按簇数分型（<4085 = FAT12）。分型的意义：FAT12 的 FAT 项是
            # 1.5 字节，读法不同，所以必须说准。
            self.kind = "fat12"
            self.fs = "fat12"
        self._fat_cache = (-1, b"")

    # ---- FAT 表 ----
    def _fat_entry(self, n):
        """第 n 个 FAT 项。0 = 空闲；>=0x0FFFFFF8（FAT32）/0xFFF8（FAT16）= 结束。"""
        if self.kind == "fat32":
            per, bits = 4, 32
        elif self.kind == "fat16":
            per, bits = 2, 16
        else:
            per, bits = 1.5, 12
        if n <= 0:
            return 0
        if self.kind == "fat12":
            off = self.fat_start + n + n // 2
            cstart, cache = self._fat_cache
            if not (cstart <= off and off + 2 <= cstart + len(cache)):
                cache = self.read(off // 512 * 512, 1 << 16)
                cstart = off // 512 * 512
                self._fat_cache = (cstart, cache)
            b = cache[off - cstart:off - cstart + 2]
            if len(b) < 2:
                return 0
            v = b[0] | (b[1] << 8)
            return (v >> 4) if (n & 1) else (v & 0x0FFF)
        off = self.fat_start + int(n * per)
        cstart, cache = self._fat_cache
        if not (cstart <= off and off + per <= cstart + len(cache)):
            cstart = off // 512 * 512
            cache = self.read(cstart, 1 << 16)
            self._fat_cache = (cstart, cache)
        b = cache[off - cstart:off - cstart + int(per)]
        if len(b) < per:
            return 0
        v = int.from_bytes(b, "little")
        return v & (0x0FFFFFFF if bits == 32 else 0xFFFF)

    def cluster_used(self, lcn):
        """绝对簇索引 → FAT 里这一项是不是 0（0 = 空闲）。"""
        n = lcn - self.data_start // self.cluster + 2
        if n < 2 or n >= self.cluster_count + 2:
            return None
        return self._fat_entry(n) != 0

    def _chain(self, start, max_clusters):
        """沿 FAT 链走，返回簇号列表。链断/成环就停（已删除文件的链通常已经没了）。"""
        out, n, seen = [], start, set()
        while 2 <= n < self.cluster_count + 2 and len(out) < max_clusters:
            if n in seen:
                break                     # 成环：FAT 被写坏了，别原地转圈
            seen.add(n)
            out.append(n)
            nxt = self._fat_entry(n)
            if nxt == 0 or nxt >= 0x0FFFFFF7:
                break
            n = nxt
        return out

    # ---- 数据段 ----
    def runs_for(self, first, size, no_fat_chain=False):
        """已删除文件的数据段 → (`runs`, 是否完整)。

        FAT 删除文件时会**把 FAT 链清零**，所以链通常是断的。这时候唯一的办法是
        **假设文件在磁盘上是连续存放的** —— 这是 FAT 恢复的行业惯例，也是它的上限：
        文件一旦被碎片化，拼出来的内容就会从断点开始错。这里如实把 `complete=False`
        交回去，让上层把评级降下来，而不是假装拿到了完整数据。

        `no_fat_chain` 只有 exFAT 用得上，FAT 里忽略。
        """
        need = max(1, (size + self.cluster - 1) // self.cluster) if size else 0
        if not need:
            return [], True
        if first < 2 or first >= self.cluster_count + 2:
            return [], False
        chain = self._chain(first, need + 64)
        if len(chain) >= need:
            runs, a, cnt = [], chain[0], 1
            for c in chain[1:]:
                if c == a + cnt:
                    cnt += 1
                else:
                    runs.append((self._abs_lcn(a), cnt, False))
                    a, cnt = c, 1
                if sum(r[1] for r in runs) + cnt >= need:
                    break
            runs.append((self._abs_lcn(a), cnt, False))
            return runs, True
        # 链断了：连续假设
        n = min(need, self.cluster_count + 2 - first)
        return [(self._abs_lcn(first), n, False)], n >= need

    # ---- 目录遍历 ----
    def _dir_clusters(self, first):
        """一个目录占用的簇（目录本身也可能被删，链断了就按 1 簇 + 连续试探）。"""
        if self.kind != "fat32" and first == 0:
            return None                   # 根目录：固定区域，见 _iter_dirs
        chain = self._chain(first, 1 << 16)
        if chain:
            return chain
        return [first] if 2 <= first < self.cluster_count + 2 else []


class FatImageVolume(FatVolume):
    """打开一份 FAT 整卷镜像（.pciimg）。只换底层读，上层不动。"""

    def __init__(self, path, letter=None, base=0):
        from .recovery import _ImageReader
        self.letter = letter or "镜像"
        self.path = path
        self._raw = _ImageReader(path, base=base)
        self.base = self._raw.base
        try:
            self._parse_boot()
        except Exception:
            self.close()
            raise


# ───────────────────────── exFAT ─────────────────────────

class ExfatVolume(_FatBase):
    """exFAT 卷（只读）。

    和 FAT 的三个关键区别：
      1. 引导扇区布局完全不同（0x40 起是一串 u64/u32，而不是 BPB）；
      2. 目录项是 32 字节的 **entry set**（主项 + 若干 secondary），不是一个项一个文件；
      3. 删除文件只清 **in-use 位（bit7）**，名字/大小/首簇全都留着 —— 所以恢复率高。

    位图（Allocation Bitmap）是判断「簇是不是又给别人了」的准确来源，
    在根目录里找 type=0x81 的项拿它的首簇和长度。找不到就 `cluster_used()` 返回 None，
    评级会退回「无法确认」，绝不拿 False 冒充「空闲」。
    """

    kind = "exfat"
    fs = "exfat"

    def __init__(self, letter):
        from .recovery import _RawVolume, _letter_norm
        self.letter = _letter_norm(letter)
        self.path = "\\\\.\\" + self.letter
        self._raw = _RawVolume(self.letter)
        try:
            self._parse_boot()
        except Exception:
            self.close()
            raise

    def _parse_boot(self):
        from .recovery import RecoverError, boot_kind, _u32, _u64
        bs = self.read(0, 512)
        if len(bs) < 512:
            raise RecoverError(f"{self.letter} 连引导扇区都读不出来")
        if boot_kind(bs) != "exfat":
            raise RecoverError(f"{self.letter} 不是 exFAT")
        bps_shift = bs[108]
        spc_shift = bs[109]
        if not (9 <= bps_shift <= 12) or spc_shift > 25:
            raise RecoverError("exFAT 的扇区/簇大小不常见，暂不支持")
        self.bytes_per_sector = 1 << bps_shift
        self.cluster = 1 << (bps_shift + spc_shift)
        self.fat_start = _u32(bs, 80) * self.bytes_per_sector
        self.fat_bytes = _u32(bs, 84) * self.bytes_per_sector
        self.data_start = _u32(bs, 88) * self.bytes_per_sector
        self.cluster_count = _u32(bs, 92)
        self.root_cluster = _u32(bs, 96)
        self.total_sectors = _u64(bs, 72) // self.bytes_per_sector
        self._fat_cache = (-1, b"")
        self._bitmap = None              # (首簇, 字节数)
        try:
            self._find_bitmap()
        except Exception:                # noqa: BLE001
            self._bitmap = None          # 位图读不到不影响扫名字，只是评级保守

    def _fat_entry(self, n):
        """exFAT 的 FAT 项（4 字节）。NoFatChain 的文件不维护 FAT，这里只用于找位图。"""
        if not self.fat_bytes or n <= 0:
            return 0
        off = self.fat_start + n * 4
        cstart, cache = self._fat_cache
        if not (cstart <= off and off + 4 <= cstart + len(cache)):
            cstart = off // 512 * 512
            cache = self.read(cstart, 1 << 16)
            self._fat_cache = (cstart, cache)
        b = cache[off - cstart:off - cstart + 4]
        return int.from_bytes(b, "little") & 0x0FFFFFFF if len(b) == 4 else 0

    def _find_bitmap(self):
        """在根目录里找 Allocation Bitmap（type=0x81），记下它的首簇和长度。"""
        for ent in self._iter_entry_set(self.root_cluster, max_clusters=64):
            if ent.get("type") == 0x81:
                self._bitmap = (ent["first"], ent["size"])
                return
        self._bitmap = None

    def cluster_used(self, lcn):
        """绝对簇索引 → 位图里这一位（1 = 已用）。位图找不到就 None。"""
        if not self._bitmap:
            return None
        first, length = self._bitmap
        n = lcn - self.data_start // self.cluster      # 位图里的第几位（簇号 - 2）
        if n < 0 or (n >> 3) >= length:
            return None
        if first < 2 or first >= self.cluster_count + 2:
            return None
        base = self.data_start + (first - 2) * self.cluster
        byte_off = base + (n >> 3)
        sec = byte_off // self.bytes_per_sector * self.bytes_per_sector
        b = self.read(sec, self.bytes_per_sector)
        idx = byte_off - sec
        if idx >= len(b):
            return None
        return bool(b[idx] >> (n & 7) & 1)

    # ---- 簇链 / 数据段 ----
    def _chain(self, start, max_clusters):
        out, n, seen = [], start, set()
        while 2 <= n < self.cluster_count + 2 and len(out) < max_clusters:
            if n in seen:
                break
            seen.add(n)
            out.append(n)
            nxt = self._fat_entry(n)
            if nxt == 0 or nxt >= 0x0FFFFFF7:
                break
            n = nxt
        return out

    def runs_for(self, first, size, no_fat_chain=False):
        """exFAT 的已删除文件数据段。

        exFAT 删除时**不清 FAT 链**（只清位图），所以链一般还在 → 能按真实碎片拼回来。
        只有当 secondary 项带 NoFatChain 标志（文件当初是连续分配的）或链断了，
        才退回「连续簇」。`complete` 如实反映是哪种情况。
        """
        need = max(1, (size + self.cluster - 1) // self.cluster) if size else 0
        if not need:
            return [], True
        if first < 2 or first >= self.cluster_count + 2:
            return [], False
        if no_fat_chain:
            n = min(need, self.cluster_count + 2 - first)
            return [(self._abs_lcn(first), n, False)], n >= need
        chain = self._chain(first, need + 64)
        if len(chain) >= need:
            runs, a, cnt = [], chain[0], 1
            for c in chain[1:]:
                if c == a + cnt:
                    cnt += 1
                else:
                    runs.append((self._abs_lcn(a), cnt, False))
                    a, cnt = c, 1
                if sum(r[1] for r in runs) + cnt >= need:
                    break
            runs.append((self._abs_lcn(a), cnt, False))
            return runs, True
        n = min(need, self.cluster_count + 2 - first)
        return [(self._abs_lcn(first), n, False)], n >= need

    # ---- entry set ----
    def _iter_entry_set(self, first_cluster, max_clusters=1 << 16):
        """遍历一个目录的 entry set，产出 dict（含已删除的）。"""
        chain = self._chain(first_cluster, max_clusters)
        if not chain:
            return
        pending = []                      # 待配对的 secondary（stream / name / bitmap）
        for cno in chain:
            off = self.data_start + (cno - 2) * self.cluster
            buf = self.read(off, self.cluster)
            for p in range(0, len(buf) - 31, 32):
                e = buf[p:p + 32]
                t = e[0]
                if t == 0x00:
                    # 0x00 之后理论上全空；目录里可能有空洞，**不要**在这里 break
                    continue
                live = bool(t & 0x80)
                base = t & 0x7F
                if base == 0x05:                  # File entry（主项）
                    pending = [{"type": base, "live": live, "raw": e,
                                "n": int(e[1])}]
                    continue
                if base == 0x01:
                    # Allocation Bitmap（0x81 是 in-use 的样子）。它是**独立项**，
                    # 不属于任何 entry set —— 以前把它塞进 pending 等主项，
                    # 结果位图永远找不到，簇占用判断全变成「不知道」，评级全掉到 risky。
                    yield {"type": 0x81, "live": live, "name": "",
                           "first": int.from_bytes(e[20:24], "little"),
                           "size": int.from_bytes(e[24:32], "little"),
                           "is_dir": False, "mtime": 0, "mtime_text": "",
                           "no_fat": False}
                    continue
                if not pending:
                    continue
                if base in (0x40, 0x41, 0x81, 0x82):
                    pending.append({"type": base, "live": live, "raw": e})
                    # 收齐 SecondaryCount 条就结算
                    if len(pending) >= pending[0].get("n", 0) + 1:
                        yield from self._close_set(pending)
                        pending = []
        if pending:
            yield from self._close_set(pending)

    def _close_set(self, pending):
        """把一个 entry set 拼成条目 dict。已删除的 type 位被清，按 0x40/0x41 认。"""
        head = pending[0]
        item = {"type": head["type"], "live": head["live"], "name": "",
                "first": 0, "size": 0, "is_dir": False, "mtime": 0, "no_fat": False}
        # exFAT File Directory Entry 的字段偏移（微软规范，别凭直觉挪一格）：
        #   0 EntryType / 1 SecondaryCount / 2 SetChecksum(2) / 4 FileAttributes(2)
        #   6 Reserved1(2) / 8 CreateTimestamp(4) / 12 LastModifiedTimestamp(4)
        attr = int.from_bytes(head["raw"][4:6], "little")
        item["is_dir"] = bool(attr & 0x10)
        ts = int.from_bytes(head["raw"][12:16], "little")     # LastModifiedTimestamp
        item["mtime"], item["mtime_text"] = _dos_dt(ts >> 16, ts & 0xFFFF)
        for e in pending[1:]:
            raw = e["raw"]
            if e["type"] == 0x40:                              # Stream extension
                item["no_fat"] = bool(raw[1] & 0x02)
                item["first"] = int.from_bytes(raw[20:24], "little")
                item["size"] = int.from_bytes(raw[24:32], "little")
            elif e["type"] == 0x41:                            # File name
                chars = []
                for i in range(2, 32, 2):
                    code = raw[i] | (raw[i + 1] << 8)
                    if code == 0:
                        break
                    chars.append(chr(code))
                item["name"] = (item.get("name") or "") + "".join(chars)
            elif e["type"] == 0x81:                            # Allocation Bitmap
                item["type"] = 0x81
                item["first"] = int.from_bytes(raw[20:24], "little")
                item["size"] = int.from_bytes(raw[24:32], "little")
        return [item]

    def _dir_clusters(self, first):
        return self._chain(first, 1 << 16)


class ExfatImageVolume(ExfatVolume):
    """打开一份 exFAT 整卷镜像。"""

    def __init__(self, path, letter=None, base=0):
        from .recovery import _ImageReader
        self.letter = letter or "镜像"
        self.path = path
        self._raw = _ImageReader(path, base=base)
        self.base = self._raw.base
        try:
            self._parse_boot()
        except Exception:
            self.close()
            raise


def image_kind(path, base=0):
    """镜像里 `base` 处的卷首是哪种文件系统（fat32 / exfat / ntfs / unknown）。

    ⚠️ 必须走 `vdisk`（4.22.1 修）：以前这里是 `open(path,"rb").seek(base)`，
    按**文件偏移**读。扁平镜像（dd）看不出问题，但 VHD / VHDX / VMDK / QCOW2 / E01
    在文件偏移上的字节不是盘上的字节 —— 于是「VHDX 里的 FAT32 分区」会被判成
    `unknown`，`open_fat_volume` 抛「这不是 FAT/exFAT 卷（识别为 未知）」，
    用户拿着一个完好的镜像却被告知格式不对。调用方明明已经用 `_image_kind_at`
    （走 vdisk）认出是 fat32 了，这里又重新按裸文件读一遍，等于白认。

    判据只有一份：`recovery._image_kind_at`（`open_image_volume` 路由用的就是它）。
    这里再抄一遍「怎么读引导扇区」的话，两边迟早会走岔 —— 这一版就是栽在抄出来的
    第二份上。所以这里只做转发。
    """
    from .recovery import _image_kind_at
    return _image_kind_at(path, base)


def open_fat_volume(letter_or_path, is_image=False, base=0):
    """按引导扇区自动选 FAT 还是 exFAT，返回卷对象。认不出抛 RecoverError。"""
    from .recovery import RecoverError
    probe = letter_or_path
    kind = ""
    if is_image:
        kind = image_kind(probe, base)
    else:
        from .recovery import probe_volume
        kind = (probe_volume(probe) or {}).get("kind") or ""
    if kind == "exfat":
        return (ExfatImageVolume(probe, base=base) if is_image
                else ExfatVolume(probe))
    if kind in ("fat32", "fat"):
        return (FatImageVolume(probe, base=base) if is_image
                else FatVolume(probe))
    raise RecoverError(f"这不是 FAT/exFAT 卷（识别为 {kind or '未知'}）")


def fs_label(vol):
    return {"fat12": "FAT12", "fat16": "FAT16", "fat32": "FAT32",
            "exfat": "exFAT"}.get(getattr(vol, "fs", ""), "FAT")


def is_fat(v):
    """这个对象是不是本模块的卷（给 recovery 分流用，别去 isinstance 私有基类）。"""
    return isinstance(v, _FatBase)


def scan_deleted(vol, limit=3000, budget=120, progress=None, cancel=None):
    """扫 FAT/exFAT 的目录树，列出已删除的文件（**只读**）。

    参数和返回值和 `recovery.scan_deleted()` 保持一致，所以界面上两种文件系统
    走的是同一条路。`vol` 可以是盘符，也可以是已经打开的卷对象。

    预算的用法和 NTFS 那边不一样：NTFS 扫的是「固定大小的 MFT」，这里扫的是
    **整个目录树**（U 盘上可能几十万个目录项），所以按时间 + 取消信号双重兜底，
    到点就带着已有结果返回，并标 `truncated`。
    """
    from .recovery import (_confidence, RecoverError, _letter_norm)

    # `recovery.scan_deleted` 的 limit 语义是「None = 全部」，4.20.0 起那边默认就是 None。
    # 这里以前直接 `limit * 4` 算上限，传 None 立刻 TypeError —— 文档说「参数保持一致」
    # 就得不只是口头一致。`recovery` 那条路会替它换成 20 万，但直接用这个函数就会崩。
    limit = 10 ** 9 if limit is None else int(limit)

    own = not isinstance(vol, _FatBase)
    if own:
        v = open_fat_volume(vol)
    else:
        v = vol
    t0 = time.time()
    budget_s = budget if budget is not None else 120
    try:
        cands = []
        scanned = 0
        truncated = False
        # 广度优先走目录树：[(首簇, 路径, 是否根)]
        queue = [(v.root_cluster, "", True)]
        seen_dirs = set()
        while queue:
            first, parent, is_root = queue.pop(0)
            if cancel and cancel():
                truncated = True
                break
            if time.time() - t0 > budget_s:
                truncated = True
                break
            key = (first, is_root)
            if key in seen_dirs:
                continue
            seen_dirs.add(key)
            try:
                entries = list(_walk_dir(v, first, is_root))
            except (RecoverError, OSError):
                continue
            scanned += len(entries)
            for e in entries:
                if e.get("live"):
                    if e.get("is_dir") and not e.get("name") in (".", ".."):
                        queue.append((e["first"], _join(parent, e["name"]), False))
                    continue
                if e.get("is_dir"):
                    # 已删除的目录：列出来，也进去看看（里面的文件多半还在）
                    queue.append((e["first"], _join(parent, e["name"]), False))
                name = e.get("name") or ""
                if not name or name in (".", ".."):
                    continue
                if e.get("type") == 0x81:          # 位图项，不是文件
                    continue
                size = int(e.get("size") or 0)
                if not e.get("is_dir"):
                    runs, complete = v.runs_for(e["first"], size,
                                                bool(e.get("no_fat")))
                else:
                    runs, complete = [], True
                cands.append({
                    "name": name,
                    "size": size,
                    "mtime": e.get("mtime_text") or "",
                    "_t": e.get("mtime") or 0,
                    "is_dir": bool(e.get("is_dir")),
                    "resident": False,
                    "runs": runs,
                    "compressed": False,
                    "encrypted": False,
                    "data_off": b"",
                    "letter": v.letter,
                    "fs": v.fs,
                    "_whole": complete,
                    "name_lossy": bool(e.get("lossy")),
                    "path": parent or "",
                })
            if progress:
                progress(scanned, max(scanned, len(cands)))
            if len(cands) >= limit * 4:
                truncated = True
                break

        cands.sort(key=lambda c: -c["_t"])
        keep = cands[:max(limit, 200)]
        order = {"good": 0, "dir": 1, "risky": 2, "no_data": 5}
        for it in keep:
            it["confidence"] = _confidence(v, it)
            if not it.get("_whole") and it["confidence"] in ("good", "unknown"):
                # 数据段是「按连续簇猜」的：文件一旦碎片化就会拼错，
                # 不能报 good。这是 FAT 恢复的物理上限，必须写在评级里。
                it["confidence"] = "risky"
        keep.sort(key=lambda c: (order.get(c["confidence"], 9), -c["_t"]))
        items = keep[:limit]
        for it in items:
            it.pop("_t", None)
            it.pop("_whole", None)
            it["path"] = _decorate_path(it.get("path") or "", it)
            it["cluster_count"] = sum(c for _l, c, _sp in it["runs"])

        stats = {
            "letter": v.letter,
            "fs": fs_label(v),
            "records": scanned,
            "scanned": scanned,
            "truncated": truncated,
            "elapsed": round(time.time() - t0, 1),
            "found": len(items),
            "candidates": len(cands),
            "good": sum(1 for i in items if i["confidence"] == "good"),
            "risky": sum(1 for i in items if i["confidence"] == "risky"),
            "dirs": len(seen_dirs),
        }
        return items, stats
    finally:
        if own:
            v.close()


def _join(parent, name):
    return f"{parent}\\{name}" if parent else name


def _decorate_path(parent, item):
    """路径显示：删掉的文件已经不在目录里了，标出来别让人以为还在。"""
    name = item.get("name") or ""
    if parent:
        return f"{parent}\\{name}"
    return name


def _walk_dir(v, first, is_root):
    """遍历一个目录，产出条目（含已删除）。FAT 和 exFAT 各走各的解析。"""
    if isinstance(v, ExfatVolume):
        yield from v._iter_entry_set(first)
        return
    # ---- FAT12/16/32 ----
    if is_root and v.kind != "fat32":
        start, length = v.root_start, v.root_bytes
        buf = v.read(start, length)
        yield from _parse_dir_block(buf, 0)
        return
    chain = v._dir_clusters(first)
    for cno in chain or []:
        off = v.data_start + (cno - 2) * v.cluster
        buf = v.read(off, v.cluster)
        yield from _parse_dir_block(buf, 0)


def _parse_dir_block(buf, _base):
    """解析一块 FAT 目录区（32 字节一项），产出条目 dict。

    已删除项的判定就是**首字节 0xE5**。长文件名的恢复靠 `_lfn_from_pending()`：
    已删除的 LFN 项序号被抹成 0xE5，但物理顺序没变，紧挨短名项的那条是第 1 段。
    """
    pending = []              # 连续的 LFN 项（可能已删除）
    for p in range(0, len(buf) - 31, 32):
        e = buf[p:p + 32]
        first_byte = e[0]
        attr = e[11]
        if first_byte == 0x00:
            pending = []
            continue
        if attr == 0x0F:                       # LFN 项（在用或已删除都是 0x0F）
            pending.append(e)
            continue
        if attr & 0x08:                        # 卷标
            pending = []
            continue
        live = first_byte != 0xE5
        short = _fat_name(e, deleted=not live)
        name = _lfn_from_pending(pending) or short
        # LFN 存在的话名字是完整的（只有序号被抹、字符都在）；只有短名时首字符丢了
        lossy = (not live) and not pending and first_byte == 0xE5
        pending = []
        if not short and not name:
            continue
        # 起始簇：低 16 位在 0x1A，FAT32 的高 16 位在 0x14（FAT12/16 这两位是保留的 0）
        cluster = (int.from_bytes(e[26:28], "little")
                   | (int.from_bytes(e[20:22], "little") << 16))
        size = int.from_bytes(e[28:32], "little")
        mtime, text = _dos_dt(int.from_bytes(e[24:26], "little"),
                              int.from_bytes(e[22:24], "little"))
        yield {"type": 0x85, "live": live, "name": name, "first": cluster,
               "size": size, "is_dir": bool(attr & 0x10), "mtime": mtime,
               "mtime_text": text, "no_fat": False, "lossy": lossy}
