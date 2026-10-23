r"""health_assistant.lznt1 — LZNT1 解压（NTFS 压缩用的就是它）

为什么需要自己写
    NTFS 压缩文件在盘上存的是 **LZNT1 压缩过的簇**。读出来不解压的话，
    导出的是一个打不开的垃圾文件 —— 所以 4.14 之前这类文件是直接「拒收」的。
    要真的能恢复，就得把 LZNT1 解压实现出来。

格式（[MS-XCA] 2.5 / 3.1，别凭印象改）
    · 压缩数据按 **4KB chunk** 切开；每个 chunk 前面 2 字节头：
        低 12 位 = 后面跟的字节数 - 1；
        bit15 = 1 表示这个 chunk 压缩过，0 表示原样存放；
    · 压缩 chunk 内部：先 1 字节 flag（8 个 token 的标志，LSB 优先），
        flag 位 = 0 → 后面跟 1 个原样字节；
        flag 位 = 1 → 后面跟 2 字节（小端）的 16 位值 v，按当前输出位置拆成
        (offset, length)：
            obits = max(bit_length(位置 - 1), 4)，最大 12
            lbits = 16 - obits
            offset = (v >> lbits) + 1        ← **offset 在【高】位**
            length = (v & ((1 << lbits) - 1)) + 3
        也就是**位置越大，offset 用的位越多**（能回看得更远），length 位相应变少。

    高低位这一条实测踩过：写反了照样能跑、长度也对，但内容从第一个压缩对开始
    变成 `\\x9c\\x9f\\x9c\\x9f…` 这种周期串（offset 被解成 2），而且**单测自己的
    构造样本不会报错** —— 因为样本也是按错的理解构造的。只能拿真文件比对。
    · 引用不能跨 chunk（每个 chunk 独立解），所以位置要从 chunk 起点算。
"""

from __future__ import annotations

__all__ = ["decompress_chunk", "decompress", "CHUNK"]

CHUNK = 4096


def decompress_chunk(src, out, start, limit):
    """解一个 chunk，追加到 `out`（不返回新对象，NTFS 一个文件动辄几百 MB）。

    `start` 是这个 chunk 在 `out` 里的起始下标 —— 「位置」必须按 chunk 内偏移算，
    用全局位置会让 offset 位宽算错，解出来长度对、内容错。
    """
    i = 0
    n = len(src)
    while i < n and len(out) < limit:
        flags = src[i]
        i += 1
        for bit in range(8):
            if i >= n or len(out) >= limit:
                return
            if not (flags >> bit) & 1:
                out.append(src[i])
                i += 1
                continue
            if i + 1 >= n:
                return
            val = src[i] | (src[i + 1] << 8)
            i += 2
            pos = len(out) - start
            if pos <= 0:
                return                      # 开头就引用自己：数据坏了
            obits = min(max((pos - 1).bit_length(), 4), 12)
            lbits = 16 - obits
            offset = (val >> lbits) + 1
            length = (val & ((1 << lbits) - 1)) + 3
            if offset > pos:
                return                      # 往回看不存在的字节：截断在这里
            src_pos = len(out) - offset
            for _ in range(length):
                out.append(out[src_pos])
                src_pos += 1
                if len(out) >= limit:
                    return


def decompress(data, expected=None):
    """解压一整段 LZNT1 数据（自带 chunk 头）。`expected` 给定时到量就停。"""
    out = bytearray()
    pos = 0
    n = len(data)
    while pos + 2 <= n:
        head = data[pos] | (data[pos + 1] << 8)
        pos += 2
        size = (head & 0x0FFF) + 1
        chunk = data[pos:pos + size]
        pos += size
        if not chunk:
            break
        if head & 0x8000:
            start = len(out)
            decompress_chunk(chunk, out, start, expected or (len(out) + CHUNK))
        else:
            # 没压缩的 chunk：原样搬（最多一个 chunk）
            out.extend(chunk[:CHUNK] if expected is None
                       else chunk[:max(0, expected - len(out))])
        if expected is not None and len(out) >= expected:
            break
    return bytes(out if expected is None else out[:expected])
