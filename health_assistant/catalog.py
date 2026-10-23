r"""health_assistant.catalog — 扫描结果存档与筛选（一次几小时的扫描不该白做）

两件事
    1. **存档**：`raw` 模式整卷扫一块 2T 的盘要几小时，关掉程序就全没了。
       存成 JSON 之后可以反复打开看、可以带走去别处分析，也可以作为「上次扫到哪」
       的参照（下次只关心新删的东西）。
    2. **筛选**：几千条平铺在表里找不到东西。按类型 / 时间 / 关键字过滤是
       任何恢复软件的标配，这里也做成纯函数，界面只负责传参。

存什么
    item 里的 `runs` 是元组列表，JSON 会变成列表，读回来要转回元组（`recover_one`
    依赖 `for lcn, count, sparse in runs` 这种解包）。驻留条目的 `data_off` 是
    原始字节，用 base64 存 —— 不存的话那些小文件就恢复不了了。

不存什么
    不存盘上任何一个字节的内容（除了驻留条目的 ≤1KB 数据），所以 catalog 很小，
    也不涉及隐私泄露的风险面。
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import os

__all__ = ["MAGIC", "save", "load", "default_path", "filter_items",
           "EXT_GROUPS", "group_of", "summarize"]

MAGIC = "health_assistant-catalog-1"

# 按扩展名分组 —— 界面上「类型」下拉就是这几项
EXT_GROUPS = {
    "image": ("图片", ("jpg", "jpeg", "png", "gif", "bmp", "webp", "heic", "tif",
                       "tiff", "raw", "cr2", "nef", "arw", "dng", "psd")),
    "doc": ("文档", ("doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "txt",
                     "md", "csv", "rtf", "odt", "ods", "wps", "et", "dps")),
    "video": ("视频", ("mp4", "mov", "avi", "mkv", "wmv", "flv", "m4v", "3gp",
                       "mpg", "mpeg", "ts", "rmvb")),
    "audio": ("音频", ("mp3", "wav", "flac", "aac", "m4a", "ogg", "wma", "ape")),
    "archive": ("压缩包", ("zip", "rar", "7z", "tar", "gz", "bz2", "xz", "iso")),
    "code": ("代码/数据", ("py", "c", "cpp", "h", "hpp", "cs", "lua", "js", "ts",
                          "json", "xml", "yml", "yaml", "sql", "html", "css",
                          "ini", "log", "bat", "cmd", "ps1", "sh")),
    "exe": ("程序", ("exe", "dll", "sys", "msi", "apk", "jar", "bin")),
}


def group_of(name):
    """文件名 → 分组键（image / doc / … / other）。"""
    ext = os.path.splitext(str(name or ""))[1].lower().lstrip(".")
    for key, (_label, exts) in EXT_GROUPS.items():
        if ext in exts:
            return key
    return "other"


def group_label(key):
    if key == "other":
        return "其他"
    return EXT_GROUPS.get(key, ("其他", ()))[0]


def _item_out(it):
    """把 item 变成 JSON 友好结构（bytes → base64，tuple → list）。"""
    out = dict(it)
    data = out.pop("data_off", b"")
    if isinstance(data, (bytes, bytearray)) and data:
        out["data_b64"] = base64.b64encode(bytes(data)).decode("ascii")
    runs = out.get("runs")
    if runs:
        out["runs"] = [[int(a), int(b), bool(c)] for a, b, c in runs]
    return out


def _item_in(raw):
    it = dict(raw)
    b64 = it.pop("data_b64", "")
    it["data_off"] = base64.b64decode(b64) if b64 else b""
    runs = it.get("runs") or []
    it["runs"] = [(int(a), int(b), bool(c)) for a, b, c in runs]
    return it


def default_path(folder, letter=""):
    """建议的存档文件名（放在用户选的目录里）。"""
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    src = (letter or "scan").replace(":", "").replace("\\", "")
    return os.path.join(folder, f"扫描结果_{src}_{stamp}.pcirc")


def save(path, items, stats=None, meta=None):
    """把扫描结果写成 JSON。返回落盘路径。"""
    if not path.lower().endswith(".pcirc"):
        path += ".pcirc"
    payload = {
        "magic": MAGIC,
        "saved": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "stats": stats or {},
        "meta": meta or {},
        "count": len(items),
        "items": [_item_out(it) for it in items],
    }
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False)
    os.replace(tmp, path)
    return path


def load(path):
    """读回存档，返回 `(items, stats, info)`。

    `info` 是 `{"saved": 存档时间, "meta": 存的时候带的信息（盘符/扫描方式）}`。
    格式不对抛 ValueError。"""
    with open(path, "r", encoding="utf-8") as fh:
        payload = json.load(fh)
    if not isinstance(payload, dict) or payload.get("magic") != MAGIC:
        raise ValueError("这不是本工具存的扫描结果（格式标记不对）")
    items = [_item_in(x) for x in payload.get("items") or []]
    return items, payload.get("stats") or {}, {
        "saved": payload.get("saved") or "",
        "meta": payload.get("meta") or {}}


def _item_day(it):
    """条目日期（从 mtime 文本里取）。取不到返回 None。"""
    text = str(it.get("mtime") or "")
    if len(text) < 10:
        return None
    try:
        return dt.date.fromisoformat(text[:10])
    except ValueError:
        return None


def filter_items(items, kind="", days=0, keyword=""):
    """按类型 / 时间 / 关键字过滤。

    · `kind`：EXT_GROUPS 的键，或 "other"；空串 = 全部
    · `days`：0 = 不限；1 = 今天；7 / 30 = 最近 N 天（按 mtime 的日期算）
      注意：**日期未知的条目在按时间筛时会被保留**，因为「不知道」不等于「不符合」。
    · `keyword`：在文件名和原路径里找（不区分大小写）
    """
    kw = (keyword or "").strip().lower()
    today = dt.date.today()
    out = []
    for it in items:
        if kind:
            g = group_of(it.get("name") if not it.get("is_dir") else "")
            if it.get("is_dir"):
                if kind != "dir":
                    continue
            elif g != kind:
                continue
        if days:
            d = _item_day(it)
            if d is not None and (today - d).days >= days:
                continue
        if kw and kw not in str(it.get("name") or "").lower() \
                and kw not in str(it.get("path") or "").lower():
            continue
        out.append(it)
    return out


def summarize(items):
    """给界面用的小结：总数 / 各类型数 / 日期范围。"""
    groups = {}
    oldest = newest = None
    for it in items:
        key = "dir" if it.get("is_dir") else group_of(it.get("name"))
        groups[key] = groups.get(key, 0) + 1
        d = _item_day(it)
        if d:
            oldest = d if oldest is None or d < oldest else oldest
            newest = d if newest is None or d > newest else newest
    return {"total": len(items), "groups": groups,
            "oldest": oldest.isoformat() if oldest else "",
            "newest": newest.isoformat() if newest else ""}
