"""
health_assistant.planclean — 清理候选的收集（CLI 与 GUI 共用同一套口径）

把「扫描出可清理目录」这一步从命令行交互里拆出来：
  · CLI 用它打印清单、问 yes、调 trash_paths()
  · GUI 用它填表、让用户勾选、再调 trash_paths()

返回结构：
    {
      "cands":        [ {path, name, size, files, idle_days, category, note, confidence} ],
      "profile_paths": set(精确放行的路径)   # 用户目录缓存 + 空点目录
      "empty_paths":  [路径],               # 本次纳入的空点目录
      "scanned":      扫描过的目录数,
      "elapsed":      残留扫描耗时(秒),
      "profile_sec":  用户目录扫描耗时(秒),
      "errors":       [文本],
      "ghosts":       [注册表幽灵项],
      "pres":         profile.scan() 原始结果(可能为 None),
      "counts":       {"dot": n, "appdata": n, "empty_top": n, "empty_cache": n,
                     "empty_user": n},
    }
"""

from __future__ import annotations

import json
import os
import time

from . import leftover, profile, slim

__all__ = ["collect", "write_ledger", "KINDS", "KIND_LABELS", "source_of"]

# 「all」刻意不含瘦身（zombie/userjunk）—— 瘦身一次能到几十 GB，混进「全部」会让
# 用户以为什么都没变就多出 25GB 候选，勾选后一键全删风险太大。要瘦身就明确选它。
KINDS = ("leftover", "cache", "profile", "emptydot", "slim", "zombie",
         "userjunk", "all")
KIND_LABELS = {
    "leftover": "程序残留",
    "cache": "工具链缓存",
    "profile": "用户目录缓存",
    "emptydot": "空目录（点目录 + 空文件夹）",
    "slim": "系统盘瘦身（僵尸 + 无用文件）",
    "zombie": "　└ 僵尸文件",
    "userjunk": "　└ 无用用户文件",
    "all": "全部（残留 + 缓存 + 用户目录 + 空目录）",
}

_WANT = {"leftover": ("leftover",), "cache": ("cache",),
         "profile": (), "emptydot": (), "all": ("leftover", "cache"),
         "slim": (), "zombie": (), "userjunk": ()}

# 根目录的中文名（note 里要写给人看，不能出现 Documents / Desktop 这种英文目录名）
_ROOT_CN = {"Documents": "文档", "Desktop": "桌面", "Downloads": "下载"}

# planclean 的 kind → slim.scan 的 kind
_SLIM_KIND = {"slim": "all", "zombie": "zombie", "userjunk": "userjunk"}


def source_of(item, profile_paths=()):
    """给一行候选标注来源，用于表格「来源」列。"""
    if item.get("origin") == "slim":
        return slim.KIND_LABELS.get(item.get("kind"), "瘦身")
    if item.get("category") == "emptydot":
        return "空点目录"
    if item.get("category") == "emptyuser":
        return "空文件夹"
    if item.get("category") == "manual":
        return "手工指定"
    if item["path"] in profile_paths:
        return "用户目录"
    return "系统残留"


def collect(kind="all", min_mb=10.0, older=0, active_days=45, roots=None,
            cache_repeat=False, include_state=False, paths=None,
            profile_budget=None, empty_budget=None, slim_budget=None,
            slim_older=60, on_log=None):
    """扫描并返回可清理候选。不删除任何东西。"""
    log = on_log or (lambda _s: None)
    want = _WANT.get(kind, ("leftover", "cache"))

    out = {"cands": [], "profile_paths": set(), "empty_paths": [],
           "scanned": 0, "elapsed": 0.0, "profile_sec": 0.0,
           "errors": [], "ghosts": [], "pres": None, "slim": None,
           "counts": {"dot": 0, "appdata": 0, "empty_top": 0, "empty_cache": 0,
                      "empty_user": 0}}

    # ---- 手工指定目录：只统计，不扫描规则 ----
    if paths:
        cands = []
        for p in paths:
            ap = os.path.abspath(p)
            if not os.path.isdir(ap):
                out["errors"].append(f"跳过（不是目录）: {p}")
                log(f"跳过（不是目录）: {p}")
                continue
            size, files, _t = leftover.dir_size(ap)
            cands.append({"path": ap, "name": os.path.basename(ap), "size": size,
                          "files": files, "idle_days": 0, "category": "manual",
                          "note": "手工指定", "confidence": "manual"})
        out["cands"] = cands
        log(f"手工指定 {len(cands)} 个目录")
        return out

    cands = []

    # ---- 系统盘瘦身：僵尸文件 / 无用用户文件 ----
    sk = _SLIM_KIND.get(kind)
    if sk:
        sb = float(slim_budget if slim_budget is not None else 25)
        label = {"all": "僵尸文件 + 无用用户文件", "zombie": "僵尸文件",
                 "userjunk": "无用用户文件"}.get(sk, sk)
        log(f"扫描{label}（预算 {sb:g}s，小于 {min_mb:g}MB 的不单列）…")
        sres = slim.scan(kind=sk, older_days=older or int(slim_older),
                         min_mb=min_mb, budget=sb)
        out["slim"] = sres
        out["errors"].extend(sres["errors"])
        for it in sres["items"]:
            it = dict(it)
            it["origin"] = "slim"
            cands.append(it)
        note = (f"瘦身候选 {len(sres['items'])} 项 / {slim.format_size(sres['total'])}")
        if sres["small_files"]:
            note += (f"；另有 {sres['small_files']} 个零散小文件"
                     f"（{slim.format_size(sres['small_bytes'])}）"
                     f"低于 {min_mb:g}MB 未列出")
        log(note)

    # ---- 程序残留 / 工具链缓存 ----
    if want:
        scan_roots = [(r, "data", "自定义根目录") for r in roots] if roots else None
        log(f"扫描程序残留（阈值 {min_mb:g}MB，活跃判定 {active_days} 天）…")
        data = leftover.scan(min_mb=min_mb, older_days=older or 0,
                             roots=scan_roots, active_days=active_days)
        cands = [i for i in data["items"] if i["category"] in want]
        out["scanned"] = data["scanned_dirs"]
        out["elapsed"] = data["elapsed"]
        out["errors"].extend(data["errors"])
        out["ghosts"] = data["ghosts"]
        log(f"程序残留扫描完成：{data['scanned_dirs']} 个目录 / {data['elapsed']}s，"
            f"命中 {len(cands)} 个")

    # ---- 用户目录点目录 / AppData 缓存 ----
    if kind in ("profile", "all"):
        budget = float(profile_budget if profile_budget is not None else 20)
        log(f"梳理用户目录点目录 / AppData（预算 {budget:g}s）…")
        pres = profile.scan(budget=budget, min_mb=min_mb)
        out["pres"] = pres
        out["profile_sec"] = pres["elapsed"]
        pc = profile.cache_candidates(pres, min_mb=min_mb, allow_repeat=cache_repeat)
        if older:
            pc = [c for c in pc if c["idle_days"] >= older]
        for c in pc:
            c["note"] = (c.get("note") or "") + "  ·  用户目录缓存"
        out["profile_paths"] = {c["path"] for c in pc}
        cands = pc + cands
        out["counts"]["dot"] = len(pres.get("dot") or [])
        out["counts"]["appdata"] = pres["summary"]["appdata_count"]
        log(f"用户目录缓存候选 {len(pc)} 个（点目录 {out['counts']['dot']} 项 / "
            f"AppData {out['counts']['appdata']} 项）")

    # ---- 空点目录 ----
    if kind in ("emptydot", "all"):
        eb = float(empty_budget if empty_budget is not None else 6)
        log(f"查找空的点目录（预算 {eb:g}s）…")
        ed = profile.empty_dots(budget=eb)
        empty_paths = profile.empty_dot_targets(ed, include_state=bool(include_state))
        out["empty_paths"] = empty_paths
        for p in empty_paths:
            cands.append({"path": p, "name": os.path.basename(p) or p,
                          "size": 0, "files": 0, "idle_days": 0,
                          "category": "emptydot", "note": "空的点目录",
                          "confidence": "high"})
        c = ed["counts"]
        out["counts"]["empty_top"] = c["top"]
        out["counts"]["empty_cache"] = c["cache"]
        out["profile_paths"].update(empty_paths)
        log(f"空点目录：顶层空壳 {c['top']} + 缓存类 {c['cache']}"
            + (f" + 状态类 {c['state']}" if include_state else "")
            + f"，本次纳入 {len(empty_paths)} 个"
            + ("（超出预算已截断）" if ed["truncated"] else ""))

        # ---- 文档 / 桌面 / 下载里的空文件夹 ----
        # empty_dots 只看以 . 开头的目录，普通文件夹里的空壳扫不到（用户反馈过的漏项）。
        # 这类默认**不勾选**：里面确实没东西，但文件夹本身可能是用户有意留的位置。
        log(f"查找「文档 / 桌面 / 下载」里的空文件夹（预算 {eb:g}s）…")
        ud = profile.empty_user_dirs(budget=eb)
        for it in ud["items"]:
            p = it["path"]
            cands.append({"path": p, "name": os.path.basename(p) or p,
                          "size": 0, "files": 0, "idle_days": 0,
                          "category": "emptyuser",
                          "note": "「%s」里的空文件夹（里面一个文件都没有）"
                                  % _ROOT_CN.get(it["root"], it["root"]),
                          "confidence": "medium", "default_check": False})
            out["empty_paths"].append(p)
        out["counts"]["empty_user"] = len(ud["items"])
        out["profile_paths"].update(it["path"] for it in ud["items"])
        if ud["items"]:
            log("空文件夹 " + "、".join(f"{i['root']}/{i['rel']}"[:40]
                                     for i in ud["items"][:5])
                + (f" 等 {len(ud['items'])} 个" if len(ud["items"]) > 5 else "")
                + ("（超出预算已截断）" if ud["truncated"] else ""))

    # ---- 去重：程序残留与用户目录扫描会同时命中 AppData\Local\pip 这类目录 ----
    seen, uniq = set(), []
    for c in sorted(cands, key=lambda x: -x["size"]):
        key = os.path.normcase(os.path.abspath(c["path"]))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(c)
    out["cands"] = uniq
    return out


def write_ledger(kind, ok_list, bad):
    """把本次清理的成败逐条落盘（界面/终端输出会滚走，审计要能回查）。

    写入 %APPDATA%\\health_assistant\\clean-ledger-<时间>.json，返回路径或 None。
    """
    base = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "health_assistant")
    try:
        os.makedirs(base, exist_ok=True)
        path = os.path.join(base, time.strftime("clean-ledger-%Y%m%d-%H%M%S.json"))
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({
                "at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "host": os.environ.get("COMPUTERNAME", "?"),
                "kind": kind,
                "ok": [{"path": p, "note": n} for p, n in ok_list],
                "failed": [{"path": p, "reason": r} for p, r in bad],
            }, fh, ensure_ascii=False, indent=1)
        return path
    except OSError:
        return None
