"""
health_assistant.checks.cleanup — 系统盘残留数据盘点

包含: disk.leftover

只做"发现与量化"，不做删除；真正清理走命令行 `health_assistant clean`。
"""

from __future__ import annotations

from .. import leftover
from ..core import Result, Severity, check, cli_cmd, short_path

__all__ = ["disk_leftover"]


@check("disk.leftover", "系统盘残留数据", group="cleanup", order=10,
       desc="无程序认领的目录（疑似卸载残留）+ 注册表幽灵项 + 工具链缓存")
def disk_leftover(ctx):
    res = Result()
    cfg = ctx.config.get("cleanup", {}) or {}
    min_mb = float(cfg.get("min_mb", 10))
    active_days = int(cfg.get("active_days", 45))
    top = int(cfg.get("top", 12))

    try:
        data = leftover.scan(min_mb=min_mb, active_days=active_days)
    except Exception as exc:
        return res.fail(f"扫描失败: {type(exc).__name__}: {exc}")

    items = data["items"]
    leftovers = [i for i in items if i["category"] == "leftover"]
    caches = [i for i in items if i["category"] == "cache"]
    live = [i for i in items if i["category"] == "live"]
    ghosts = data["ghosts"]

    res.kv([
        ("已登记程序", f"{data['programs']} 个"),
        ("扫描目录", f"{data['scanned_dirs']} 个（{len(data['roots'])} 个根目录）"),
        ("活体引用", f"{data['live_paths']} 条（服务/自启/进程 exe）"),
        ("耗时", f"{data['elapsed']}s"),
    ])

    # ---- 疑似卸载残留 ----
    if leftovers:
        reclaim = sum(i["size"] for i in leftovers)
        res.text(f"疑似卸载残留（无程序认领，>={min_mb:g}MB）—— 合计 {leftover.format_size(reclaim)}")
        res.table(
            ["路径", "体积", "闲置", "可信度"],
            [[short_path(i["path"], 50), leftover.format_size(i["size"]),
              f"{i['idle_days']}天", "高" if i["confidence"] == "high" else "中"]
             for i in leftovers[:top]],
            ["l", "r", "r", "l"])
        if len(leftovers) > top:
            res.text(f"  …另有 {len(leftovers) - top} 项，用 `health_assistant clean` 看全量")
        res.add(Severity.WARN,
                f"{len(leftovers)} 个疑似卸载残留目录，占 {leftover.format_size(reclaim)}",
                impact="程序早就卸了，目录还留着；再装新版可能读到旧配置，也白占空间。"
                       "第一条只列清单不删，看过没问题再执行第二条（移到回收站，可还原）",
                # 命令里不放 # 注释：用户整行粘到 cmd 会被当成参数报错
                fix=f"{cli_cmd('clean')}\n{cli_cmd('clean', '--yes')}",
                gain=f"释放 {leftover.format_size(reclaim)}",
                save_bytes=reclaim)

    # ---- 工具链缓存 ----
    if caches:
        reclaim = sum(i["size"] for i in caches)
        res.text(f"工具链缓存（可清理，会重新生成）—— 合计 {leftover.format_size(reclaim)}")
        res.table(["路径", "体积", "说明"],
                  [[short_path(i["path"], 46), leftover.format_size(i["size"]), i["note"]]
                   for i in caches[:top]],
                  ["l", "r", "l"])
        res.add(Severity.INFO,
                f"{len(caches)} 个工具链缓存，可回收约 {leftover.format_size(reclaim)}"
                f"（同一条 clean 命令一起清）", kind="info")

    # ---- 仍在使用的（避免误删说明） ----
    if live:
        res.text("近期仍有写入、已排除的目录（程序应该还在用）")
        res.table(["路径", "体积", "最近活动"],
                  [[short_path(i["path"], 46), leftover.format_size(i["size"]),
                    f"{i['idle_days']}天前"] for i in live[:top]],
                  ["l", "r", "r"])

    # ---- 注册表幽灵 ----
    if ghosts:
        res.text("注册表幽灵项（登记了安装目录但目录已不存在）")
        res.table(["程序", "登记目录"],
                  [[g["name"][:36], short_path(g["location"], 44)] for g in ghosts[:top]],
                  ["l", "l"])
        res.add(Severity.INFO,
                f"{len(ghosts)} 条注册表残留：在「清理」页点「注册表残留」可备份后清除"
                "（只删那一行登记，不释放磁盘空间）")

    if not (leftovers or caches or ghosts):
        res.add(Severity.OK, "未发现明显残留")

    res.metrics.update({
        "leftover_dirs": len(leftovers),
        "leftover_bytes": sum(i["size"] for i in leftovers),
        "cache_dirs": len(caches),
        "cache_bytes": sum(i["size"] for i in caches),
        "ghost_entries": len(ghosts),
        "scanned_dirs": data["scanned_dirs"],
    })
    return res
