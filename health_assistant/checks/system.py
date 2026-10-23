"""
health_assistant.checks.system — 系统资源类巡检项

包含: system.info / cpu.usage / memory.usage / disk.usage
"""

from __future__ import annotations

import datetime as dt
import os
import platform
import shutil
import textwrap
import time

from .. import metrics
from ..core import (Result, Severity, check, cli_cmd, dur, fb, hostname, pct)

__all__ = ["system_info", "cpu_usage", "memory_usage", "disk_usage",
           "PROC_HEADERS", "PROC_ALIGNS", "proc_rows", "proc_detail_text",
           "proc_detail_rows"]

PROC_HEADERS = ["PID", "进程", "CPU%", "内存", "私有内存", "启动参数 / 路径"]
PROC_ALIGNS = ["r", "l", "r", "r", "r", "l"]


def _clip_mid(text, width):
    """超宽时保留头尾、中间省略 —— 命令行开头是程序、结尾常是关键参数。"""
    text = str(text or "")
    if len(text) <= width:
        return text
    head = max(16, width // 3)
    return text[:head] + " … " + text[-(width - head - 3):]


def proc_rows(snapshot, by="cpu", limit=10, width=64):
    rows = []
    for r in metrics.top_procs(snapshot, by=by, limit=limit):
        rows.append([r["pid"], r["name"][:26], f"{r['cpu']:.1f}", fb(r["mem"]),
                     fb(r.get("mem_priv") or 0),
                     _clip_mid(r.get("cmdline") or r.get("exe") or "-", width)])
    return rows


def proc_detail_rows(snapshot, by="cpu", limit=3):
    return metrics.top_procs(snapshot, by=by, limit=limit)


def proc_detail_text(rows, width=104):
    """把进程摊成多行明细：路径、完整命令行、用户、启动时间、父子关系。"""
    if not rows:
        return ""
    out = []
    for r in rows:
        head = (f"  [{r['pid']}] {r['name']}   CPU {r['cpu']:.1f}%   "
                f"内存 {fb(r['mem'])}（私有 {fb(r.get('mem_priv') or 0)}）")
        out.append(head)
        if r.get("exe"):
            out.append("      路径: " + r["exe"])
        cmd = r.get("cmdline") or r.get("exe") or "-"
        wrapped = textwrap.wrap(cmd, width=width - 12) or ["-"]
        out.append("      命令: " + wrapped[0])
        for line in wrapped[1:]:
            out.append("            " + line)
        extra = [f"PID {r['pid']}", f"父 PID {r['ppid']}"]
        if r.get("user"):
            extra.append(f"用户 {r['user']}")
        if r.get("started"):
            extra.append("启动 " + dt.datetime.fromtimestamp(r["started"]).strftime("%m-%d %H:%M"))
        if r.get("status"):
            extra.append(r["status"])
        out.append("      " + " · ".join(extra))
    return "\n".join(out)


# ───────────────────────────── 系统概况 ─────────────────────────────

@check("system.info", "系统概况", group="system", order=10,
       desc="主机名 / OS / 权限 / 运行时长 / 系统盘余量")
def system_info(ctx):
    res = Result()

    rows = [
        ("计算机名", hostname()),
        ("当前用户", os.environ.get("USERNAME", "?")),
        ("权限", "管理员" if ctx.admin else "普通用户（部分项受限）"),
        ("操作系统", f"{platform.system()} {platform.release()} (build {platform.version()})"),
        ("架构", platform.machine()),
    ]

    if metrics.HAS_PSUTIL:
        try:
            boot_ts = metrics.psutil.boot_time()
            rows.append(("开机时间", dt.datetime.fromtimestamp(boot_ts).strftime("%Y-%m-%d %H:%M:%S")))
            rows.append(("已运行", dur(time.time() - boot_ts)))
            res.metrics["uptime_sec"] = int(time.time() - boot_ts)
        except Exception:
            pass

    res.kv(rows)

    # 系统盘余量
    try:
        drive = os.environ.get("SystemDrive", "C:") + "\\"
        u = shutil.disk_usage(drive)
        free_gb = u.free / 1024 ** 3
        min_gb = float(ctx.thr("disk_free_min_gb", 5))
        res.metrics["system_drive_free_gb"] = round(free_gb, 1)
        if free_gb < min_gb:
            res.add(Severity.WARN, f"系统盘 {drive} 剩余 {fb(u.free)}，低于阈值 {min_gb:g}GB")
        else:
            res.add(Severity.OK, f"系统盘 {drive} 剩余 {fb(u.free)}")
    except Exception:
        pass

    if not ctx.admin:
        res.add(Severity.INFO, "非管理员权限：服务 / 全部端口 / 事件日志等项可能不完整")

    return res


# ───────────────────────────── CPU ─────────────────────────────

@check("cpu.usage", "CPU 使用分析", group="system", order=20,
       desc="总体与每核使用率、上下文切换、占用 TOP")
def cpu_usage(ctx):
    res = Result()
    if not metrics.HAS_PSUTIL:
        return res.fail("未安装 psutil，无法采集 CPU 数据")

    ps = metrics.psutil
    try:
        phys = ps.cpu_count(logical=False)
        logi = ps.cpu_count(logical=True)
        kv = [("核心数", f"{phys} 物理核 / {logi} 逻辑核")]
        try:
            f = ps.cpu_freq()
            if f and f.current:
                kv.append(("当前频率", f"{f.current:.0f} MHz" + (f"（最大 {f.max:.0f}）" if f.max else "")))
        except Exception:
            pass
        res.kv(kv)
    except Exception:
        pass

    try:
        per = ps.cpu_percent(interval=0.8, percpu=True)
    except Exception:
        per = []
    total = sum(per) / len(per) if per else 0.0

    # 每核分组（最多 16 行）
    if per:
        step = max(1, -(-len(per) // 16))
        bars = []
        for i in range(0, len(per), step):
            chunk = per[i:i + step]
            label = f"core{i}" if len(chunk) == 1 else f"core{i}-{i + len(chunk) - 1}"
            avg = sum(chunk) / len(chunk)
            bars.append((label, f"{avg:.1f}%", avg / 100.0))
        res.bars(bars, width=22)

    warn, err = float(ctx.thr("cpu_warn", 75)), float(ctx.thr("cpu_error", 90))
    res.metrics.update({"cpu_total": round(total, 1),
                        "cpu_cores_logical": per and len(per) or 0})

    # 只看总负载和「单个进程吃满」—— 单核瞬时 >85% 是正常波动，报了只会制造噪声
    pcfg = ctx.config.get("proc", {}) or {}
    top_n = int(pcfg.get("top", 10))
    det_n = int(pcfg.get("detail", 5))
    width = int(pcfg.get("cmdline_width", 64))
    snap = ctx.cached("proc.snap", lambda: metrics.proc_snapshot(sample=0.4))

    hog = [r for r in metrics.top_procs(snap, "cpu", 5)
           if r["cpu"] >= float(ctx.thr("proc_cpu_warn", 35))]
    if hog:
        p = hog[0]
        res.add(Severity.WARN,
                f"{p['name']} 单独占用 CPU {p['cpu']:.0f}%（PID {p['pid']}）",
                impact=f"一个进程吃掉 {p['cpu']:.0f}% CPU，会让其他程序卡顿、风扇狂转。"
                       f"先跑第一条看它到底是什么，确认没用再跑第二条终止",
                fix=f"{cli_cmd('proc', p['pid'])}\n{cli_cmd('kill', p['pid'])}",
                gain="CPU 占用下降")
    elif total >= err:
        res.add(Severity.ERROR, f"CPU 总体 {total:.1f}%，达到异常阈值 {err:g}%",
                impact="整体 CPU 打满，操作会明显卡顿",
                fix=cli_cmd("proc"))
    elif total >= warn:
        res.add(Severity.WARN, f"CPU 总体 {total:.1f}%，超过警告阈值 {warn:g}%",
                impact="CPU 偏高，多任务时会感觉变慢",
                fix=cli_cmd("proc"))
    else:
        res.add(Severity.OK, f"CPU 总体 {total:.1f}%，正常")

    try:
        t = ps.cpu_times()
        res.kv([("累计时间", f"user {t.user:.0f}s / system {t.system:.0f}s / idle {t.idle:.0f}s")])
    except Exception:
        pass

    try:
        s1 = ps.cpu_stats()
        time.sleep(0.4)
        s2 = ps.cpu_stats()
        res.kv([
            ("上下文切换", f"{(s2.ctx_switches - s1.ctx_switches) / 0.4:,.0f} 次/秒"),
            ("中断", f"{(s2.interrupts - s1.interrupts) / 0.4:,.0f} 次/秒"),
        ])
    except Exception:
        pass

    res.text(f"CPU 占用 TOP {top_n}（带启动参数）")
    res.table(PROC_HEADERS, proc_rows(snap, "cpu", top_n, width), PROC_ALIGNS)
    detail = proc_detail_rows(snap, "cpu", det_n)
    if detail:
        res.text("占用最高进程的完整信息")
        res.text(proc_detail_text(detail))
    res.metrics["proc_total"] = len(snap)
    return res


# ───────────────────────────── 内存 ─────────────────────────────

@check("memory.usage", "内存使用分析", group="system", order=30,
       desc="物理内存 / 提交(Commit) / 页面文件 / 占用 TOP")
def memory_usage(ctx):
    res = Result()
    ms = metrics.memory_status()

    if ms:
        used = ms["total_phys"] - ms["avail_phys"]
        load = pct(used, ms["total_phys"])
        commit_used = ms["total_commit"] - ms["avail_commit"]
        res.kv([
            ("物理内存", f"总 {fb(ms['total_phys'])} / 已用 {fb(used)} ({load:.1f}%) "
                        f"/ 可用 {fb(ms['avail_phys'])}"),
            ("提交(Commit)", f"上限 {fb(ms['total_commit'])} / 已提交 {fb(commit_used)} "
                            f"({pct(commit_used, ms['total_commit']):.1f}%)"),
        ])
        res.metrics.update({
            "mem_percent": round(load, 1),
            "mem_avail_gb": round(ms["avail_phys"] / 1024 ** 3, 2),
        })

        warn, err = float(ctx.thr("mem_warn", 80)), float(ctx.thr("mem_error", 90))
        if load >= err or ms["avail_phys"] < 512 * 1024 ** 2:
            res.add(Severity.ERROR, f"物理内存吃紧：已用 {load:.1f}%，仅剩 {fb(ms['avail_phys'])}")
        elif load >= warn:
            res.add(Severity.WARN, f"物理内存偏高：已用 {load:.1f}%，超过阈值 {warn:g}%")
        else:
            res.add(Severity.OK, f"物理内存正常：已用 {load:.1f}%")
    elif metrics.HAS_PSUTIL:
        v = metrics.psutil.virtual_memory()
        res.kv([("物理内存", f"总 {fb(v.total)} / 已用 {fb(v.used)} ({v.percent:.1f}%)")])
        res.metrics["mem_percent"] = v.percent
        res.add(Severity.OK if v.percent < ctx.thr("mem_warn", 80) else Severity.WARN,
                f"物理内存使用率 {v.percent:.1f}%（GlobalMemoryStatusEx 不可用，口径退化为 psutil）")
    else:
        return res.fail("既无 GlobalMemoryStatusEx 也无 psutil，无法采集内存数据")

    if metrics.HAS_PSUTIL:
        try:
            s = metrics.psutil.swap_memory()
            res.kv([("页面文件", f"总 {fb(s.total)} / 已用 {fb(s.used)} ({s.percent:.1f}%)")])
            res.metrics["pagefile_percent"] = s.percent
        except Exception:
            pass

    pcfg = ctx.config.get("proc", {}) or {}
    top_n = int(pcfg.get("top", 10))
    det_n = int(pcfg.get("detail", 5))
    width = int(pcfg.get("cmdline_width", 64))
    snap = ctx.cached("proc.snap", lambda: metrics.proc_snapshot(sample=0.4))
    res.text(f"内存占用 TOP {top_n}（带启动参数）")
    res.table(PROC_HEADERS, proc_rows(snap, "mem", top_n, width), PROC_ALIGNS)
    detail = proc_detail_rows(snap, "mem", det_n)
    if detail:
        # 同一进程常有好几个实例（浏览器/编辑器），按名字合并后再给结论
        grouped = {}
        for r in metrics.top_procs(snap, "mem", 60):
            g = grouped.setdefault(r["name"], {"n": 0, "mem": 0, "priv": 0})
            g["n"] += 1
            g["mem"] += r["mem"]
            g["priv"] += r.get("mem_priv") or 0
        g_rows = sorted([(v["mem"], k, v) for k, v in grouped.items()], reverse=True)[:8]
        res.text("按进程名合并的内存占用（多实例程序看这个更准）")
        res.table(["进程", "实例数", "物理内存", "提交内存"],
                  [[k[:28], f"{v['n']}", fb(v["mem"]), fb(v["priv"])]
                   for _m, k, v in g_rows],
                  ["l", "r", "r", "r"])
        res.text("占用最高进程的完整信息")
        res.text(proc_detail_text(detail))
    res.metrics["proc_total"] = len(snap)
    return res


# ───────────────────────────── 磁盘 ─────────────────────────────

@check("disk.usage", "磁盘巡检", group="system", order=40,
       desc="分区容量、使用率阈值、磁盘 IO")
def disk_usage(ctx):
    res = Result()
    if not metrics.HAS_PSUTIL:
        return res.fail("未安装 psutil，无法采集磁盘数据")

    parts = metrics.disk_usage_rows()
    if not parts:
        return res.fail("未取到任何分区信息")

    rows = []
    worst = Severity.OK
    warn = float(ctx.thr("disk_warn", 80))
    err = float(ctx.thr("disk_error", 90))
    min_free = float(ctx.thr("disk_free_min_gb", 5)) * 1024 ** 3

    for p in parts:
        r = pct(p["used"], p["total"])
        rows.append([p["device"], p["fstype"][:10], fb(p["total"]),
                     fb(p["used"]), fb(p["free"]), f"{r:.1f}%"])
        if r >= err or p["free"] < min_free:
            worst = Severity.worst(worst, Severity.ERROR)
            res.add(Severity.ERROR, f"{p['device']} 空间告急：使用率 {r:.1f}%，剩余 {fb(p['free'])}")
        elif r >= warn:
            worst = Severity.worst(worst, Severity.WARN)
            res.add(Severity.WARN, f"{p['device']} 空间偏紧：使用率 {r:.1f}%")

    res.table(["盘符", "类型", "总容量", "已用", "可用", "使用率"],
              rows, ["l", "l", "r", "r", "r", "r"])
    if worst == Severity.OK:
        res.add(Severity.OK, f"{len(parts)} 个分区容量充足")

    io = metrics.disk_io()
    if io:
        io_rows = [[name[:20], fb(c.read_bytes), fb(c.write_bytes),
                    f"{c.read_count:,}", f"{c.write_count:,}"]
                   for name, c in list(io.items())[:8]]
        res.table(["磁盘", "累计读", "累计写", "读次数", "写次数"],
                  io_rows, ["l", "r", "r", "r", "r"])

    res.metrics["partitions"] = len(parts)
    res.metrics["min_free_gb"] = round(min(p["free"] for p in parts) / 1024 ** 3, 1)
    return res


@check("disk.health", "硬盘健康", group="system", order=45,
       desc="物理磁盘的 SMART 健康状态、磨损、温度、通电时间（只读，不会去修）")
def disk_health(ctx):
    """硬盘快坏的时候，症状就是「什么都查不出原因的卡」—— 这项专门看那个。

    只读：不调任何 SMART 写入、不跑 chkdsk、不「修复」坏道。
    该换盘就换盘、该备份就备份，工具只负责让人提前知道。
    """
    res = Result()
    from .. import smart

    try:
        ds = smart.disks()
    except Exception as exc:
        return res.fail(f"{type(exc).__name__}: {exc}")
    if not ds:
        res.add(Severity.INFO, "读不到物理磁盘的健康信息", kind="info")
        res.text("这台机器可能不支持（很旧的系统，或者磁盘控制器没暴露 SMART）。\n"
                 "这种情况请用厂商工具看：三星 Magician、Intel MAS、CrystalDiskInfo。")
        return res

    rows, notes = [], []
    worst = Severity.OK
    for d in ds:
        sev, why = smart.verdict(d)
        letters = "、".join(d["letters"]) or "未分配盘符"
        rows.append([
            letters, d["name"][:30], f"{d['media']}/{d['bus']}", fb(d["size"]),
            d["health"],
            "—" if d["wear"] is None else f"{d['wear']:.0f}%",
            "—" if d["temp"] is None else f"{d['temp']:.0f}℃",
            "—" if d["hours"] is None else f"{d['hours']:.0f} 小时",
        ])

        # 每块盘都单独给一条结论 —— 表格默认折在「详细数据」里，
        # 而「哪块盘什么状态」恰恰是这项检查的主内容，不能让人去点开才看到
        bits = [f"{d['media']}/{d['bus']}", fb(d["size"])]
        if d["wear"] is not None:
            bits.append(f"磨损 {d['wear']:.0f}%")
        if d["temp"] is not None:
            bits.append(f"{d['temp']:.0f}℃")
        if d["hours"] is not None:
            bits.append(f"通电 {d['hours']:.0f} 小时")
        detail = "　·　".join(bits)
        if sev == "ok":
            res.add(Severity.OK, f"{letters}　{d['name']}　{detail}　{why}",
                    kind="info")
        else:
            worst = Severity.worst(
                worst, Severity.ERROR if sev == "error" else Severity.WARN)
            res.add(Severity.ERROR if sev == "error" else Severity.WARN,
                    f"{letters}　{d['name']}　{detail}　—　{why}",
                    impact="硬盘是唯一坏了会丢数据的部件，等它彻底坏掉就来不及了。",
                    gain="提前备份 + 换盘，避免数据丢失" if sev == "error" else "早点备份",
                    kind="problem")
        # 读错误计数是「有过坏道」的旁证；为 0 或读不到就不提
        if d["read_err"]:
            notes.append(f"{letters} 累计记录过 {d['read_err']:.0f} 次读错误"
                         f"（偶发不一定是坏事，持续增长才是）")

    res.table(["盘符", "型号", "类型", "容量", "健康", "磨损", "温度", "通电"],
              rows, ["l", "l", "l", "r", "l", "r", "r", "r"])

    if worst == Severity.OK:
        total_h = [d["hours"] for d in ds if d["hours"]]
        extra = f"，最长通电 {max(total_h):.0f} 小时（约 {max(total_h) / 24 / 365:.1f} 年）" if total_h else ""
        res.summary = f"{len(ds)} 块硬盘健康状态正常{extra}"
    if notes:
        res.text("\n".join(notes))
    res.text("「磨损」是 SSD 的寿命消耗百分比（100% 就是写满了设计寿命），"
             "机械盘不报这一项；「温度」NVMe 一般有，部分 SATA 盘不给。\n"
             "显示「—」是真的读不到，不是 0 —— 这块盘该看的数据用系统接口拿不到。")

    res.metrics["disks"] = len(ds)
    res.metrics["disks_bad"] = sum(1 for d in ds if smart.verdict(d)[0] != "ok")
    return res
