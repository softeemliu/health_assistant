"""
health_assistant.checks.ops — 运维类巡检项

包含: process.top / service.health / startup.items / eventlog.errors
"""

from __future__ import annotations

import os
import xml.etree.ElementTree as ET

from .. import metrics
from ..core import Kind, Result, Severity, check, cli_cmd, run_cmd
from .system import (PROC_ALIGNS, PROC_HEADERS, proc_detail_rows,
                     proc_detail_text, proc_rows)

__all__ = ["process_top", "service_health", "startup_items", "eventlog_errors"]


# ───────────────────────────── 进程 ─────────────────────────────

@check("process.top", "进程 TOP", group="ops", order=10,
       desc="CPU / 内存占用最高的进程，含完整启动参数与父进程")
def process_top(ctx):
    res = Result()
    if not metrics.HAS_PSUTIL:
        return res.fail("未安装 psutil，无法采集进程数据")

    pcfg = ctx.config.get("proc", {}) or {}
    top_n = int(pcfg.get("top", 10))
    det_n = int(pcfg.get("detail", 5))
    width = int(pcfg.get("cmdline_width", 64))

    snap = ctx.cached("proc.snap", lambda: metrics.proc_snapshot(sample=0.5))
    if not snap:
        return res.fail("进程快照为空（可能权限不足）")

    cpu_top = metrics.top_procs(snap, "cpu", 1)
    mem_top = metrics.top_procs(snap, "mem", 1)

    res.text("按 CPU 排序")
    res.table(PROC_HEADERS, proc_rows(snap, "cpu", top_n, width), PROC_ALIGNS)
    res.text("按内存排序")
    res.table(PROC_HEADERS, proc_rows(snap, "mem", top_n, width), PROC_ALIGNS)

    detail = proc_detail_rows(snap, "cpu", det_n)
    res.text("CPU TOP 进程明细（路径 / 完整命令行 / 用户 / 启动时间 / 父进程）")
    res.text(proc_detail_text(detail))

    res.kv([
        ("进程总数", f"{len(snap)}"),
        ("CPU 最高", f"{cpu_top[0]['name']} (PID {cpu_top[0]['pid']}, {cpu_top[0]['cpu']:.1f}%)"
                     if cpu_top else "-"),
        ("内存最高", f"{mem_top[0]['name']} (PID {mem_top[0]['pid']}, "
                     f"{mem_top[0]['mem'] / 1024 ** 2:.0f}MB)" if mem_top else "-"),
        ("终止进程", f"用 kill 子命令，如 {cli_cmd('kill', '1234')}"
                     f" 或 {cli_cmd('kill', 'notepad', '--tree')}"),
    ])
    res.metrics["process_count"] = len(snap)
    res.add(Severity.INFO, f"共 {len(snap)} 个进程")
    return res


# ───────────────────────────── 服务 ─────────────────────────────

# 这些服务无论如何都该在跑
MUST_RUN = {
    "eventlog": "事件日志",
    "winmgmt": "WMI 管理",
    "bfe": "防火墙基础过滤引擎",
    "mpssvc": "Windows 防火墙",
}

# 这些按「自动启动」配置时才该在跑；manual（按需启动）停了是正常的。
# gpsvc 刻意不收：非域电脑上它按需启动、用完就停，属正常行为，收了会反复误报。
CHECK_AUTO = {
    "windefend": "Defender 实时防护",
    "wuauserv": "Windows Update",
    "wscsvc": "安全中心监视",
    "securityhealthservice": "安全中心托盘",
}


@check("service.health", "服务巡检", group="ops", order=20,
       desc="关键系统服务是否在跑（按需启动的服务不误报）")
def service_health(ctx):
    res = Result()
    svcs = metrics.service_list()
    if not svcs:
        return res.fail("枚举服务失败（需要管理员权限）")

    by_name = {n.lower(): (n, d, st, s) for n, d, st, s in svcs}
    running = sum(1 for _n, _d, st, _s in svcs if st == "running")

    rows, broken = [], []
    for key, label in MUST_RUN.items():
        hit = by_name.get(key)
        if not hit:
            continue
        n, d, st, s = hit
        ok = st == "running"
        rows.append([label, n, f"{st} / {s}", "正常" if ok else "未运行"])
        if not ok:
            broken.append((n, label))

    for key, label in CHECK_AUTO.items():
        hit = by_name.get(key)
        if not hit:
            continue
        n, d, st, s = hit
        auto = s.startswith("auto")
        ok = (st == "running") or (not auto)   # manual 停了属正常
        rows.append([label, n, f"{st} / {s}",
                     "正常" if ok else "自动启动却没在跑"])
        if not ok:
            broken.append((n, label))

    res.table(["关键服务", "服务名", "状态 / 启动类型", "判断"], rows,
              ["l", "l", "l", "l"])
    res.kv([("服务总数", f"{len(svcs)}  运行中 {running}")])

    if broken:
        items = "、".join(lb for _n, lb in broken)
        first = broken[0][0]
        res.add(Severity.WARN,
                f"{len(broken)} 个关键服务该在跑却没跑：{items}",
                impact="这些服务管着防火墙、补丁、实时防护或组策略，停着等于少了防护",
                fix=(f'powershell -Command "Start-Service {first}"\n'
                     f'powershell -Command "Get-Service {first} | Format-List *"\n'
                     '（第一条启动它，多个服务就把名字换掉重复执行；'
                     '第二条看它的依赖项和失败原因）'),
                gain="恢复安全防护")
    else:
        res.add(Severity.OK, "关键系统服务全部在运行")

    # 非关键服务只做留档：不在清单里制造焦虑
    loose = [(n, d, st) for n, d, st, s in svcs
             if s.startswith("auto") and st != "running"
             and n.lower() not in MUST_RUN and n.lower() not in CHECK_AUTO]
    if loose:
        res.text(f"另有 {len(loose)} 个自动启动但未运行的服务（如 "
                 f"{'、'.join(n for n, _d, _s in loose[:4])}…）。这类多为按需触发，"
                 "用到时才启动，不必强行拉起。")
        if any(n.lower() == "gpsvc" for n, _d, _s in loose):
            res.text("其中「组策略客户端(gpsvc)」在非域电脑上按需启动、用完自动停止，"
                     "属 Windows 正常行为，不是故障。")
        res.table(["按需服务", "显示名", "状态"],
                  [[n[:26], d[:36], st] for n, d, st in loose[:20]], ["l", "l", "l"])

    res.metrics.update({"services": len(svcs), "services_running": running,
                        "critical_down": len(broken)})
    return res


# ───────────────────────────── 自启项 ─────────────────────────────

@check("startup.items", "开机自启项", group="ops", order=30,
       desc="注册表 Run/RunOnce 与启动目录（可禁用 / 恢复，不删注册表）")
def startup_items(ctx):
    res = Result()
    from .. import startup

    try:
        its = startup.items()
    except Exception as exc:
        return res.fail(f"{type(exc).__name__}: {exc}")

    if not its:
        res.add(Severity.OK, "未发现开机自启项")
        res.metrics["startup_count"] = 0
        return res

    rows = []
    for it in its:
        state = "—" if not it["can_toggle"] else ("已启用" if it["enabled"] else "已停用")
        where = "启动文件夹" if it["kind"] == "startupdir" else it["source"]
        rows.append([where, it["name"][:30], state, it["cmd"][:70]])
    res.table(["位置", "名称", "状态", "命令/路径"], rows, ["l", "l", "l", "l"])

    enabled = [i for i in its if i["can_toggle"] and i["enabled"]]
    disabled = [i for i in its if not i["enabled"]]
    broken = [i for i in its if i["exists"] is False]
    third = [i for i in enabled if not startup._is_system(i["name"])]

    lines = [f"共 {len(its)} 项：正在开机运行 {len(enabled)} 项"
             f"{f'，已停用 {len(disabled)} 项' if disabled else ''}"
             f"{f'，断链 {len(broken)} 个' if broken else ''}。"]
    if third:
        names = "、".join(i["name"] for i in third[:8])
        lines.append(f"其中第三方 {len(third)} 个：{names}"
                     f"{'…' if len(third) > 8 else ''}")
    if broken:
        lines.append("断链的那几个（" + "、".join(i["name"] for i in broken[:5])
                     + "）指向的程序已经不在了，关掉它们开机最快见效。")
    res.text("\n".join(lines))

    if broken or len(third) > 3:
        target = (broken or third)[0]
        if broken:
            head = ("断链自启项 " + "、".join(i["name"] for i in broken[:3])
                    + ("…" if len(broken) > 3 else "") + f"，指向的程序已经不在"
                    + (f"；另有 {len(third)} 个第三方自启项" if third else ""))
        else:
            head = f"第三方自启项 {len(third)} 个，可按需关掉"
        res.add(Severity.INFO if not broken else Severity.WARN, head,
                impact="开机时每个自启项都要启动一次，多了会明显拖慢开机。",
                fix=cli_cmd("startup", "--disable", f'"{target["name"]}"', "-y"),
                gain=f"关掉 {len(broken)} 个断链项" if broken else "开机快一点",
                kind=Kind.PROBLEM if broken else Kind.NOTICE)
        res.text("在界面上点「管理自启项」可以直接勾选停用 —— 只是标记为不启动，"
                 "想恢复随时再打开，不会删掉任何注册表项。")
    else:
        res.add(Severity.OK, f"自启项 {len(its)} 个，没什么要处理的", kind="info")

    res.metrics["startup_count"] = len(its)
    res.metrics["startup_enabled"] = len(enabled)
    res.metrics["startup_disabled"] = len(disabled)
    res.metrics["startup_broken"] = len(broken)
    res.metrics["startup_third"] = len(third)
    return res


# ───────────────────────────── 事件日志 ─────────────────────────────

def _strip_ns(tag):
    return tag.split("}", 1)[-1]


def _event_errors(log="System", count=6):
    """wevtutil /f:xml —— 避开 /f:text 的本地化字段名。"""
    q = "*[System[(Level=1 or Level=2)]]"
    code, out = run_cmd(["wevtutil", "qe", log, f"/c:{count}", "/rd:true", "/f:xml", f"/q:{q}"],
                        timeout=25, encoding="utf-8")
    if code != 0 or not (out or "").strip():
        return []
    try:
        root = ET.fromstring(
            "<Root>" + out.replace('<?xml version="1.0" encoding="utf-8"?>', "") + "</Root>")
    except Exception:
        return []

    evs = []
    for ev in root:
        if _strip_ns(ev.tag) != "Event":
            continue
        d = {"log": log, "source": "?", "id": "?", "level": "2", "time": "",
             "data": {}, "vals": []}
        for child in ev:
            tag = _strip_ns(child.tag)
            if tag == "System":
                for f in child:
                    t = _strip_ns(f.tag)
                    if t == "Provider":
                        d["source"] = f.get("Name") or "?"
                    elif t in ("EventID", "Level", "Computer"):
                        d[t.lower()] = (f.text or "").strip()
                    elif t == "TimeCreated":
                        d["time"] = (f.get("SystemTime") or "")[:19].replace("T", " ")
            elif tag in ("EventData", "UserData"):
                vals = []
                for f in child.iter():
                    fname = f.get("Name")
                    txt = (f.text or "").strip()
                    if fname and txt:
                        d["data"][fname] = txt
                    if _strip_ns(f.tag) == "Data":
                        vals.append(txt)
                d["vals"] = vals
        evs.append(d)
    return evs


# 会真正影响使用的事件来源 —— 其余多为系统内部噪声（TPM/DCOM 等）
_CRASH_SOURCES = ("application error", "windows error reporting",
                  ".net runtime", "application hang", "sidebyside")


def _crash_name(ev):
    """从崩溃事件里取出是哪个程序崩了。

    新版事件用 <Data Name="AppName">，经典事件（EventID 1000）用无 Name 的
    <Data> 按位置排列，第 1 个就是故障程序名，第 4 个是故障模块。
    """
    for key in ("AppName", "FaultingApplicationName", "ApplicationName",
                "AppPath", "FaultingApplicationPath"):
        v = ev["data"].get(key)
        if v:
            return os.path.basename(v.replace("\\", "/"))
    for v in (ev.get("vals") or [])[:6]:
        low = v.lower()
        if low.endswith((".exe", ".dll")):
            return os.path.basename(v.replace("\\", "/"))
    return ""


def _crash_path(ev):
    for key in ("AppPath", "FaultingApplicationPath"):
        v = ev["data"].get(key)
        if v:
            return v
    for v in (ev.get("vals") or []):
        if v.lower().endswith(".exe") and ("\\" in v or "/" in v):
            return v
    return ""


# 企业管控 / 安全类组件：崩了也不是用户自己能修的
_MANAGED_HINT = ("datacloak", "yunshu", "亿格", "edr", "sangfor", "symantec",
                 "mcafee", "trendmicro", "eset", "kaspersky")


@check("eventlog.errors", "错误级事件", group="ops", order=40,
       desc="System / Application 最近错误与严重事件（按来源聚合，只报程序崩溃）")
def eventlog_errors(ctx):
    res = Result()
    per_log = int(ctx.config.get("event_count", 30))
    all_evs = []
    for log in ("System", "Application"):
        evs = _event_errors(log, per_log)
        all_evs.extend(evs)

    if not all_evs:
        res.add(Severity.OK, "未发现错误级事件")
        res.metrics["error_events"] = 0
        return res

    # 按 来源+事件ID 聚合，重复刷屏的才算异常
    agg = {}
    for e in all_evs:
        key = (e["log"], e["source"], e["id"])
        g = agg.setdefault(key, {"n": 0, "last": "", "prog": "", "path": ""})
        g["n"] += 1
        g["last"] = max(g["last"], e["time"])
        if not g["prog"]:
            g["prog"] = _crash_name(e)
            g["path"] = _crash_path(e)

    rows = sorted([(v["n"], k, v) for k, v in agg.items()],
                  key=lambda x: (-x[0], x[1][0]))
    res.table(["日志", "来源", "事件ID", "次数", "最近一次", "涉及程序", "程序位置"],
              [[k[0], k[1][:30], k[2], str(v["n"]), v["last"],
                v["prog"][:24], v["path"][:46]]
               for n, k, v in rows],
              ["l", "l", "r", "r", "l", "l", "l"])

    # 只有「程序崩溃」类才值得报成待办：能定位到具体软件
    crashes = [(n, k, v) for n, k, v in rows
               if k[1].lower() in _CRASH_SOURCES or v["prog"]]
    if crashes:
        total_c = sum(n for n, _k, _v in crashes)
        names = sorted({v["prog"] for _n, _k, v in crashes if v["prog"]})
        who = "、".join(names[:4]) if names else "未知程序"
        path = next((v["path"] for _n, _k, v in crashes if v["path"]), "")
        managed = any(h in (path + " " + who).lower() for h in _MANAGED_HINT)
        if managed:
            fix = (f"该程序位于 {path or '（未取到路径）'}\n"
                   "这是公司管控/安全类组件，崩溃属版本或策略冲突，"
                   "自己重装可能反而登不上内网 —— 找 IT 报一下程序名和崩溃时间即可")
            impact = "管控组件反复崩溃会让内网访问、加密盘、水印等功能时好时坏"
        else:
            fix = (f"程序位置: {path or '（未取到路径）'}\n"
                   "先升级/重装该程序；仍崩就查它自己的日志目录\n"
                   f"{cli_cmd('run', 'eventlog.errors', '-f', 'json')} 可导出全部崩溃记录")
            impact = "程序反复崩溃会丢未保存的数据，且常伴随后台卡顿"
        res.add(Severity.WARN,
                f"{total_c} 次程序崩溃（{who}）",
                impact=impact, fix=fix, gain="减少数据丢失风险")
        res.metrics["crash_events"] = total_c

    noise = sum(n for n, k, v in rows if (n, k, v) not in crashes)
    if noise:
        res.text(f"另有 {noise} 条系统内部错误（多为 TPM / 卷影副本 / 设备驱动提示），"
                 "不影响日常使用，仅在反复出现同一来源时再查。")

    res.metrics["error_events"] = len(all_evs)
    res.metrics["error_sources"] = len(agg)
    if not crashes:
        res.add(Severity.OK, f"{len(all_evs)} 条错误事件均属系统噪声，无需处理",
                kind="info")
    return res
