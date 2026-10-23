"""
health_assistant.render — 文本 / JSON / Markdown 渲染器

所有渲染器签名一致：
    render_xxx(meta: dict, items: list[(Check, Result)], summary: Summary) -> str
文本渲染器额外支持 color=True 输出 ANSI 颜色。
"""

from __future__ import annotations

import json

from .core import (ActionPlan, Bars, KV, Severity, Table, Text, dwidth, fb, pad)

__all__ = ["render_text", "render_json", "render_markdown",
           "STATUS_COLOR", "STATUS_MARK", "render_plan_text"]

_ANSI = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "cyan": "\033[36m", "magenta": "\033[35m",
}

STATUS_COLOR = {
    Severity.OK: "green", Severity.INFO: "cyan",
    Severity.WARN: "yellow", Severity.ERROR: "red",
}

STATUS_MARK = {
    Severity.OK: "[OK]  ", Severity.INFO: "[INFO]",
    Severity.WARN: "[WARN]", Severity.ERROR: "[BAD] ",
}

WIDTH = 78


def _c(text, color, on):
    if on and color in _ANSI:
        return f"{_ANSI[color]}{text}{_ANSI['reset']}"
    return text


def _cmd_line(fix):
    """从 fix 的多行文案里挑一条真命令，塞进 Markdown 表格。

    fix 里既有可直接执行的命令（health_assistant.cmd / netsh / powershell…），
    也有「首选：绑 127.0.0.1」这类说明行。说明行被包进 `代码` 里很怪，
    所以优先挑第一条不像说明的；实在没有就退回第一行。
    """
    lines = [ln.strip() for ln in fix.splitlines() if ln.strip()]
    for ln in lines:
        if "：" not in ln and "→" not in ln and not ln.startswith(("（", "(")):
            return ln
    return lines[0] if lines else ""


# ───────────────────── 待处理清单（文本 / HTML 共用口径） ─────────────────────

def render_plan_text(plan: ActionPlan, color=False):
    """把待处理清单渲染成文本。这是报告里唯一真正需要人动脑读的部分。"""
    L = []
    if not plan.count:
        L.append(_c("  ✓ 没有需要处理的问题，以下是留档信息。", "green", color))
        return L

    head = f"  要处理 {plan.count} 件事"
    if plan.total_save:
        # 只算清单里这几项；clean 里还会列出「删后需重下」的条目，总量会比这里多，
        # 先标清楚口径，免得用户拿两个数对不上就以为工具在瞎报。
        head += f"，合计可释放 {fb(plan.total_save)}（不含「删后需重下」项）"
    L.append(_c(head, "bold", color))
    L.append("")

    for i, e in enumerate(plan.entries, 1):
        sev = _c("[必须]" if e["severity"] == Severity.ERROR else "[建议]",
                 "red" if e["severity"] == Severity.ERROR else "yellow", color)
        tail = f"   收益 {e['gain']}" if e["gain"] else ""
        L.append(f"  {i}. {sev} {e['text']}{tail}")
        if e["impact"]:
            L.append(f"     为什么: {e['impact']}")
        if e["fix"]:
            for ln in e["fix"].splitlines():
                L.append(_c(f"     > {ln}", "cyan", color))
        else:
            L.append(_c("     > 需人工处理（无自动命令）", "dim", color))
        L.append(_c(f"     依据: {e['ref']}", "dim", color))
        L.append("")
    return L


# ───────────────────────────── 文本 ─────────────────────────────

def _table_lines(tb: Table, indent="  "):
    cols = len(tb.headers)
    widths = [dwidth(h) for h in tb.headers]
    for r in tb.rows:
        for i in range(cols):
            cell = r[i] if i < len(r) else ""
            widths[i] = max(widths[i], dwidth(cell))

    out = []
    head = "  ".join(pad(tb.headers[i], widths[i], tb.aligns[i]) for i in range(cols))
    out.append(indent + head.rstrip())
    for r in tb.rows:
        line = "  ".join(
            pad(r[i] if i < len(r) else "", widths[i], tb.aligns[i]) for i in range(cols)
        )
        out.append(indent + line.rstrip())
    return out


def render_text(meta, items, summary, color=False, show_metrics=False, full=False):
    """文本报告。默认只详列有问题的检查，零问题项收成一行（--full 展开）。"""
    L = []
    L.append(_c("=" * WIDTH, "dim", color))
    L.append(_c(f"  本机巡检报告  {meta.get('host', '?')}", "bold", color))
    L.append(f"  {meta.get('os', '')}   |   {meta.get('time', '')}   |   工具 {meta.get('tool', '')}")
    if not meta.get("admin", True):
        L.append(_c("  注意: 非管理员权限，服务/端口/事件日志等部分项受限", "yellow", color))
    L.append(_c("=" * WIDTH, "dim", color))

    plan = ActionPlan(items)
    quiet = [(c, r) for c, r in items if not r.needs_action]
    quiet_ids = {id(r) for _c2, r in quiet}

    L.extend(render_plan_text(plan, color=color))
    L.append(_c("-" * WIDTH, "dim", color))
    L.append(f"  巡检 {summary.total} 项 / 耗时 {summary.elapsed:.1f}s"
             f" / {len(items) - len(quiet)} 项有问题，{len(quiet)} 项正常")
    L.append(_c("-" * WIDTH, "dim", color))

    if quiet and not full:
        L.append("")
        L.append(_c("  正常项（加 --full 看明细）:", "dim", color))
        for chk, res in quiet:
            note = res.summary or (res.findings[0].text if res.findings else "")
            L.append("    " + _c("✓", "green", color) + f" {chk.title:<14} "
                     + _c(note[:56], "dim", color))

    for idx, (chk, res) in enumerate(items, 1):
        if not full and id(res) in quiet_ids:
            continue
        L.append("")
        L.append(_c("-" * WIDTH, "dim", color))
        status = _c(STATUS_MARK.get(res.status, res.status), STATUS_COLOR.get(res.status, "dim"), color)
        title = _c(f"[{idx}] {chk.title}", "bold", color)
        L.append(f"{status} {title}   {_c(chk.id, 'dim', color)}   {res.elapsed_ms}ms")
        if res.summary:
            L.append("  " + _c(res.summary, STATUS_COLOR.get(res.status, "dim"), color))

        for blk in res.blocks:
            if isinstance(blk, KV):
                w = min(24, max((dwidth(k) for k, _ in blk.rows), default=0))
                for k, v in blk.rows:
                    L.append("  " + pad(k, w) + " : " + v)
            elif isinstance(blk, Table):
                L.append("")
                L.extend(_table_lines(blk))
            elif isinstance(blk, Text):
                for line in blk.text.splitlines():
                    L.append("  " + line)
            elif isinstance(blk, Bars):
                wlab = min(18, max((dwidth(a) for a, _, _ in blk.rows), default=0))
                for label, val, ratio in blk.rows:
                    filled = int(round(max(0.0, min(1.0, ratio)) * blk.width))
                    bar = "#" * filled + "." * (blk.width - filled)
                    L.append("  " + pad(label, wlab) + "  " + bar + "  " + pad(val, 8, "r"))

        for f in res.findings:
            L.append("  " + _c(STATUS_MARK.get(f.severity, "[----]"), STATUS_COLOR.get(f.severity, "dim"), color)
                     + " " + f.text)
        if res.error and not res.summary.startswith("检查"):
            L.append(_c("  错误详情: " + str(res.error).splitlines()[0], "dim", color))
        if show_metrics and res.metrics:
            L.append(_c("  metrics: " + json.dumps(res.metrics, ensure_ascii=False), "dim", color))

    L.append("")
    L.append(_c("=" * WIDTH, "dim", color))
    return "\n".join(L)


# ───────────────────────────── JSON ─────────────────────────────

def render_json(meta, items, summary):
    doc = {
        "tool": meta.get("tool"),
        "host": meta.get("host"),
        "os": meta.get("os"),
        "user": meta.get("user"),
        "admin": meta.get("admin"),
        "generated_at": meta.get("time"),
        "summary": summary.to_dict(),
        "action_plan": ActionPlan(items).to_dict(),
        "checks": [
            {
                "id": chk.id,
                "title": chk.title,
                "group": chk.group,
                "admin_required": chk.admin,
                "elapsed_ms": res.elapsed_ms,
                **res.to_dict(),
            }
            for chk, res in items
        ],
    }
    return json.dumps(doc, ensure_ascii=False, indent=2)


# ───────────────────────────── Markdown ─────────────────────────────

def render_markdown(meta, items, summary):
    L = [f"# 本机巡检报告 — {meta.get('host', '?')}", ""]
    L.append(f"- 系统：{meta.get('os', '')}")
    L.append(f"- 时间：{meta.get('time', '')}")
    L.append(f"- 权限：{'管理员' if meta.get('admin') else '普通用户'}")
    L.append(f"- 汇总：共 **{summary.total}** 项，"
             f"异常 **{summary.count.get(Severity.ERROR, 0)}**，"
             f"警告 **{summary.count.get(Severity.WARN, 0)}**，"
             f"正常 {summary.count.get(Severity.OK, 0)}，耗时 {summary.elapsed:.1f}s")
    L.append("")

    plan = ActionPlan(items)
    L.append("## 待处理")
    L.append("")
    if not plan.count:
        L.append("没有需要处理的问题。")
    else:
        if plan.total_save:
            L.append(f"合计可释放 **{fb(plan.total_save)}**（不含「删后需重下」项）。")
            L.append("")
        L.append("| # | 事项 | 为什么 | 怎么做 | 收益 |")
        L.append("|:--|:---|:---|:---|:---|")
        for i, e in enumerate(plan.entries, 1):
            fix = f"`{_cmd_line(e['fix'])}`" if e["fix"] else "需人工"
            L.append(f"| {i} | {e['text']} | {e['impact'] or '-'} | {fix} | {e['gain'] or '-'} |")
    L.append("")

    icon = {Severity.OK: "[OK]", Severity.INFO: "[INFO]",
            Severity.WARN: "[WARN]", Severity.ERROR: "[ERROR]"}

    for idx, (chk, res) in enumerate(items, 1):
        L.append(f"## {idx}. {chk.title}  `{chk.id}`")
        L.append(f"{icon.get(res.status, '')} {Severity.LABEL.get(res.status, res.status)}"
                 f" · {res.elapsed_ms}ms" + (f" · {res.summary}" if res.summary else ""))
        L.append("")
        for blk in res.blocks:
            if isinstance(blk, KV):
                for k, v in blk.rows:
                    L.append(f"- **{k}**：{v}")
            elif isinstance(blk, Table):
                L.append("| " + " | ".join(blk.headers) + " |")
                L.append("|" + "|".join([":---"] * len(blk.headers)) + "|")
                for r in blk.rows:
                    L.append("| " + " | ".join(c.replace("|", "\\|") for c in r) + " |")
            elif isinstance(blk, Text):
                L.append("```")
                L.append(blk.text)
                L.append("```")
            elif isinstance(blk, Bars):
                L.append("| 项 | 值 | |")
                L.append("|:---|:---|---|")
                for label, val, ratio in blk.rows:
                    filled = int(round(max(0.0, min(1.0, ratio)) * 20))
                    L.append(f"| {label} | {val} | {'█' * filled}{'░' * (20 - filled)} |")
            L.append("")
        for f in res.findings:
            L.append(f"- {icon.get(f.severity, '')} {f.text}")
        L.append("")
    return "\n".join(L)
