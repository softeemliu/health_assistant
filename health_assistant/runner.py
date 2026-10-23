"""
health_assistant.runner — 执行引擎与插件发现

职责：
  · 按选中的检查项并发执行（默认 6 路），单项异常/超时隔离，不影响其他检查
  · 记录耗时与状态汇总
  · 从目录加载外部插件（.py 文件里用 @check 注册即可）
"""

from __future__ import annotations

import importlib.util
import os
import queue
import sys
import threading
import time
import traceback

from .core import REGISTRY, Result, Severity, get_checks

__all__ = ["load_plugins", "run_checks", "Summary", "DEFAULT_WORKERS"]

DEFAULT_WORKERS = 6


# ───────────────────────────── 插件加载 ─────────────────────────────

def load_plugins(dirs, verbose=False):
    """从多个目录加载 .py 插件。返回 [(路径, 错误信息)] 供 CLI 报告。"""
    errors = []
    for d in dirs or []:
        if not d or not os.path.isdir(d):
            errors.append((d, "目录不存在"))
            continue
        if d not in sys.path:
            sys.path.insert(0, d)
        for fn in sorted(os.listdir(d)):
            if not fn.endswith(".py") or fn.startswith("_"):
                continue
            path = os.path.join(d, fn)
            mod_name = "health_assistant_plugin_" + fn[:-3].replace("-", "_").replace(" ", "_")
            try:
                spec = importlib.util.spec_from_file_location(mod_name, path)
                if spec is None or spec.loader is None:
                    errors.append((path, "无法创建模块 spec"))
                    continue
                mod = importlib.util.module_from_spec(spec)
                sys.modules[mod_name] = mod
                spec.loader.exec_module(mod)
                if verbose:
                    print(f"  已加载插件: {path}")
            except Exception:
                errors.append((path, traceback.format_exc(limit=2).strip().splitlines()[-1]))
    return errors


# ───────────────────────────── 执行 ─────────────────────────────

class Summary:
    """状态统计。"""

    def __init__(self):
        self.total = 0
        self.count = {Severity.OK: 0, Severity.INFO: 0,
                      Severity.WARN: 0, Severity.ERROR: 0}
        self.elapsed = 0.0
        self.worst = Severity.OK

    def add(self, status):
        self.total += 1
        self.count[status] = self.count.get(status, 0) + 1
        self.worst = Severity.worst(self.worst, status)

    def to_dict(self):
        return {
            "total": self.total,
            "ok": self.count[Severity.OK],
            "info": self.count[Severity.INFO],
            "warn": self.count[Severity.WARN],
            "error": self.count[Severity.ERROR],
            "worst": self.worst,
            "elapsed_sec": round(self.elapsed, 2),
        }


def _run_one(chk, ctx, timeout):
    """带超时执行单项。超时用守护线程兜底（无法强杀，只能放弃等待）。"""
    box = {}

    def worker():
        try:
            box["result"] = chk.func(ctx)
        except Exception:
            box["exc"] = traceback.format_exc()

    th = threading.Thread(target=worker, name=f"check:{chk.id}", daemon=True)
    t0 = time.perf_counter()
    th.start()
    th.join(timeout if timeout and timeout > 0 else None)
    elapsed = (time.perf_counter() - t0) * 1000

    if th.is_alive():
        res = Result().fail(f"检查超时（>{timeout}s）")
    elif "exc" in box:
        res = Result().fail("检查抛出异常")
        res.error = box["exc"]
    else:
        res = box.get("result")
        if not isinstance(res, Result):
            res = Result().fail("检查未返回 Result 对象")
    res.elapsed_ms = int(elapsed)
    return res


def _skipped(chk):
    res = Result()
    res.status = Severity.INFO
    res.summary = "跳过：需要管理员权限"
    res.elapsed_ms = 0
    return res


def run_checks(checks, ctx, timeout=60, progress=None, workers=None):
    """并发执行，逐项产出 (Check, Result)。progress(cb) 用于实时回调。

    18 个检查里绝大多数时间在等磁盘和网络（用户目录扫描 18s、残留扫描 9s、
    连通性 4s），串行跑完要 44s。并发执行后总耗时约等于「最慢那一项」。

    · workers=None 时取 config["workers"]，再退回 DEFAULT_WORKERS
    · 每项仍是独立守护线程 + join(timeout)，超时只放弃等待、不阻塞退出
    · 消费方提前 break（如用户点「停止」）时，取消标志会让工作线程不再领新任务
    """
    checks = list(checks)
    summary = Summary()
    t_all = time.perf_counter()
    if not checks:
        summary.elapsed = 0.0
        yield None, summary
        return

    if workers is None:
        workers = (ctx.config or {}).get("workers") or DEFAULT_WORKERS
    try:
        n = max(1, min(int(workers), len(checks)))
    except (TypeError, ValueError):
        n = min(DEFAULT_WORKERS, len(checks))

    results = queue.Queue()
    cancel = threading.Event()
    cursor = {"i": 0}
    guard = threading.Lock()

    def take():
        with guard:
            if cancel.is_set() or cursor["i"] >= len(checks):
                return None
            cursor["i"] += 1
            return checks[cursor["i"] - 1]

    def pump():
        while True:
            chk = take()
            if chk is None:
                return
            try:
                if chk.admin and not ctx.admin:
                    res = _skipped(chk)
                else:
                    res = _run_one(chk, ctx, timeout)
            except Exception:                     # 兜底：绝不吞掉整轮
                res = Result().fail("执行器异常")
                res.error = traceback.format_exc()
            res.set_id(chk.id)                    # 让结论能自动标注依据页
            results.put((chk, res))

    threads = [threading.Thread(target=pump, name=f"health_assistant-worker{i}", daemon=True)
               for i in range(n)]
    for th in threads:
        th.start()

    try:
        for _ in range(len(checks)):
            chk, res = results.get()
            summary.add(res.status)
            if progress:
                progress(chk, res)
            yield chk, res
    finally:
        # 消费方 break / 生成器被关闭时，让工作线程把手上这项做完就收摊
        cancel.set()

    summary.elapsed = time.perf_counter() - t_all
    yield None, summary              # 末位哨兵：把统计交回调用方
