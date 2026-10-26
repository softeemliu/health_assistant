"""health_assistant.gui.tasks — 后台线程

界面永不阻塞：所有采集/删除都在 QThread 里跑，结果用信号回主线程。
每个任务只做一件事，任务异常统一走 failed 信号，不静默吞掉。
"""

from __future__ import annotations

import json
import os
import time
import traceback
from concurrent.futures import ThreadPoolExecutor

from PySide6.QtCore import QThread, Signal

from .. import (credentials, leftover, metrics, netfix, planclean, recovery,
                regclean, slim)
from ..core import ActionPlan, Context, get_checks, hostname, is_admin, now_str
from ..runner import Summary, load_plugins, run_checks


class BaseTask(QThread):
    """统一的任务基类：run() 只负责兜异常，子类实现 work()。"""

    log = Signal(str)
    failed = Signal(str)
    progress = Signal(int, int, str)        # (已完成, 总数, 当前项)

    def run(self):
        try:
            self.work()
        except Exception:
            self.failed.emit(traceback.format_exc(limit=4).strip())

    def work(self):
        raise NotImplementedError


# ───────────────────────────── 巡检 ─────────────────────────────

def meta_info():
    """报告头信息（与 CLI 的 _meta() 保持一致）。"""
    import platform
    from .. import __version__
    return {
        "tool": f"health_assistant {__version__}",
        "host": hostname(),
        "os": f"{platform.system()} {platform.release()} (build {platform.version()})",
        "user": os.environ.get("USERNAME", "?"),
        "admin": is_admin(),
        "time": now_str(),
    }


class InspectTask(BaseTask):
    """逐项执行巡检，每完成一项就发一次 item 信号。"""

    item = Signal(object)
    done = Signal(object)

    def __init__(self, cfg, selector=None, plugin_dirs=(), parent=None):
        super().__init__(parent)
        self.cfg = cfg
        self.selector = selector
        self.plugin_dirs = list(plugin_dirs or [])
        self._stop = False

    def stop(self):
        self._stop = True

    def work(self):
        cfg = json.loads(json.dumps(self.cfg))          # 跨线程用副本，避免共享可变状态
        for path, err in load_plugins(self.plugin_dirs, verbose=False):
            self.log.emit(f"插件加载失败 {path}: {err}")

        checks = get_checks(self.selector, include_disabled=cfg.get("disabled") or [])
        if not checks:
            self.failed.emit(f"没有匹配的检查项：{self.selector}")
            return

        ctx = Context(cfg)
        timeout = int(cfg.get("timeout", 60) or 60)
        workers = int(cfg.get("workers", 6) or 6)
        total = len(checks)
        self.progress.emit(0, total, "准备开始")

        order = {c.id: i for i, c in enumerate(checks)}
        items, pair, n = [], [], 0
        summary = Summary()
        t0 = time.perf_counter()
        for chk, res in run_checks(checks, ctx, timeout=timeout, workers=workers):
            if self._stop:
                self.log.emit("已按用户要求中止，剩余检查项未执行")
                break
            if chk is None:
                continue
            pair.append((chk, res))
            summary.add(res.status)
            d = res.to_dict()
            d.update({
                "id": chk.id, "title": chk.title, "group": chk.group,
                "admin": bool(chk.admin), "elapsed_ms": int(getattr(res, "elapsed_ms", 0)),
            })
            items.append(d)
            n += 1
            self.progress.emit(n, total, f"{chk.title}（{chk.id}）")
            self.item.emit(d)

        # 并发完成顺序是乱的，详情/导出按原定检查顺序排回去
        items.sort(key=lambda d: order.get(d["id"], 0))
        pair.sort(key=lambda cr: order.get(cr[0].id, 0))

        summary.elapsed = time.perf_counter() - t0
        plan = ActionPlan(pair)
        self.progress.emit(len(items), total, "完成")
        self.done.emit({"meta": meta_info(), "summary": summary.to_dict(), "plan": plan.to_dict(),
                        "items": items, "pairs": pair, "summary_obj": summary,
                        "stopped": self._stop, "elapsed": round(summary.elapsed, 2)})


def _worst(statuses):
    rank = {"ok": 0, "info": 1, "warn": 2, "error": 3}
    worst = "ok"
    for s in statuses:
        if rank.get(s, 0) > rank.get(worst, 0):
            worst = s
    return worst


# ───────────────────────────── 进程 ─────────────────────────────

class ProcsTask(BaseTask):
    """进程快照 + 并行补齐启动参数。

    4.6.0 起分两段回报：
      1. 先发一次 ``partial``（只有名字 / CPU / 内存这些便宜字段）—— 表格立刻能用；
      2. 再按「占 CPU、占内存」从大到小批量补齐启动参数，**每补一批就发一次 ``partial``**。
    表格默认就按占用排序，所以第一屏是最先补齐的；用户不用等 400 个进程全部补完。
    补齐带缓存（见 metrics.enrich_procs），第二次进这一页几乎是瞬间。
    """

    done = Signal(object)
    partial = Signal(object)

    def __init__(self, sample=0.4, parent=None):
        super().__init__(parent)
        self.sample = sample
        self._stop = False

    def stop(self):
        self._stop = True

    def work(self):
        t0 = time.perf_counter()
        rows = metrics.proc_snapshot(sample=self.sample)
        if not rows:
            self.failed.emit("进程快照为空：psutil 不可用或权限不足")
            return
        total = len(rows)
        self.partial.emit(rows)                  # 便宜的字段先给界面

        order = sorted(range(total), key=lambda i: (-(rows[i].get("cpu") or 0),
                                                    -(rows[i].get("mem") or 0)))
        # 每批 20 个：本机有两个受保护进程（LsaIso / 安全客户端）单次读取要 1 秒，
        # 批次大了会被它们整批拖住；小批次能让其余进程先补完先显示。
        step = 20
        with ThreadPoolExecutor(max_workers=6) as pool:
            for i in range(0, total, step):
                if self._stop:
                    self.log.emit("已按用户要求中止补齐，表格里剩余项没有启动参数")
                    break
                chunk = [rows[k] for k in order[i:i + step]]
                list(pool.map(metrics.enrich_procs, [[r] for r in chunk]))
                self.progress.emit(min(i + step, total), total, "补齐启动参数…")
                self.partial.emit(rows)
        self.log.emit(f"进程快照 {total} 个，用时 {time.perf_counter() - t0:.1f}s")
        self.done.emit(rows)


class KillTask(BaseTask):
    """终止进程（含安全闸，逐个回报结果）。"""

    done = Signal(object)

    def __init__(self, targets, tree=False, force=False, parent=None):
        super().__init__(parent)
        self.targets = list(targets or [])       # [(pid, name)]
        self.tree = tree
        self.force = force

    def work(self):
        out = []
        for i, (pid, name) in enumerate(self.targets, 1):
            self.progress.emit(i, len(self.targets), f"{name} ({pid})")
            ok, notes = metrics.kill_process(pid, tree=self.tree, force=self.force)
            out.append({"pid": pid, "name": name, "ok": ok, "notes": notes})
        self.done.emit(out)


class ProcDetailTask(BaseTask):
    done = Signal(object)

    def __init__(self, pid, parent=None):
        super().__init__(parent)
        self.pid = pid

    def work(self):
        self.done.emit(metrics.proc_detail(self.pid) or {})


# ───────────────────────────── 端口 ─────────────────────────────

class PortsTask(BaseTask):
    done = Signal(object)

    def work(self):
        rows = metrics.net_listeners(detail=True)
        if not rows:
            self.failed.emit("读取端口失败：需要管理员权限，或 psutil 不可用")
            return
        merged = {}
        for r in rows:
            key = (r["port"], r["pid"])
            if key in merged:
                merged[key]["ips"].append(r["ip"])
            else:
                merged[key] = dict(r, ips=[r["ip"]])
        data = sorted(merged.values(), key=lambda r: (r["port"], r["name"]))
        self.done.emit(data)


# ───────────────────────────── 空间去哪了 ─────────────────────────────

class DiskUseTask(BaseTask):
    """统计一个目录下各子项的体积。

    渐进式：每算完一项就 emit 一次 item，界面边算边填表，
    不用盯着转圈等全盘扫完。用户换目录 / 关窗口时 stop()，后台立刻收手。
    """

    item = Signal(object)                  # 单项算完就发一条
    done = Signal(object)

    def __init__(self, path, budget=20.0, min_bytes=0, keep=0, parent=None):
        super().__init__(parent)
        self.path = path
        self.budget = budget
        self.min_bytes = min_bytes
        self.keep = keep
        self._stop = False

    def stop(self):
        self._stop = True

    def work(self):
        from .. import diskuse
        res = diskuse.children(
            self.path, budget=self.budget, min_bytes=self.min_bytes,
            keep=self.keep, on_item=self.item.emit,
            should_stop=lambda: self._stop)
        self.done.emit(res)


class UserTrashTask(BaseTask):
    """把用户在「空间去哪了」里点名的一项移到回收站。

    走 leftover.trash_by_user —— 那条通道的闸门比清理页更硬（盘符根 / 系统目录 /
    链接挂载点 / 在用检测都拦），失败原因原样回传界面，不吞。
    """

    done = Signal(object)                  # (成功[(path, 说明)], 失败[(path, 原因)])

    def __init__(self, path, parent=None):
        super().__init__(parent)
        self.path = path

    def work(self):
        self.progress.emit(0, 1, f"正在移到回收站：{os.path.basename(self.path)}")
        res = leftover.trash_by_user([self.path])
        self.progress.emit(1, 1, "完成")
        self.done.emit(res)


# ───────────────────────────── 清理 ─────────────────────────────

class CleanScanTask(BaseTask):
    """扫描可清理目录（不删除）。"""

    done = Signal(object)

    def __init__(self, opts, parent=None):
        super().__init__(parent)
        self.opts = dict(opts or {})

    def work(self):
        t0 = time.perf_counter()
        plan = planclean.collect(on_log=self.log.emit, **self.opts)
        plan["elapsed_total"] = round(time.perf_counter() - t0, 1)
        self.done.emit(plan)


class CleanRunTask(BaseTask):
    """把选中条目移到回收站。

    分两路：目录型候选（残留/缓存/空点）走 leftover.trash_paths 的老三重闸；
    瘦身候选（僵尸文件/无用用户文件，含 .lnk/.dmp/.msi 这类**文件**）走
    slim.trash 自己的白名单与四道闸 —— trash_paths 只接受目录，混在一起会全被拒。
    """

    done = Signal(object)

    def __init__(self, paths, kind="all", allow_exact=None, allow_system_names=False,
                 slim_paths=None, parent=None):
        super().__init__(parent)
        self.paths = list(paths or [])
        self.kind = kind
        self.allow_exact = set(allow_exact or ())
        self.allow_system_names = allow_system_names
        self.slim_paths = list(slim_paths or [])

    def work(self):
        ok_list, bad = [], []
        if self.paths:
            o, b = leftover.trash_paths(
                self.paths, max_batch=max(1, len(self.paths)),
                allow_exact=self.allow_exact,
                allow_system_names=self.allow_system_names)
            ok_list += o
            bad += b
        if self.slim_paths:
            o, b = slim.trash(self.slim_paths, max_batch=max(1, len(self.slim_paths)))
            ok_list += o
            bad += b
        ledger = planclean.write_ledger(self.kind, ok_list, bad)
        self.done.emit({"ok": ok_list, "bad": bad, "ledger": ledger})


class GhostDeleteTask(BaseTask):
    """备份后删除注册表幽灵项（已安装程序登记项）。"""

    done = Signal(object)

    def __init__(self, ghosts, parent=None):
        super().__init__(parent)
        self.ghosts = list(ghosts or [])

    def work(self):
        n = len(self.ghosts)
        self.progress.emit(0, n, "导出注册表备份…")
        res = regclean.delete_ghosts(self.ghosts, log=self.log.emit)
        self.progress.emit(n, n, "完成")
        self.done.emit(res)


# ───────────────────────────── 网络修复 ─────────────────────────────

class NetDiagTask(BaseTask):
    """逐条检索网络问题：每查完一层就发一次 partial，界面边查边显示。"""

    done = Signal(object)
    stage = Signal(int, int, str)      # (第几步, 共几步, 这一步查什么)
    partial = Signal(object)           # {"issues": [...], "passed": [...]} 这一步新发现的

    def __init__(self, parent=None):
        super().__init__(parent)
        self._stop = False

    def stop(self):
        self._stop = True

    def work(self):
        last = None
        for ev in netfix.diagnose_stream(should_stop=lambda: self._stop):
            if ev.get("done"):
                last = ev
                break
            self.stage.emit(ev["i"], ev["n"], ev["label"])
            self.partial.emit({"issues": ev["issues"], "passed": ev["passed"]})
            if ev["issues"]:
                self.log.emit(f"{ev['label']}：{len(ev['issues'])} 条结论")
        if last is None:
            last = {"issues": [], "passed": [], "summary": "已中止（结果不完整）",
                    "data": {}, "done": True, "stopped": True}
        self.done.emit(last)


class NetFixTask(BaseTask):
    """逐条执行修复命令；manual 级只回报「需人工」，不执行。"""

    done = Signal(object)

    def __init__(self, issues, parent=None):
        super().__init__(parent)
        self.issues = list(issues or [])

    def work(self):
        out = []
        n = len(self.issues)
        for i, it in enumerate(self.issues, 1):
            self.progress.emit(i, n, it.get("fix_label") or it.get("title", ""))
            res = netfix.run_fix(it, log=self.log.emit)
            out.append({"issue": it, "res": res})
            self.log.emit(f"{it.get('title', '')[:30]} → {res.get('msg', '')[:60]}")
        self.done.emit(out)


# ───────────────────────────── 凭据 ─────────────────────────────

class CredsTask(BaseTask):
    """kind: system / browser / ftp / all。

    all 时一次取齐三类，结果按 key 分开，界面一次填满三张表。
    """

    done = Signal(object)

    def __init__(self, kind="all", reveal=True, parent=None):
        super().__init__(parent)
        self.kind = kind
        self.reveal = reveal

    def work(self):
        if self.kind == "system":
            self.done.emit({"system": credentials.cred_enum(reveal=self.reveal),
                            "browser": [], "ftp": [], "errors": []})
            return
        if self.kind == "browser":
            self.done.emit({"system": [], "browser": credentials.browser_logins(reveal=self.reveal),
                            "ftp": [], "errors": []})
            return
        if self.kind == "ftp":
            sites, errors = credentials.ftp_sites_all(reveal=self.reveal)
            self.done.emit({"system": [], "browser": [], "ftp": sites, "errors": errors})
            return

        errors = []
        try:
            sys_rows = credentials.cred_enum(reveal=self.reveal)
        except Exception as exc:
            sys_rows = []
            errors.append(f"系统凭据: {type(exc).__name__}: {exc}")
        try:
            br_rows = credentials.browser_logins(reveal=self.reveal)
        except Exception as exc:
            br_rows = []
            errors.append(f"浏览器: {type(exc).__name__}: {exc}")
        ftp_rows, ftp_err = [], []
        try:
            ftp_rows, ftp_err = credentials.ftp_sites_all(
                reveal=self.reveal, browser_logins_rows=br_rows)
        except Exception as exc:
            errors.append(f"FTP/网络位置: {type(exc).__name__}: {exc}")
        errors.extend(ftp_err)
        self.done.emit({"system": sys_rows, "browser": br_rows,
                        "ftp": ftp_rows, "errors": errors})


class ImportCsvTask(BaseTask):
    """导入浏览器导出的密码 CSV（可并入本地缓存，补齐浏览器 v20 条目）。"""

    done = Signal(object)

    def __init__(self, path, save=True, parent=None):
        super().__init__(parent)
        self.path = path
        self.save = save

    def work(self):
        rows = credentials.import_password_csv(self.path)
        total = len(credentials.load_imported())
        if self.save and rows:
            total, _n = credentials.save_imported(rows, source=self.path)
        self.done.emit({"rows": rows, "cache_total": total})


# ───────────────────────────── FTP ─────────────────────────────

class FtpTask(BaseTask):
    """跑一次 FTP 操作（连接 / 列目录 / 上传 / 下载 / 删除都在后台线程）。

    fn(task) 在后台线程执行，返回值通过 done 发回主线程；
    上传下载时 fn 里轮询 task.stopped() 就能中途停下（下一个数据块边界生效）。
    密码只在这个任务的内存里过一遍，不写日志、不写配置。
    """

    done = Signal(object)
    xfer = Signal(int, int, str)          # (已传字节, 总字节, 当前文件名)

    def __init__(self, fn, parent=None):
        super().__init__(parent)
        self.fn = fn
        self._stop = False

    def stop(self):
        self._stop = True

    def stopped(self):
        return self._stop

    def work(self):
        from .. import ftpclient
        try:
            self.done.emit(self.fn(self))
        except ftpclient.FtpCancelled:
            self.done.emit({"__cancelled__": True})


# ───────────────────────────── 数据恢复 ─────────────────────────────

class RecoveryScanTask(BaseTask):
    """找可恢复的东西（三种模式共用）。

    全部在后台线程、全部只读：
      auto     一键自动：回收站 → 已删除记录 →（必要时）格式化残留，结果合并去重（默认）
      recycle  只扫回收站（保留给「就想看看回收站」的调用）
      mft      扫当前 MFT 找已删除记录（几十秒，需要管理员读原始卷）
      raw      扫残留旧记录 + INDX 目录索引 —— 格式化之后也能带回原名和目录（慢）
      carve    在未分配空间里按文件类型抠（只认内容，直接写目标目录）

    为什么默认是 auto：用户既不知道也不记得文件是怎么没的（"回收站清空了吗？
    我是删了还是格式化了？"），让他先做这道选择题等于把判断成本推给他。
    实际上这件事有明确的判断顺序，程序自己跑一遍就行。
    """

    done = Signal(object)
    partial = Signal(object)        # 边扫边出的一批（{"items": [...], "stage": 名字}）

    def __init__(self, mode, letter, target=None, budget=None, deep=False,
                 image=None, image_base=0, groups=None, parent=None):
        super().__init__(parent)
        self.mode = mode
        self.letter = letter
        self.target = target
        self.budget = budget            # 秒；None 用各模式自己的默认值
        self.deep = deep                # 整卷扫描（连已分配区域也扫，慢）
        self.image = image              # 有值就扫这份镜像，不再碰源盘
        self.image_base = image_base    # 整盘镜像里卷首的字节偏移（0 = 从文件头开始）
        self.groups = groups            # 按类型找时只找这些大类（None = 全部）
        self._stop = False
        self._stream_keys = set()       # 已经推给界面的记录号（同一块盘多路扫会重）

    def stop(self):
        self._stop = True

    def stopped(self):
        return self._stop

    def _batch(self, tag):
        """给 recovery 的 on_batch 用：同一批里去重后通过 partial 信号发给界面。

        为什么要在这里去重：`auto` 模式会先扫已删除记录、必要时再深挖格式化残留，
        后一路会把前一路扫到过的记录再交一遍。列表那边是靠「记录号」去重的，
        边扫边显示也得同样处理，否则用户会看到同一行出现两次。
        """
        def sink(batch):
            if self._stop:
                return
            out = []
            for it in batch:
                idx = it.get("idx")
                if isinstance(idx, int):
                    if idx in self._stream_keys:
                        continue
                    self._stream_keys.add(idx)
                out.append(it)
            if out:
                self.partial.emit({"items": out, "stage": tag})
        return sink

    def work(self):
        out = {"mode": self.mode, "letter": self.letter, "items": [], "stats": {},
               "image": self.image}
        # 扫镜像时把「卷对象」换成读镜像，后面的代码一行不用改。
        # 4.14.0 起按镜像里的引导扇区选解析器（NTFS / FAT / exFAT 都能开）。
        vol = None
        if self.image and self.mode != "recycle":
            try:
                vol, _kind = recovery.open_image_volume(
                    self.image, letter=self.letter or "镜像",
                    base=self.image_base)
            except Exception as exc:                # noqa: BLE001
                self.failed.emit(f"打不开镜像文件：{exc}")
                return
        try:
            self._work(out, vol)
        finally:
            if vol is not None:
                vol.close()
        self.done.emit(out)

    def _auto(self, out, src):
        """一键查找：按「又快又稳 → 又慢又全」自动跑，结果合并去重。

        三步的判断顺序是固定的，不需要用户选：
          1. **回收站**（秒级）：还在回收站的文件根本没被动过，原样还原最准；
          2. **已删除记录**（几十秒）：NTFS 扫 $MFT，FAT/exFAT 扫目录项，
             能带回文件名和原目录；
          3. **格式化残留**（几分钟起）：只有前两步几乎没捞到东西、或者用户勾了
             「找得更彻底」才跑 —— 它要扫整卷，无脑跑会让每次点按钮都等很久。

        三步的结果按「记录号」去重（回收站条目没有记录号，用名字+大小+路径）：
        同一条 MFT 记录在 ② 和 ③ 里都会出现，保留先入的（证据更强的那份）。
        """
        merged, seen = [], {}
        stages = []
        t0 = time.time()

        def take(items, tag):
            added = 0
            for it in items or []:
                idx = it.get("idx")
                key = (("i", idx) if idx is not None
                       else ("n", it.get("name"), it.get("size"), it.get("path")))
                if key in seen:
                    continue
                it["_stage"] = tag
                seen[key] = it
                merged.append(it)
                added += 1
            return added

        # ── 第 1 步：回收站（镜像里没有回收站，跳过）──
        if not self.image and not self._stop:
            self.progress.emit(0, 3, "第 1 步 / 3：看回收站…")
            try:
                rec = recovery.recycle_items(self.letter) or []
            except Exception:                      # noqa: BLE001
                rec = []
            stages.append(("回收站", take(rec, "recycle")))

        # ── 第 2 步：已删除记录（NTFS=MFT，FAT/exFAT=目录项）──
        st2, items2 = {}, []
        if not self._stop:
            self.progress.emit(0, 3, "第 2 步 / 3：扫磁盘上的已删除记录…")
            try:
                items2, st2 = recovery.scan_deleted(
                    src, limit=None, on_batch=self._batch("已删除记录"),
                    progress=lambda i, n: None if self._stop else self.progress.emit(
                        i, max(n, 1), "第 2 步 / 3：正在扫已删除记录…"),
                    progress2=lambda i, n: None if self._stop else self.progress.emit(
                        i, max(n, 1), "第 2 步 / 3：正在逐个确认内容还在不在…"),
                    cancel=self.stopped)
            except Exception as exc:               # noqa: BLE001
                # 这一步失败（多半是没管理员权限 / 文件系统认不出）不该把第 1 步
                # 已经拿到的回收站结果一起扔掉 —— 记下原因，接着走。
                out.setdefault("notes", []).append(f"扫已删除记录没做成：{exc}")
            stages.append(("已删除记录", take(items2, "deleted")))

        # ── 第 3 步：格式化残留（只在「几乎没找到」或用户要求时）──
        need_deep = bool(self.deep) or len(items2) < 8
        st3 = {}
        if need_deep and not self._stop:
            self.progress.emit(0, 3, "第 3 步 / 3：深挖格式化后的残留（慢，可随时停）…")
            try:
                items3, st3 = recovery.metadata_scan(
                    src, on_batch=self._batch("格式化残留"),
                    budget=self.budget or (900 if self.deep else 180),
                    only_free=not self.deep, limit=None,
                    progress=lambda i, n, text: None if self._stop else self.progress.emit(
                        i, max(n, 1), "第 3 步 / 3：正在深挖格式化残留…"),
                    cancel=self.stopped)
            except Exception as exc:               # noqa: BLE001
                out.setdefault("notes", []).append(f"深挖格式化残留没做成：{exc}")
            stages.append(("格式化残留", take(items3, "residual")))

        order = {"recycle": 0, "good": 1, "dir": 2, "risky": 3,
                 "unknown": 4, "no_data": 5, "name_only": 6}
        merged.sort(key=lambda i: (order.get(i.get("confidence"), 9),
                                   -int(i.get("_t") or 0)))
        out["items"] = merged
        out["stats"] = {
            "found": len(merged),
            "good": sum(1 for i in merged if i.get("confidence") == "good"),
            "risky": sum(1 for i in merged if i.get("confidence") == "risky"),
            "recycle": sum(1 for i in merged if i.get("confidence") == "recycle"),
            "stages": stages,
            "deep_ran": need_deep,
            "deep_wanted": bool(self.deep),
            "letter": self.letter,
            "fs": st2.get("fs") or st3.get("fs") or "",
            "truncated": bool(st2.get("truncated") or st3.get("truncated")),
            # 「认出来多少条」和「列出多少条」是两件事：界面一次只摆 2000 行（分批加载），
            # 但结果本身是全量的，不能让人以为「就这么点」。
            "candidates": st2.get("candidates") or st3.get("candidates") or 0,
            "unverified": st2.get("unverified") or st3.get("unverified") or 0,
            "elapsed": round(time.time() - t0, 1),
            "fs_label": getattr(src, "fs", "") or "",
        }

    def _work(self, out, vol):
        src = vol if vol is not None else self.letter
        if self.mode == "auto":
            self._auto(out, src)
        elif self.mode == "recycle":
            self.progress.emit(0, 1, "正在读回收站…")
            out["items"] = recovery.recycle_items(self.letter)
            out["stats"] = {"found": len(out["items"])}
        elif self.mode == "mft":
            items, st = recovery.scan_deleted(
                src, limit=None, on_batch=self._batch("已删除记录"),
                progress=lambda i, n: None if self._stop else self.progress.emit(
                    i, n, "正在扫磁盘上的已删除记录…"),
                progress2=lambda i, n: None if self._stop else self.progress.emit(
                    i, max(n, 1), "正在逐个确认内容还在不在…"),
                cancel=self.stopped)
            out["items"] = items
            out["stats"] = st
        elif self.mode == "raw":
            # 格式化/目录全丢：扫盘上的残留旧记录 + 目录索引（两路合并，能带回原名和目录）
            items, st = recovery.metadata_scan(
                src, on_batch=self._batch("格式化残留"),
                # 整卷扫描按专业软件的路子给足时间：几百 GB 扫几个小时很正常
                budget=self.budget or (900 if self.deep else 180),
                only_free=not self.deep, limit=None,
                progress=lambda i, n, text: None if self._stop else self.progress.emit(
                    i, max(n, 1), text),
                cancel=self.stopped)
            out["items"] = items
            out["stats"] = st
        elif self.mode == "carve":
            def _stage(done, total, found):
                if self._stop:
                    return
                gb = done / (1024 ** 3)
                all_gb = total / (1024 ** 3)
                self.progress.emit(
                    done, total,
                    f"正在按文件类型找…已扫 {gb:.1f} / {all_gb:.1f}GB，找到 {found} 个")
            made, st = recovery.carve(
                src, self.target, groups=self.groups,
                progress=_stage, cancel=self.stopped)
            out["items"] = [{"name": os.path.basename(m), "path": m,
                             "size": os.path.getsize(m) if os.path.exists(m) else 0,
                             "confidence": "good", "mtime": "", "is_dir": False}
                            for m in made]
            out["stats"] = st
        else:
            self.failed.emit(f"未知的查找方式：{self.mode}")


class RecoveryRestoreTask(BaseTask):
    """把勾选的条目复制到目标目录（回收站 / MFT 两条路用）。

    逐条做、逐条回报成败：一条失败不影响其他条，也不静默吞掉失败原因。
    """

    done = Signal(object)

    def __init__(self, mode, letter, items, target, image=None, image_base=0,
                 parent=None):
        super().__init__(parent)
        self.mode = mode
        self.letter = letter
        self.items = list(items)
        self.target = target
        self.image = image              # 从镜像里导出：不碰源盘
        self.image_base = image_base    # 整盘镜像里卷首的字节偏移
        self._stop = False

    def stop(self):
        self._stop = True

    def work(self):
        ok, bad = [], []
        vol = None
        try:
            if self.mode in ("mft", "raw"):
                if self.image:
                    vol, _kind = recovery.open_image_volume(
                        self.image, letter=self.letter or "镜像",
                        base=self.image_base)
                else:
                    # 恢复也要按真实文件系统开（FAT / exFAT 的 runs 和 NTFS 同构）
                    vol = recovery.open_volume(self.letter)[0]
            path_cache = {}
            for i, item in enumerate(self.items, 1):
                if self._stop:
                    break
                self.progress.emit(i, len(self.items),
                                   f"正在恢复 {item.get('name', '')}")
                # 扫描时为省时间没算的那部分原路径，现在卷已经打开了，顺手补上，
                # 否则恢复出来会平铺在目标目录里，原来的目录结构就没了。
                if vol is not None and self.mode in ("mft", "raw"):
                    recovery.fill_path(vol, item, path_cache)
                try:
                    if self.mode == "recycle":
                        dest = recovery.restore_recycle(item, self.target)
                    else:
                        # 注意：必须传「可调用对象」，不能写 self._stop or (lambda: False)
                        # —— self._stop 是 False，`False or 函数` 的结果恒为「真」，恢复会
                        # 在第一个数据段之后就被当成「用户取消」而中断，写出半截文件。
                        dest = recovery.recover_one(vol, item, self.target,
                                                    cancel=lambda: self._stop)
                    # 写完立刻自检：大小对不对、文件头像不像这个扩展名、是不是全零。
                    # 不通过不算「成功」——宁可报一条「可能有问题的」，也不假装全好了。
                    good, why = recovery.verify_recovered(dest, item)
                    ok.append({"name": item.get("name"), "dest": dest,
                               "good": good, "why": why})
                except Exception as exc:            # noqa: BLE001
                    bad.append({"name": item.get("name"),
                                "why": f"{type(exc).__name__}: {exc}"})
        finally:
            if vol is not None:
                vol.close()
        shaky = [r for r in ok if not r.get("good")]
        self.done.emit({"ok": ok, "bad": bad, "target": self.target,
                        "shaky": shaky})


# ───────────────────────────── 整卷镜像 ─────────────────────────────

class ImageTask(BaseTask):
    """把整块卷只读复制成镜像文件（断点续传 + 坏道跳过 + 多遍重读）。

    为什么要它：专业流程的第一步。对镜像可以反复扫、慢慢扫，源盘只读一遍；
    扫到一半断电也不怕 —— 下次同一个文件继续写；盘上有坏道也不会整次白做
    （坏区被跳过并记进 `.badmap`，而不是让整个镜像任务失败）。
    """

    done = Signal(object)

    def __init__(self, letter, dest, parent=None, passes=3, retries=2):
        super().__init__(parent)
        self.letter = letter
        self.dest = dest
        self.passes = passes
        self.retries = retries
        self._stop = False

    def stop(self):
        self._stop = True

    def work(self):
        # SMART 预检要跑一次 PowerShell（几百毫秒到几秒），先吱一声，
        # 否则用户会以为「点了没反应」。
        self.log.emit(f"正在看 {self.letter} 的健康状态…")
        try:
            st = recovery.image_volume(
                self.letter, self.dest,
                progress=lambda done, total, text: self.progress.emit(done, total, text),
                cancel=lambda: self._stop,
                passes=self.passes, retries=self.retries)
        except Exception as exc:                    # noqa: BLE001
            self.failed.emit(str(exc))
            return
        for line in st.get("notes") or []:
            self.log.emit(line)
        pre = st.get("smart") or {}
        if pre.get("level") == "warn":
            self.log.emit(f"提醒：{pre.get('text')}")
        if st.get("resumed"):
            self.log.emit(f"从断点续写：{st['done'] / 2 ** 20:.0f} MB")
        self.done.emit(st)
