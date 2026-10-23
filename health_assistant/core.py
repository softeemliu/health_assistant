"""
health_assistant.core — 应用框架核心

包含四部分：
  1. 结果模型   : Severity / Finding / KV / Table / Text / Bars / Result
  2. 检查注册   : @check 装饰器 + REGISTRY
  3. 运行上下文 : Context（配置 / 权限 / 缓存）
  4. 通用工具   : 格式化、外部命令、Windows 原生调用

新增一个巡检项只需三步：
    from health_assistant.core import check, Result, KV, Finding, Severity

    @check("demo.hello", "示例检查", group="system", order=900)
    def demo(ctx):
        res = Result()
        res.kv([("主机名", "abc")])
        res.add(severity=Severity.OK, summary="一切正常")
        return res
"""

from __future__ import annotations

import ctypes
import datetime as dt
import json
import os
import re
import socket
import subprocess
import sys
import threading
import unicodedata

__all__ = [
    "Severity", "Kind", "Finding", "KV", "Table", "Text", "Bars", "Result",
    "ActionPlan", "Check", "REGISTRY", "check", "get_checks", "Context",
    "DEFAULT_CONFIG", "load_config", "deep_merge",
    "fb", "pct", "dur", "dwidth", "pad", "short_path", "run_cmd", "is_admin",
    "no_window_kwargs", "cli_cmd", "BASE_DIR",
    "hostname", "now_str", "chrome_time", "filetime_to_dt", "sockaddr_text",
]

IS_WINDOWS = os.name == "nt"

# 项目根目录（health_assistant 包的上一级）。命令行入口、配置、产物都相对于它。
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ───────────────────────────── 1. 结果模型 ─────────────────────────────

class Severity:
    """检查结论等级。数值用于汇总排序。"""
    OK = "ok"
    INFO = "info"
    WARN = "warn"
    ERROR = "error"

    RANK = {OK: 0, INFO: 1, WARN: 2, ERROR: 3}
    LABEL = {OK: "正常", INFO: "信息", WARN: "警告", ERROR: "异常"}

    @classmethod
    def worst(cls, *levels):
        best = cls.OK
        for lv in levels:
            if lv and cls.RANK.get(lv, 0) > cls.RANK.get(best, 0):
                best = lv
        return best


class Kind:
    """结论的性质 —— 决定它进不进「待处理清单」。

    problem : 真的要动一次（清缓存 / 关自启 / 关端口 / 换凭据存放）→ 进待处理清单
    notice  : 提醒一句，但不是本次能自动解决的（如浏览器 v20 加密）
    info    : 纯记录，正常状态 → 只在依据页留档
    """
    PROBLEM = "problem"
    NOTICE = "notice"
    INFO = "info"


class Finding:
    """一条结论。

    除等级外还带结构化字段，让报告能直接给出「该怎么做」：
      impact     不处理会怎样（一句白话）
      fix        可直接复制的修复命令；无则留空
      gain       收益描述（"释放 13.2GB" / "少 17 个开机项"）
      save_bytes 收益可量化的部分（字节），用于全局合计
      ref        依据页（检查 id），报告里可跳转
      kind       Kind.* —— 决定是否进「待处理清单」
    """

    __slots__ = ("severity", "text", "impact", "fix", "gain",
                 "save_bytes", "ref", "kind")

    def __init__(self, severity: str, text: str, impact: str = "", fix: str = "",
                 gain: str = "", save_bytes: int = 0, ref: str = "", kind: str = ""):
        self.severity = severity
        self.text = text
        self.impact = impact or ""
        self.fix = fix or ""
        self.gain = gain or ""
        self.save_bytes = int(save_bytes or 0)
        self.ref = ref or ""
        if kind:
            self.kind = kind
        elif severity in (Severity.WARN, Severity.ERROR):
            self.kind = Kind.PROBLEM
        elif severity == Severity.OK:
            self.kind = Kind.INFO
        else:
            self.kind = Kind.NOTICE

    @property
    def is_problem(self):
        return self.kind == Kind.PROBLEM

    def to_dict(self):
        return {"severity": self.severity, "text": self.text, "kind": self.kind,
                "impact": self.impact, "fix": self.fix, "gain": self.gain,
                "save_bytes": self.save_bytes, "ref": self.ref}


class KV:
    """键值对块。"""
    __slots__ = ("rows",)

    def __init__(self, rows):
        self.rows = [(str(k), str(v)) for k, v in rows]

    def to_dict(self):
        return {"type": "kv", "rows": self.rows}


class Table:
    """表格块。aligns: 'l' / 'r'。"""
    __slots__ = ("headers", "rows", "aligns")

    def __init__(self, headers, rows, aligns=None):
        self.headers = [str(h) for h in headers]
        self.rows = [[str(c) for c in r] for r in rows]
        self.aligns = aligns or ["l"] * len(self.headers)

    def to_dict(self):
        return {"type": "table", "headers": self.headers, "rows": self.rows,
                "aligns": self.aligns}


class Text:
    """纯文本块（多行原样输出）。"""
    __slots__ = ("text",)

    def __init__(self, text):
        self.text = str(text)

    def to_dict(self):
        return {"type": "text", "text": self.text}


class Bars:
    """条形图块。rows: [(label, value_text, ratio 0~1)]"""
    __slots__ = ("rows", "width")

    def __init__(self, rows, width=24):
        self.rows = [(str(a), str(b), float(c)) for a, b, c in rows]
        self.width = width

    def to_dict(self):
        return {"type": "bars", "rows": self.rows}


class Result:
    """一个检查项的产出。

    统一用 add() 记录结论，块级内容用 kv()/table()/text()/bars() 追加。
    metrics 用于 JSON 导出与历史对比（放纯数值，不放长文本）。
    """

    def __init__(self):
        self.status = Severity.OK
        self.summary = ""
        self.blocks = []
        self.findings = []
        self.metrics = {}
        self.error = None
        self._check_id = ""

    # ---- 结论 ----
    def add(self, severity=Severity.INFO, summary=None, impact="", fix="",
            gain="", save_bytes=0, ref="", kind=""):
        """记录一条 Finding。

        severity 参与最终状态汇总；其余字段让这条结论能直接变成「待办」。
        只要给了 fix / impact / gain 任意一项，就自动视为要处理的问题。
        """
        if summary:
            k = kind
            if not k and severity in (Severity.WARN, Severity.ERROR):
                k = Kind.PROBLEM
            self.findings.append(Finding(severity, summary, impact=impact, fix=fix,
                                         gain=gain, save_bytes=save_bytes,
                                         ref=ref or self._check_id, kind=k))
        self.status = Severity.worst(self.status, severity)
        return self

    @property
    def problems(self):
        """只保留真正要处理的结论。"""
        return [f for f in self.findings if f.is_problem]

    @property
    def needs_action(self):
        return bool(self.problems)

    def set_id(self, check_id):
        """由 runner 回填：让 add() 里的 ref 能自动指向本检查。"""
        self._check_id = check_id

    def fail(self, message):
        self.status = Severity.ERROR
        self.summary = message
        self.error = message
        return self

    # ---- 内容块 ----
    def kv(self, rows):
        self.blocks.append(KV(rows))
        return self

    def table(self, headers, rows, aligns=None):
        if rows:
            self.blocks.append(Table(headers, rows, aligns))
        return self

    def text(self, s):
        self.blocks.append(Text(s))
        return self

    def bars(self, rows, width=24):
        if rows:
            self.blocks.append(Bars(rows, width))
        return self

    # ---- 序列化 ----
    def to_dict(self):
        return {
            "status": self.status,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "metrics": self.metrics,
            "blocks": [b.to_dict() for b in self.blocks],
            "error": self.error,
        }


# ───────────────────── 待处理清单（跨检查汇总） ─────────────────────

class ActionPlan:
    """把散在各检查里的「要处理的事」汇成一张按收益排序的清单。

    报告首页只显示这份清单 —— 正常项不进清单，只在依据页留档。
    """

    def __init__(self, items):
        self.entries = []
        for chk, res in items:
            for f in res.findings:
                if not f.is_problem:
                    continue
                self.entries.append({
                    "check": chk.id, "title": chk.title, "group": chk.group,
                    "severity": f.severity, "text": f.text,
                    "impact": f.impact, "fix": f.fix, "gain": f.gain,
                    "save_bytes": f.save_bytes, "ref": f.ref or chk.id,
                })
        self.entries.sort(key=lambda e: (
            -Severity.RANK.get(e["severity"], 0),
            -e["save_bytes"],
        ))

    @property
    def count(self):
        return len(self.entries)

    @property
    def total_save(self):
        return sum(e["save_bytes"] for e in self.entries)

    @property
    def with_fix(self):
        return sum(1 for e in self.entries if e["fix"])

    def to_dict(self):
        return {"count": self.count, "total_save": self.total_save,
                "with_fix": self.with_fix, "entries": self.entries}


# ───────────────────────────── 2. 检查注册 ─────────────────────────────

class Check:
    __slots__ = ("id", "title", "group", "func", "order", "admin", "desc", "tags")

    def __init__(self, cid, title, group, func, order=100, admin=False, desc="", tags=()):
        self.id = cid
        self.title = title
        self.group = group
        self.func = func
        self.order = order
        self.admin = admin
        self.desc = desc
        self.tags = tuple(tags)

    def __repr__(self):
        return f"<Check {self.id} {self.title}>"


REGISTRY = {}

GROUP_TITLES = {
    "system": "系统资源",
    "profile": "用户目录",
    "network": "网络",
    "ops": "运维",
    "security": "安全与账号",
    "cleanup": "磁盘清理",
    "custom": "自定义",
    "misc": "其他",
}


def check(cid, title, group="system", order=100, admin=False, desc="", tags=()):
    """注册一个巡检项。被装饰函数签名: func(ctx) -> Result"""
    def deco(fn):
        if cid in REGISTRY:
            raise ValueError(f"重复的检查 ID: {cid}")
        REGISTRY[cid] = Check(cid, title, group, fn, order, admin, desc, tags)
        return fn
    return deco


GROUP_ORDER = ["system", "profile", "network", "ops", "security", "cleanup", "custom", "misc"]


def _group_rank(name):
    try:
        return GROUP_ORDER.index(name)
    except ValueError:
        return len(GROUP_ORDER)


def get_checks(selector=None, include_disabled=None):
    """按选择器过滤并排序。

    selector: 逗号/空格分隔，每项可以是
      · 分组名        system / network / ops / security / profile / cleanup
      · 完整检查 ID   cpu.usage
      · ID 前缀       cpu  → cpu.usage
      · 模糊片段      ftp  → ftp.discovery（同时匹配 ID 与标题）
    """
    allc = sorted(REGISTRY.values(), key=lambda c: (_group_rank(c.group), c.order, c.id))
    if include_disabled is not None:
        allc = [c for c in allc if c.id not in set(include_disabled)]
    if not selector:
        return allc
    want = {s.strip().lower() for s in re.split(r"[,；;\s]+", selector) if s.strip()}
    if not want:
        return allc

    out = []
    for c in allc:
        cid, grp, title = c.id.lower(), c.group.lower(), c.title.lower()
        for sel in want:
            if (sel == grp or sel == cid
                    or cid.startswith(sel + ".")
                    or sel in cid or (len(sel) > 1 and sel in title)):
                out.append(c)
                break
    return out


# ───────────────────────────── 3. 配置 / 上下文 ─────────────────────────────

DEFAULT_CONFIG = {
    "timeout": 60,                       # 单项超时秒数
    "workers": 6,                        # 并行执行的检查项个数
    "disabled": [],                      # 禁用的检查 ID
    "plugin_dirs": [],                   # 额外插件目录（相对路径按配置文件所在目录解析）
    "event_count": 6,                    # 每个事件日志取多少条
    "custom_dirs": [],                   # 自定义巡检的目录列表（插件可读）
    "reveal": True,                      # 默认显示密码明文；命令行 --mask 可遮罩
    "proc": {
        "top": 10,                       # CPU/内存 TOP 列几个
        "detail": 5,                     # 其中几个展开完整启动参数
        "cmdline_width": 64,             # 表格里命令行列宽（超出中间省略）
    },
    "profile": {
        "budget": 20,                    # 用户目录扫描总预算（秒，并行）
        "dir_seconds": 5,                # 单个目录最多统计几秒（到点标 ≥）
        "top": 15,                       # 每张表最多列几行
        "min_mb": 200,                   # 多大算"大文件"
        "deep": False,                   # True = 不限单目录时间，全部测准（慢）
    },
    "ports": {
        "top": 40,                       # 监听端口表最多列几条
        "detail": 8,                     # 其中几个展开完整命令行
    },
    "cleanup": {
        "min_mb": 10,                    # 只报告不小于该体积的残留目录
        "active_days": 45,               # 最近 N 天有写入 → 视为仍在使用
        "top": 12,                       # 报告里每类最多列几行
        "batch": 10,                     # 一次最多清理几个目录
        # 系统盘瘦身（僵尸文件 / 无用用户文件）
        "slim_older": 60,                # 安装包/压缩包多久没动过才算"用不着了"
        "slim_budget": 25,               # 瘦身扫描的时间预算（秒）
        "slim_batch": 200,               # 瘦身一次最多处理几项（候选动辄一两百条）
    },
    "thresholds": {
        "cpu_warn": 75,
        "cpu_error": 90,
        "mem_warn": 80,
        "mem_error": 90,
        "disk_warn": 80,
        "disk_error": 90,
        "disk_free_min_gb": 5,
        "startup_warn": 15,
        "svc_down_warn": 1,
    },
    "network": {
        "ping_targets": ["223.5.5.5", "8.8.8.8"],
        "dns_targets": ["www.baidu.com", "www.qq.com"],
        "tcp_targets": [["223.5.5.5", 443]],
        "watch_ports": [21, 23, 445, 1433, 3306, 3389, 6379, 27017],
    },
    "ftp_ports": [21, 2121, 990],
}


def deep_merge(base, override):
    """dict 深合并；list / 标量直接覆盖。"""
    if not isinstance(base, dict) or not isinstance(override, dict):
        return override
    out = dict(base)
    for k, v in override.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


# 4.16.0 改名前后的目录名。改名只该影响「以后写哪里」，**不该让历史记录失联**：
# 清理台账、注册表备份、凭据备份、启动项备份都还在老目录里，不搬过来用户就以为没了。
_OLD_NAME = "pcinspect"
_NEW_NAME = "health_assistant"


def migrate_legacy_dirs():
    r"""把老目录（%APPDATA%\pcinspect、%LOCALAPPDATA%\pcinspect）里的东西搬到新目录。

    幂等、只复制不删除：老目录留着当保底，用户确认没事了自己删。
    目标已存在的同名文件不覆盖 —— 新目录里的永远更新。
    返回搬过去的文件数（给日志用）。
    """
    import shutil
    moved = 0
    for env in ("APPDATA", "LOCALAPPDATA"):
        root = os.environ.get(env)
        if not root:
            continue
        src = os.path.join(root, _OLD_NAME)
        dst = os.path.join(root, _NEW_NAME)
        if not os.path.isdir(src):
            continue
        for base, _dirs, files in os.walk(src):
            rel = os.path.relpath(base, src)
            target_dir = os.path.join(dst, rel) if rel != "." else dst
            try:
                os.makedirs(target_dir, exist_ok=True)
            except OSError:
                continue
            for fn in files:
                s_path = os.path.join(base, fn)
                d_path = os.path.join(target_dir, fn)
                if os.path.exists(d_path):
                    continue
                try:
                    shutil.copy2(s_path, d_path)
                    moved += 1
                except OSError:
                    continue
    return moved


def load_config(path=None):
    """加载配置；未指定时尝试 %APPDATA%/health_assistant/config.json。返回 (config, 来源说明)"""
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))       # 深拷贝
    candidates = []
    if path:
        candidates.append((path, True))
    else:
        appdata = os.environ.get("APPDATA")
        if appdata:
            candidates.append((os.path.join(appdata, _NEW_NAME, "config.json"), False))
            # 老版本（叫 pcinspect 的时候）留下的配置也认，别让用户改过的设置凭空消失
            candidates.append((os.path.join(appdata, _OLD_NAME, "config.json"), False))
        candidates.append((os.path.join(os.getcwd(), "health_assistant.config.json"), False))

    for p, required in candidates:
        if not p or not os.path.isfile(p):
            if required:
                raise FileNotFoundError(f"配置文件不存在: {p}")
            continue
        with open(p, "r", encoding="utf-8-sig") as fh:
            user = json.load(fh)
        cfg = deep_merge(cfg, user)
        base = os.path.dirname(os.path.abspath(p))
        # 相对插件目录改为绝对路径
        cfg["plugin_dirs"] = [
            d if os.path.isabs(d) else os.path.normpath(os.path.join(base, d))
            for d in cfg.get("plugin_dirs", [])
        ]
        return cfg, p
    return cfg, None


class Context:
    """传给每个 check 的运行上下文。

    检查项并行执行（见 runner.run_checks），所以 cached() 必须线程安全：
    同一 key 只允许一个线程真正计算，其余线程等它算完直接取结果，
    否则四个 profile 检查会各自扫一遍用户目录。
    """

    def __init__(self, config, admin=None, verbose=False):
        self.config = config
        self.admin = is_admin() if admin is None else bool(admin)
        self.verbose = verbose
        self.cache = {}
        self._locks = {}
        self._locks_guard = threading.Lock()

    def thr(self, key, default=None):
        return self.config.get("thresholds", {}).get(key, default)

    def net(self, key, default=None):
        return self.config.get("network", {}).get(key, default)

    def _lock_for(self, key):
        with self._locks_guard:
            lock = self._locks.get(key)
            if lock is None:
                lock = self._locks[key] = threading.Lock()
            return lock

    def cached(self, key, factory):
        """同一项检查内需要复用的昂贵结果（如进程快照 / 用户目录扫描）。"""
        with self._lock_for(key):
            if key not in self.cache:
                self.cache[key] = factory()
            return self.cache[key]


# ───────────────────────────── 4. 通用工具 ─────────────────────────────

def is_admin():
    if not IS_WINDOWS:
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def hostname():
    try:
        return socket.gethostname()
    except Exception:
        return "?"


def now_str():
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def fb(n):
    """字节数格式化"""
    try:
        n = float(n)
    except Exception:
        return str(n)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(n) < 1024.0 or unit == "PB":
            return f"{int(n)}B" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024.0


def pct(a, b):
    try:
        return 0.0 if not b else a * 100.0 / b
    except Exception:
        return 0.0


def dur(sec):
    sec = int(max(0, sec))
    d, sec = divmod(sec, 86400)
    h, sec = divmod(sec, 3600)
    m, s = divmod(sec, 60)
    if d:
        return f"{d}天{h}小时{m}分"
    if h:
        return f"{h}小时{m}分"
    return f"{m}分{s}秒"


def dwidth(s):
    """终端显示宽度（CJK 算 2 列）"""
    w = 0
    for ch in str(s):
        w += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return w


def pad(s, width, align="l"):
    s = str(s)
    gap = max(0, width - dwidth(s))
    return (" " * gap + s) if align == "r" else (s + " " * gap)


def short_path(p, width=46):
    """长路径保留尾部，前面加省略号（比硬截断好读）。"""
    p = str(p)
    if len(p) <= width:
        return p
    return "…" + p[-(width - 1):]


def cli_cmd(*args):
    """把「下一步该敲的命令」拼成可复制到任意目录直接执行的字符串。

    踩过的坑：报告里原来写 `python -m health_assistant clean --kind profile`，
    用户在自己的 cmd（C:\\Users\\xxx）里粘贴，直接 No module named health_assistant ——
    因为包没装进 site-packages，只能从项目目录 `python -m` 跑。

    现在统一走项目根目录的 health_assistant.cmd（内部 pushd 到根目录再调 python -m），
    绝对路径、与当前目录无关，粘贴即执行。

    打包成 EXE 之后没有 health_assistant.cmd、也没有 python，指向的就是 EXE 自己
    （`"健康助手.exe" smart` 这种带参数启动会进命令行模式，见 health_assistant_app.py）。
    """
    if getattr(sys, "frozen", False):
        cmd = f'"{sys.executable}"'
    else:
        launcher = os.path.join(BASE_DIR, "health_assistant.cmd")
        cmd = f'"{launcher}"' if os.path.isfile(launcher) else "python -m health_assistant"
    if args:
        cmd += " " + " ".join(str(a) for a in args)
    return cmd


def no_window_kwargs():
    """隐藏子进程控制台窗口的 kwargs。

    GUI 是 pythonw 起的（本身没有控制台），这时再子进程调 ping / wevtutil / netsh
    这类控制台程序，Windows 会给每个子进程新开一个黑窗口 —— 巡检一跑就是几个
    黑框轮着闪。加 CREATE_NO_WINDOW + STARTUPINFO(SW_HIDE) 就彻底不闪了。
    """
    if not IS_WINDOWS:
        return {}
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0            # SW_HIDE
    return {"creationflags": 0x08000000, "startupinfo": si}   # CREATE_NO_WINDOW


def run_cmd(cmd, timeout=20, encoding=None):
    """执行外部命令，返回 (rc, 合并输出)。不抛异常，不弹窗。"""
    try:
        p = subprocess.run(
            cmd, capture_output=True, timeout=timeout,
            encoding=encoding or ("oem" if IS_WINDOWS else "utf-8"),
            errors="replace", **no_window_kwargs(),
        )
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as exc:
        return -1, f"{type(exc).__name__}: {exc}"


def filetime_to_dt(high, low):
    try:
        v = (int(high) << 32) | int(low)
        if not v:
            return "从未"
        return (dt.datetime(1601, 1, 1) + dt.timedelta(microseconds=v // 10)).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return "-"


def chrome_time(us):
    try:
        us = int(us or 0)
        if us <= 0:
            return "未知"
        return (dt.datetime(1601, 1, 1) + dt.timedelta(microseconds=us)).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return "未知"


def sockaddr_text(sa):
    """SOCKET_ADDRESS → '1.2.3.4'（供 GetAdaptersAddresses 用）"""
    try:
        if not sa.lpSockaddr or sa.iSockaddrLength <= 0:
            return None
        raw = ctypes.string_at(sa.lpSockaddr, sa.iSockaddrLength)
        fam = int.from_bytes(raw[:2], "little")
        if fam == socket.AF_INET and len(raw) >= 8:
            return socket.inet_ntop(socket.AF_INET, raw[4:8])
        if fam == socket.AF_INET6 and len(raw) >= 24:
            return socket.inet_ntop(socket.AF_INET6, raw[8:24])
    except Exception:
        return None
    return None
