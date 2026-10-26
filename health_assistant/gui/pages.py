"""health_assistant.gui.pages — 各功能页

DetailPage    巡检明细（左树右详情，首页）
ProcsPage     进程（含启动参数、结束进程）
PortsPage     监听端口（含进程/服务/参数）
CleanPage     清理（扫描 → 勾选 → 移到回收站；含注册表残留）
CredsPage     凭据（系统 / 浏览器 / FTP 与网络位置，含导出导入引导）
"""

from __future__ import annotations

import json
import os
import subprocess
import time

from PySide6.QtCore import QItemSelectionModel, Qt, QThreadPool, QTimer, Signal
from PySide6.QtGui import QColor, QGuiApplication
from PySide6.QtWidgets import (QAbstractItemView, QButtonGroup, QCheckBox,
                               QComboBox, QDialog, QDialogButtonBox,
                               QDoubleSpinBox, QFileDialog, QFrame,
                               QHBoxLayout, QHeaderView, QInputDialog, QLabel,
                               QLineEdit, QMenu, QMessageBox, QPlainTextEdit,
                               QProgressBar, QPushButton, QRadioButton,
                               QScrollArea, QSizePolicy, QSpinBox, QSplitter,
                               QTabWidget, QTextBrowser, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget)

from .. import (catalog, credentials, filelock, leftover, memtrim, metrics,
                partitions, planclean, recovery, regclean, slim)
from ..core import (GROUP_ORDER, GROUP_TITLES, cli_cmd, fb, is_admin,
                    no_window_kwargs)
from .preview_ui import PreviewDialog, PreviewJob, PreviewPane
from .theme import C, SEV, SEV_LABEL, sev_color
from .widgets import (Badge, BlockView, CheckTable, DataTable, EmptyState,
                      FindingList, hline, show_error, window_busy)

DB_PORTS = {1433, 3306, 3389, 5432, 6379, 9200, 27017}
VIEW_STEP = 2000      # 恢复结果一次摆多少行（十几万行塞进表格会卡死，翻到底靠「多看」按钮）


class Page(QWidget):
    """页面基类：统一持有后台任务引用，避免线程被回收。"""

    notify = Signal(str)

    def __init__(self, cfg, parent=None):
        super().__init__(parent)
        self.cfg = cfg
        self._task = None

    def _hold(self, task):
        """保存任务引用并在结束后释放。"""
        self._task = task
        task.finished.connect(lambda: self._release(task))
        return task

    def _release(self, task):
        if self._task is task:
            self._task = None
        task.deleteLater()

    def is_busy(self):
        return self._task is not None and self._task.isRunning()


# ══════════════════════════════ 明细 ══════════════════════════════

class DetailPage(Page):
    """巡检明细：左侧按状态筛选的检查项，右侧该项的结论、依据与操作。

    右键是主操作入口 —— 树上一个检查项可以复制结论/命令、复制重跑命令、
    跳到相关页面；右侧每张结论卡片也能右键复制。
    """

    goto_page = Signal(str)          # "clean" / "ports" / "procs"

    def __init__(self, cfg, parent=None):
        super().__init__(cfg, parent)
        self._data = {}
        self._nodes = {}
        self._current = None
        self._status = "all"
        self._running = False
        self._placeholder = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(8)

        # ── 顶部：只有搜索 ──
        # 原来「要处理的 / 全部 / 正常的」三个筛选分页已去掉：普通使用者不关心状态分级，
        # 一律全列，有问题的项用颜色+粗体标出（3.5.3 按用户要求删）。
        bar = QHBoxLayout()
        bar.setSpacing(6)
        tip = QLabel("所有检查项都在下面，有问题的用红色标出")
        tip.setObjectName("Muted")
        bar.addWidget(tip)
        bar.addStretch(1)
        self.ed_filter = QLineEdit()
        self.ed_filter.setPlaceholderText("搜索问题关键词…")
        self.ed_filter.setClearButtonEnabled(True)
        self.ed_filter.setFixedWidth(210)
        self.ed_filter.textChanged.connect(lambda _t: self._apply_filter())
        bar.addWidget(self.ed_filter)
        outer.addLayout(bar)

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(10)

        left = QWidget()
        lv = QVBoxLayout(left)
        lv.setContentsMargins(0, 0, 0, 0)
        lv.setSpacing(6)
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setColumnCount(2)
        self.tree.setIndentation(12)
        self.tree.setAnimated(True)
        self.tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.tree.header().setSectionResizeMode(1, QHeaderView.Fixed)
        self.tree.setColumnWidth(1, 64)
        self.tree.setStyleSheet(
            f"QTreeWidget{{background:{C['panel']};border:1px solid {C['border']};"
            f"border-radius:8px;padding:4px;outline:none;}}"
            f"QTreeWidget::item{{padding:5px 4px;border-radius:5px;}}"
            f"QTreeWidget::item:hover{{background:#f4f7fb;}}"
            f"QTreeWidget::item:selected{{background:{C['accent_soft']};color:{C['text']};}}")
        self.tree.currentItemChanged.connect(self._on_pick)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._tree_menu)
        self.tree.setToolTip("右键检查项可直接复制命令、重跑或跳到相关页面")
        lv.addWidget(self.tree, 1)
        left.setMinimumWidth(300)
        left.setMaximumWidth(430)
        body.addWidget(left)

        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(0, 0, 0, 0)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.body = QWidget()
        self.blay = QVBoxLayout(self.body)
        self.blay.setContentsMargins(18, 16, 18, 16)
        self.blay.setSpacing(12)
        self.scroll.setWidget(self.body)
        rv.addWidget(self.scroll)
        body.addWidget(right, 1)

        outer.addLayout(body, 1)

        self._placeholder = EmptyState("检查完成后，这里显示每一项的结果",
                                       "左侧只列出需要处理的问题；想看全部就点上面的「全部」")
        self.blay.addWidget(self._placeholder)
        self.blay.addStretch(1)

    # ---- 状态分类 ----
    # 树右侧的状态词：不显示耗时（毫秒对普通使用者毫无意义）
    _WORD = {"ok": "正常", "warn": "要注意", "error": "有问题",
             "other": "—", "skip": "跳过", "none": ""}

    # 分组名的白话版（只改界面显示，不动 core / 报告）
    _PLAIN_TITLES = {
        "system": "电脑运行状态", "profile": "文件与缓存", "network": "网络连接",
        "ops": "后台与开机", "security": "账号与密码", "cleanup": "可清理空间",
        "custom": "自定义", "misc": "其他",
    }

    # id 前缀 → (页签/窗口 key, 按钮文字)：右键「跳到…处理」
    _PAGE_HINTS = (
        ("profile.secrets", "creds", "查看保存的密码"),
        ("profile.cred", "creds", "查看保存的密码"),
        ("disk.leftover", "clean", "去清理空间"),
        ("cleanup", "clean", "去清理空间"),
        ("profile", "clean", "去清理空间"),
        # 磁盘告警时最该做的是「看清谁占着」——下钻比一键清理更有用（也不动任何文件）
        ("disk", "disk_use", "看空间去哪了"),
        # 开机慢是最好解决的一类「电脑变慢」：断链项和最占时间的第三方项一关就见效
        ("startup", "startup", "管理开机自启项"),
        ("network", "ports", "查看端口（技术）"),
        ("memory.usage", "procs", "查看进程（技术）"),
        ("system.cpu", "procs", "查看进程（技术）"),
        ("system.mem", "procs", "查看进程（技术）"),
        ("ops.process", "procs", "查看进程（技术）"),
    )

    # 系统盘剩余低于这个数，体检页就把「去瘦身」当首选按钮推出来（GB）
    _SLIM_OFFER_GB = 20
    # 内存使用率高于这个数，体检页就把「内存加速」当首选按钮推出来（%）
    _MEM_OFFER_PCT = 80.0

    @staticmethod
    def _bucket(d):
        if not d:
            return "none"
        sev = d.get("status", "info")
        if sev in ("warn", "error", "ok"):
            return sev
        if "跳过" in (d.get("summary") or ""):
            return "skip"
        return "other"

    @staticmethod
    def _search_blob(d):
        parts = [d.get("summary") or ""]
        parts += [f.get("text", "") for f in d.get("findings") or []]
        return " ".join(parts).lower()

    @staticmethod
    def _first_fix(d):
        for f in d.get("findings") or []:
            if (f.get("fix") or "").strip():
                return f["fix"].strip()
        return ""

    def _page_of(self, d):
        cid = (d or {}).get("id") or self._current or ""
        metrics_d = (d or {}).get("metrics") or {}
        # 系统盘吃紧时把「去瘦身」顶到最前面：比「去清理空间」更能真正腾出空间，
        # 也顺带让它别再藏在「类型」下拉里（体检页是默认页签，这是最显眼的入口）。
        if cid == "system.info":
            try:
                free = float(metrics_d.get("system_drive_free_gb"))
            except (TypeError, ValueError):
                free = None
            if free is not None and free < self._SLIM_OFFER_GB:
                return "clean_slim", f"去瘦身腾空间（剩 {free:g}GB）"
        # 内存吃紧时同理：直接给「内存加速」，别让人自己去任务管理器里翻
        if cid.startswith("memory"):
            try:
                load = float(metrics_d.get("mem_percent"))
            except (TypeError, ValueError):
                load = None
            if load is not None and load >= self._MEM_OFFER_PCT:
                return "mem_boost", f"内存加速（已用 {load:g}%）"
        # 硬盘健康是纯报告：不该给「去处理」按钮（没有能一键处理的动作，
        # 该做的是备份和换盘，那是用户自己的事）
        if cid == "disk.health":
            return None
        for prefix, key, label in self._PAGE_HINTS:
            if cid == prefix or cid.startswith(prefix + "."):
                return key, label
        return None

    # ---- 准备 / 更新 ----
    def prepare(self, checks):
        self.tree.clear()
        self._nodes.clear()
        self._data.clear()
        self._current = None
        # 不再有筛选分页：一律全列（有问题的项在树里加粗+标色）
        self._status = "all"
        for grp in GROUP_ORDER + sorted({c.group for c in checks} - set(GROUP_ORDER)):
            subset = [c for c in checks if c.group == grp]
            if not subset:
                continue
            name = self._PLAIN_TITLES.get(grp, GROUP_TITLES.get(grp, grp))
            top = QTreeWidgetItem([name, ""])
            top.setFlags(Qt.ItemIsEnabled)
            f = top.font(0)
            f.setBold(True)
            top.setFont(0, f)
            top.setForeground(0, QColor(C["muted"]))
            top.setData(0, Qt.UserRole, None)
            top.setData(0, Qt.UserRole + 1, name)
            self.tree.addTopLevelItem(top)
            for c in subset:
                it = QTreeWidgetItem([c.title, ""])
                it.setData(0, Qt.UserRole, c.id)
                it.setToolTip(0, f"{c.id}\n{c.desc or c.title}")
                it.setForeground(0, QColor(C["faint"]))
                it.setTextAlignment(1, Qt.AlignRight | Qt.AlignVCenter)
                top.addChild(it)
                self._nodes[c.id] = it
            top.setExpanded(True)
        self._refresh_groups()
        self._apply_filter()
        self._reset_body()

    def upsert(self, d):
        cid = d.get("id")
        self._data[cid] = d
        it = self._nodes.get(cid)
        if it is not None:
            sev = d.get("status", "info")
            it.setForeground(0, sev_color(sev))
            f = it.font(0)
            f.setBold(sev in ("warn", "error"))
            it.setFont(0, f)
            it.setText(1, self._WORD.get(self._bucket(d), ""))
            it.setForeground(1, sev_color(sev) if sev in ("warn", "error", "ok")
                             else QColor(C["faint"]))
            it.setData(0, Qt.UserRole + 1, self._search_blob(d))
            self._refresh_groups()
            self._apply_filter()
        if self._current == cid:
            self._show(cid)
        elif self._current is None:
            self._select_first()

    def _refresh_groups(self):
        """分组标题显示「总数 + 异常/警告数」，让首屏一眼看出哪组有货。"""
        for i in range(self.tree.topLevelItemCount()):
            top = self.tree.topLevelItem(i)
            name = top.data(0, Qt.UserRole + 1) or top.text(0)
            bad = warn = 0
            for j in range(top.childCount()):
                b = self._bucket(self._data.get(top.child(j).data(0, Qt.UserRole)))
                bad += 1 if b == "error" else 0
                warn += 1 if b == "warn" else 0
            total = top.childCount()
            top.setText(0, name)
            top.setText(1, f"{total} 项")
            top.setTextAlignment(1, Qt.AlignRight | Qt.AlignVCenter)
            if bad or warn:
                bits = []
                if bad:
                    bits.append(f"{bad} 个问题")
                if warn:
                    bits.append(f"{warn} 个要注意")
                top.setText(1, " · ".join(bits))
                top.setForeground(0, QColor(SEV["error"][0] if bad else SEV["warn"][0]))
                top.setForeground(1, QColor(SEV["error"][0] if bad else SEV["warn"][0]))
            else:
                top.setForeground(0, QColor(C["muted"]))
                top.setForeground(1, QColor(C["faint"]))

    def _select_first(self):
        for i in range(self.tree.topLevelItemCount()):
            top = self.tree.topLevelItem(i)
            if top.isHidden():
                continue
            for j in range(top.childCount()):
                ch = top.child(j)
                if ch.isHidden():
                    continue
                if ch.data(0, Qt.UserRole) in self._data:
                    self.tree.setCurrentItem(ch)
                    return

    def _match_status(self, d):
        b = self._bucket(d)
        k = self._status
        if k == "all":
            return True
        if k == "problem":
            return b in ("warn", "error")
        return b == k

    def _apply_filter(self):
        text = (self.ed_filter.text() or "").strip().lower()
        for i in range(self.tree.topLevelItemCount()):
            top = self.tree.topLevelItem(i)
            shown = 0
            for j in range(top.childCount()):
                ch = top.child(j)
                cid = ch.data(0, Qt.UserRole)
                hit = self._match_status(self._data.get(cid))
                if hit and text:
                    blob = (f"{ch.text(0)} {cid} "
                            f"{ch.data(0, Qt.UserRole + 1) or ''}").lower()
                    hit = text in blob
                ch.setHidden(not hit)
                shown += 1 if hit else 0
            top.setHidden(shown == 0)
        self._sync_empty_state()

    # ---- 筛选 ----
    # 状态分页已删，只留搜索框；_status 恒为 "all"（保留字段供 only_one / 右键复用）

    def only_one(self, cid):
        self._status = "all"
        self.ed_filter.setText(cid)
        self._apply_filter()
        self.focus(cid)

    def clear_filter(self):
        self._status = "all"
        self.ed_filter.clear()
        self._apply_filter()

    def _on_pick(self, cur, _prev):
        if cur is None:
            return
        cid = cur.data(0, Qt.UserRole)
        if cid:
            self._current = cid
            self._show(cid)

    def focus(self, cid):
        # 跳过来时如果正被筛掉，先恢复显示，否则用户看不到目标
        if self._status != "all" or self.ed_filter.text():
            self.clear_filter()
        it = self._nodes.get(cid)
        if it is not None:
            self.tree.setCurrentItem(it)
            self.tree.scrollToItem(it)
            parent = it.parent()
            if parent is not None:
                parent.setExpanded(True)

    # ---- 复制 / 右键 ----
    def _copy(self, text, what):
        if not text:
            self.notify.emit(f"{what}：没有内容可复制")
            return
        QGuiApplication.clipboard().setText(text)
        self.notify.emit(f"已复制{what}")

    def _as_markdown(self, d):
        if not d:
            return ""
        lines = [f"## {d.get('title') or d.get('id')}", ""]
        lines.append(f"- 检查项：`{d.get('id')}`　分组：{d.get('group', '')}"
                     f"　状态：{SEV_LABEL.get(d.get('status', 'info'), '')}"
                     f"　耗时：{d.get('elapsed_ms', 0)}ms")
        if d.get("summary"):
            lines += ["", d["summary"]]
        for f in d.get("findings") or []:
            lines += ["", f"- **[{SEV_LABEL.get(f.get('severity', 'info'), '')}]** "
                          f"{f.get('text', '')}"]
            if f.get("impact"):
                lines.append(f"  - 影响：{f['impact']}")
            if f.get("gain"):
                lines.append(f"  - 收益：{f['gain']}")
            if f.get("fix"):
                lines.append("  - 做法：")
                lines.append("    ```")
                for ln in f["fix"].splitlines():
                    lines.append("    " + ln)
                lines.append("    ```")
        return "\n".join(lines)

    def copy_current(self):
        self._copy(self._as_markdown(self._data.get(self._current)), "本项结论")

    def _tree_menu(self, pos):
        it = self.tree.itemAt(pos)
        cid = it.data(0, Qt.UserRole) if it is not None else None
        d = self._data.get(cid) or {}
        fix = self._first_fix(d)
        menu = QMenu(self)
        if cid:
            menu.addAction("查看这一项", lambda: self.focus(cid))
            menu.addSeparator()
            a1 = menu.addAction("复制结论（Markdown）",
                                lambda: self._copy(self._as_markdown(d), "本项结论"))
            a2 = menu.addAction("复制修复命令", lambda: self._copy(fix, "修复命令"))
            a3 = menu.addAction("复制本项 JSON", lambda: self._copy(
                json.dumps(d, ensure_ascii=False, indent=2) if d else "", "JSON"))
            for x in (a1, a2, a3):
                x.setEnabled(bool(d))
            a2.setEnabled(bool(fix))
            menu.addSeparator()
            menu.addAction("复制「重跑本项」命令",
                           lambda: self._copy(cli_cmd("run", cid), "重跑命令"))
            target = self._page_of(d)
            if target:
                key, label = target
                menu.addAction(f"跳到{label}处理",
                               lambda _c=False, k=key: self.goto_page.emit(k))
            menu.addSeparator()
            menu.addAction("只看这一项", lambda: self.only_one(cid))
        menu.addAction("清除筛选 / 显示全部", self.clear_filter)
        menu.exec(self.tree.viewport().mapToGlobal(pos))

    def _finding_menu(self, f, gpos):
        f = f or {}
        fix = (f.get("fix") or "").strip()
        bits = [f.get("text", "")]
        if f.get("impact"):
            bits.append(f"影响：{f['impact']}")
        if f.get("gain"):
            bits.append(f"收益：{f['gain']}")
        if fix:
            bits += ["", fix]
        menu = QMenu(self)
        menu.addAction("复制这条结论",
                       lambda: self._copy("\n".join(x for x in bits if x), "这条结论"))
        a = menu.addAction("复制命令", lambda: self._copy(fix, "命令"))
        a.setEnabled(bool(fix))
        menu.addSeparator()
        menu.addAction("复制本项全部结论", self.copy_current)
        menu.exec(gpos)

    # ---- 渲染 ----
    # ---- 渲染 ----
    def _clear_body(self):
        while self.blay.count():
            item = self.blay.takeAt(0)
            w = item.widget()
            if w is not None:
                w.hide()
                w.setParent(None)
                w.deleteLater()
            elif item.layout() is not None:
                _drop_layout(item.layout())
        self._placeholder = None      # 已被销毁，别留着悬空引用

    def _reset_body(self):
        self._clear_body()
        self._placeholder = EmptyState()
        self.blay.addWidget(self._placeholder)
        self.blay.addStretch(1)
        self._sync_empty_state()

    # ---- 右侧空态 ----
    def set_running(self, on):
        """检查开始/结束时更新空态文案（检查中 vs 一切正常）。"""
        self._running = bool(on)
        self._sync_empty_state()

    def _empty_texts(self):
        if self._running:
            # 检查没结束时绝不提前说「一切正常」——中途恰好还没查到 warn 项而已
            return ("正在逐项检查…", "完成后这里会显示每一项的结果")
        if not self._data:
            return ("检查完成后，这里显示每一项的结果",
                    "点左边任意一项，可以看它查到了什么、该怎么处理")
        q = (self.ed_filter.text() or "").strip()
        if q:
            return (f"没有找到包含「{q}」的项目", "换个关键词试试，或点搜索框后的 × 清空")
        if not any(self._bucket(d) in ("warn", "error") for d in self._data.values()):
            return ("✓ 一切正常", "所有检查都通过了，不需要处理任何东西")
        return ("这里暂时没有内容", "点左边任意一项查看结果")

    def _sync_empty_state(self):
        """左侧列表有可见项 → 选中并显示详情；空着 → 按状态给一句人话解释。

        两个方向都要处理：列表从有到空（搜索无结果）时把右侧旧详情换成说明页；
        从空恢复（清空搜索）时自动选中第一条可见项，别让右侧停在旧说明上。
        """
        visible = 0
        for i in range(self.tree.topLevelItemCount()):
            top = self.tree.topLevelItem(i)
            if top.isHidden():
                continue
            for j in range(top.childCount()):
                if not top.child(j).isHidden():
                    visible += 1
                    break
        if visible:
            if self._placeholder is not None:
                self._select_first()
            return
        if self._placeholder is None:
            self._reset_body()        # 列表空了但右侧还挂着旧详情
            return
        self._placeholder.set_texts(*self._empty_texts())
        self._placeholder.show()

    def _show(self, cid):
        d = self._data.get(cid)
        self._clear_body()
        if not d:
            lb = QLabel("该项尚未执行")
            lb.setObjectName("Muted")
            self.blay.addWidget(lb)
            self.blay.addStretch(1)
            return

        sev = d.get("status", "info")
        head = QHBoxLayout()
        head.setSpacing(10)
        title = QLabel(d.get("title", cid))
        title.setObjectName("H1")
        head.addWidget(title)
        head.addWidget(Badge(SEV_LABEL.get(sev, sev), sev))
        head.addStretch(1)

        # 常用操作只留「去处理」一个跳转；复制命令 / 重跑这类技术操作都在右键里
        target = self._page_of(d)
        if target:
            key, label = target
            b_go = QPushButton(label)
            b_go.clicked.connect(
                lambda _c=False, k=key: self.goto_page.emit(k))
            head.addWidget(b_go)
        self.blay.addLayout(head)

        if d.get("summary"):
            sm = QLabel(d["summary"])
            sm.setWordWrap(True)
            sm.setStyleSheet(f"color:{C['text']}; font-size:13px;")
            self.blay.addWidget(sm)

        if d.get("error"):
            err = QPlainTextEdit()
            err.setReadOnly(True)
            err.setPlainText(d["error"])
            err.setFixedHeight(120)
            self.blay.addWidget(err)

        self._fl = FindingList()
        self._fl.item_menu.connect(self._finding_menu)
        self._fl.render(d.get("findings") or [])
        if d.get("findings"):
            fs = d["findings"]
            bad = [f for f in fs if f.get("severity") in ("warn", "error")]
            cap0 = QLabel(f"要处理的事（{len(bad)} 条）" if bad else f"结论（{len(fs)} 条）")
            cap0.setObjectName("H2")
            self.blay.addWidget(cap0)
            self.blay.addWidget(self._fl)

        blocks = d.get("blocks") or []
        if blocks:
            self.blay.addWidget(hline())
            # 「依据数据」直接摊开显示，不再做折叠开关：
            # 折叠等于把这块内容藏到第二层，用户明确要求「查看详细数据直接展开，不要收缩」。
            cap = QLabel("依据数据")
            cap.setObjectName("H2")
            bv = BlockView()
            bv.render(blocks)
            self.blay.addWidget(cap)
            self.blay.addWidget(bv)

        if not d.get("summary") and not blocks and not d.get("findings"):
            lb = QLabel("（该项没有输出内容）")
            lb.setObjectName("Muted")
            self.blay.addWidget(lb)

        self.blay.addStretch(1)


def _drop_layout(lay):
    while lay.count():
        item = lay.takeAt(0)
        w = item.widget()
        if w is not None:
            w.hide()
            w.setParent(None)
            w.deleteLater()
        elif item.layout() is not None:
            _drop_layout(item.layout())


# ══════════════════════════════ 进程 ══════════════════════════════

class ProcDialog(QDialog):
    """单进程详情。"""

    def __init__(self, d, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"进程详情 · {d.get('name', '')} ({d.get('pid', '?')})")
        self.resize(860, 520)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 14, 14, 14)
        lay.setSpacing(10)

        rows = [
            ["PID", str(d.get("pid", ""))],
            ["进程名", d.get("name", "")],
            ["父进程 PID", str(d.get("ppid", ""))],
            ["状态", d.get("status", "")],
            ["用户", d.get("user", "")],
            ["CPU", f"{d.get('cpu', 0):.1f}%"],
            ["内存", f"{fb(d.get('mem') or 0)}（私有 {fb(d.get('mem_priv') or 0)}）"],
            ["线程数", str(d.get("threads", ""))],
            ["启动时间", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(d["started"]))
             if d.get("started") else "—"],
            ["可执行文件", d.get("exe") or "—"],
            ["工作目录", d.get("cwd") or "—"],
            ["启动参数", d.get("cmdline") or "—"],
            ["服务名", d.get("service") or "—"],
            ["监听端口", ", ".join(d.get("listening") or []) or "—"],
            ["连接数", str(d.get("connections", 0))],
            ["子进程", ", ".join(f"{n}({p})" for p, n in (d.get("children") or [])) or "—"],
        ]
        tb = DataTable([("项目", 130, "l"), ("值", -1, "l")], sortable=False)
        tb.set_rows(rows)
        lay.addWidget(tb, 1)

        btns = QDialogButtonBox(QDialogButtonBox.Close)
        btns.rejected.connect(self.reject)
        btns.accepted.connect(self.accept)
        lay.addWidget(btns)


class UnlockDialog(QDialog):
    """解除文件 / 文件夹占用：查清是谁开着它，再让对方松手。

    边界（也是给用户看的话）：
      · 能做的：看到占用者 → 让它"正常退出"（等于替用户点 ×，程序自己会问要不要保存）
        或强制结束；
      · 做不到也不想做的：替别的进程单独关掉某个文件句柄 —— 要往别人进程里注入代码，
        轻则程序崩、重则数据损坏，风险远大于收益；
      · 本工具不代删任意文件：解除占用后回资源管理器自己删/改名。
    """

    notify = Signal(str)

    def __init__(self, parent=None, path=""):
        super().__init__(parent)
        self.setWindowTitle("解除文件 / 文件夹占用")
        self.resize(1020, 660)
        self.setAcceptDrops(True)
        self._res = None

        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(9)

        row = QHBoxLayout()
        row.setSpacing(8)
        row.addWidget(QLabel("文件 / 文件夹"))
        self.ed = QLineEdit(path)
        self.ed.setPlaceholderText("把文件或文件夹拖进来，或点右边「选择…」")
        self.ed.setClearButtonEnabled(True)
        self.ed.returnPressed.connect(self.scan)
        row.addWidget(self.ed, 1)
        btn_file = QPushButton("选择文件…")
        btn_file.clicked.connect(self.pick_file)
        row.addWidget(btn_file)
        btn_dir = QPushButton("选择文件夹…")
        btn_dir.clicked.connect(self.pick_dir)
        row.addWidget(btn_dir)
        self.btn_scan = QPushButton("查占用")
        self.btn_scan.setObjectName("Primary")
        self.btn_scan.clicked.connect(self.scan)
        row.addWidget(self.btn_scan)
        lay.addLayout(row)

        self.lb_state = QLabel("选一个文件或文件夹，点「查占用」。"
                               "（可以直接把文件从资源管理器拖到这个窗口）")
        self.lb_state.setObjectName("Muted")
        self.lb_state.setWordWrap(True)
        lay.addWidget(self.lb_state)

        self.table = CheckTable([
            ("进程", 200, "l"),
            ("PID", 76, "r"),
            ("类型", 110, "l"),
            ("能否正常退出", 130, "l"),
            ("占用原因", 190, "l"),
            ("程序路径", -1, "l"),
        ])
        lay.addWidget(self.table, 1)

        self.lb_perm = QLabel("")
        self.lb_perm.setWordWrap(True)
        self.lb_perm.setObjectName("Muted")
        lay.addWidget(self.lb_perm)

        bar = QHBoxLayout()
        bar.setSpacing(8)
        bar.addStretch(1)
        self.btn_copy = QPushButton("复制处理命令")
        self.btn_copy.setEnabled(False)
        self.btn_copy.clicked.connect(self.copy_cmd)
        bar.addWidget(self.btn_copy)
        btn_rescan = QPushButton("重新检查")
        btn_rescan.clicked.connect(self.scan)
        bar.addWidget(btn_rescan)
        self.btn_close_app = QPushButton("让它正常退出")
        self.btn_close_app.setToolTip("给它的窗口发关闭消息，等于替你点 ×：程序会自己问要不要保存")
        self.btn_close_app.setEnabled(False)
        self.btn_close_app.clicked.connect(self.do_close)
        bar.addWidget(self.btn_close_app)
        self.btn_kill = QPushButton("强制结束")
        self.btn_kill.setObjectName("Danger")
        self.btn_kill.setToolTip("进程会被直接杀掉，没保存的内容会丢")
        self.btn_kill.setEnabled(False)
        self.btn_kill.clicked.connect(self.do_kill)
        bar.addWidget(self.btn_kill)
        btn_quit = QPushButton("关闭")
        btn_quit.clicked.connect(self.accept)
        bar.addWidget(btn_quit)
        lay.addLayout(bar)

        self.table.counts_changed.connect(
            lambda n, _t: self._sync_buttons())

        if path:
            QTimer.singleShot(120, self.scan)

    # ---- 选路径 ----
    def pick_file(self):
        p, _ = QFileDialog.getOpenFileName(self, "选择文件")
        if p:
            self.ed.setText(p)
            self.scan()

    def pick_dir(self):
        p = QFileDialog.getExistingDirectory(self, "选择文件夹")
        if p:
            self.ed.setText(p)
            self.scan()

    def dragEnterEvent(self, ev):
        if ev.mimeData().hasUrls():
            ev.acceptProposedAction()

    def dropEvent(self, ev):
        urls = ev.mimeData().urls()
        if urls:
            self.ed.setText(urls[0].toLocalFile())
            self.scan()
            ev.acceptProposedAction()

    # ---- 查询 ----
    def scan(self):
        target = (self.ed.text() or "").strip().strip('"')
        if not target:
            QMessageBox.information(self, "先选个东西", "请先把文件或文件夹拖进来，或点「选择…」。")
            return
        if not os.path.exists(target):
            QMessageBox.warning(self, "路径不在了", f"{target}\n\n可能已经被删掉或移走了。")
            return
        self.btn_scan.setEnabled(False)
        self.btn_scan.setText("查询中…")
        QGuiApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            res = filelock.lockers(target)
            perm = filelock.permission_report(target)
        finally:
            QGuiApplication.restoreOverrideCursor()
            self.btn_scan.setEnabled(True)
            self.btn_scan.setText("查占用")
        self._res = res
        self.ed.setText(res["path"])

        rows, pays = [], []
        for h in res["holders"]:
            rows.append([
                h["name"], (str(h["pid"]), h["pid"]), h["kind"],
                "能（它就问你要不要保存）" if h["can_close"] else "不能（没有窗口）",
                h["reason"], h["exe"] or "—",
            ])
            pays.append(h)
        self.table.set_check_rows(rows, pays, checked=False)
        for r, h in enumerate(res["holders"]):
            self.table.set_row_checked(r, True)      # 默认都勾上，用户自己取消

        n = len(res["holders"])
        if n:
            self.lb_state.setText(
                f"查到 {n} 个进程占着它（共检查 {res['files_checked']} 个文件）。"
                f"勾掉不想动的，再点「让它正常退出」——这是最安全的做法。")
            self.lb_perm.setText("解除之后回到资源管理器重试删除/改名即可。"
                                 "（本工具不代删任意文件，删除只走清理页的白名单通道）")
            self._cmds = []
            self.btn_copy.setEnabled(False)
        elif res["error"]:
            self.lb_state.setText("查询没完全成功：" + res["error"])
            self._show_perm(perm)
        else:
            self.lb_state.setText(
                "没查到占用者。这种情况九成是权限/只读问题，不是被占用 —— 命令给你，自己决定要不要执行。")
            self._show_perm(perm)
        self._sync_buttons()

    def _show_perm(self, perm):
        note = perm.get("note") or ""
        cmds = perm.get("commands") or []
        if not cmds:
            self.lb_perm.setText(note)
            self.btn_copy.setEnabled(False)
            self._cmds = []
            return
        self._cmds = cmds
        self.lb_perm.setText(f"{note}\n" + "    ".join(cmds))
        self.btn_copy.setEnabled(True)

    def copy_cmd(self):
        cmds = getattr(self, "_cmds", []) or []
        if not cmds:
            return
        QGuiApplication.clipboard().setText("\n".join(cmds))
        self.lb_state.setText("处理命令已复制。请在「开始菜单 → 命令提示符(管理员)」里逐条粘贴执行。")

    def _sync_buttons(self):
        n = len(self.table.checked_payloads()) if self._res else 0
        self.btn_close_app.setEnabled(n > 0)
        self.btn_kill.setEnabled(n > 0)
        if n:
            self.btn_close_app.setText(f"让它正常退出（{n}）")
            self.btn_kill.setText(f"强制结束（{n}）")
        else:
            self.btn_close_app.setText("让它正常退出")
            self.btn_kill.setText("强制结束")

    # ---- 动作 ----
    def do_close(self):
        picked = self.table.checked_payloads()
        if not picked:
            return
        pids = [h["pid"] for h in picked]
        sent, no_win = filelock.close_gracefully(pids)
        msg = []
        if sent:
            msg.append(f"已请 {len(sent)} 个程序关闭（它们自己会问要不要保存，注意看弹窗）。")
        if no_win:
            names = ", ".join(
                next((h["name"] for h in picked if h["pid"] == p), str(p)) for p in no_win)
            msg.append(f"{len(no_win)} 个没有窗口、收不到关闭消息：{names}\n"
                       "这些只能「强制结束」，或者手动去关。")
        self.notify.emit(f"已发送关闭请求 {len(sent)} 个")
        QMessageBox.information(self, "已发送", "\n\n".join(msg) or "没有可处理的进程。")
        QTimer.singleShot(900, self.scan)     # 等它自己退，再复查

    def do_kill(self):
        picked = self.table.checked_payloads()
        if not picked:
            return
        listing = "\n".join(f"· {h['name']}（PID {h['pid']}）" for h in picked[:12])
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Warning)
        box.setWindowTitle("确认强制结束")
        box.setText(f"将强制结束这 {len(picked)} 个进程：\n\n{listing}\n\n"
                    "没保存的内容会丢失。优先用「让它正常退出」。")
        box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        box.setDefaultButton(QMessageBox.No)
        box.button(QMessageBox.Yes).setText("强制结束")
        box.button(QMessageBox.No).setText("取消")
        if box.exec() != QMessageBox.Yes:
            return
        ok = bad = 0
        for h in picked:
            try:
                metrics.psutil.Process(h["pid"]).kill()
                ok += 1
            except Exception:
                bad += 1
        self.notify.emit(f"强制结束 {ok} 个进程" + (f"，{bad} 个失败" if bad else ""))
        QMessageBox.information(self, "结束结果", f"成功 {ok} 个，失败 {bad} 个。")
        QTimer.singleShot(600, self.scan)


class MemBoostDialog(QDialog):
    """内存加速：看清谁占着，再决定释放工作集 / 清空待机缓存 / 结束进程。

    界面上把话说清楚（用户反馈里最讨厌"假加速"）：释放工作集只是把进程暂时占着的
    物理页交还给系统，进程还在、它那一行数字变小，但这部分多半变成「待机缓存」——
    待机本来就算在「可用」里，所以可用数字通常不会明显变大。
    真想腾出内存，最有效的还是把不用的程序关掉（第二颗按钮干这个）。
    """

    _SAFE_MB = 300          # 默认勾选的门槛：低于这个体积换出去也省不下什么
    _SAFE_TOP_N = 12        # 默认最多勾这么多（一次把 60 多个进程换出去会卡一下）
    # 这些是桌面外壳进程：换出去会掉图标/任务栏重绘，默认不勾（想勾可以自己点）
    _SHELL_NAMES = {"explorer.exe", "dwm.exe", "sihost.exe",
                    "startmenuexperiencehost.exe", "searchhost.exe",
                    "textinputhost.exe", "shellexperiencehost.exe"}

    notify = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("内存加速")
        self.resize(980, 660)
        self._all = []

        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(9)

        self.lb_head = QLabel("")
        self.lb_head.setObjectName("H1")
        lay.addWidget(self.lb_head)

        self.lb_verdict = QLabel("")
        self.lb_verdict.setWordWrap(True)
        lay.addWidget(self.lb_verdict)

        tip = QLabel(
            "「释放内存」= 把进程暂时占着的物理页交还给系统：进程不退出、数据不丢，"
            "下次用到会重新读回来（那一下可能略微卡顿）。\n"
            "实话实说：这属于「整理」不是「扩容」——系统的「可用」一般不会明显变大，"
            "内存不紧张时做了基本没感觉。真要腾出内存，最有效的是把不用的程序关掉。")
        tip.setWordWrap(True)
        tip.setObjectName("Muted")
        lay.addWidget(tip)

        self.table = CheckTable([
            ("进程", 230, "l"),
            ("PID", 76, "r"),
            ("内存", 100, "r"),
            ("说明", -1, "l"),
        ])
        self.table.setToolTip("按内存从大到小排；系统关键进程不会被动")
        lay.addWidget(self.table, 1)

        bar = QHBoxLayout()
        bar.setSpacing(8)
        self.lb_state = QLabel("")
        self.lb_state.setObjectName("Muted")
        self.lb_state.setMinimumWidth(1)
        self.lb_state.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        bar.addWidget(self.lb_state, 1)
        btn_all = QPushButton("全选可释放项")
        btn_all.clicked.connect(self.check_all_safe)
        bar.addWidget(btn_all)
        btn_none = QPushButton("全不选")
        btn_none.clicked.connect(lambda: self.table.set_all_checked(False))
        bar.addWidget(btn_none)
        self.btn_purge = QPushButton("清空系统缓存…")
        self.btn_purge.setToolTip("清空待机列表：可用内存里的缓存部分被丢弃，读盘会变慢，不建议常用")
        self.btn_purge.clicked.connect(self.do_purge)
        bar.addWidget(self.btn_purge)
        lay.addLayout(bar)

        bar2 = QHBoxLayout()
        bar2.setSpacing(8)
        bar2.addStretch(1)
        btn_reload = QPushButton("刷新")
        btn_reload.clicked.connect(self.reload)
        bar2.addWidget(btn_reload)
        self.btn_kill = QPushButton("结束选中进程")
        self.btn_kill.setObjectName("Danger")
        self.btn_kill.setToolTip("这才是真腾内存，但没保存的东西会丢")
        self.btn_kill.clicked.connect(self.do_kill)
        bar2.addWidget(self.btn_kill)
        self.btn_trim = QPushButton("释放选中进程的内存")
        self.btn_trim.setObjectName("Primary")
        self.btn_trim.clicked.connect(self.do_trim)
        bar2.addWidget(self.btn_trim)
        btn_close = QPushButton("关闭")
        btn_close.clicked.connect(self.accept)
        bar2.addWidget(btn_close)
        lay.addLayout(bar2)

        self.reload()

    # ---- 数据 ----
    def reload(self):
        st = memtrim.status()
        used = max(0, st["total"] - st["avail"])
        head = (f"已用 {fb(used)} / {fb(st['total'])}（{st['load']}%）"
                f"　可用 {fb(st.get('phys_avail') or st['avail'])}")
        if st.get("standby"):
            head += f"，其中待机缓存 {fb(st['standby'])}"
        self.lb_head.setText(head)

        # 按真实压力给一句结论（用户最需要的就是"现在该不该做这件事"）
        load = st["load"]
        if load >= 80:
            text, color = ("内存确实紧：已用超过 80%，系统已经在换页了。"
                           "先释放闲置进程，不够就把不用的程序关掉。", SEV["error"][0])
        elif load >= 60:
            text, color = ("内存还算够用（已用 60%~80%）。释放一下能少换点页，但不会明显变快。",
                           SEV["warn"][0])
        else:
            text, color = ("内存很宽裕（已用不到 60%），做这一步基本不会有感觉，"
                           "卡的话更可能是 CPU / 磁盘的事。", C["muted"])
        self.lb_verdict.setText(text)
        self.lb_verdict.setStyleSheet(f"color:{color}; font-size:13px;")

        self._all = memtrim.candidates(50)
        rows, pays = [], []
        for c in self._all:
            if c["blocked"]:
                note = f"{c['blocked']}，不会动"
            elif c["rss"] >= self._SAFE_MB * 1024 ** 2:
                note = ("桌面外壳进程，释放后图标可能重绘一下"
                        if (c["name"] or "").lower() in self._SHELL_NAMES else
                        "可释放（下次用到要重新读，可能顿一下）")
            else:
                note = "占用不大，收益有限"
            rows.append([c["name"], (str(c["pid"]), c["pid"]),
                         (fb(c["rss"]), c["rss"]), note])
            pays.append(c)
        self.table.set_check_rows(rows, pays, checked=False)
        n = self.check_all_safe()
        self.lb_state.setText(f"共 {len(self._all)} 个进程，默认勾选 {n} 个"
                              f"（占用最大的前 {self._SAFE_TOP_N} 个）")
        admin = bool(st.get("admin"))
        self.btn_purge.setEnabled(admin)
        if not admin:
            self.btn_purge.setToolTip("需要管理员身份：用管理员方式启动本工具才可用")

    def check_all_safe(self):
        """勾上「占用最大且非系统、非外壳」的前 N 个 —— 一次换出几十个进程会整机顿一下。"""
        n = 0
        for r, c in enumerate(self._all):
            on = (not c["blocked"]
                  and c["rss"] >= self._SAFE_MB * 1024 ** 2
                  and (c["name"] or "").lower() not in self._SHELL_NAMES
                  and n < self._SAFE_TOP_N)
            self.table.set_row_checked(r, on)
            n += 1 if on else 0
        return n

    def _picked(self):
        return [c for c in self.table.checked_payloads() if not c["blocked"]]

    # ---- 动作 ----
    def do_trim(self):
        picked = self._picked()
        if not picked:
            QMessageBox.information(self, "先勾几个", "请在列表里勾选要释放的进程。")
            return
        st0 = memtrim.status()
        self.btn_trim.setEnabled(False)
        self.btn_trim.setText("正在释放…")
        QGuiApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            _rows, freed, failed = memtrim.trim([c["pid"] for c in picked])
        finally:
            QGuiApplication.restoreOverrideCursor()
            self.btn_trim.setEnabled(True)
            self.btn_trim.setText("释放选中进程的内存")
        st1 = memtrim.status()
        self.notify_trim(len(picked) - failed, failed, freed, st0, st1)
        self.reload()

    def notify_trim(self, ok_n, failed, freed, st0, st1):
        QMessageBox.information(
            self, "释放结果",
            f"处理 {ok_n} 个进程，合计释放 {fb(freed)}"
            + (f"；{failed} 个没动成（多为受保护进程）" if failed else "") + "\n\n"
            f"系统可用：{fb(st0.get('phys_avail') or st0['avail'])}"
            f" → {fb(st1.get('phys_avail') or st1['avail'])}\n\n"
            "说明：这部分多半变成了系统的待机缓存（仍算「可用」），所以可用数字不一定上涨；"
            "内存吃紧时 Windows 会优先回收它。要真腾出内存，还是关掉不用的程序。")

    def do_kill(self):
        picked = self._picked()
        if not picked:
            QMessageBox.information(self, "先勾几个", "请在列表里勾选要结束的进程。")
            return
        listing = "\n".join(f"· {c['name']}（PID {c['pid']}，{fb(c['rss'])}）" for c in picked[:12])
        if len(picked) > 12:
            listing += f"\n… 另有 {len(picked) - 12} 个"
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Warning)
        box.setWindowTitle("确认结束进程")
        box.setText(f"将强制结束这 {len(picked)} 个进程：\n\n{listing}\n\n"
                    "没保存的内容会丢失；浏览器标签、文档改动都会没。")
        box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        box.setDefaultButton(QMessageBox.No)
        box.button(QMessageBox.Yes).setText("结束进程")
        box.button(QMessageBox.No).setText("取消")
        if box.exec() != QMessageBox.Yes:
            return
        ok = bad = 0
        for c in picked:
            try:
                metrics.psutil.Process(c["pid"]).kill()
                ok += 1
            except Exception:
                bad += 1
        self.notify.emit(f"已结束 {ok} 个进程" + (f"，{bad} 个失败（可能已退出或受保护）" if bad else ""))
        QMessageBox.information(self, "结束结果",
                                f"成功 {ok} 个，失败 {bad} 个。"
                                + ("\n失败的通常是受保护进程或已经自己退出了。" if bad else ""))
        self.reload()

    def do_purge(self):
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Warning)
        box.setWindowTitle("清空系统缓存")
        box.setText("这会把系统「待机缓存」全部丢弃。\n\n"
                    "· 可用内存里的缓存部分会被释放，但之后打开文件、启动程序都要重新读盘，"
                    "一两分钟内可能更慢；\n"
                    "· 对日常使用几乎没有收益，不建议经常做；\n"
                    "· 需要管理员权限（当前已经是）。")
        box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        box.setDefaultButton(QMessageBox.No)
        box.button(QMessageBox.Yes).setText("继续")
        box.button(QMessageBox.No).setText("取消")
        if box.exec() != QMessageBox.Yes:
            return
        QGuiApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            res = memtrim.purge_standby()
        finally:
            QGuiApplication.restoreOverrideCursor()
        if res["ok"]:
            QMessageBox.information(
                self, "已清空",
                f"待机缓存已清空，系统可用：{fb(res['before'].get('phys_avail', 0))}"
                f" → {fb(res['after'].get('phys_avail', 0))}\n\n"
                "接下来一两分钟读盘会慢一点，属正常现象。")
        else:
            QMessageBox.warning(self, "没做成", res["msg"])
        self.reload()


class StartupDialog(QDialog):
    """开机自启项：看清哪些在开机时启动，勾选后停用 / 恢复。

    这里的「停用」不是删除 —— 和任务管理器那个开关完全一致，只是标记为不启动，
    随时能改回来。想彻底删掉 Run 键的话，右键有「复制彻底删除的命令」，自己决定。
    """

    notify = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("开机自启项")
        self.resize(1120, 680)
        self._items = []
        self._shown = []

        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(9)

        top = QHBoxLayout()
        top.setSpacing(8)
        self.lb_head = QLabel("正在读取…")
        self.lb_head.setObjectName("H2")
        top.addWidget(self.lb_head, 1)
        self.btn_refresh = QPushButton("刷新")
        self.btn_refresh.clicked.connect(self.reload)
        top.addWidget(self.btn_refresh)
        lay.addLayout(top)

        self.lb_tip = QLabel(
            "「停用」只是让它开机时不启动，不是删除 —— 随时可以再启用，"
            "手动打开程序也照样能用。")
        self.lb_tip.setObjectName("Muted")
        self.lb_tip.setWordWrap(True)
        lay.addWidget(self.lb_tip)

        bar = QHBoxLayout()
        bar.setSpacing(8)
        self.cb_filter = QComboBox()
        self.cb_filter.addItems(["全部", "正在开机运行", "已停用", "断链（程序已不在）"])
        self.cb_filter.currentIndexChanged.connect(self._fill)
        bar.addWidget(self.cb_filter)
        self.ed_search = QLineEdit()
        self.ed_search.setPlaceholderText("搜名称 / 程序路径…")
        self.ed_search.setClearButtonEnabled(True)
        self.ed_search.textChanged.connect(self._fill)
        bar.addWidget(self.ed_search, 1)
        bar.addStretch(1)
        lay.addLayout(bar)

        self.table = CheckTable([
            ("状态", 92, "l"),
            ("名称", 230, "l"),
            ("位置", 160, "l"),
            ("说明", 200, "l"),
            ("命令 / 程序路径", -1, "l"),
        ])
        self.table.counts_changed.connect(lambda _n, _t: self._sync_buttons())
        self.table.setToolTip("勾选后点右下角「停用选中项」；右键可复制程序路径或彻底删除的命令")
        self.table.extra_actions = [
            ("停用选中项（开机不启动）", lambda: self.apply(False)),
            ("恢复选中项（开机启动）", lambda: self.apply(True)),
            ("-", None),
            ("复制程序路径", self.copy_exe),
            ("打开程序所在文件夹", self.open_exe_dir),
            ("复制彻底删除的命令（高级）", self.copy_delete_cmd),
        ]
        lay.addWidget(self.table, 1)

        self.lb_note = QLabel("")
        self.lb_note.setObjectName("Muted")
        self.lb_note.setWordWrap(True)
        lay.addWidget(self.lb_note)

        foot = QHBoxLayout()
        foot.setSpacing(8)
        self.btn_undo = QPushButton("撤销上次改动")
        self.btn_undo.setToolTip("把最近一次停用/恢复改回原样（每次改动前都会自动备份）")
        self.btn_undo.clicked.connect(self.undo)
        foot.addWidget(self.btn_undo)
        foot.addStretch(1)
        self.btn_enable = QPushButton("恢复选中项")
        self.btn_enable.setEnabled(False)
        self.btn_enable.clicked.connect(lambda: self.apply(True))
        foot.addWidget(self.btn_enable)
        self.btn_disable = QPushButton("停用选中项")
        self.btn_disable.setObjectName("Primary")
        self.btn_disable.setEnabled(False)
        self.btn_disable.setToolTip("开机时不再自动启动（不删除、不影响以后手动打开）")
        self.btn_disable.clicked.connect(lambda: self.apply(False))
        foot.addWidget(self.btn_disable)
        btn_quit = QPushButton("关闭")
        btn_quit.clicked.connect(self.accept)
        foot.addWidget(btn_quit)
        lay.addLayout(foot)

        self.reload()

    # ---- 读取 ----
    def reload(self):
        from .. import startup
        QGuiApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            self._items = startup.items()
        except Exception as exc:
            QGuiApplication.restoreOverrideCursor()
            show_error(self, "读取失败", f"{type(exc).__name__}: {exc}",
                       summary="读取开机自启项失败。")
            return
        finally:
            QGuiApplication.restoreOverrideCursor()

        run_n = sum(1 for i in self._items if i["can_toggle"] and i["enabled"])
        off_n = sum(1 for i in self._items if not i["enabled"])
        broken = [i for i in self._items if i["exists"] is False]
        head = f"共 {len(self._items)} 项：正在开机运行 {run_n} 项"
        if off_n:
            head += f"，已停用 {off_n} 项"
        self.lb_head.setText(head)

        note = []
        if broken:
            note.append(f"{len(broken)} 个指向的程序已经不在（"
                        + "、".join(i["name"] for i in broken[:4])
                        + "），这类停用最安全，开机最快见效。")
        note.append("不在这个列表里的启动项来自「任务计划程序」，去任务管理器 → 启动 里看。")
        self.lb_note.setText("　".join(note))
        self.btn_undo.setEnabled(bool(startup.history(1)))
        self._fill()

    def _fill(self):
        idx = self.cb_filter.currentIndex()
        key = (self.ed_search.text() or "").strip().lower()
        rows, pays = [], []
        for it in self._items:
            if idx == 1 and not (it["can_toggle"] and it["enabled"]):
                continue
            if idx == 2 and it["enabled"]:
                continue
            if idx == 3 and it["exists"] is not False:
                continue
            if key and key not in it["name"].lower() and key not in (it["cmd"] or "").lower():
                continue
            if not it["can_toggle"]:
                state = "只跑一次"
            else:
                state = "已启用" if it["enabled"] else "已停用"
            where = "启动文件夹" if it["kind"] == "startupdir" else it["source"]
            rows.append([state, it["name"], where, it["note"] or "—",
                         it["cmd"] or "—"])
            pays.append(it)
        self._shown = pays
        self.table.set_check_rows(rows, pays, checked=False)
        self._sync_buttons()

    def _sync_buttons(self):
        picked = self.table.checked_payloads()
        can_off = [i for i in picked if i["can_toggle"] and i["enabled"]]
        can_on = [i for i in picked if i["can_toggle"] and not i["enabled"]]
        self.btn_disable.setEnabled(bool(can_off))
        self.btn_enable.setEnabled(bool(can_on))
        self.btn_disable.setText(f"停用选中项（{len(can_off)}）" if can_off else "停用选中项")
        self.btn_enable.setText(f"恢复选中项（{len(can_on)}）" if can_on else "恢复选中项")

    # ---- 动作 ----
    def apply(self, on):
        from .. import startup
        picked = [i for i in self.table.checked_payloads()
                  if i["can_toggle"] and i["enabled"] != on]
        if not picked:
            QMessageBox.information(
                self, "没有可改的项",
                "勾选的那些已经是这个状态了，或者不支持停用（只运行一次的项）。")
            return
        hklm = [i for i in picked if i["hive"] == "HKLM"]
        if hklm and not on:
            listing = "、".join(i["name"] for i in hklm[:5])
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Question)
            box.setWindowTitle("其中有「所有用户」的自启项")
            box.setText(f"{len(hklm)} 项属于所有用户（{listing}），"
                        "改它们需要管理员权限。\n\n"
                        "如果当前不是管理员，这几项会失败，其余照常改。继续吗？")
            box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
            box.setDefaultButton(QMessageBox.Yes)
            box.button(QMessageBox.Yes).setText("继续")
            box.button(QMessageBox.No).setText("只改当前用户的")
            ret = box.exec()
            if ret == QMessageBox.No:
                picked = [i for i in picked if i["hive"] != "HKLM"]

        QGuiApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            ok_n, bad = startup.set_many(picked, on)
        finally:
            QGuiApplication.restoreOverrideCursor()

        word = "恢复" if on else "停用"
        self.notify.emit(f"开机自启：{word} {ok_n} 项"
                         + (f"，{len(bad)} 项失败" if bad else ""))
        if bad:
            groups = {}
            for name, why in bad:
                groups.setdefault(why, []).append(name)
            lines = [f"成功 {ok_n} 项，失败 {len(bad)} 项。", ""]
            for why, names in groups.items():
                lines.append(f"{why} —— {len(names)} 项")
                lines += [f"    {n}" for n in names[:4]]
            lines.append("")
            lines.append("「所有用户」的项请右键复制处理命令，在管理员命令提示符里执行。")
            QMessageBox.warning(self, "部分没改成", "\n".join(lines))
        self.reload()

    def undo(self):
        from .. import startup
        ok, msg = startup.restore_last()
        if ok:
            self.notify.emit("开机自启：" + msg)
        else:
            QMessageBox.warning(self, "撤销失败", msg)
        self.reload()

    def _pick(self):
        row = getattr(self.table, "context_row", -1)
        if row < 0:
            QMessageBox.information(self, "先选一行", "请在某一项上右键。")
            return None
        return self.table.payload_at(row)

    def copy_exe(self):
        it = self._pick()
        if not it:
            return
        if not it["exe"]:
            QMessageBox.information(self, "没有程序路径",
                                    "这一项解析不出程序路径（可能是启动文件夹里的快捷方式）。")
            return
        QGuiApplication.clipboard().setText(it["exe"])
        self.notify.emit("程序路径已复制")

    def open_exe_dir(self):
        it = self._pick()
        if not it:
            return
        target = it["exe"] or (it["key"] if it["kind"] == "startupdir" else "")
        if not target:
            QMessageBox.information(self, "打不开", "这一项没有可打开的位置。")
            return
        folder = target if os.path.isdir(target) else os.path.dirname(target)
        if not os.path.isdir(folder):
            QMessageBox.warning(self, "文件夹不在了", folder)
            return
        try:
            os.startfile(folder)
        except Exception as exc:
            QMessageBox.warning(self, "打不开", f"{folder}\n\n{exc}")

    def copy_delete_cmd(self):
        from .. import startup
        it = self._pick()
        if not it:
            return
        cmds = startup.delete_commands(it)
        QGuiApplication.clipboard().setText("\n".join(cmds))
        self.notify.emit("彻底删除的命令已复制")


class ProcsPage(Page):
    """进程列表：搜索、排序、结束进程、查看详情。"""

    def __init__(self, cfg, parent=None):
        super().__init__(cfg, parent)
        self._rows = []
        self._row_pids = []           # 表格每一行对应的 pid（见 _apply_filter / _on_partial）

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)

        bar = QHBoxLayout()
        bar.setSpacing(8)
        self.ed = QLineEdit()
        self.ed.setPlaceholderText("搜索进程名 / PID / 启动参数…")
        self.ed.setClearButtonEnabled(True)
        self.ed.setMinimumWidth(300)
        self.ed.textChanged.connect(self._lazy_filter)
        bar.addWidget(self.ed, 1)

        self.cb_sort = QComboBox()
        self.cb_sort.addItems(["按 CPU 排序", "按内存排序", "按名称排序", "按 PID 排序"])
        self.cb_sort.currentIndexChanged.connect(self._apply_filter)
        bar.addWidget(self.cb_sort)

        self.btn_refresh = QPushButton("刷新")
        self.btn_refresh.clicked.connect(self.reload)
        bar.addWidget(self.btn_refresh)

        # 内存加速放主位：普通用户「电脑卡」十次有八次是内存吃紧，
        # 而这个动作以前只存在于任务管理器里（3.9.0 补上入口）。
        self.btn_mem = QPushButton("内存加速…")
        self.btn_mem.setToolTip("看谁占内存：释放闲置进程的内存，或直接结束不用的程序")
        self.btn_mem.clicked.connect(self.open_mem_boost)
        bar.addWidget(self.btn_mem)

        # 开机自启同理：「开机慢」最常见的解法就在这里，别让它只在任务管理器里
        self.btn_startup = QPushButton("开机自启…")
        self.btn_startup.setToolTip("看哪些程序开机就启动，勾选后停用（可随时恢复，不删注册表）")
        self.btn_startup.clicked.connect(self.open_startup)
        bar.addWidget(self.btn_startup)

        self.btn_detail = QPushButton("详情")
        self.btn_detail.clicked.connect(lambda: self.show_detail(self.table.currentRow()))
        bar.addWidget(self.btn_detail)

        self.btn_kill = QPushButton("结束进程")
        self.btn_kill.setObjectName("Danger")
        self.btn_kill.clicked.connect(self.kill_selected)
        bar.addWidget(self.btn_kill)
        lay.addLayout(bar)

        self.info = QLabel("点「刷新」采集当前进程快照")
        self.info.setObjectName("Muted")
        lay.addWidget(self.info)

        self.table = DataTable([
            ("PID", 72, "r"),
            ("进程", 200, "l"),
            ("CPU%", 72, "r"),
            ("内存", 92, "r"),
            ("私有", 92, "r"),
            ("用户", 118, "l"),
            ("状态", 88, "l"),
            ("路径 / 启动参数", -1, "l"),
        ])
        lay.addWidget(self.table, 1)
        self.table.cellDoubleClicked.connect(self.show_detail)
        self.table.extra_actions = [
            ("结束此进程", lambda: self.kill_selected()),
            ("结束进程树", lambda: self.kill_selected(tree=True)),
            ("查看详情", lambda: self.show_detail(self.table.currentRow())),
        ]

        self._filter_timer = QTimer(self)
        self._filter_timer.setSingleShot(True)
        self._filter_timer.setInterval(220)
        self._filter_timer.timeout.connect(self._apply_filter)

    # ---- 采集 ----
    def reload(self):
        if self.is_busy():
            return
        from .tasks import ProcsTask
        self.btn_refresh.setEnabled(False)
        self.info.setText("正在采集进程快照…")
        task = self._hold(ProcsTask(sample=0.4, parent=self))
        task.progress.connect(self._on_progress)
        task.log.connect(self.notify.emit)
        task.failed.connect(self._on_fail)
        task.partial.connect(self._on_partial)     # 便宜的字段一到就先显示
        task.done.connect(self._on_rows)
        task.start()

    def open_mem_boost(self):
        """打开「内存加速」窗口（体检页内存项告警时也会直接调这里）。"""
        dlg = MemBoostDialog(self)
        dlg.notify.connect(self.notify)      # 结果写进状态栏 / 运行日志
        dlg.exec()

    def open_startup(self):
        """打开「开机自启项」窗口（体检页开机自启项也会直接调这里）。"""
        dlg = StartupDialog(self)
        dlg.notify.connect(self.notify)
        dlg.exec()

    def _on_progress(self, i, n, text):
        self.info.setText(f"{text}  {i}/{n}　表格已经能看能筛，剩下的参数在后台补")

    def _on_fail(self, msg):
        self.btn_refresh.setEnabled(True)
        self.info.setText("采集失败：" + msg.splitlines()[-1])
        QMessageBox.warning(self, "进程采集失败", msg)

    def _on_rows(self, rows):
        self._rows = rows
        self.btn_refresh.setEnabled(True)
        self.info.setText(f"共 {len(rows)} 个进程"
                          + (f"（筛选后 {self.table.rowCount()} 个）" if self.ed.text() else ""))
        self._apply_filter()

    def _on_partial(self, rows):
        """后台补一批启动参数就刷一遍。

        只改已经建好的单元格，**不重建表格**：400 行 × 8 列重建一次要几十毫秒，
        每批来一次反而把主线程占满（这也是「进程」页以前一打开就整机发卡的一部分原因）。
        """
        self._rows = rows
        if not self._row_pids:            # 第一次回报：还没有表，正常建一次
            self._apply_filter()
            return
        by_pid = {r["pid"]: r for r in rows}
        changed = 0
        for i, pid in enumerate(self._row_pids):
            r = by_pid.get(pid)
            if not r or not r.get("detail"):
                continue
            cmd = r.get("cmdline") or r.get("exe") or "—"
            it = self.table.item(i, 7)
            if it is not None and it.text() != cmd:
                it.setText(cmd)
                it.setToolTip(cmd)
                changed += 1
            ju = r.get("user") or "—"
            iu = self.table.item(i, 5)
            if iu is not None and iu.text() != ju:
                iu.setText(ju)
        if changed and self._rows:
            self.info.setText(f"共 {len(self._rows)} 个进程　启动参数还在后台补…")

    # ---- 展示 ----
    def _lazy_filter(self):
        self._filter_timer.start()

    def _apply_filter(self):
        key = self.ed.text().strip().lower()
        rows = self._rows
        if key:
            rows = [r for r in rows
                    if key in r["name"].lower()
                    or key in str(r["pid"])
                    or key in (r.get("cmdline") or "").lower()
                    or key in (r.get("user") or "").lower()]
        mode = self.cb_sort.currentIndex()
        if mode == 0:
            rows = sorted(rows, key=lambda r: -(r.get("cpu") or 0))
        elif mode == 1:
            rows = sorted(rows, key=lambda r: -(r.get("mem") or 0))
        elif mode == 2:
            rows = sorted(rows, key=lambda r: r["name"].lower())
        else:
            rows = sorted(rows, key=lambda r: r["pid"])

        out, styles = [], {}
        for i, r in enumerate(rows):
            cmd = r.get("cmdline") or r.get("exe") or "—"
            out.append([
                (str(r["pid"]), r["pid"]),
                r["name"],
                (f"{r.get('cpu', 0):.1f}", round(r.get("cpu") or 0, 2)),
                (fb(r.get("mem") or 0), r.get("mem") or 0),
                (fb(r.get("mem_priv") or 0), r.get("mem_priv") or 0),
                r.get("user") or "—",
                r.get("status") or "—",
                cmd,
            ])
            styles[(i, 7)] = {"tip": cmd}
        self.table.set_rows(out, styles)
        # 记住「表格第 i 行是哪个 pid」：后台补参数时就地改格子，不用重建整张表
        self._row_pids = [r["pid"] for r in rows]
        if self._rows:
            self.info.setText(f"共 {len(self._rows)} 个进程"
                              f"，当前显示 {len(out)} 个"
                              + (f"（筛选 “{key}”）" if key else ""))

    # ---- 操作 ----
    def _selected_procs(self):
        rows = sorted({i.row() for i in self.table.selectedIndexes()})
        out = []
        for r in rows:
            pid_item = self.table.item(r, 0)
            name_item = self.table.item(r, 1)
            if pid_item and name_item:
                try:
                    out.append((int(pid_item.text()), name_item.text()))
                except ValueError:
                    pass
        return out

    def show_detail(self, row):
        if row < 0:
            QMessageBox.information(self, "提示", "请先选中一个进程")
            return
        it = self.table.item(row, 0)
        if it is None:
            return
        from .tasks import ProcDetailTask
        d = metrics.proc_detail(int(it.text()))
        if not d:
            QMessageBox.warning(self, "读取失败", "该进程可能已退出或受保护，无法读取详情")
            return
        ProcDialog(d, self).exec()

    def kill_selected(self, tree=False):
        targets = self._selected_procs()
        if not targets:
            QMessageBox.information(self, "提示", "请先选中要结束的进程")
            return
        me = os.getpid()
        plan, refused = [], []
        for pid, name in targets:
            low = name.lower()
            if pid <= 4:
                refused.append(f"{name}({pid})：系统核心进程，不可终止")
            elif pid == me:
                refused.append(f"{name}({pid})：巡检工具自身")
            elif low in metrics.KILL_BLOCK_NAMES:
                refused.append(f"{name}({pid})：系统关键进程，界面不提供强制终止")
            else:
                plan.append((pid, name))
        if refused:
            QMessageBox.warning(self, "已跳过", "以下进程不会被动：\n\n" + "\n".join(refused))
        if not plan:
            return

        tip = "（含子进程）" if tree else ""
        detail = "\n".join(f"· {n}  (PID {p})" for p, n in plan[:15])
        if len(plan) > 15:
            detail += f"\n… 另有 {len(plan) - 15} 个"
        ok = QMessageBox.question(
            self, "确认结束进程",
            f"将结束以下 {len(plan)} 个进程{tip}：\n\n{detail}\n\n"
            "未保存的数据会丢失，确定继续？",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if ok != QMessageBox.Yes:
            return

        from .tasks import KillTask
        task = self._hold(KillTask(plan, tree=tree, parent=self))
        task.done.connect(self._on_killed)
        task.failed.connect(lambda m: QMessageBox.critical(self, "终止失败", m))
        task.start()

    def _on_killed(self, results):
        lines = []
        for r in results:
            mark = "成功" if r["ok"] else "失败"
            extra = "；".join(r["notes"]) if r["notes"] else ""
            lines.append(f"{r['name']}({r['pid']}): {mark}" + (f"  — {extra}" if extra else ""))
            self.notify.emit(f"结束进程 {r['name']}({r['pid']}) → {mark} {extra}")
        QMessageBox.information(self, "结束进程结果", "\n".join(lines))
        self.reload()


# ══════════════════════════════ 端口 ══════════════════════════════


class NetHelpPage(Page):
    """网络页：给不懂技术的人一个「上不了网点这里」的一级入口。

    3.5.4 起诊断结果直接显示在本页（不再弹独立窗口）：
    首屏是一句人话 + 大按钮，点完就在同一页里逐条出结论、逐条修。
    """

    def __init__(self, cfg, parent=None):
        super().__init__(cfg, parent)
        self._started = False

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        # ① 首屏：人话引导 + 一个按钮
        self.intro = QWidget()
        iv = QVBoxLayout(self.intro)
        iv.setContentsMargins(28, 34, 28, 24)
        iv.setSpacing(12)
        title = QLabel("上不了网？网页打不开？")
        title.setObjectName("H1")
        iv.addWidget(title)
        tip = QLabel(
            "点下面的按钮，工具会像网管一样一层一层检查：\n"
            "网卡 → 网线 / Wi-Fi → 能不能上网 → 域名解析 → 代理 → 系统设置。\n\n"
            "查完会告诉你每一层的情况：\n"
            "　· 能自动修的，点「一键修复」就好；\n"
            "　· 需要确认的，会先问你；\n"
            "　· 修不了的，给你一句话，照着说给 IT 听就行。")
        tip.setObjectName("Muted")
        tip.setWordWrap(True)
        iv.addWidget(tip)
        self.btn_run = QPushButton("开始检查网络")
        self.btn_run.setObjectName("Primary")
        self.btn_run.setMinimumWidth(180)
        self.btn_run.setFixedHeight(40)
        self.btn_run.clicked.connect(self.start)
        iv.addWidget(self.btn_run)
        iv.addStretch(1)
        lay.addWidget(self.intro)

        # ② 结果区：同一个页面内展开，不弹窗
        from .netfix_panel import NetFixPanel
        self.panel = NetFixPanel(self)
        self.panel.hide()
        self.panel.changed.connect(lambda: self.notify.emit("网络修复已执行"))
        lay.addWidget(self.panel, 1)

    def start(self):
        """点按钮 / 工具条「修复网络」：切到结果区并开始逐条检索。"""
        self.intro.hide()
        self.panel.show()
        self._started = True
        self.panel.scan()

    def stop(self):
        if getattr(self.panel, "_task", None) is not None:
            self.panel.stop()


class PortsPage(Page):
    """监听端口：谁在听、对外还是仅本机、能不能关。"""

    def __init__(self, cfg, parent=None):
        super().__init__(cfg, parent)
        self._rows = []

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)

        bar = QHBoxLayout()
        bar.setSpacing(8)
        self.ed = QLineEdit()
        self.ed.setPlaceholderText("搜索端口 / 进程 / 服务 / 参数…")
        self.ed.setClearButtonEnabled(True)
        self.ed.textChanged.connect(self._lazy_filter)
        bar.addWidget(self.ed, 1)
        self.chk_ext = QCheckBox("只看对外暴露")
        self.chk_ext.stateChanged.connect(self._apply_filter)
        bar.addWidget(self.chk_ext)
        self.btn_refresh = QPushButton("刷新")
        self.btn_refresh.clicked.connect(self.reload)
        bar.addWidget(self.btn_refresh)
        # 网络修复已经是一级页签（主窗口「网络」页），这里不再放弹窗按钮
        self.btn_kill = QPushButton("结束占用进程")
        self.btn_kill.setObjectName("Danger")
        self.btn_kill.clicked.connect(self.kill_selected)
        bar.addWidget(self.btn_kill)
        lay.addLayout(bar)

        self.info = QLabel("点「刷新」读取当前监听端口")
        self.info.setObjectName("Muted")
        lay.addWidget(self.info)

        self.table = DataTable([
            ("端口", 74, "r"),
            ("绑定", 150, "l"),
            ("暴露", 86, "c"),
            ("PID", 72, "r"),
            ("进程", 190, "l"),
            ("服务", 170, "l"),
            ("启动参数 / 路径", -1, "l"),
        ])
        lay.addWidget(self.table, 1)
        self.table.extra_actions = [
            ("结束占用进程", lambda: self.kill_selected()),
            ("在进程中查看", lambda: self._goto_proc()),
        ]
        self._filter_timer = QTimer(self)
        self._filter_timer.setSingleShot(True)
        self._filter_timer.setInterval(220)
        self._filter_timer.timeout.connect(self._apply_filter)

    def reload(self):
        if self.is_busy():
            return
        from .tasks import PortsTask
        self.btn_refresh.setEnabled(False)
        self.info.setText("正在读取监听端口…")
        task = self._hold(PortsTask(parent=self))
        task.failed.connect(self._on_fail)
        task.done.connect(self._on_rows)
        task.start()

    def _on_fail(self, msg):
        self.btn_refresh.setEnabled(True)
        self.info.setText("读取失败：" + msg.splitlines()[-1])

    def _on_rows(self, rows):
        self._rows = rows
        self.btn_refresh.setEnabled(True)
        self._apply_filter()

    @staticmethod
    def _bind_of(r):
        ips = set(r.get("ips") or [])
        if ips & {"0.0.0.0", "::"}:
            return "全部网卡", "对外"
        if ips and all(i in ("127.0.0.1", "::1") for i in ips):
            return "仅本机", "本机"
        return ", ".join(sorted(ips))[:26], "指定网卡"

    def _lazy_filter(self):
        self._filter_timer.start()

    def _apply_filter(self):
        key = self.ed.text().strip().lower()
        only_ext = self.chk_ext.isChecked()
        rows = []
        for r in self._rows:
            bind, expo = self._bind_of(r)
            if only_ext and expo != "对外":
                continue
            if key and not (key in str(r["port"]) or key in r["name"].lower()
                            or key in (r.get("service") or "").lower()
                            or key in (r.get("cmdline") or "").lower()):
                continue
            rows.append((r, bind, expo))

        out, styles = [], {}
        for i, (r, bind, expo) in enumerate(rows):
            cmd = r.get("cmdline") or r.get("exe") or "—"
            out.append([
                (str(r["port"]), r["port"]),
                bind,
                expo,
                (str(r["pid"]), r["pid"]),
                r["name"],
                r.get("service") or "—",
                cmd,
            ])
            risky = r["port"] in DB_PORTS and expo == "对外"
            if risky:
                styles[(i, 0)] = {"fg": SEV["error"][0], "bold": True}
                styles[(i, 2)] = {"fg": SEV["error"][0], "bg": SEV["error"][1]}
            elif expo == "对外":
                styles[(i, 2)] = {"fg": SEV["warn"][0]}
            styles[(i, 1)] = {"tip": ", ".join(sorted(r.get("ips") or []))}
            styles[(i, 6)] = {"tip": cmd}
        self.table.set_rows(out, styles)
        ext = sum(1 for r in self._rows if self._bind_of(r)[1] == "对外")
        self.info.setText(f"{len(self._rows)} 组监听（{ext} 组对外暴露）"
                          f"，当前显示 {len(out)} 组"
                          + ("　红色 = 常见数据库/远程桌面端口且对外暴露" if rows else ""))

    def _selected(self):
        rows = sorted({i.row() for i in self.table.selectedIndexes()})
        out = []
        for r in rows:
            p = self.table.item(r, 3)
            n = self.table.item(r, 4)
            if p and n:
                try:
                    out.append((int(p.text()), n.text()))
                except ValueError:
                    pass
        return out

    def _goto_proc(self):
        sel = self._selected()
        if sel:
            QGuiApplication.clipboard().setText(str(sel[0][0]))
            self.notify.emit(f"已复制 PID {sel[0][0]}，可到「进程」页搜索")

    def kill_selected(self):
        targets = self._selected()
        if not targets:
            QMessageBox.information(self, "提示", "请先选中一个端口行")
            return
        me = os.getpid()
        plan, refused = [], []
        for pid, name in targets:
            if pid <= 4:
                refused.append(f"{name}({pid})：系统核心进程")
            elif pid == me:
                refused.append(f"{name}({pid})：巡检工具自身")
            elif name.lower() in metrics.KILL_BLOCK_NAMES:
                refused.append(f"{name}({pid})：系统关键进程（svchost 等由服务管理器托管）")
            else:
                plan.append((pid, name))
        if refused:
            QMessageBox.warning(self, "已跳过", "\n".join(refused))
        if not plan:
            return
        detail = "\n".join(f"· {n}  (PID {p})" for p, n in plan)
        if QMessageBox.question(self, "确认结束进程",
                                f"将结束以下进程：\n\n{detail}\n\n确定继续？",
                                QMessageBox.Yes | QMessageBox.No,
                                QMessageBox.No) != QMessageBox.Yes:
            return
        from .tasks import KillTask
        task = self._hold(KillTask(plan, parent=self))
        task.done.connect(self._on_killed)
        task.start()

    def _on_killed(self, results):
        msg = []
        for r in results:
            mark = "成功" if r["ok"] else "失败"
            msg.append(f"{r['name']}({r['pid']}): {mark}")
            self.notify.emit(f"结束进程 {r['name']}({r['pid']}) → {mark}")
        QMessageBox.information(self, "结束进程结果", "\n".join(msg))
        self.reload()


# ══════════════════════════════ 清理 ══════════════════════════════

def _ghost_judge(g):
    """带缓存的判定：一条幽灵项现在能不能删。"""
    v = regclean.judge(g)
    return dict(g, judge=v)


class GhostDialog(QDialog):
    """注册表幽灵项：勾选 → 备份成 .reg → 删掉「已安装程序」里那一行登记。

    只动 Uninstall 子树，MSI 托管项和系统隐藏组件一律标「保留」，不给勾。
    """

    changed = Signal()          # 删成功过，通知清理页重扫

    def __init__(self, ghosts, parent=None):
        super().__init__(parent)
        self.setWindowTitle("注册表残留（已安装程序登记项）")
        self.resize(1080, 540)
        self._rows = []
        self._task = None

        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(9)

        tip = QLabel(
            "这些条目在「程序和功能」里登记了安装目录，但那个目录已经不在了 —— 属于卸载后没清干净的登记。\n"
            "删掉它们只是让列表干净，不会释放磁盘空间；删除前会把整项导出成 .reg"
            "（在 %LOCALAPPDATA%\\health_assistant\\reg-backup 下），双击即可导回。")
        tip.setWordWrap(True)
        tip.setObjectName("Muted")
        lay.addWidget(tip)

        self.table = CheckTable([
            ("", 58, "c"),
            ("程序", 206, "l"),
            ("版本", 92, "l"),
            ("登记的安装目录", -1, "l"),
            ("判定", 330, "l"),
        ])
        self.table.setToolTip("右键任意一行：删除这一条 / 复制注册表路径 / 查看键值")
        self.table.extra_actions = [
            ("删除这一条（先备份）", self.delete_current),
            ("只勾选这一行", self.select_only_current),
            ("-", None),
            ("复制注册表路径", self.copy_key),
            ("复制判定与键值", self.copy_detail),
            ("查看这一条的全部键值", self.show_detail),
        ]
        self.table.itemDoubleClicked.connect(lambda _it: self.show_detail())
        self.table.counts_changed.connect(self._on_counts)
        lay.addWidget(self.table, 1)

        bar = QHBoxLayout()
        bar.setSpacing(8)
        self.btn_all = QPushButton("全选可删项")
        self.btn_all.clicked.connect(lambda: self.table.set_all_checked(True))
        self.btn_none = QPushButton("全不选")
        self.btn_none.clicked.connect(lambda: self.table.set_all_checked(False))
        self.lb = QLabel("")
        self.lb.setObjectName("Muted")
        self.btn_del = QPushButton("备份并删除选中")
        self.btn_del.setObjectName("Danger")
        self.btn_del.setEnabled(False)
        self.btn_del.clicked.connect(self.delete_checked)
        self.btn_close = QPushButton("关闭")
        self.btn_close.clicked.connect(self.accept)
        bar.addWidget(self.btn_all)
        bar.addWidget(self.btn_none)
        bar.addWidget(self.lb, 1)
        bar.addWidget(self.btn_del)
        bar.addWidget(self.btn_close)
        lay.addLayout(bar)

        self.reload(ghosts)

    # ---- 数据 ----
    def reload(self, ghosts=None):
        if ghosts is not None:
            src = ghosts
        else:
            src = [g for g in self._rows]
        judged = [_ghost_judge(g) for g in src]
        judged.sort(key=lambda g: (g["judge"]["action"] != "delete",
                                   g.get("name", "").lower()))
        self._rows = judged
        rows = []
        for g in judged:
            ok = g["judge"]["action"] == "delete"
            rows.append([
                ("可删" if ok else "保留"),
                g.get("name", "")[:40],
                g.get("version") or "-",
                g.get("location", ""),
                g["judge"]["reason"],
            ])
        self.table.set_check_rows(rows, judged, checked=True)
        deletable = 0
        for r, g in enumerate(judged):
            it = self.table.item(r, 0)
            if g["judge"]["action"] != "delete":
                if it is not None:      # 保留项：不给勾，也点不动
                    it.setCheckState(Qt.Unchecked)
                    it.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                    it.setText("保留")
                for c in range(1, 6):
                    cell = self.table.item(r, c)
                    if cell is not None:
                        cell.setForeground(QColor(C["muted"]))
            else:
                deletable += 1
                if it is not None:
                    it.setText("可删")
            # 列宽有限，截断的单元格靠 tooltip 看全文
            for c in range(1, 6):
                cell = self.table.item(r, c)
                if cell is not None:
                    cell.setToolTip(cell.text())
        self.btn_del.setEnabled(deletable > 0)
        self._on_counts(0, 0)
        self.lb.setText(f"共 {len(judged)} 条 · 可删 {deletable} 条 · "
                        f"保留 {len(judged) - deletable} 条（原因看最后一列）")

    def _on_counts(self, n, _total):
        picked = [p for p in self.table.checked_payloads()
                  if p.get("judge", {}).get("action") == "delete"]
        self.btn_del.setText(f"备份并删除选中（{len(picked)}）")
        self.btn_del.setEnabled(bool(picked) and self._task is None)

    def _payload(self, row=None):
        if row is None:
            row = getattr(self.table, "context_row", -1)
        if row is None or row < 0:
            return None
        return self.table.payload_at(row)

    def _picked(self):
        return [p for p in self.table.checked_payloads()
                if p.get("judge", {}).get("action") == "delete"]

    # ---- 右键动作 ----
    def delete_current(self):
        g = self._payload()
        if g is None:
            QMessageBox.information(self, "先选一行", "请在一行上右键。")
            return
        if g["judge"]["action"] != "delete":
            QMessageBox.information(self, "这条不建议删", g["judge"]["reason"])
            return
        self._run([g])

    def select_only_current(self):
        row = getattr(self.table, "context_row", -1)
        if row < 0:
            return
        self.table.set_all_checked(False)
        self.table.set_row_checked(row, True)

    def copy_key(self):
        g = self._payload()
        if g is None:
            return
        QGuiApplication.clipboard().setText(regclean.display_path(g))
        self.lb.setText("注册表路径已复制到剪贴板")

    def _detail_text(self, g):
        vals = regclean.values_of(g)
        lines = [f"程序：{g.get('name', '')}",
                 f"版本：{g.get('version') or '-'}",
                 f"登记目录：{g.get('location', '')}（当前不存在）",
                 f"注册表：{regclean.display_path(g)}",
                 f"判定：{'可删' if g['judge']['action'] == 'delete' else '保留'}"
                 f" —— {g['judge']['reason']}",
                 "", "键值："]
        if not vals:
            lines.append("  （读不到，可能已被删除或权限不足）")
        for k in sorted(vals):
            lines.append(f"  {k} = {str(vals[k])[:200]}")
        return "\n".join(lines)

    def copy_detail(self):
        g = self._payload()
        if g is None:
            return
        QGuiApplication.clipboard().setText(self._detail_text(g))
        self.lb.setText("判定与键值已复制到剪贴板")

    def show_detail(self):
        g = self._payload()
        if g is None:
            return
        dlg = QDialog(self)
        dlg.setWindowTitle(g.get("name", "")[:60])
        dlg.resize(760, 460)
        v = QVBoxLayout(dlg)
        box = QPlainTextEdit(self._detail_text(g))
        box.setReadOnly(True)
        v.addWidget(box, 1)
        row = QHBoxLayout()
        row.addStretch(1)
        btn = QPushButton("复制")
        btn.clicked.connect(lambda: QGuiApplication.clipboard().setText(box.toPlainText()))
        row.addWidget(btn)
        ok = QPushButton("关闭")
        ok.clicked.connect(dlg.accept)
        row.addWidget(ok)
        v.addLayout(row)
        dlg.exec()

    # ---- 删除 ----
    def delete_checked(self):
        picked = self._picked()
        if not picked:
            QMessageBox.information(self, "没有勾选", "请先勾选要删除的条目。")
            return
        self._run(picked)

    def _run(self, picked):
        if self._task is not None:
            return
        names = "\n".join(f"· {p.get('name', '')[:50]}" for p in picked[:12])
        if len(picked) > 12:
            names += f"\n… 另有 {len(picked) - 12} 条"
        warn = QMessageBox(self)
        warn.setIcon(QMessageBox.Warning)
        warn.setWindowTitle("确认删除注册表登记项")
        warn.setText(f"将删除这 {len(picked)} 条「已安装程序」登记项：\n\n{names}\n\n"
                     "只删注册表里的这一行登记（登记的目录本来就不存在，不释放磁盘空间）。\n"
                     "删除前会自动导出 .reg 备份，导入备份即可还原。")
        warn.setInformativeText("确认继续？")
        warn.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        warn.setDefaultButton(QMessageBox.No)
        warn.button(QMessageBox.Yes).setText("备份并删除")
        warn.button(QMessageBox.No).setText("取消")
        if warn.exec() != QMessageBox.Yes:
            return

        from .tasks import GhostDeleteTask
        self._busy(True)
        task = GhostDeleteTask(picked, parent=self)
        self._task = task
        task.log.connect(self.lb.setText)
        task.progress.connect(lambda i, n, s: self.lb.setText(f"{s}（{i}/{n}）"))
        task.failed.connect(self._on_fail)
        task.done.connect(self._on_done)
        task.finished.connect(self._clear_task)
        task.start()

    def _clear_task(self):
        self._task = None
        self._on_counts(0, 0)

    def _busy(self, on):
        self.btn_del.setEnabled(not on)
        self.btn_all.setEnabled(not on)
        self.btn_none.setEnabled(not on)
        if on:
            self.lb.setText("正在备份并删除…")

    def _on_fail(self, msg):
        self._busy(False)
        self._on_counts(0, 0)
        show_error(self, "删除失败", msg, summary="删除注册表登记项时出错，详见调用栈。")

    def _on_done(self, res):
        self._busy(False)
        ok, skipped, bad = res["ok"], res["skipped"], res["bad"]
        gone = {o["key"] for o in ok}
        lines = [f"已删除 {len(ok)} 条"]
        if skipped:
            lines.append(f"跳过 {len(skipped)} 条")
            lines += [f"· {s['name'][:40]}：{s['reason']}" for s in skipped[:8]]
        if bad:
            lines.append(f"失败 {len(bad)} 条")
            lines += [f"· {b['name'][:40]}：{b['reason']}" for b in bad[:8]]
        if res.get("backup"):
            lines.append("")
            lines.append("备份：" + res["backup"])
        lines.append("")
        lines.append("（重新导入备份 .reg 即可还原这些登记项）")

        box = QMessageBox(self)
        box.setIcon(QMessageBox.Information)
        box.setWindowTitle("注册表清理结果")
        box.setText(lines[0] + ("　·　看下面明细" if (skipped or bad) else ""))
        box.setInformativeText("\n".join(lines[1:]))
        open_btn = None
        if res.get("backup"):
            open_btn = box.addButton("打开备份文件夹", QMessageBox.ActionRole)
        box.addButton("好", QMessageBox.AcceptRole)
        box.exec()
        if open_btn is not None and box.clickedButton() is open_btn:
            try:
                os.startfile(os.path.dirname(res["backup"]))
            except OSError as exc:
                QMessageBox.warning(self, "打不开", str(exc))

        rest = [g for g in self._rows if regclean.display_path(g) not in gone]
        if ok:
            self.changed.emit()
        self.reload(rest)


class SpaceHogDialog(QDialog):
    """系统盘空间大头（只报告，不代跑）。

    休眠文件、旧系统备份、虚拟内存这几样一关就能省几个 GB，但都属于
    「改了会影响系统功能」的操作（没休眠、不能回退旧版本、蓝屏没得分析）。
    按项目约定只给位置、体积和做法，绝不代执行 —— 所以这个框没有「立即处理」按钮。
    """

    def __init__(self, hogs, parent=None):
        super().__init__(parent)
        self.setWindowTitle("系统盘空间大头")
        self.resize(1040, 520)
        self._hogs = list(hogs or [])

        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(9)

        tip = QLabel(
            "系统盘上最占地方的几样东西。这里只报告、不动手 —— 关休眠、删旧系统备份、"
            "调虚拟内存都会影响系统功能，\n"
            "所以只给做法让你自己决定。右键任意一行可以复制它的处理命令。")
        tip.setWordWrap(True)
        tip.setObjectName("Muted")
        lay.addWidget(tip)

        self.table = DataTable([
            ("体积", 92, "r"),
            ("项目", 112, "l"),
            ("位置", 258, "l"),
            ("说明", -1, "l"),
            ("怎么处理", 296, "l"),
        ], sortable=False)
        self.table.setToolTip("右键可复制这一行的处理命令")
        self.table.extra_actions = [
            ("复制这一行的处理命令", self.copy_cmd),
            ("复制这一行的说明", self.copy_note),
        ]
        lay.addWidget(self.table, 1)

        bar = QHBoxLayout()
        self.lb_sum = QLabel("")
        self.lb_sum.setObjectName("Muted")
        bar.addWidget(self.lb_sum, 1)
        btn_copy = QPushButton("复制全部")
        btn_copy.clicked.connect(self.copy_all)
        bar.addWidget(btn_copy)
        btn_close = QPushButton("关闭")
        btn_close.setObjectName("Primary")
        btn_close.clicked.connect(self.accept)
        bar.addWidget(btn_close)
        lay.addLayout(bar)

        self._fill()

    def _fill(self):
        rows = []
        for h in self._hogs:
            rows.append([fb(h["size"]), h["title"], h["path"],
                         h.get("note") or "", h.get("cmd") or "—"])
        self.table.set_rows(rows)
        total = sum(h["size"] for h in self._hogs)
        self.lb_sum.setText(f"共 {len(self._hogs)} 项，合计 {fb(total)}"
                            "（休眠/虚拟内存/旧系统备份属系统托管，不建议手动删文件）")

    def _current(self):
        row = self.table.currentRow()
        if 0 <= row < len(self._hogs):
            return self._hogs[row]
        return None

    def copy_cmd(self):
        h = self._current()
        if not h:
            QMessageBox.information(self, "先选一行", "请先在表格里点一行。")
            return
        text = h.get("cmd") or h.get("note") or ""
        QGuiApplication.clipboard().setText(text)
        self.lb_sum.setText(f"已复制：{text[:64]}")

    def copy_note(self):
        h = self._current()
        if not h:
            QMessageBox.information(self, "先选一行", "请先在表格里点一行。")
            return
        QGuiApplication.clipboard().setText(f"{h['title']}　{fb(h['size'])}\n"
                                           f"{h['path']}\n{h.get('note') or ''}\n"
                                           f"{h.get('cmd') or ''}")
        self.lb_sum.setText("已复制这一行的说明")

    def copy_all(self):
        lines = []
        for h in self._hogs:
            lines.append(f"{fb(h['size'])}\t{h['title']}\t{h['path']}\t"
                         f"{h.get('cmd') or h.get('note') or ''}")
        QGuiApplication.clipboard().setText("\n".join(lines))
        self.lb_sum.setText(f"已复制全部 {len(self._hogs)} 项")


class DiskUseDialog(QDialog):
    """空间去哪了：从盘符开始一层层往下钻，看体积到底被谁占了。

    为什么不是「一键列出全盘大文件」
        全盘扫一遍要几分钟，而且列出来的大文件往往不是问题所在 ——
        C 盘满十次有八次是某几个目录慢慢涨起来的。下钻是唯一既快又能定位的做法：
        每层只统计直接子项（并行），看到大头就双击进去，跟着体积走。

    数字的可信度
        有时间预算，到点就停。没算完的那项体积是**下界**，界面标「≥」，
        状态栏也写清楚 —— 宁可说「至少这么多」，也不给一个假精确的数字。
    """

    notify = Signal(str)

    _BUDGET = 20.0          # 单层统计的时间预算（秒）

    def __init__(self, parent=None, path=None):
        super().__init__(parent)
        self.setWindowTitle("空间去哪了")
        self.resize(1180, 720)
        self._path = ""
        self._items = []
        self._task = None
        self._trash_task = None
        self._token = 0
        self._pending = False
        self._scanning = False

        from .. import diskuse
        self._drives = diskuse.drives()
        self._jumps = diskuse.quick_jump()

        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(9)

        top = QHBoxLayout()
        top.setSpacing(8)
        top.addWidget(QLabel("磁盘"))
        self.cb_drive = QComboBox()
        for d in self._drives:
            used_pct = (d["used"] * 100 // d["total"]) if d["total"] else 0
            self.cb_drive.addItem(
                f"{d['letter']} {d['label'] or '本地磁盘'}　已用 {fb(d['used'])} / "
                f"共 {fb(d['total'])}（{used_pct}%）", d["path"])
        self.cb_drive.setMinimumWidth(330)
        self.cb_drive.activated.connect(self._on_drive)
        top.addWidget(self.cb_drive)

        self.cb_jump = QComboBox()
        self.cb_jump.addItem("常用位置…", "")
        for j in self._jumps:
            self.cb_jump.addItem(f"{j['desc']}　{j['path']}", j["path"])
        self.cb_jump.setMinimumWidth(320)
        self.cb_jump.activated.connect(self._on_jump)
        top.addWidget(self.cb_jump)
        top.addStretch(1)

        self.btn_up = QPushButton("上一级")
        self.btn_up.clicked.connect(self.go_up)
        top.addWidget(self.btn_up)
        self.btn_open = QPushButton("打开此文件夹")
        self.btn_open.clicked.connect(self.open_here)
        top.addWidget(self.btn_open)
        lay.addLayout(top)

        self.lb_path = QLabel("")
        self.lb_path.setObjectName("H2")
        self.lb_path.setWordWrap(True)
        self.lb_path.setTextInteractionFlags(Qt.TextSelectableByMouse)
        lay.addWidget(self.lb_path)

        self.lb_state = QLabel("正在统计…")
        self.lb_state.setObjectName("Muted")
        self.lb_state.setWordWrap(True)
        lay.addWidget(self.lb_state)

        self.table = DataTable([
            ("体积", 110, "r"),
            ("文件数", 90, "r"),
            ("类型", 70, "l"),
            ("名称", 260, "l"),
            ("完整路径", -1, "l"),
        ])
        self.table.cellDoubleClicked.connect(self._on_dbl)
        self.table.setToolTip("双击文件夹进入下一层；双击文件在资源管理器里定位。"
                              "右键可以删除（移到回收站，能还原）")
        self.table.extra_actions = [
            ("进入这个文件夹（看里面谁大）", lambda: self._enter(self.table.currentRow())),
            ("在资源管理器里打开", self.open_current),
            ("复制完整路径", self.copy_current),
            ("-", None),
            ("删除到回收站…", self.delete_current, self._delete_state),
        ]
        lay.addWidget(self.table, 1)

        foot = QHBoxLayout()
        foot.setSpacing(8)
        self.lb_sum = QLabel("")
        self.lb_sum.setObjectName("Muted")
        foot.addWidget(self.lb_sum, 1)
        btn_quit = QPushButton("关闭")
        btn_quit.clicked.connect(self.accept)
        foot.addWidget(btn_quit)
        lay.addLayout(foot)

        self._flush_timer = QTimer(self)
        self._flush_timer.setSingleShot(True)
        self._flush_timer.setInterval(180)
        self._flush_timer.timeout.connect(self._flush)

        start = path or (self._drives[0]["path"] if self._drives else "")
        if start:
            QTimer.singleShot(80, lambda: self.scan(start))
        else:
            self.lb_state.setText("没有找到本地固定磁盘。")

    # ---- 导航 ----
    def _on_drive(self, idx):
        p = self.cb_drive.itemData(idx)
        if p:
            self.scan(p)

    def _on_jump(self, idx):
        p = self.cb_jump.itemData(idx)
        self.cb_jump.setCurrentIndex(0)
        if p:
            self.scan(p)

    def go_up(self):
        if not self._path:
            return
        parent = os.path.dirname(self._path.rstrip("\\/"))
        if not parent or parent == self._path:
            return
        self.scan(parent)

    def open_here(self):
        if self._path and os.path.isdir(self._path):
            try:
                os.startfile(self._path)
            except Exception as exc:
                QMessageBox.warning(self, "打不开", f"{self._path}\n\n{exc}")

    # ---- 扫描 ----
    def scan(self, path):
        path = os.path.normpath(path)
        if not os.path.isdir(path):
            QMessageBox.warning(self, "路径不在了", path)
            return
        self._stop_task()
        self._token += 1
        token = self._token
        self._path = path
        self._items = []
        self._pending = False
        self._scanning = True
        self.table.set_rows([])
        self.lb_path.setText(path)
        self.lb_state.setText("正在统计各文件夹体积…（大的文件夹会先算，没算完会标「≥」）")
        self.lb_sum.setText("")
        self.btn_up.setEnabled(os.path.dirname(path.rstrip("\\/")) not in ("", path))
        self.btn_open.setEnabled(True)

        from .tasks import DiskUseTask
        task = DiskUseTask(path, budget=self._BUDGET, parent=self)
        task.item.connect(lambda it, t=token: self._on_item(it, t))
        task.done.connect(lambda res, t=token: self._on_done(res, t))
        task.failed.connect(self._on_fail)
        task.finished.connect(task.deleteLater)
        self._task = task
        task.start()

    def _stop_task(self):
        t = self._task
        self._task = None
        if t is not None and t.isRunning():
            t.stop()
            t.wait(1500)

    def _on_item(self, it, token):
        if token != self._token:
            return
        self._items.append(it)
        if not self._flush_timer.isActive():
            self._flush_timer.start()

    def _flush(self):
        rows, styles = [], {}
        items = sorted(self._items, key=lambda x: -x["size"])
        for i, it in enumerate(items):
            if it.get("unscanned"):
                size_cell = ("没算完", -1)
            else:
                size_cell = (("≥" if it["partial"] else "") + fb(it["size"]), it["size"])
            if it["is_dir"]:
                # 0 字节的目录写成「0B 文件夹」会被当成「没扫到」，这里直接标明是空的
                empty_dir = (not it["partial"] and not it.get("unscanned")
                             and it["files"] == 0)
                typ = "空文件夹" if empty_dir else "文件夹"
            else:
                typ = "文件"
            rows.append([
                size_cell,
                (f"{it['files']:,}" if it["is_dir"] else "—", it["files"]),
                typ,
                it["name"],
                it["path"],
            ])
            styles[(i, 4)] = {"tip": it["path"]}
            if it.get("unscanned"):
                styles[(i, 0)] = {"fg": C["muted"]}
            elif it["partial"]:
                styles[(i, 0)] = {"fg": C["muted"], "tip": "没算完，这是下限"}
        self.table.set_rows(rows, styles)
        known = sum(i["size"] for i in items)
        n_empty = sum(1 for i in items
                      if i["is_dir"] and i["files"] == 0
                      and not i["partial"] and not i.get("unscanned"))
        self.lb_sum.setText(
            f"已统计 {len(items)} 项，合计 ≥ {fb(known)}"
            + (f"　·　其中 {n_empty} 个是空文件夹（0 字节，右键可直接删）"
               if n_empty else "")
            + ("　（还在统计…）" if self._pending else ""))

    def _on_done(self, res, token):
        if token != self._token:
            return
        self._task = None
        self._pending = False
        self._scanning = False
        self._flush_timer.stop()
        if res.get("error"):
            self.lb_state.setText("这个文件夹读不了：" + res["error"])
            self.lb_sum.setText("")
            return
        # 用最终结果覆盖（并行回调的顺序和最终排序可能不同）
        self._items = res["items"]
        self._flush()
        parts = [f"共 {len(res['items'])} 项，用时 {res['elapsed']:.1f} 秒"]
        if res.get("truncated"):
            parts.append("有文件夹没统计完（标「≥」的是下限）—— 点进去会重新精算")
        if res.get("denied"):
            parts.append(f"{res['denied']} 个位置没权限读")
        if res.get("rest"):
            parts.append(f"另有 {res['rest']['count']} 项较小，合计 {fb(res['rest']['size'])}")
        self.lb_state.setText("　·　".join(parts))

    def _on_fail(self, msg):
        self._scanning = False
        self.lb_state.setText("统计失败：" + msg.strip().splitlines()[-1])

    # ---- 表格操作 ----
    def _item_at(self, row):
        if row < 0:
            return None
        name_item = self.table.item(row, 3)
        if name_item is None:
            return None
        target = name_item.text()
        for it in sorted(self._items, key=lambda x: -x["size"]):
            if it["name"] == target:
                return it
        return None

    def _on_dbl(self, row, _col):
        self._enter(row)

    def _enter(self, row):
        it = self._item_at(row)
        if it is None:
            return
        if not it["is_dir"]:
            self._reveal(it["path"])
            return
        self.scan(it["path"])

    def _reveal(self, path):
        try:
            subprocess.Popen(["explorer", "/select,", os.path.normpath(path)],
                             **no_window_kwargs())
        except Exception as exc:
            QMessageBox.warning(self, "打不开", f"{path}\n\n{exc}")

    def open_current(self):
        it = self._item_at(self.table.currentRow())
        if it is None:
            QMessageBox.information(self, "先选一行", "请先选中一行。")
            return
        if it["is_dir"]:
            try:
                os.startfile(it["path"])
            except Exception as exc:
                QMessageBox.warning(self, "打不开", f"{it['path']}\n\n{exc}")
        else:
            self._reveal(it["path"])

    def copy_current(self):
        it = self._item_at(self.table.currentRow())
        if it is None:
            return
        QGuiApplication.clipboard().setText(it["path"])
        self.notify.emit("路径已复制")

    # ---- 删除（右键，移到回收站） ----
    def _delete_state(self):
        """右键菜单里「删除」能不能点：能点是 True，不能点返回一句原因（显示在菜单项上）。"""
        it = self._item_at(self.table.context_row)
        if it is None:
            return "先右键某一行"
        if self._trash_task is not None:
            return "正在删除上一项…"
        return leftover.named_block_reason(it["path"]) or True

    def delete_current(self):
        it = self._item_at(self.table.context_row)
        if it is None:
            return
        path = it["path"]
        reason = leftover.named_block_reason(path)
        if reason:
            QMessageBox.information(self, "这个位置不代删", reason)
            return

        size = ("没算完" if it.get("unscanned")
                else ("≥" if it["partial"] else "") + fb(it["size"]))
        detail = f"{size}，{it['files']:,} 个文件" if it["is_dir"] else size
        box = QMessageBox(self)
        box.setWindowTitle("删除到回收站")
        box.setIcon(QMessageBox.Warning)
        box.setText(f"要把「{it['name']}」移到回收站吗？")
        box.setInformativeText(
            f"{'文件夹' if it['is_dir'] else '文件'}　{detail}\n"
            f"位置：{path}\n\n"
            "移到回收站之后可以还原，不会马上消失。"
            "确认里面没有还要用的东西再动手。")
        b_cancel = box.addButton("取消", QMessageBox.RejectRole)
        b_ok = box.addButton("移到回收站", QMessageBox.AcceptRole)
        box.setDefaultButton(b_cancel)
        box.exec()
        if box.clickedButton() is not b_ok:
            return

        self._stop_task()                     # 先停掉体积统计，别和删除抢同一个目录
        self.table.setEnabled(False)
        self.btn_up.setEnabled(False)
        self.btn_open.setEnabled(False)
        self.lb_state.setText(f"正在把「{it['name']}」移到回收站…（大文件夹要等一会儿）")

        from .tasks import UserTrashTask
        task = UserTrashTask(path, parent=self)
        task.progress.connect(lambda _done, _total, msg: self.lb_state.setText(msg))
        task.done.connect(self._on_delete_done)
        task.failed.connect(self._on_delete_fail)
        task.finished.connect(task.deleteLater)
        self._trash_task = task
        task.start()

    def _on_delete_done(self, res):
        ok, bad = res
        self._trash_task = None
        self.table.setEnabled(True)
        if ok:
            self.notify.emit(ok[0][1])
        elif bad:
            QMessageBox.warning(self, "没删掉", bad[0][1])
        # 重新统计当前目录：删掉的项立刻从表里消失，合计也跟着少
        self.scan(self._path)

    def _on_delete_fail(self, msg):
        self._trash_task = None
        self.table.setEnabled(True)
        self.btn_up.setEnabled(True)
        self.btn_open.setEnabled(True)
        self.lb_state.setText("删除失败：" + msg.strip().splitlines()[-1])

    # ---- 收尾 ----
    def closeEvent(self, ev):
        self._stop_task()
        t = self._trash_task
        if t is not None:
            t.wait(3000)
        super().closeEvent(ev)

    def reject(self):
        self._stop_task()
        t = self._trash_task
        if t is not None:
            t.wait(3000)          # 删除动到一半就走会留下半个目录，等它收尾
        super().reject()


class CleanPage(Page):
    """扫描可清理目录 → 勾选 → 移到回收站。"""

    # 瘦身候选里「删了肯定不影响使用」的几类，扫描完默认勾上；
    # 临时文件（可能正被占用）和旧安装包（删了要重下）一律让用户自己勾。
    _SLIM_SAFE = ("shortcut", "crashdump", "officetmp")
    # 瘦身这一族类型（含两个子集）
    _SLIM_KINDS = ("slim", "zombie", "userjunk")

    def __init__(self, cfg, parent=None):
        super().__init__(cfg, parent)
        self._plan = None
        self._ghosts = []

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)

        # ── 模式条：两个大按钮，第一眼就能看见「系统盘瘦身」 ──
        # 以前它只是「类型」下拉里的一个值（默认还停在「全部」），等于藏在第二层，
        # 用户反馈过「藏得太深」。现在两种主用途各给一个大按钮，点下去直接切类型
        # 并立刻开扫，一次点击就到结果。
        mode_bar = QHBoxLayout()
        mode_bar.setSpacing(0)
        self.btn_mode_clean = QPushButton("常规清理")
        self.btn_mode_slim = QPushButton("系统盘瘦身")
        self._mode_group = QButtonGroup(self)
        self._mode_group.setExclusive(True)
        tips = (
            "清缓存、程序残留、空目录 —— 都是删了不影响使用的缓存",
            "找出 C 盘真正占地方的东西：断链快捷方式、崩溃转储、临时文件、\n"
            "旧安装包（一次可能腾出几十 GB）。默认只勾「删了肯定没影响」的几类。",
        )
        for i, b in enumerate((self.btn_mode_clean, self.btn_mode_slim)):
            b.setCheckable(True)
            b.setCursor(Qt.PointingHandCursor)
            b.setProperty("mode", True)
            b.setProperty("seg", "first" if i == 0 else "last")
            b.setToolTip(tips[i])
            self._mode_group.addButton(b, i)
            mode_bar.addWidget(b)
        self.btn_mode_clean.setChecked(True)
        self._mode_group.idClicked.connect(self.use_mode)

        self.lb_mode = QLabel()
        self.lb_mode.setObjectName("Muted")
        # 同 lb_state：不限最小宽度，长句才会被压缩而不是把右边按钮顶走
        self.lb_mode.setMinimumWidth(1)
        self.lb_mode.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        mode_bar.addSpacing(12)
        mode_bar.addWidget(self.lb_mode, 1)

        self.btn_disk_use = QPushButton("空间去哪了…")
        self.btn_disk_use.setToolTip("从盘符开始一层层往下钻，看体积到底被哪个文件夹占了\n"
                                     "（只统计、不删任何东西）")
        self.btn_disk_use.clicked.connect(self.open_disk_use)
        mode_bar.addWidget(self.btn_disk_use)

        self.btn_hogs = QPushButton("C 盘空间大头…")
        self.btn_hogs.setToolTip("系统盘最占地方的东西（休眠文件 / 旧系统备份 / 虚拟内存 / 回收站）\n"
                                 "只报告体积和处理方法，不代你执行")
        self.btn_hogs.clicked.connect(self.open_hogs)
        mode_bar.addWidget(self.btn_hogs)

        # 「文件删不掉」是清理场景里最常见的卡点（被占用 / 权限不足），
        # 入口就放在这一行，别塞进二级菜单（3.9.1）
        self.btn_unlock = QPushButton("文件删不掉？")
        self.btn_unlock.setToolTip("查是谁占着这个文件/文件夹，让它松手（不代删任何文件）")
        self.btn_unlock.clicked.connect(self.open_unlock)
        mode_bar.addWidget(self.btn_unlock)
        lay.addLayout(mode_bar)

        bar = QHBoxLayout()
        bar.setSpacing(8)
        bar.addWidget(QLabel("类型"))
        self.cb_kind = QComboBox()
        for k in planclean.KINDS:
            self.cb_kind.addItem(planclean.KIND_LABELS[k], k)
        self.cb_kind.setCurrentIndex(len(planclean.KINDS) - 1)      # 默认「全部」
        self.cb_kind.setMinimumWidth(230)
        self.cb_kind.currentIndexChanged.connect(self._on_kind_changed)
        bar.addWidget(self.cb_kind)

        bar.addWidget(QLabel("体积 ≥"))
        self.sp_min = QDoubleSpinBox()
        self.sp_min.setRange(0, 100000)
        self.sp_min.setDecimals(0)
        self.sp_min.setSuffix(" MB")
        self.sp_min.setValue(10)
        self.sp_min.setFixedWidth(96)
        bar.addWidget(self.sp_min)

        self.lb_old = QLabel("闲置 ≥")
        bar.addWidget(self.lb_old)
        self.sp_old = QSpinBox()
        self.sp_old.setRange(0, 3650)
        self.sp_old.setSuffix(" 天")
        self.sp_old.setValue(0)
        self.sp_old.setFixedWidth(84)
        bar.addWidget(self.sp_old)

        self.chk_repeat = QCheckBox("含需重新下载的缓存")
        bar.addWidget(self.chk_repeat)
        self.chk_state = QCheckBox("含工具状态目录")
        bar.addWidget(self.chk_state)

        self.btn_scan = QPushButton("扫描")
        self.btn_scan.setObjectName("Primary")
        self.btn_scan.clicked.connect(self.scan)
        bar.addWidget(self.btn_scan)
        bar.addStretch(1)
        lay.addLayout(bar)

        bar2 = QHBoxLayout()
        bar2.setSpacing(8)
        self.lb_state = QLabel("点「扫描」列出可清理目录；全部移到回收站，可撤销")
        self.lb_state.setObjectName("Muted")
        # 文案可能很长（瘦身候选会带「另有 N 个零散小文件」），不限最小宽度才能被压缩，
        # 否则 QLabel 按全文撑开、把右边的按钮顶走，长文字还会溢到按钮区。
        self.lb_state.setMinimumWidth(1)
        self.lb_state.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        bar2.addWidget(self.lb_state, 1)
        self.btn_all = QPushButton("全选")
        self.btn_all.clicked.connect(lambda: self.table.set_all_checked(True))
        self.btn_none = QPushButton("全不选")
        self.btn_none.clicked.connect(lambda: self.table.set_all_checked(False))
        self.btn_ghosts = QPushButton("注册表残留（0）")
        self.btn_ghosts.setToolTip("登记了安装目录但目录已不存在的「已安装程序」条目，可备份后清除")
        self.btn_ghosts.setEnabled(False)
        self.btn_ghosts.clicked.connect(self.open_ghosts)
        bar2.addWidget(self.btn_all)
        bar2.addWidget(self.btn_none)
        bar2.addWidget(self.btn_ghosts)
        self.btn_clean = QPushButton("移到回收站")
        self.btn_clean.setObjectName("Danger")
        self.btn_clean.setEnabled(False)
        self.btn_clean.clicked.connect(lambda: self.run_clean())
        bar2.addWidget(self.btn_clean)
        lay.addLayout(bar2)

        self.table = CheckTable([
            ("体积", 100, "r"),
            ("闲置", 80, "r"),
            ("来源", 96, "l"),
            ("路径", -1, "l"),
            ("说明", 0, "l"),
        ])
        self.table.counts_changed.connect(self._on_counts)
        self.table.setToolTip("右键任意一行可直接清除、勾选或打开所在文件夹")
        self.table.extra_actions = [
            ("清除选中项（移到回收站）", self.clean_checked),
            ("清除这一行（移到回收站）", self.clean_current),
            ("-", None),
            ("勾选 / 取消勾选此行", self.toggle_current),
            ("只勾选这一行", self.select_only_current),
            ("打开所在文件夹", self.open_current_dir),
        ]
        lay.addWidget(self.table, 1)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setFixedHeight(4)
        self.progress.hide()
        lay.addWidget(self.progress)

        self._sync_mode()      # 初始停在「常规清理」，说明文字一起对齐

    # ---- 模式 / 扫描 ----
    def _sync_mode(self):
        """按当前「类型」把顶部两个大按钮与说明文字对齐（单一来源：cb_kind）。"""
        slim_mode = self.cb_kind.currentData() in self._SLIM_KINDS
        (self.btn_mode_slim if slim_mode else self.btn_mode_clean).setChecked(True)
        self.lb_mode.setText(
            "找出 C 盘真正占地方的东西，只勾「删了肯定没影响」的几类"
            if slim_mode else
            "清缓存、程序残留、空目录 —— 不动你的文件和程序")

    def use_mode(self, idx):
        """顶部大按钮：0 = 常规清理，1 = 系统盘瘦身。切完立刻扫，一点就到结果。"""
        if self.is_busy():
            # 扫描/清理进行中不切：切了结果会落到另一个模式上，数字就对不上了
            self._sync_mode()
            self.notify.emit("正在忙（扫描或清理中），等这次做完再切换")
            return
        target = "slim" if idx == 1 else "all"
        if self.cb_kind.currentData() != target:
            self.cb_kind.setCurrentIndex(self.cb_kind.findData(target))
        self.scan()                     # 不用再点一次「扫描」

    def enter_slim(self):
        """外部（体检页「去瘦身」）进来时切到瘦身模式并直接开扫。"""
        if self.is_busy():
            self._sync_mode()
            return
        if self.cb_kind.currentData() not in self._SLIM_KINDS:
            self.cb_kind.setCurrentIndex(self.cb_kind.findData("slim"))
        self.scan()

    def _on_kind_changed(self, _idx=0):
        """切到瘦身类型时对齐参数含义 —— 免得界面写「闲置 ≥ 0 天」而实际按 60 天筛。"""
        kind = self.cb_kind.currentData()
        slim_mode = kind in self._SLIM_KINDS
        # 这两个勾选只对「常规清理」有用（瘦身不看它们），留在界面上会让人
        # 以为勾了能改变瘦身范围
        for w in (self.chk_repeat, self.chk_state):
            w.setVisible(not slim_mode)
        if slim_mode:
            if self.sp_old.value() == 0:
                self.sp_old.setValue(int((self.cfg.get("cleanup", {}) or {})
                                         .get("slim_older", 60)))
            if self.sp_min.value() < 10:
                self.sp_min.setValue(10)
            self.lb_state.setText("瘦身模式：断链快捷方式 / 崩溃转储 / Office 残留锁文件"
                                  "已预先勾上；临时文件和旧安装包请自己挑")
        else:
            self.lb_state.setText("点「扫描」列出可清理目录；全部移到回收站，可撤销")
        self._sync_mode()

    def scan(self):
        if self.is_busy():
            return
        from .tasks import CleanScanTask
        pcfg = self.cfg.get("profile", {}) or {}
        opts = {
            "kind": self.cb_kind.currentData(),
            "min_mb": float(self.sp_min.value()),
            "older": int(self.sp_old.value()),
            "active_days": int((self.cfg.get("cleanup", {}) or {}).get("active_days", 45)),
            "cache_repeat": self.chk_repeat.isChecked(),
            "include_state": self.chk_state.isChecked(),
            "profile_budget": pcfg.get("budget", 20),
            "empty_budget": pcfg.get("empty_budget", 6),
            "slim_budget": (self.cfg.get("cleanup", {}) or {}).get("slim_budget", 25),
            "slim_older": (self.cfg.get("cleanup", {}) or {}).get("slim_older", 60),
        }
        self.btn_scan.setEnabled(False)
        self.btn_scan.setText("扫描中…")
        self.progress.show()
        self.lb_state.setText("正在扫描，请稍候…")
        self.table.setRowCount(0)
        # 扫描期间把整窗盖住：不然用户还能去点「移到回收站」「空间大头」或者切模式，
        # 结果落到别的模式上、或者半路被切走，数字就对不上了（3.8.3 反馈）。
        window_busy(self, "正在扫描，请稍候…",
                    "瘦身扫描要翻目录，十几秒是正常的；完成后会自动关掉")
        task = self._hold(CleanScanTask(opts, parent=self))
        task.log.connect(self._on_log)
        task.failed.connect(self._on_scan_fail)
        task.done.connect(self._on_plan)
        task.start()

    def _on_log(self, s):
        self.lb_state.setText(s)
        self.notify.emit(s)

    def _on_scan_fail(self, msg):
        window_busy(self, None)
        self._reset_buttons()
        self.lb_state.setText("扫描失败：" + msg.splitlines()[-1])
        show_error(self, "扫描失败", msg, summary="扫描可清理目录时出错，详见下方调用栈。")

    def _on_run_fail(self, msg):
        # 清理失败不能沿用「扫描失败」的文案，也要把按钮状态恢复，否则页面卡在「正在移到回收站…」
        window_busy(self, None)
        self.progress.hide()
        self._on_counts(len(self.table.checked_payloads()), self.table.rowCount())
        self.lb_state.setText("清理失败：" + msg.splitlines()[-1])
        show_error(self, "清理失败", msg,
                   summary="移到回收站时出错，这些条目可能未被改动；可重新扫描后重试单个条目。")

    def _reset_buttons(self):
        self.progress.hide()
        self.btn_scan.setEnabled(True)
        self.btn_scan.setText("扫描")

    def _on_plan(self, plan):
        window_busy(self, None)          # 先撤遮罩，后面可能有弹窗
        self._plan = plan
        self._ghosts = list(plan.get("ghosts") or [])
        self._reset_buttons()
        self.btn_ghosts.setText(f"注册表残留（{len(self._ghosts)}）")
        self.btn_ghosts.setEnabled(bool(self._ghosts))
        cands = plan["cands"]
        profile_paths = plan["profile_paths"]
        has_slim = any(c.get("origin") == "slim" for c in cands)
        rows, payloads, styles = [], [], {}
        for c in cands:
            src = planclean.source_of(c, profile_paths)
            size_txt = fb(c["size"]) if c["size"] else "0B"
            rows.append([
                (size_txt, c["size"]),
                (f"{c.get('idle_days', 0)} 天", c.get("idle_days", 0)),
                src,
                c["path"],
                c.get("note") or "",
            ])
            payloads.append(c)
        self.table.set_check_rows(rows, payloads, checked=not has_slim)
        if has_slim:
            # 瘦身候选默认不全勾：临时文件 + 旧安装包一次能到几十 GB，
            # 全选后一键删太容易出事。只把「删了肯定没影响」的几类预先勾上。
            for r, c in enumerate(cands):
                if c.get("origin") == "slim" and c.get("kind") in self._SLIM_SAFE:
                    self.table.set_row_checked(r, True)
        # 「文档 / 桌面 / 下载」里的空文件夹默认不勾：里面确实一个文件都没有，
        # 但文件夹本身可能是用户有意留着的位置（比如 Office 模板目录），由用户自己决定。
        for r, c in enumerate(cands):
            if c.get("default_check") is False:
                self.table.set_row_checked(r, False)
        total = sum(c["size"] for c in cands)
        note = (f"候选 {len(cands)} 项，合计 {fb(total)}"
                f"　·　扫描用时 {plan.get('elapsed_total', 0)}s")
        # 顶部这一行留白有限，长句会被裁掉甚至溢到按钮上（实测过），
        # 所以副信息走悬浮提示，状态栏只留数字。
        detail = []
        slim_res = plan.get("slim") or {}
        if slim_res.get("small_files"):
            detail.append(f"另有 {slim_res['small_files']} 个零散小文件"
                          f"（{fb(slim_res['small_bytes'])}）因体积过小未列出，"
                          f"把「体积 ≥」调小可以看到")
        if has_slim:
            detail.append("断链快捷方式 / 崩溃转储 / Office 残留锁文件默认已勾选；"
                          "临时文件可能正被程序占用、旧安装包删了要重下，所以留给你自己挑")
        empties = [c for c in cands if c.get("category") == "emptyuser"]
        if empties:
            detail.append(f"其中 {len(empties)} 个是你「文档 / 桌面 / 下载」里的空文件夹"
                          "（0 字节，一个文件都没有），默认没勾 —— 想删自己勾上")
        if plan.get("ghosts"):
            detail.append(f"另有 {len(plan['ghosts'])} 条注册表幽灵项"
                          f"（点「注册表残留」可备份后清除）")
            note += f"　·　注册表残留 {len(plan['ghosts'])}"
        self.lb_state.setText(note)
        self.lb_state.setToolTip("\n".join(detail) or note)
        self.notify.emit(note + ("　·　" + detail[0] if detail else ""))
        if not cands:
            QMessageBox.information(
                self, "没有候选",
                "未发现符合条件的条目。可以降低「体积 ≥」阈值，或把「闲置 ≥」设为 0。")

    def open_unlock(self):
        """「文件删不掉？」：查占用 / 权限，让占用方松手（不代删任何文件）。"""
        dlg = UnlockDialog(self)
        dlg.notify.connect(self.notify)
        dlg.exec()

    def open_disk_use(self, path=None):
        """「空间去哪了」：目录体积逐层下钻（只统计，不删）。"""
        dlg = DiskUseDialog(self, path=path)
        dlg.notify.connect(self.notify)
        dlg.exec()

    def open_hogs(self):
        """系统盘空间大头（只报告）。每次现算，不缓存 —— 回收站大小随时在变。"""
        try:
            hogs = slim.space_hogs()
        except Exception as exc:
            show_error(self, "读取失败", f"{type(exc).__name__}: {exc}",
                       summary="统计系统盘空间占用时出错。")
            return
        if not hogs:
            QMessageBox.information(self, "没什么大头",
                                    "没找到明显占地方的系统文件。")
            return
        SpaceHogDialog(hogs, self).exec()

    def open_ghosts(self):
        """打开注册表残留清单（右键可单条删除）。"""
        if not self._ghosts:
            QMessageBox.information(self, "没有残留",
                                    "这次扫描没有发现「登记了安装目录但目录已不存在」的条目。")
            return
        dlg = GhostDialog(self._ghosts, self)
        dlg.changed.connect(self.scan)          # 删掉过就重扫，数字要对得上
        dlg.exec()

    def _on_counts(self, n, total):
        self.btn_clean.setEnabled(n > 0)
        size = 0
        if self._plan:
            picked = {c["path"] for c in self.table.checked_payloads()}
            size = sum(c["size"] for c in self._plan["cands"] if c["path"] in picked)
        self.btn_clean.setText(f"移到回收站（{n} 项" + (f" / {fb(size)}" if n else "") + "）")

    # ---- 右键动作 ----
    def _ctx_payload(self):
        """右键那一行对应的候选目录（可能为 None）。"""
        row = getattr(self.table, "context_row", -1)
        if row < 0:
            return None
        return self.table.payload_at(row)

    def _need_payload(self):
        c = self._ctx_payload()
        if c is None:
            QMessageBox.information(self, "先选一行", "请在一行候选目录上右键。")
        return c

    def clean_checked(self):
        self.run_clean()

    def clean_current(self):
        c = self._need_payload()
        if c:
            self.run_clean([c])

    def toggle_current(self):
        row = getattr(self.table, "context_row", -1)
        if row < 0:
            return
        it = self.table.item(row, 0)
        if it is None:
            return
        self.table.set_row_checked(row, it.checkState() != Qt.Checked)

    def select_only_current(self):
        row = getattr(self.table, "context_row", -1)
        if row < 0:
            return
        self.table.set_all_checked(False)
        self.table.set_row_checked(row, True)

    def open_current_dir(self):
        c = self._need_payload()
        if not c:
            return
        path = c["path"]
        # 瘦身候选可能是文件（.lnk/.dmp/.msi），统一打开它所在的文件夹
        target = path if os.path.isdir(path) else os.path.dirname(path)
        if not os.path.exists(target):
            QMessageBox.information(self, "位置已经不在了",
                                    f"{path}\n\n可能已被清理或程序自己删掉了，重新扫描一次即可。")
            return
        try:
            os.startfile(target)
        except OSError as exc:
            QMessageBox.warning(self, "打不开", f"{target}\n\n{exc}")

    # ---- 执行 ----
    def run_clean(self, picked=None):
        if self.is_busy():
            self.notify.emit("正在忙（扫描或清理进行中），等这次做完再操作")
            return
        picked = list(picked) if picked else self.table.checked_payloads()
        if not picked:
            return
        total = sum(c["size"] for c in picked)
        listing = "\n".join("· " + c["path"] for c in picked[:12])
        if len(picked) > 12:
            listing += f"\n… 另有 {len(picked) - 12} 个"
        warning = QMessageBox()
        warning.setIcon(QMessageBox.Warning)
        warning.setWindowTitle("确认清理")
        unit = "项" if any(c.get("origin") == "slim" for c in picked) else "个目录"
        head = (f"将把这 1 {unit}（约 {fb(total)}）移到回收站："
                if len(picked) == 1 else
                f"将把 {len(picked)} {unit}（约 {fb(total)}）移到回收站：")
        tail = "这些内容会先进入回收站，确认无影响后再清空回收站即可撤销。"
        if any(c.get("kind") == "oldinstaller" for c in picked):
            tail += "\n其中包含旧安装包 / 压缩包 —— 删掉以后要用得重新下载。"
        if any(c.get("kind") == "temp" for c in picked):
            tail += "\n其中包含临时文件 —— 程序正在用的那几个会删不掉，跳过即可。"
        warning.setText(f"{head}\n\n{listing}\n\n{tail}")
        warning.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        warning.setDefaultButton(QMessageBox.No)
        warning.button(QMessageBox.Yes).setText("移到回收站")
        warning.button(QMessageBox.No).setText("取消")
        if warning.exec() != QMessageBox.Yes:
            return

        from .tasks import CleanRunTask
        # 瘦身候选含文件（.lnk/.dmp/.msi），必须走 slim 自己的删除通道；
        # leftover.trash_paths 只认目录，混在一起会把它们全判成「不是目录」。
        slim_paths = [c["path"] for c in picked if c.get("origin") == "slim"]
        dir_paths = [c["path"] for c in picked if c.get("origin") != "slim"]
        self.btn_clean.setEnabled(False)
        self.progress.show()
        self.lb_state.setText("正在移到回收站…")
        window_busy(self, "正在移到回收站…",
                    "逐条处理，全部进回收站可以撤销；失败的项目会单独说明原因")
        task = self._hold(CleanRunTask(
            dir_paths,
            kind=self.cb_kind.currentData(),
            allow_exact=(self._plan or {}).get("profile_paths") or set(),
            allow_system_names=self.chk_state.isChecked(),
            slim_paths=slim_paths,
            parent=self))
        task.failed.connect(self._on_run_fail)
        task.done.connect(self._on_done)
        task.start()

    def _on_done(self, res):
        window_busy(self, None)          # 先撤遮罩，再弹结果
        self.progress.hide()
        ok, bad = res["ok"], res["bad"]
        freed = 0
        if self._plan:
            sizes = {c["path"]: c["size"] for c in self._plan["cands"]}
            freed = sum(sizes.get(p, 0) for p, _n in ok)
        lines = [f"成功 {len(ok)} 个，约 {fb(freed)}", f"失败 {len(bad)} 个"]
        if bad:
            # 47 条路径平铺出来没人看得下去，按「原因」分组：一眼看清是权限、
            # 占用还是别的，再决定下一步；完整清单在台账 json 里。
            groups = {}
            for p, why in bad:
                groups.setdefault(why, []).append(p)
            lines.append("")
            for why, ps in sorted(groups.items(), key=lambda kv: -len(kv[1])):
                lines.append(f"{why} —— {len(ps)} 项")
                lines += [f"    {p}" for p in ps[:3]]
                if len(ps) > 3:
                    lines.append(f"    …另有 {len(ps) - 3} 项")
                lines.append("")
        if res.get("ledger"):
            lines.append("台账（每一项成功/失败都在里面）：" + res["ledger"])
            self.notify.emit("清理台账已写入 " + res["ledger"])
        self.notify.emit(f"清理完成：成功 {len(ok)} 个 / 失败 {len(bad)} 个，释放 {fb(freed)}")
        QMessageBox.information(self, "清理结果", "\n".join(lines).rstrip())
        self.scan()


# ══════════════════════════════ 凭据 ══════════════════════════════

# chrome:// 和 edge:// 不能交给默认浏览器处理，只能定位到 exe 再用参数打开
_BROWSER_EXES = {
    "chrome": (r"%ProgramFiles%\Google\Chrome\Application\chrome.exe",
               r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe",
               r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
    "edge": (r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe",
             r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe",
             r"%LocalAppData%\Microsoft\Edge\Application\msedge.exe"),
}
_BROWSER_URLS = {
    "chrome": "chrome://password-manager/settings",
    "edge": "edge://settings/passwords",
}


def open_browser_password_page(kind):
    """打开浏览器新窗口，并把密码管理页地址放进剪贴板。

    为什么做不到一键直达：Chromium 出于安全策略会**丢弃命令行传入的
    chrome:// / edge:// 地址**（实测 Chrome 与 Edge 都只得到一个空白新标签页，
    `--new-window`、`--app=` 同样绕不过）。所以在地址栏粘一次这一步绕不开，
    这里能做的是把地址提前复制好、把浏览器窗口开出来，用户只需 Ctrl+V 回车。

    返回 dict：exe / url / copied / launched。
    """
    exe = None
    for raw in _BROWSER_EXES.get(kind, ()):
        path = os.path.expandvars(raw)
        if os.path.isfile(path):
            exe = path
            break

    url = _BROWSER_URLS.get(kind, "")
    copied = False
    if url:
        try:
            QGuiApplication.clipboard().setText(url)
            copied = True
        except Exception:
            copied = False

    launched = False
    if exe:
        try:
            subprocess.Popen([exe, "--new-window"], **no_window_kwargs())
            launched = True
        except OSError:
            launched = False
    return {"exe": exe, "url": url, "copied": copied, "launched": launched}


GUIDE_HTML = """
<style>
  h3 { margin: 0 0 4px 0; font-size: 14px; }
  p, li { font-size: 13px; line-height: 1.65; }
  .k { background: #eef3fb; padding: 1px 5px; border-radius: 4px;
        font-family: Consolas, monospace; font-size: 12px; }
  .warn { color: #b45309; font-size: 12px; }
  .muted { color: #6b7280; font-size: 12px; }
  .step { font-weight: bold; }
</style>

<h3>① 在本机浏览器里导出</h3>
<p><b>为什么要走两步</b>：Chrome / Edge 会丢掉命令行传进去的
<span class="k">chrome://</span> 地址（只开一个空白页），所以这里帮你把地址复制好，
<b>在浏览器的地址栏粘一下</b>这一步省不掉：</p>
<ol>
  <li>点下面「打开 Chrome + 复制地址」——浏览器弹出一个新窗口，地址已在剪贴板里；</li>
  <li>在那个新窗口的<b>地址栏按 Ctrl+V，再回车</b>，就进密码页了；</li>
  <li>页面里点 <span class="k">设置 → 导出密码</span> → 输入 Windows 登录密码确认 →
      浏览器会把 <span class="k">passwords.csv</span> 存进「下载」目录。</li>
</ol>

<h3>② 手机上的密码（换新手机想找回旧密码时）</h3>
<ul>
  <li><b>Android / Chrome</b>：手机浏览器打开
      <span class="k">passwords.google.com</span> → 右上头像 →
      <span class="k">导出密码</span>，CSV 会发到该账号的 Gmail，回电脑下载即可。</li>
  <li><b>iPhone</b>：<span class="k">设置 → 密码</span> 需要 Face ID 才能看，
      但 iOS 不提供 CSV 导出；先在 Mac 的「密码」App 里导出，或
      电脑端登录同一 iCloud 账号后从浏览器侧导出。</li>
  <li><b>QQ / 360 / 夸克</b>：多在 <span class="k">设置 → 密码管理 → 导出</span>，
      部分只给加密包，必须用该浏览器自己的账号口令打开 —— 这种先手工记几条要紧的。</li>
  <li><b>把密码带进新手机</b>：手机端 Chrome 没有 CSV 导入入口。做法是回电脑，
      在 <span class="k">chrome://password-manager/settings</span> 点「导入」选中这个 CSV，
      让它进 Google 账号，新手机登录同账号即自动同步；iPhone 同理走 iCloud 钥匙串。</li>
</ul>

<h3>③ 回到本工具导入并解密</h3>
<p>点「选择 CSV 并导入」→ 解析出站点 / 账号 / 密码 → 在<span class="k">本次运行内</span>
补齐浏览器 v20 加密的条目。<b>密码不落盘</b>：3.7.2 起取消了明文缓存，关掉工具就没了。
浏览器库里 v20 加密的条目会立刻用这份明文补齐 —— 这就是「解密」：
v20 是 Chromium 用当前 Windows 账号 DPAPI 加密的凭据，只有本机这个账号解得开，
导出的 CSV 只是把手机 / 其他设备上的账号也一起带进来。</p>

<p class="warn">⚠️ 导出的 CSV 是明文。导入完就删掉（或放进 BitLocker 加密盘）；
本机若装了数据管控（DLP / 水印 / 屏幕审计），这些内容可能被记录。</p>
"""


class ExportGuideDialog(QDialog):
    """「从浏览器导出密码 → 导回来解密」的分步引导。"""

    import_csv = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("导出浏览器密码并导回本工具")
        self.resize(760, 640)

        lay = QVBoxLayout(self)
        lay.setSpacing(10)

        # 常驻提示条：点完按钮这里会变成「已复制，去地址栏 Ctrl+V 回车」
        self.hint = QLabel()
        self.hint.setWordWrap(True)
        self.hint.setTextFormat(Qt.RichText)
        lay.addWidget(self.hint)
        self._show_hint("muted",
                        "浏览器不允许命令行直接跳到它的内部页（chrome:// / edge:// 会被丢弃，"
                        "只开空白页）。所以按钮做两件事：开一个新窗口 + 把地址复制到剪贴板，"
                        "你在新窗口地址栏 <b>Ctrl+V 再回车</b> 就到位。")

        body = QTextBrowser()
        body.setOpenExternalLinks(True)
        body.setHtml(GUIDE_HTML)
        lay.addWidget(body, 1)

        row = QHBoxLayout()
        row.setSpacing(8)
        b_chrome = QPushButton("打开 Chrome + 复制地址")
        b_chrome.clicked.connect(lambda: self._open("chrome"))
        b_edge = QPushButton("打开 Edge + 复制地址")
        b_edge.clicked.connect(lambda: self._open("edge"))
        b_import = QPushButton("选择 CSV 并导入…")
        b_import.setObjectName("Primary")
        b_import.clicked.connect(self._pick)
        for b in (b_chrome, b_edge, b_import):
            row.addWidget(b)
        row.addStretch(1)
        b_close = QPushButton("关闭")
        b_close.clicked.connect(self.accept)
        row.addWidget(b_close)
        lay.addLayout(row)

    def _show_hint(self, kind, text):
        color = {"ok": C["accent"], "bad": SEV["error"][0]}.get(kind, C["muted"])
        self.hint.setStyleSheet(
            f"color:{color}; background:{C['panel']}; border:1px solid {C['border']};"
            f" border-radius:6px; padding:8px 10px;")
        self.hint.setText(text)

    def _open(self, kind):
        name = "Chrome" if kind == "chrome" else "Edge"
        res = open_browser_password_page(kind)
        url = res.get("url") or ""
        kurl = f"<span style='font-family:Consolas'>{url}</span>"

        if res.get("launched"):
            self._show_hint(
                "ok",
                f"已在<b>{name}</b>里开出一个新窗口，地址已复制到剪贴板。<br>"
                f"现在切到那个窗口，在<b>地址栏按 Ctrl+V，再回车</b> —— 就进密码页了。<br>"
                f"<span style='color:{C['muted']}'>地址：{kurl}</span>")
            self.setWindowTitle(f"导出浏览器密码（{name} 已打开，地址已复制）")
            return

        if res.get("copied"):
            self._show_hint(
                "ok",
                f"本机没找到 {name} 的可执行文件，但地址已经复制好了：{kurl}"
                f"<br>在任意浏览器地址栏 <b>Ctrl+V 再回车</b> 即可。")
            self.setWindowTitle("导出浏览器密码（地址已复制）")
            return

        self._show_hint(
            "bad",
            f"没能自动打开 {name}。手动打开浏览器，在地址栏输入：{kurl}")

    def _pick(self):
        self.accept()
        self.import_csv.emit()


class CredsPage(Page):
    """系统凭据 / 浏览器已保存登录 / FTP 与网络位置。

    明文直接显示（打码开关已去掉）：本页是给本机主自己看的，口令原文才有用；
    需要对外发报告时走命令行 `--mask`。
    """

    def __init__(self, cfg, parent=None):
        super().__init__(cfg, parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)

        bar = QHBoxLayout()
        bar.setSpacing(8)
        self.lb = QLabel("明文显示（本机自查用）；要外发就把屏幕遮一下，或改用命令行 --mask")
        self.lb.setObjectName("Muted")
        bar.addWidget(self.lb, 1)
        self.btn_guide = QPushButton("导出密码步骤…")
        self.btn_guide.setToolTip("从浏览器/手机导出密码 → 导回本工具解密")
        self.btn_guide.clicked.connect(self.show_export_guide)
        bar.addWidget(self.btn_guide)
        self.btn_import = QPushButton("导入 CSV…")
        self.btn_import.clicked.connect(self.import_csv)
        bar.addWidget(self.btn_import)
        self.btn_refresh = QPushButton("刷新")
        self.btn_refresh.clicked.connect(self.reload)
        bar.addWidget(self.btn_refresh)
        lay.addLayout(bar)

        self.tabs = QTabWidget()
        lay.addWidget(self.tabs, 1)

        self.t_sys = DataTable([("目标", 300, "l"), ("用户名", 160, "l"),
                                ("密码", -1, "l"), ("类型", 178, "l"),
                                ("最后写入", 140, "l"), ("备注", 0, "l")])
        self.t_browser = DataTable([("浏览器", 100, "l"), ("配置", 90, "l"),
                                    ("站点", -1, "l"), ("用户名", 170, "l"),
                                    ("密码", 230, "l"), ("状态", 110, "l")])
        self.t_ftp = DataTable([("客户端", 110, "l"), ("类型", 110, "l"),
                                ("主机 / 站点", -1, "l"), ("端口", 64, "r"),
                                ("用户名", 150, "l"), ("密码", 200, "l"),
                                ("说明", 0, "l")])
        self.tabs.addTab(self.t_sys, "系统凭据")
        self.tabs.addTab(self.t_browser, "浏览器登录")
        self.tabs.addTab(self.t_ftp, "FTP / 网络位置")
        self.tabs.currentChanged.connect(self._ensure)

        # 右键是主操作入口：系统凭据可删（带备份+复核）；浏览器 / FTP 只给指引
        self.t_sys.extra_actions = [
            ("删除这条凭据…", self.delete_system_cred),
            ("复制目标名", self.copy_target),
            ("-", None),
            ("复制这一行", self.copy_row),
        ]
        self.t_browser.extra_actions = [
            ("复制站点地址", self.copy_origin),
            ("到浏览器里删（复制步骤）", self.copy_browser_how),
        ]
        self.t_ftp.extra_actions = [
            ("复制主机 / 用户名", self.copy_row),
            ("到客户端里删（说明）", self.copy_ftp_how),
        ]
        self._sys_rows = []
        self._browser_rows = []
        self._ftp_rows = []
        self._pending_note = ""

    def _ensure(self, _idx=None):
        if not getattr(self, "_loaded", False):
            self.reload()

    def show_export_guide(self):
        """分步引导：在浏览器/手机导出密码，再导回这里解密。"""
        dlg = ExportGuideDialog(self)
        dlg.import_csv.connect(self.import_csv)
        dlg.exec()

    def reload(self):
        if self.is_busy():
            return
        from .tasks import CredsTask
        self._loaded = True
        self.btn_refresh.setEnabled(False)
        self.lb.setText("正在读取凭据（系统 / 浏览器 / 网络位置）…")
        task = self._hold(CredsTask("all", reveal=True, parent=self))
        task.failed.connect(self._on_fail)
        task.done.connect(self._on_all)
        task.start()

    def _on_fail(self, msg):
        self.btn_refresh.setEnabled(True)
        self.lb.setText("读取失败：" + msg.splitlines()[-1])

    def _on_all(self, payload):
        self.btn_refresh.setEnabled(True)
        for e in payload.get("errors") or []:
            self.notify.emit(f"[凭据] {e}")
        self._fill("system", payload.get("system") or [])
        self._fill("browser", payload.get("browser") or [])
        self._fill("ftp", payload.get("ftp") or [])
        summary = (f"系统凭据 {self.t_sys.rowCount()} 条　·　"
                   f"浏览器登录 {self.t_browser.rowCount()} 条　·　"
                   f"FTP / 网络位置 {self.t_ftp.rowCount()} 条　·　明文显示")
        # 删完会立刻 reload，reload 会先把状态栏改成「正在读取…」，
        # 所以删除结果要挂在 _pending_note 上，等这轮读完再拼回去，
        # 否则用户根本看不到「已删除 + 备份路径」。
        if self._pending_note:
            summary = f"{self._pending_note}　·　{summary}"
            self._pending_note = ""
        self.lb.setText(summary)

    def _fill(self, kind, rows):
        if kind == "system":
            self._sys_rows = list(rows)
            out, styles = [], {}
            for i, r in enumerate(rows):
                out.append([r.get("target", ""), r.get("user") or "—",
                            r.get("password") or "—", r.get("type_name", ""),
                            r.get("last", ""), r.get("comment") or ""])
                note = r.get("pw_note") or ""
                if note:
                    styles[(i, 5)] = {"tip": note}
                if not r.get("password"):
                    styles[(i, 2)] = {"fg": C["faint"]}
            self.t_sys.set_rows(out, styles)
            self.tabs.setTabText(0, f"系统凭据（{len(rows)}）")
        elif kind == "browser":
            self._browser_rows = list(rows)
            out, styles = [], {}
            for i, r in enumerate(rows):
                pw = r.get("password") or ""
                state = {"plain": "明文", "v20": "v20 加密",
                         "masked": "已打码", "fail": "解密失败"}.get(
                             r.get("pw_state", ""), r.get("pw_state", ""))
                out.append([r.get("browser", ""), r.get("profile", ""),
                            r.get("origin", ""), r.get("user") or "—",
                            pw or "—", state])
                if not pw:
                    styles[(i, 4)] = {"fg": C["faint"]}
                    styles[(i, 5)] = {"fg": SEV["warn"][0], "tip": r.get("pw_note") or ""}
                elif r.get("pw_note"):
                    styles[(i, 5)] = {"tip": r["pw_note"]}
            self.t_browser.set_rows(out, styles)
            self.tabs.setTabText(1, f"浏览器登录（{len(rows)}）")
        else:
            self._ftp_rows = list(rows)
            out, styles = [], {}
            for i, r in enumerate(rows):
                kind_desc = r.get("kind_desc") or r.get("protocol", "")
                out.append([r.get("client", ""), kind_desc, r.get("host", ""),
                            str(r.get("port", "—")), r.get("user") or "—",
                            r.get("password") or "—", r.get("pw_note") or ""])
                if not r.get("password"):
                    styles[(i, 5)] = {"fg": C["faint"]}
                if r.get("detail"):
                    styles[(i, 2)] = {"tip": r["detail"]}
            self.t_ftp.set_rows(out, styles)
            self.tabs.setTabText(2, f"FTP / 网络位置（{len(rows)}）")

    # ---- 右键动作（凭据维护） ----
    @staticmethod
    def _ctx(table, rows):
        r = getattr(table, "context_row", -1)
        if r is None or r < 0 or r >= len(rows):
            return None
        return rows[r]

    def copy_target(self):
        it = self._ctx(self.t_sys, self._sys_rows)
        if it:
            QGuiApplication.clipboard().setText(it.get("target", ""))
            self.notify.emit("已复制目标名（注意剪贴板可能被 DLP 审计）")

    def copy_origin(self):
        it = self._ctx(self.t_browser, self._browser_rows)
        if it:
            QGuiApplication.clipboard().setText(it.get("origin", ""))
            self.notify.emit("已复制站点地址")

    def copy_row(self):
        for table, rows in ((self.t_sys, self._sys_rows),
                            (self.t_browser, self._browser_rows),
                            (self.t_ftp, self._ftp_rows)):
            it = self._ctx(table, rows)
            if it:
                txt = "\t".join(str(v) for v in (
                    it.get("target") or it.get("origin") or it.get("host") or "",
                    it.get("user") or "", it.get("password") or ""))
                QGuiApplication.clipboard().setText(txt)
                self.notify.emit("这一行已复制（含明文密码，别外发）")
                return

    def copy_browser_how(self):
        QGuiApplication.clipboard().setText(
            "浏览器保存的密码不在系统凭据里，本工具不直接改浏览器密码库"
            "（改坏了整库打不开）。\n"
            "在浏览器里删：设置 → 自动填充 → 密码管理器 → 搜索站点 → 删除。")
        self.notify.emit("已复制「到浏览器里删」的步骤")

    def copy_ftp_how(self):
        QGuiApplication.clipboard().setText(
            "FTP 客户端（FileZilla / WinSCP / Total Commander）的站点密码存在各自"
            "配置文件里，请在客户端里删站点。\n"
            "FileZilla：文件 → 站点管理器 → 选中站点 → 删除。")
        self.notify.emit("已复制「到客户端里删」的说明")

    def delete_system_cred(self):
        """删除一条系统凭据：白名单 + 确认 + 删前复核 + 先备份。

        红线（项目约定）：任何删除都要可回滚。Windows 凭据的密码读不出来备份，
        所以这里只备份「删了什么」（目标/用户名/类型），并在弹窗里说清楚。
        """
        from .. import credentials
        it = self._ctx(self.t_sys, self._sys_rows)
        if not it:
            self.notify.emit("凭据：先在一行上右键")
            return
        target = (it.get("target") or "").strip()
        if not target:
            self.notify.emit("凭据：这一条没有目标名，不能删")
            return

        box = QMessageBox(self)
        box.setIcon(QMessageBox.Warning)
        box.setWindowTitle("删除这条凭据？")
        box.setText(f"目标：{target}\n用户名：{it.get('user') or '—'}\n"
                    f"类型：{it.get('type_name') or '—'}")
        box.setInformativeText(
            "删掉后这条登录信息就没了：密码既无法备份也无法还原。\n"
            "工具会先记一份「删了什么」的备份文件，方便以后重建。\n\n确认删除？")
        box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        box.setDefaultButton(QMessageBox.No)
        box.button(QMessageBox.Yes).setText("删除")
        box.button(QMessageBox.No).setText("取消")
        if box.exec() != QMessageBox.Yes:
            return

        try:
            now = credentials.cred_enum(reveal=False)
        except Exception as exc:
            show_error(self, "读取凭据失败，已中止", f"{type(exc).__name__}: {exc}",
                       "无法复核这条凭据是否还在，所以没有删。")
            return
        hit = [c for c in now if (c.get("target") or "").lower() == target.lower()]
        if not hit:
            self.notify.emit("凭据：这条已经不在了，已刷新列表")
            self.reload()
            return

        path, err = credentials.cred_backup(hit)
        if not path:
            show_error(self, "备份失败，已取消删除", err,
                       "没有备份就不删 —— 这是硬规矩。")
            return

        ok, err2 = credentials.cred_delete(hit[0]["target"])
        if ok:
            self.notify.emit(f"凭据：已删除 {target}")
            self._pending_note = f"已删除 1 条系统凭据（{target}）；备份 {path}"
            self.lb.setText(self._pending_note)
        else:
            show_error(self, "删除失败", err2,
                       "多半是权限或策略限制（公司管控机可能禁止改系统凭据）。")
        self.reload()

    def import_csv(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "选择浏览器导出的密码 CSV", os.path.expanduser("~/Downloads"),
            "CSV 文件 (*.csv)")
        if not path:
            return
        from .tasks import ImportCsvTask
        # 3.7.2 起不再把明文密码写进本机缓存（安全考虑）：解析结果只在本次运行内用于
        # 补齐浏览器 v20 条目，关掉工具就没了。要用持久缓存请走命令行 --save。
        task = self._hold(ImportCsvTask(path, save=False, parent=self))
        task.done.connect(self._on_import)
        task.failed.connect(lambda m: QMessageBox.critical(self, "导入失败", m))
        task.start()

    def _on_import(self, res):
        n = len(res.get("rows") or [])
        msg = (f"已解析 {n} 条密码，本次运行内用于补齐浏览器 v20 条目。\n\n"
               "· 密码不落盘：关掉工具就没了（3.7.2 起取消明文缓存）\n"
               "· 导出的 CSV 本身是明文文件，导入完请删掉\n"
               "· 需要持久补齐请用命令行：health_assistant.cmd import-passwords CSV --save")
        self.notify.emit(f"导入密码 CSV：{n} 条（未落盘）")
        QMessageBox.information(self, "导入完成", msg)
        self.reload()


# ══════════════════════════════ FTP ══════════════════════════════

class _LocalTable(DataTable):
    """本机文件列表：除了看，还能把资源管理器里的文件/文件夹直接拖进来。

    拖文件夹 = 进入那个文件夹；拖文件 = 切到它所在的目录并选中（再点上传）。
    拖到别的表格上不会有反应 —— 这个行为只属于本机这一栏。
    """

    def __init__(self, columns, on_drop=None, parent=None):
        super().__init__(columns, parent=parent, sortable=False)
        self._on_drop = on_drop
        self.setAcceptDrops(True)
        self.setDragDropMode(QAbstractItemView.DropOnly)
        self.setToolTip("可以直接把资源管理器里的文件夹/文件拖到这里")

    @staticmethod
    def _has_paths(ev):
        md = ev.mimeData()
        return bool(md is not None and md.hasUrls()
                    and any(u.isLocalFile() for u in md.urls()))

    def dragEnterEvent(self, ev):
        if self._has_paths(ev):
            ev.acceptProposedAction()
        else:
            super().dragEnterEvent(ev)

    def dragMoveEvent(self, ev):
        if self._has_paths(ev):
            ev.acceptProposedAction()
        else:
            super().dragMoveEvent(ev)

    def dropEvent(self, ev):
        if not self._has_paths(ev):
            super().dropEvent(ev)
            return
        paths = [u.toLocalFile() for u in ev.mimeData().urls() if u.isLocalFile()]
        ev.acceptProposedAction()
        if paths and self._on_drop is not None:
            self._on_drop(paths)


class SavedFtpDialog(QDialog):
    """从本机已经保存的账号里挑一个来连 FTP。

    来源只有三类（都在这台电脑上，和打开「控制面板 → 凭据管理器」看到的一样）：
    凭据管理器里带 ftp 的、凭据管理器里名字是 IP/域名的、FileZilla/WinSCP 等客户端
    自己存的站点。读不到密码的行会标出来 —— 不假装能用。
    """

    COLS = [("来源", 156, "l"), ("主机", -1, "l"), ("端口", 66, "r"),
            ("用户名", 150, "l"), ("密码", 150, "l")]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("从本机读取已保存的账号")
        self.resize(820, 430)
        self.picked = None
        self._rows = []

        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(8)

        self.lb_head = QLabel("正在读取…")
        self.lb_head.setObjectName("H2")
        lay.addWidget(self.lb_head)

        self.table = DataTable(self.COLS, sortable=False)
        lay.addWidget(self.table, 1)

        self.lb_note = QLabel(
            "密码是这台电脑自己存的（Windows 凭据管理器 / FTP 客户端配置），"
            "本工具只读一次填进输入框，不保存、不写日志、不外发。")
        self.lb_note.setObjectName("Faint")
        self.lb_note.setWordWrap(True)
        lay.addWidget(self.lb_note)

        row = QHBoxLayout()
        row.setSpacing(8)
        self.lb_scan = QLabel("")
        self.lb_scan.setObjectName("Muted")
        self.lb_scan.setWordWrap(True)
        row.addWidget(self.lb_scan, 1)
        self.btn_rescan = QPushButton("重新扫描")
        self.btn_rescan.clicked.connect(self.scan)
        row.addWidget(self.btn_rescan)
        self.btn_use = QPushButton("用这个账号连接")
        self.btn_use.setObjectName("Primary")
        self.btn_use.clicked.connect(self._accept)
        row.addWidget(self.btn_use)
        self.btn_cancel = QPushButton("关闭")
        self.btn_cancel.clicked.connect(self.reject)
        row.addWidget(self.btn_cancel)
        lay.addLayout(row)

        self.table.cellDoubleClicked.connect(lambda _r, _c: self._accept())
        self.scan()

    def scan(self):
        self.lb_scan.setText("")
        try:
            rows, notes = credentials.ftp_account_candidates(reveal=True)
        except Exception as exc:
            rows, notes = [], [f"{type(exc).__name__}: {exc}"]
        self._rows = rows
        out = []
        for r in rows:
            pw = r["password"] if r["can_use"] else "（没存密码）"
            out.append([r["source"], r["host"], str(r["port"]), r["user"] or "—", pw])
        if not out:
            out = [["没找到能直接用的账号 —— 手动填也行", "", "", "", ""]]
        self.table.set_rows(out)
        n_ok = sum(1 for r in rows if r["can_use"])
        if rows:
            self.lb_head.setText(f"找到 {len(rows)} 个可能的账号，其中 {n_ok} 个带密码")
            self.lb_scan.setText("选中一行（或双击）即可填入并连接。")
        else:
            self.lb_head.setText("没找到本机保存的 FTP 账号")
            self.lb_scan.setText(
                "已查过：Windows 凭据管理器、FileZilla、WinSCP、Total Commander、"
                "浏览器里存的 ftp:// 站点、资源管理器里的网络位置。"
                "如果之前是在别的电脑上登录过，这台就不会有记录。")
        if notes:
            self.lb_scan.setText(self.lb_scan.text() + "　" + "；".join(notes[:2]))
        self.btn_use.setEnabled(bool(self._rows))
        if self._rows:
            self.table.selectRow(0)

    def _accept(self):
        sel = sorted({i.row() for i in self.table.selectedIndexes()})
        if not sel or sel[0] >= len(self._rows):
            self.lb_scan.setText("先在表里选一行")
            return
        self.picked = self._rows[sel[0]]
        self.accept()


class FtpPage(Page):
    """FTP 客户端：左边本机、右边服务器，选中就来回传。

    刻意做到的几件事：
    - **密码只在内存**：不写配置、不写日志、不进报告，工具关掉就没了；
    - **传输全在后台线程**：进度条实时走，随时能点「停止」；
    - **删除必须确认，而且只删选中的那几项**：FTP 上没有回收站，删了就是没了；
    - **连不上说清楚卡在哪**：连完立刻探一次端口，区分「端口不通」和「端口通但不是 FTP」。
    """

    COLS = [("名称", -1, "l"), ("大小", 92, "r"), ("修改时间", 150, "l")]
    HINT = ("FTP 是明文协议：用户名和密码在网络上不加密，只建议连自己人的服务器。"
            "这里的密码不保存到磁盘、不写进日志，关掉工具就没了。")

    def __init__(self, cfg, parent=None):
        super().__init__(cfg, parent)
        self._session = None
        self._local_dir = os.path.expanduser("~")
        self._local_rows = []
        self._remote_rows = []
        self._busy = False
        self._xferring = False
        self._xfer_head = "传输"
        self._t0 = 0.0

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)
        lay.addWidget(self._build_conn())
        lay.addLayout(self._build_ops())
        lay.addWidget(self._build_body(), 1)
        lay.addLayout(self._build_footer())

        self._goto_local(self._local_dir)
        self._show_remote_placeholder()
        self._sync()

    # ───────────── 界面 ─────────────
    def _build_conn(self):
        card = QFrame()
        card.setObjectName("Card")
        v = QVBoxLayout(card)
        v.setContentsMargins(12, 10, 12, 10)
        v.setSpacing(7)

        row = QHBoxLayout()
        row.setSpacing(8)
        self.ed_host = QLineEdit()
        self.ed_host.setPlaceholderText("服务器地址，如 192.168.1.20 或 ftp.example.com")
        self.ed_host.setMinimumWidth(230)
        self.ed_host.returnPressed.connect(self.connect_server)
        row.addWidget(self.ed_host, 2)

        self.sp_port = QSpinBox()
        self.sp_port.setRange(1, 65535)
        self.sp_port.setValue(21)
        self.sp_port.setFixedWidth(86)
        self.sp_port.setToolTip("FTP 默认 21；服务器改了端口就填这里")
        row.addWidget(self.sp_port)

        self.ed_user = QLineEdit()
        self.ed_user.setPlaceholderText("用户名")
        self.ed_user.setMinimumWidth(110)
        self.ed_user.returnPressed.connect(self.connect_server)
        row.addWidget(self.ed_user, 1)

        self.ed_pass = QLineEdit()
        self.ed_pass.setPlaceholderText("密码")
        self.ed_pass.setEchoMode(QLineEdit.Password)
        self.ed_pass.setMinimumWidth(110)
        self.ed_pass.returnPressed.connect(self.connect_server)
        row.addWidget(self.ed_pass, 1)

        self.chk_tls = QCheckBox("加密(FTPS)")
        self.chk_tls.setToolTip("服务器支持 FTPS 才勾；普通 FTP 全程不加密")
        row.addWidget(self.chk_tls)

        self.btn_conn = QPushButton("连接")
        self.btn_conn.setObjectName("Primary")
        self.btn_conn.setMinimumWidth(84)
        self.btn_conn.clicked.connect(self.connect_server)
        row.addWidget(self.btn_conn)

        self.btn_disc = QPushButton("断开")
        self.btn_disc.clicked.connect(self.disconnect_server)
        row.addWidget(self.btn_disc)

        self.badge = Badge("未连接", "info")
        row.addWidget(self.badge)
        v.addLayout(row)

        bottom = QHBoxLayout()
        bottom.setSpacing(8)
        hint = QLabel(self.HINT)
        hint.setObjectName("Faint")
        hint.setWordWrap(True)
        bottom.addWidget(hint, 1)
        # 以前在资源管理器里连过、勾过「保存密码」的，账号就躺在 Windows 凭据管理器里，
        # 不必手打 —— 但必须由用户主动点，不能偷偷读。
        self.btn_saved = QPushButton("读取本机已保存的账号…")
        self.btn_saved.setToolTip("从 Windows 凭据管理器 / FileZilla / WinSCP 等读出 FTP 账号，"
                                  "选中后自动填好并连接")
        self.btn_saved.clicked.connect(self.open_saved_accounts)
        bottom.addWidget(self.btn_saved)
        v.addLayout(bottom)
        return card

    def _build_ops(self):
        bar = QHBoxLayout()
        bar.setSpacing(8)
        self.btn_up = QPushButton("上传到服务器 →")
        self.btn_up.setToolTip("把左边选中的文件/文件夹传到右边这个目录；文件夹会连子目录一起传")
        self.btn_up.clicked.connect(self.upload_selected)
        bar.addWidget(self.btn_up)

        self.btn_dl = QPushButton("← 下载到本机")
        self.btn_dl.setToolTip("把右边选中的文件/文件夹下到左边这个目录")
        self.btn_dl.clicked.connect(self.download_selected)
        bar.addWidget(self.btn_dl)

        line = QFrame()
        line.setFrameShape(QFrame.VLine)
        line.setStyleSheet(f"color:{C['border']};")
        bar.addWidget(line)

        self.btn_mkdir = QPushButton("新建文件夹")
        self.btn_mkdir.clicked.connect(self.mkdir_remote)
        bar.addWidget(self.btn_mkdir)

        self.btn_ren = QPushButton("重命名")
        self.btn_ren.clicked.connect(self.rename_remote)
        bar.addWidget(self.btn_ren)

        self.btn_del = QPushButton("删除")
        self.btn_del.setObjectName("Danger")
        self.btn_del.setToolTip("删除服务器上选中的项 —— FTP 没有回收站，删掉找不回来")
        self.btn_del.clicked.connect(self.delete_remote)
        bar.addWidget(self.btn_del)

        bar.addStretch(1)
        self.lb_pick = QLabel("")
        self.lb_pick.setObjectName("Muted")
        bar.addWidget(self.lb_pick)
        return bar

    def _build_body(self):
        sp = QSplitter(Qt.Horizontal)
        sp.setChildrenCollapsible(False)
        (left, self.tb_local, self.ed_lpath, self.btn_lup,
         self.btn_lref, self.btn_choose) = self._pane("本机", local=True)
        (right, self.tb_remote, self.ed_rpath, self.btn_rup,
         self.btn_rref, _unused) = self._pane("服务器")
        sp.addWidget(left)
        sp.addWidget(right)
        sp.setSizes([700, 700])

        self.btn_choose.clicked.connect(self.choose_local_dir)
        self.btn_lup.clicked.connect(self.local_up)
        self.btn_lref.clicked.connect(lambda: self._goto_local(self._local_dir))
        self.ed_lpath.returnPressed.connect(
            lambda: self._goto_local(self.ed_lpath.text().strip()))

        self.btn_rup.clicked.connect(self.remote_up)
        self.btn_rref.clicked.connect(self.refresh_remote)
        self.ed_rpath.returnPressed.connect(self.goto_remote_path)
        self.ed_rpath.setPlaceholderText("连上服务器后显示远程路径，也可以直接改路径回车跳转")

        self.tb_local.cellDoubleClicked.connect(self._on_local_dbl)
        self.tb_remote.cellDoubleClicked.connect(self._on_remote_dbl)
        self.tb_local.itemSelectionChanged.connect(self._sync)
        self.tb_remote.itemSelectionChanged.connect(self._sync)
        self.tb_local.extra_actions = [
            ("上传到服务器", self.upload_selected),
            ("-", None),
            ("打开这个文件夹", self._open_local_selected),
        ]
        self.tb_remote.extra_actions = [
            ("下载到本机", self.download_selected),
            ("-", None),
            ("新建文件夹", self.mkdir_remote),
            ("重命名", self.rename_remote),
            ("删除（不可恢复）", self.delete_remote),
        ]
        return sp

    def _pane(self, title, local=False):
        box = QWidget()
        v = QVBoxLayout(box)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(6)
        head = QHBoxLayout()
        head.setSpacing(8)
        lb = QLabel(title)
        lb.setObjectName("H2")
        head.addWidget(lb)
        path = QLineEdit()
        path.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Fixed)
        head.addWidget(path, 1)
        choose = None
        if local:
            choose = QPushButton("选择目录…")
            choose.setFixedWidth(92)
            choose.setToolTip("挑一个本机文件夹当上传来源 / 下载目的地"
                              "（也可以直接把文件夹拖到下面的列表里）")
            head.addWidget(choose)
        up = QPushButton("上一级")
        up.setFixedWidth(74)
        ref = QPushButton("刷新")
        ref.setFixedWidth(62)
        head.addWidget(up)
        head.addWidget(ref)
        v.addLayout(head)
        tb = (_LocalTable(self.COLS, self._on_local_drop) if local
              else DataTable(self.COLS, sortable=False))
        v.addWidget(tb, 1)
        return box, tb, path, up, ref, choose

    def _build_footer(self):
        row = QHBoxLayout()
        row.setSpacing(8)
        self.pb = QProgressBar()
        self.pb.setRange(0, 100)
        self.pb.setValue(0)
        self.pb.setTextVisible(False)
        self.pb.setFixedHeight(6)
        row.addWidget(self.pb, 1)
        self.lb_xfer = QLabel("")
        self.lb_xfer.setObjectName("Muted")
        row.addWidget(self.lb_xfer)
        self.btn_stop = QPushButton("停止")
        self.btn_stop.setFixedWidth(64)
        self.btn_stop.clicked.connect(self.stop_xfer)
        row.addWidget(self.btn_stop)
        return row

    # ───────────── 状态 ─────────────
    def _ready(self):
        return bool(self._session and self._session.connected)

    def _idle(self):
        return not self._busy and not self._xferring

    def _picked(self, table, rows):
        sel = sorted({i.row() for i in table.selectedIndexes()})
        return [rows[i] for i in sel if 0 <= i < len(rows)]

    def _sync(self):
        ready = self._ready()
        idle = self._idle()
        nl = len(self._picked(self.tb_local, self._local_rows))
        nr = len(self._picked(self.tb_remote, self._remote_rows))
        self.btn_conn.setEnabled(idle)
        self.btn_disc.setEnabled(ready and idle)
        self.btn_up.setEnabled(ready and idle and nl > 0)
        self.btn_dl.setEnabled(ready and idle and nr > 0)
        self.btn_mkdir.setEnabled(ready and idle)
        self.btn_ren.setEnabled(ready and idle and nr == 1)
        self.btn_del.setEnabled(ready and idle and nr > 0)
        self.btn_stop.setVisible(self._xferring)
        self.btn_stop.setEnabled(self._xferring)
        parts = []
        if nl:
            parts.append(f"本机选中 {nl} 项")
        if nr:
            parts.append(f"服务器选中 {nr} 项")
        self.lb_pick.setText("　·　".join(parts))

    @staticmethod
    def _sorted(rows):
        return sorted(rows, key=lambda r: (not r.get("is_dir"), str(r.get("name", "")).casefold()))

    # ───────────── 本机一侧 ─────────────
    def _goto_local(self, path):
        path = os.path.abspath(os.path.expandvars(os.path.expanduser(str(path or ""))))
        if not os.path.isdir(path):
            self.notify.emit(f"本机没有这个目录：{path}")
            return
        try:
            rows = []
            with os.scandir(path) as it:
                for e in it:
                    try:
                        rows.append({
                            "name": e.name, "path": e.path,
                            "is_dir": e.is_dir(follow_symlinks=False),
                            "size": e.stat(follow_symlinks=False).st_size,
                            "mtime": e.stat(follow_symlinks=False).st_mtime,
                        })
                    except OSError:
                        continue
        except OSError as exc:
            self.notify.emit(f"读不了这个目录：{exc}")
            return
        self._local_dir = path
        self.ed_lpath.setText(path)
        self.ed_lpath.setCursorPosition(0)      # 长路径从盘符开始显示，别只露出尾巴
        self.ed_lpath.setToolTip(path)
        self._local_rows = self._sorted(rows)
        self._fill(self.tb_local, self._local_rows)
        self._sync()

    def _fill(self, table, rows):
        out, styles = [], {}
        for i, r in enumerate(rows):
            ts = r.get("mtime") or 0
            out.append([
                r["name"],
                "" if r["is_dir"] else fb(r.get("size") or 0),
                time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "—",
            ])
            if r["is_dir"]:
                styles[(i, 0)] = {"bold": True}
        table.set_rows(out, styles)

    def local_up(self):
        parent = os.path.dirname(self._local_dir.rstrip("\\/"))
        if parent and os.path.isdir(parent):
            self._goto_local(parent)
        else:
            self._goto_local(self._local_dir)      # 到盘根了，刷一下

    def choose_local_dir(self):
        """挑一个本机文件夹 —— 它同时是「上传来源」和「下载目的地」。"""
        start = self._local_dir if os.path.isdir(self._local_dir) else os.path.expanduser("~")
        path = QFileDialog.getExistingDirectory(
            self, "选择本机文件夹（上传从这里挑，下载存到这里）", start)
        if path:
            self._goto_local(path)
            self.notify.emit(f"本机目录已切到 {path}")

    def _on_local_drop(self, paths):
        """从资源管理器拖进来的东西：文件夹就进去，文件就选中。"""
        dirs = [p for p in paths if os.path.isdir(p)]
        files = [p for p in paths if os.path.isfile(p)]
        if dirs and not files:
            self._goto_local(dirs[0])
            self.notify.emit(f"已切到拖入的文件夹：{dirs[0]}")
            return
        if files:
            self._goto_local(os.path.dirname(os.path.abspath(files[0])))
            self._select_local({os.path.basename(p) for p in files})
            self.notify.emit(f"已选中拖入的 {len(files)} 个文件 —— 点「上传到服务器」就传走")
            return
        self.notify.emit("拖进来的既不是文件也不是文件夹，没法用")

    def _select_local(self, names):
        self.tb_local.clearSelection()
        model = self.tb_local.model()
        sm = self.tb_local.selectionModel()
        flags = QItemSelectionModel.Select | QItemSelectionModel.Rows
        for i, r in enumerate(self._local_rows):
            if r["name"] in names:
                sm.select(model.index(i, 0), flags)
        self._sync()

    def _open_local_selected(self):
        rows = self._picked(self.tb_local, self._local_rows)
        if len(rows) == 1 and rows[0]["is_dir"]:
            self._goto_local(rows[0]["path"])

    # ───────────── 任务调度 ─────────────
    def _run(self, job, on_done, busy="处理中…", xfer=False):
        if self._busy or self._xferring:
            self.notify.emit("上一个操作还没结束，等它做完")
            return
        from .tasks import FtpTask
        task = FtpTask(job, parent=self)
        task.done.connect(lambda res, t=task: self._done(t, res, on_done))
        task.failed.connect(lambda msg, t=task: self._failed(t, msg))
        if xfer:
            task.xfer.connect(self._on_xfer)
            self._xferring = True
            self._t0 = time.monotonic()
            self.pb.setValue(0)
            self.lb_xfer.setText("准备中…")
        else:
            window_busy(self, busy)
        self._busy = True
        self._hold(task)
        self._sync()
        task.start()

    def _done(self, task, res, on_done):
        self._busy = False
        self._xferring = False
        window_busy(self, None)
        if isinstance(res, dict) and res.get("__cancelled__"):
            self._after_cancel()
        else:
            on_done(res)
        self._sync()

    def _failed(self, task, msg):
        self._busy = False
        self._xferring = False
        window_busy(self, None)
        self.lb_xfer.setText("操作失败")
        self.pb.setValue(0)
        show_error(self, "FTP 操作失败", msg,
                   summary=(msg.strip().splitlines() or ["FTP 操作失败"])[-1])
        self._sync()

    def _after_cancel(self):
        # 传到一半被打断，socket 状态不可信，直接断开让用户重连（不硬撑）
        self.pb.setValue(0)
        self.lb_xfer.setText("已停止（连接已断开，需要重新连接）")
        self._close_session()
        self.notify.emit("上传/下载已停止，连接已断开")

    # ───────────── 连接 ─────────────
    def open_saved_accounts(self):
        """挑一个本机已保存的账号，填好就地连接。"""
        dlg = SavedFtpDialog(self)
        if dlg.exec() == QDialog.Accepted and dlg.picked:
            self._apply_saved(dlg.picked)

    def _apply_saved(self, r):
        self.ed_host.setText(r["host"])
        self.sp_port.setValue(int(r["port"] or 21))
        self.ed_user.setText(r["user"])
        self.ed_pass.setText(r["password"])
        if not r["password"]:
            self.notify.emit(f"已填入 {r['host']}（来源：{r['source']}），但没有密码，补一下再连")
            self.ed_pass.setFocus()
            return
        self.notify.emit(f"已从「{r['source']}」读入账号 {r['user']}@{r['host']}，正在连接…")
        self.connect_server()

    def connect_server(self):
        if not self._idle():
            return
        from .. import ftpclient
        host = self.ed_host.text().strip()
        if not host:
            self.notify.emit("先填服务器地址")
            self.ed_host.setFocus()
            return
        port = int(self.sp_port.value())
        if self._ready():                    # 已经连着：先断掉旧的，别把连接漏在那儿
            self._close_session()
        sess = ftpclient.Session(host, port, self.ed_user.text().strip(),
                                 self.ed_pass.text(), tls=self.chk_tls.isChecked())

        def job(task):
            try:
                banner = sess.connect()
            except Exception as exc:
                sess.close()
                return {"ok": False, "err": ftpclient.friendly_error(exc),
                        "probe": ftpclient.probe(host, port, 4)}
            try:
                return {"ok": True, "session": sess, "pwd": sess.pwd(),
                        "rows": sess.listdir(), "banner": banner}
            except Exception as exc:
                sess.close()
                return {"ok": False, "err": ftpclient.friendly_error(exc),
                        "probe": None}

        self._run(job, self._on_connected, busy="正在连接服务器…")

    def _on_connected(self, res):
        if not res.get("ok"):
            self.badge.setText("连接失败")
            self.badge.set_sev("error")
            msg = res.get("err") or "连不上"
            p = res.get("probe") or {}
            if p.get("error"):
                msg += f"\n\n另外测了一下这个端口：{p['error']}"
            elif p.get("banner"):
                msg += f"\n\n这个端口的回话：{p['banner']}"
            show_error(self, "连不上服务器", msg, summary=res.get("err"))
            return
        self._session = res["session"]
        self.badge.setText("已连接")
        self.badge.set_sev("ok")
        self._set_remote(res["pwd"], res["rows"])
        self.notify.emit(f"已连接 {self._session.host}:{self._session.port}"
                         f"（{res.get('banner', '').strip()[:40]}）")

    def disconnect_server(self):
        if not self._idle():
            return
        if not self._ready():
            return
        self._close_session()
        self.notify.emit("已断开连接")
        self._sync()

    def _close_session(self):
        sess, self._session = self._session, None
        if sess is not None:
            try:
                sess.close()
            except Exception:
                pass
        self._remote_rows = []
        self.ed_rpath.setText("")
        self._show_remote_placeholder()
        self.badge.setText("未连接")
        self.badge.set_sev("info")

    def _show_remote_placeholder(self):
        """没连服务器时右栏别空着 —— 空表格看着像「这服务器是空的」。"""
        self.tb_remote.set_rows([["还没连服务器：在上面填地址和账号，点「连接」", "", ""]],
                                {(0, 0): {"fg": C["faint"]}})

    def shutdown(self):
        """窗口关闭时调用：停下正在跑的传输，断开连接。"""
        if self._task is not None and self._task.isRunning():
            self._task.stop()
            self._task.wait(2500)
        self._close_session()

    # ───────────── 服务器一侧 ─────────────
    def _set_remote(self, pwd, rows):
        self.ed_rpath.setText(pwd or "/")
        self.ed_rpath.setCursorPosition(0)      # 同上：从根开始显示
        self.ed_rpath.setToolTip(pwd or "")
        self._remote_rows = self._sorted(rows or [])
        self._fill(self.tb_remote, self._remote_rows)
        self._sync()

    def refresh_remote(self):
        if not (self._ready() and self._idle()):
            return
        sess = self._session
        self._run(lambda task: {"pwd": sess.pwd(), "rows": sess.listdir()},
                  lambda res: self._set_remote(res["pwd"], res["rows"]),
                  busy="正在读服务器目录…")

    def remote_up(self):
        if not (self._ready() and self._idle()):
            return
        sess = self._session

        def job(task):
            sess.cwd("..")
            return {"pwd": sess.pwd(), "rows": sess.listdir()}

        self._run(job, lambda res: self._set_remote(res["pwd"], res["rows"]),
                  busy="正在切换目录…")

    def goto_remote_path(self):
        if not (self._ready() and self._idle()):
            return
        path = self.ed_rpath.text().strip()
        if not path:
            return
        sess = self._session

        def job(task):
            sess.cwd(path)
            return {"pwd": sess.pwd(), "rows": sess.listdir()}

        self._run(job, lambda res: self._set_remote(res["pwd"], res["rows"]),
                  busy="正在切换目录…")

    def _enter_remote(self, name):
        sess = self._session

        def job(task):
            sess.cwd(name)
            return {"pwd": sess.pwd(), "rows": sess.listdir()}

        self._run(job, lambda res: self._set_remote(res["pwd"], res["rows"]),
                  busy="正在进入文件夹…")

    # ───────────── 上传 / 下载 ─────────────
    def _prog(self, task):
        last = {"t": 0.0}

        def cb(done, total, name):
            now = time.monotonic()
            if now - last["t"] < 0.08 and done < total:
                return
            last["t"] = now
            task.xfer.emit(int(done), int(total), str(name))

        return cb

    def _on_xfer(self, done, total, name):
        pct = int(done * 100 / total) if total else 0
        self.pb.setValue(max(0, min(100, pct)))
        el = max(time.monotonic() - self._t0, 0.05)
        self.lb_xfer.setText(f"{self._xfer_head} {fb(done)} / {fb(total)}"
                             f"　·　{fb(done / el)}/s　·　{os.path.basename(name)}")

    def stop_xfer(self):
        task = self._task
        if task is not None and task.isRunning():
            task.stop()
            self.lb_xfer.setText("正在停止…")

    def upload_selected(self):
        if not (self._ready() and self._idle()):
            return
        rows = self._picked(self.tb_local, self._local_rows)
        if not rows:
            self.notify.emit("先在左边选中要上传的文件或文件夹")
            return
        names = [r["name"] for r in rows]
        remote_names = {r["name"] for r in self._remote_rows}
        clash = [n for n in names if n in remote_names]
        if clash and not self._confirm_overwrite("服务器这个目录里", clash):
            return
        sess = self._session
        paths = [r["path"] for r in rows]

        def job(task):
            return sess.upload(paths, progress=self._prog(task), cancel=task.stopped)

        self._xfer_head = "上传"
        self._run(job, self._on_xfer_done, xfer=True)

    def download_selected(self):
        if not (self._ready() and self._idle()):
            return
        rows = self._picked(self.tb_remote, self._remote_rows)
        if not rows:
            self.notify.emit("先在右边选中要下载的文件或文件夹")
            return
        self._download_rows(rows)

    def _download_rows(self, rows):
        names = [r["name"] for r in rows]
        clash = [n for n in names
                 if os.path.exists(os.path.join(self._local_dir, n))]
        if clash and not self._confirm_overwrite("本机这个目录里", clash):
            return
        sess = self._session
        local_dir = self._local_dir

        def job(task):
            return sess.download(names, local_dir,
                                 progress=self._prog(task), cancel=task.stopped)

        self._xfer_head = "下载"
        self._run(job, self._on_xfer_done, xfer=True)

    def _on_xfer_done(self, res):
        self.pb.setValue(100 if not res.get("failed") else self.pb.value())
        ok = res.get("files", 0)
        failed = res.get("failed") or []
        head = self._xfer_head
        line = f"{head}完成：{ok} 个文件，{fb(res.get('bytes', 0))}"
        self.lb_xfer.setText(line if not failed else f"{line}；{len(failed)} 项没成功")
        self.notify.emit(line)
        if failed:
            listing = "\n".join(f"· {n} —— {why}" for n, why in failed[:10])
            if len(failed) > 10:
                listing += f"\n… 另有 {len(failed) - 10} 项"
            show_error(self, f"{head}有 {len(failed)} 项没成功",
                       f"{ok} 个成功，{len(failed)} 个没成功：\n\n{listing}",
                       summary=f"{ok} 个成功，{len(failed)} 个没成功")
        if head == "下载":
            self._goto_local(self._local_dir)      # 本机多出文件，刷新一下
        self.refresh_remote()

    # ───────────── 增删改 ─────────────
    def mkdir_remote(self):
        if not (self._ready() and self._idle()):
            return
        name, ok = QInputDialog.getText(self, "新建文件夹", "文件夹名字：")
        name = (name or "").strip()
        if not ok or not name:
            return
        sess = self._session
        self._run(lambda task: {"name": name, "ok": (sess.mkdir(name) or True)},
                  self._on_simple, busy="正在新建文件夹…")

    def rename_remote(self):
        if not (self._ready() and self._idle()):
            return
        rows = self._picked(self.tb_remote, self._remote_rows)
        if len(rows) != 1:
            self.notify.emit("一次改一个，先选中一项")
            return
        old = rows[0]["name"]
        new, ok = QInputDialog.getText(self, "重命名", "新名字：", text=old)
        new = (new or "").strip()
        if not ok or not new or new == old:
            return
        sess = self._session
        self._run(lambda task: {"name": new, "ok": (sess.rename(old, new) or True)},
                  self._on_simple, busy="正在重命名…")

    def delete_remote(self):
        if not (self._ready() and self._idle()):
            return
        from .. import ftpclient
        rows = self._picked(self.tb_remote, self._remote_rows)
        if not rows:
            self.notify.emit("先在右边选中要删除的项")
            return
        names = [r["name"] for r in rows]
        listing = "\n".join("· " + n for n in names[:12])
        if len(names) > 12:
            listing += f"\n… 另有 {len(names) - 12} 项"
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Critical)
        box.setWindowTitle("确认删除")
        box.setText(f"将从服务器上删除这 {len(names)} 项：\n\n{listing}\n\n"
                    "FTP 上没有回收站 —— 删掉就找不回来了。")
        box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        box.setDefaultButton(QMessageBox.No)
        box.button(QMessageBox.Yes).setText("删除")
        box.button(QMessageBox.No).setText("取消")
        if box.exec() != QMessageBox.Yes:
            return

        sess = self._session

        def job(task):
            ok, failed = 0, []
            for r in rows:
                try:
                    if r["is_dir"]:
                        sess.remove_dir(r["name"])      # 非空目录服务器会拒绝
                    else:
                        sess.remove_file(r["name"])
                    ok += 1
                except Exception as exc:
                    failed.append((r["name"], ftpclient.friendly_error(exc)))
            return {"ok": ok, "failed": failed}

        self._run(job, self._on_deleted, busy="正在删除…")

    def _on_deleted(self, res):
        ok = res.get("ok", 0)
        failed = res.get("failed") or []
        self.notify.emit(f"删除：成功 {ok} 项" + (f"，失败 {len(failed)} 项" if failed else ""))
        if failed:
            listing = "\n".join(f"· {n} —— {why}" for n, why in failed[:10])
            show_error(self, f"有 {len(failed)} 项没删掉",
                       f"成功 {ok} 项，失败 {len(failed)} 项：\n\n{listing}\n\n"
                       "「目录非空」是最常见的原因 —— 先把里面的东西删了再删目录。",
                       summary=f"成功 {ok} 项，失败 {len(failed)} 项")
        self.refresh_remote()

    def _on_simple(self, res):
        self.notify.emit(f"完成：{res.get('name', '')}")
        self.refresh_remote()

    # ───────────── 小工具 ─────────────
    def _confirm_overwrite(self, where, names):
        listing = "\n".join("· " + n for n in names[:10])
        if len(names) > 10:
            listing += f"\n… 另有 {len(names) - 10} 项"
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Warning)
        box.setWindowTitle("确认覆盖")
        box.setText(f"{where}已经有同名的：\n\n{listing}\n\n继续会把原来的覆盖掉。")
        box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        box.setDefaultButton(QMessageBox.No)
        box.button(QMessageBox.Yes).setText("覆盖")
        box.button(QMessageBox.No).setText("取消")
        return box.exec() == QMessageBox.Yes

    def _on_local_dbl(self, row, _col):
        if 0 <= row < len(self._local_rows) and self._local_rows[row]["is_dir"]:
            self._goto_local(self._local_rows[row]["path"])

    def _on_remote_dbl(self, row, _col):
        if not (0 <= row < len(self._remote_rows)):
            return
        item = self._remote_rows[row]
        if item["is_dir"]:
            if self._ready() and self._idle():
                self._enter_remote(item["name"])
        elif self._ready() and self._idle():
            self._download_rows([item])


# ══════════════════════════════ 数据恢复 ══════════════════════════════

class RecoveryPage(Page):
    """数据恢复：回收站 → 已删除文件 → 按类型找。

    三条路的顺序是有讲究的，界面上也按这个顺序排：
      ① 回收站里还在的：文件根本没被动过，原名、原位置都在，还原就是复制一份；
      ② 扫已删除文件（回收站被清空了）：从 MFT 记录里把名字、目录、数据簇捞回来；
      ③ 按文件类型找（格式化/目录被清了）：只剩内容，名字和目录找不回来。

    三条铁律直接写在页面上方，不藏在帮助里：
      · 扫描只读，不改动这块盘；
      · 恢复出来的文件必须存到别的盘（存回本盘等于一边捞一边盖）；
      · 不承诺都能恢复（SSD 开了 TRIM、簇已被新文件占用、加密/压缩的都可能不行）。
    """

    def __init__(self, cfg, parent=None):
        super().__init__(cfg, parent)
        self._items = []
        self._skipped = 0
        self._image = ""            # 非空表示「扫这份镜像」，不再读盘符
        self._image_letter = ""
        self._image_base = 0        # 整盘镜像里卷首的字节偏移（分区起点）
        self._image_part = None     # 选中的分区信息（界面上要告诉用户用的是哪个）
        self._shown = []            # 当前筛选后实际显示的条目
        self._fresh = False         # 刚扫完（决定要不要替用户预勾）
        self._mode = "recycle"
        self._letter = ""
        self._target = ""
        self._fs_kind = ""          # 这块盘是什么文件系统（ntfs / exfat / bitlocker…）
        self._fs_hint = ""          # 为什么用不了、现在能做什么（长文本，弹窗里看）
        self._pv_token = 0          # 预览请求序号：晚到的旧结果直接丢
        self._pv_hits = {}          # 已经看过的条目（同一条不必重复读盘）
        self._view_limit = VIEW_STEP   # 当前摆出来多少行（「多看 N 条」会往上加）
        self._matched = 0           # 符合筛选条件的一共有多少条

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 4, 6)      # 右/下留一点：别让按钮贴着边和状态栏
        lay.setSpacing(8)

        tip = QLabel("扫描不会改动这块盘；恢复出来的文件必须存到别的盘（U 盘 / 移动硬盘 / "
                     "另一个分区），存回原盘会把还没捞出来的数据盖掉。能恢复多少算多少，"
                     "不保证每个文件都完整。")
        tip.setObjectName("Muted")
        tip.setWordWrap(True)
        lay.addWidget(tip)

        lay.addWidget(self._build_pick())
        lay.addWidget(self._build_table(), 1)
        lay.addLayout(self._build_footer())
        self._load_volumes()

    # ───────────── 界面 ─────────────
    def _build_pick(self):
        card = QFrame()
        card.setObjectName("Card")
        v = QVBoxLayout(card)
        v.setContentsMargins(12, 10, 12, 10)
        v.setSpacing(8)

        row = QHBoxLayout()
        row.setSpacing(8)
        row.addWidget(QLabel("哪块盘"))
        self.cb_vol = QComboBox()
        self.cb_vol.setMinimumWidth(300)
        self.cb_vol.currentIndexChanged.connect(self._on_vol)
        row.addWidget(self.cb_vol)
        self.btn_vol = QPushButton("刷新")
        self.btn_vol.setToolTip("重新列一遍这块电脑上有哪些盘（插了 U 盘点这里）")
        self.btn_vol.clicked.connect(self._load_volumes)
        row.addWidget(self.btn_vol)
        row.addStretch(1)
        v.addLayout(row)

        # 镜像这行单独放：先做镜像、再对镜像慢慢扫，是专业流程的第一步。
        # 镜像之后源盘只读过一遍，反复扫、扫几小时都不再碰它。
        img_row = QHBoxLayout()
        img_row.setSpacing(8)
        self.btn_image = QPushButton("先做整卷镜像…")
        self.btn_image.setToolTip(
            "把这块盘整块只读复制成一个镜像文件（.pciimg），然后扫描镜像。\n"
            "好处：源盘只读一遍；扫到一半断电/程序关掉，下次同一个文件从断点接着写；\n"
            "镜像留着，以后还能换个工具交叉验证。几百 GB 要几分钟到几十分钟。")
        self.btn_image.clicked.connect(self.start_image)
        img_row.addWidget(self.btn_image)
        self.btn_open_img = QPushButton("打开已有镜像…")
        self.btn_open_img.setToolTip("之前做过镜像的话，直接扫那个文件，不用再读源盘")
        self.btn_open_img.clicked.connect(self.open_image)
        img_row.addWidget(self.btn_open_img)
        self.lb_src = QLabel("")
        self.lb_src.setObjectName("Faint")
        self.lb_src.setWordWrap(True)
        img_row.addWidget(self.lb_src, 1)
        v.addLayout(img_row)

        # 这里原来有 4 个单选：「① 回收站 / ② 已删除 / ③ 格式化残留 / ④ 按类型找」。
        # 全砍了 —— 用户既不知道也不记得文件是怎么没的（"我清空过回收站吗？"），
        # 让他先做这道选择题，等于把程序该做的判断推给他。
        # 现在只有一个按钮：点下去后台按「回收站 → 已删除记录 →（必要时）格式化残留」
        # 自动跑一遍，结果合并去重。用户只需要选盘、点按钮。
        self.lb_hint = QLabel("选好盘，点「开始查找」")
        self.lb_hint.setObjectName("Faint")
        self.lb_hint.setWordWrap(True)
        self.lb_hint.setMinimumHeight(18)
        hint_row = QHBoxLayout()
        hint_row.setSpacing(6)
        hint_row.addWidget(self.lb_hint, 1)
        # 选到「本工具解析不了的文件系统」时，这一行会变成一句短提示，
        # 旁边多出「为什么？」—— 详细原因和下一步动作放在弹窗里，不占版面。
        self.btn_why = QPushButton("为什么？")
        self.btn_why.setFlat(True)
        self.btn_why.setCursor(Qt.PointingHandCursor)
        self.btn_why.clicked.connect(self._show_fs_why)
        self.btn_why.hide()
        hint_row.addWidget(self.btn_why)
        v.addLayout(hint_row)

        deep_row = QHBoxLayout()
        deep_row.setSpacing(8)
        self.chk_deep = QCheckBox("找得更彻底（慢）")
        self.chk_deep.setToolTip(
            "勾上就一定会深挖「格式化后的残留」，而且连现在还有文件占着的区域也一起扫。\n\n"
            "什么时候勾：这块盘被格式化过、或者数据特别重要、上面找出来的东西不像是你要的。\n"
            "不勾也会自动判断 —— 常规扫描几乎没找到东西时，程序会自己往下深挖。\n"
            "几百 GB 可能要几小时，随时能停。")
        self.chk_deep.setChecked(False)
        deep_row.addWidget(self.chk_deep)
        deep_row.addSpacing(16)
        deep_row.addWidget(QLabel("按类型找时只找"))
        self.cb_group = QComboBox()
        self.cb_group.setMinimumWidth(190)
        self.cb_group.setToolTip(
            "只对「按文件类型找」有效。\n\n"
            "整盘扫一遍很慢（几百 GB 要几十分钟到几小时），知道自己在找什么就缩小范围 ——\n"
            "找照片选「照片 / 图片」，找 Office 文档选「文档 / 表格 / 幻灯片」，能快好几倍。")
        for key, label in recovery.CARVE_GROUPS.items():
            self.cb_group.addItem(label, key)
        deep_row.addWidget(self.cb_group)
        deep_row.addStretch(1)
        v.addLayout(deep_row)

        act = QHBoxLayout()
        act.setSpacing(8)
        self.btn_scan = QPushButton("开始查找")
        self.btn_scan.setObjectName("Primary")
        self.btn_scan.clicked.connect(self.start_scan)
        act.addWidget(self.btn_scan)
        self.btn_stop = QPushButton("停止")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_scan)
        act.addWidget(self.btn_stop)
        self.pb = QProgressBar()
        self.pb.setFixedHeight(6)
        self.pb.setTextVisible(False)
        self.pb.hide()
        act.addWidget(self.pb, 1)
        self.info = QLabel("选好盘，点「开始查找」")
        self.info.setObjectName("Muted")
        act.addWidget(self.info, 2)
        v.addLayout(act)
        return card

    def _build_table(self):
        box = QWidget()
        v = QVBoxLayout(box)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(6)

        # 筛选行：几千条平铺在表里根本找不到东西，先给一个筛子。
        # 这一行只在有结果时出现（空态时不占地方）。
        self.bar_filter = QWidget()
        flt = QHBoxLayout(self.bar_filter)
        flt.setContentsMargins(0, 0, 0, 0)
        flt.setSpacing(8)
        flt.addWidget(QLabel("类型"))
        self.cb_kind = QComboBox()
        self.cb_kind.addItem("全部", "")
        for key, (label, _exts) in catalog.EXT_GROUPS.items():
            self.cb_kind.addItem(label, key)
        self.cb_kind.addItem("文件夹", "dir")
        self.cb_kind.addItem("其他", "other")
        self.cb_kind.currentIndexChanged.connect(self._reset_view)
        flt.addWidget(self.cb_kind)
        flt.addWidget(QLabel("时间"))
        self.cb_time = QComboBox()
        for label, days in (("全部", 0), ("今天", 1), ("最近 7 天", 7),
                            ("最近 30 天", 30)):
            self.cb_time.addItem(label, days)
        self.cb_time.currentIndexChanged.connect(self._reset_view)
        flt.addWidget(self.cb_time)
        self.ed_kw = QLineEdit()
        self.ed_kw.setPlaceholderText("在文件名 / 原路径里找…")
        self.ed_kw.setClearButtonEnabled(True)
        self.ed_kw.setMinimumWidth(180)
        self.ed_kw.setMaximumWidth(280)
        # 每敲一个字就重建表格会卡（3000 行），防抖 300ms
        self._kw_timer = QTimer(self)
        self._kw_timer.setSingleShot(True)
        self._kw_timer.setInterval(300)
        self._kw_timer.timeout.connect(self._reset_view)
        self.ed_kw.textChanged.connect(lambda _t: self._kw_timer.start())
        flt.addWidget(self.ed_kw)
        self.lb_count = QLabel("")
        self.lb_count.setObjectName("Faint")
        flt.addWidget(self.lb_count, 1)
        # 十几万条记录不截断，也不一次全塞进表格：先摆最新的一批，点一下再看下一批。
        self.btn_more = QPushButton(f"多看 {VIEW_STEP} 条")
        self.btn_more.setToolTip(
            "再往下看一批（按删除时间从新到旧）。\n"
            "盘里认出来的记录可能有十几万条，一次全摆出来表格会卡。")
        self.btn_more.clicked.connect(self._show_more)
        self.btn_more.hide()
        flt.addWidget(self.btn_more)
        self.btn_view = QPushButton("按目录看")
        self.btn_view.setCheckable(True)
        self.btn_view.setToolTip(
            "把结果按原来的文件夹结构摊成一棵树 —— 几千条平铺找不到东西时用这个。\n"
            "勾选在两种视图之间是共享的。")
        self.btn_view.toggled.connect(self._toggle_view)
        flt.addWidget(self.btn_view)
        self.bar_filter.hide()
        v.addWidget(self.bar_filter)

        self.table = CheckTable([
            ("名称", 250, "l"),
            ("大小", 96, "r"),
            ("原位置", -1, "l"),
            ("删除时间", 168, "l"),
            ("可恢复度", 200, "l"),
        ])
        self.table.setToolTip("默认只勾「应该能完整恢复」的项；想全都要就点右下角「勾上可恢复的」")
        self.table.counts_changed.connect(self._on_counts)
        self.table.hide()               # 先只显示空态，有结果再换成表（表头空着很怪）
        v.addWidget(self.table, 1)
        # 选中一行就能看见「这是什么、能不能打开」——
        # 按类型找出来的名字是程序起的，不看内容根本没法挑。双击看大图。
        self.preview = PreviewPane()
        self.preview.open_big.connect(self.open_preview)
        self.preview.hide()
        v.addWidget(self.preview)
        self._pv_timer = QTimer(self)
        self._pv_timer.setSingleShot(True)
        self._pv_timer.setInterval(120)     # 防抖：按住方向键连翻时不要每次都读盘
        self._pv_timer.timeout.connect(self._load_preview)
        self.table.itemSelectionChanged.connect(self._on_row_pick)
        self.table.cellDoubleClicked.connect(lambda *_: self.open_preview())

        # 按目录看：和表格二选一，勾选状态共享
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["名称 / 原目录", "大小", "删除时间", "可恢复度"])
        self.tree.setAlternatingRowColors(True)
        self.tree.setUniformRowHeights(True)
        # 不设列宽的话第一列会被挤到一个字宽，名字全变成「季…」「预…」（实测）
        self.tree.setColumnWidth(0, 330)
        self.tree.setColumnWidth(1, 90)
        self.tree.setColumnWidth(2, 150)
        self.tree.setColumnWidth(3, 260)
        self.tree.itemChanged.connect(self._on_tree_check)
        self.tree.currentItemChanged.connect(self._on_tree_pick)
        self.tree.itemDoubleClicked.connect(lambda *_: self.open_preview())
        self.tree.hide()
        v.addWidget(self.tree, 1)

        self.empty = EmptyState(
            "这里会列出找到的东西",
            "先在上面选一块盘，点「开始查找」—— 刚删的、回收站清空的、格式化的，都是同一个按钮，"
            "程序会按「回收站 → 已删除记录 → 格式化残留」自己找一遍。\n"
            "找出来的东西勾上，点右下角「恢复到…」存到另一块盘。")
        v.addWidget(self.empty, 1)
        return box

    def _build_footer(self):
        row = QHBoxLayout()
        row.setSpacing(8)
        self.lb_sel = QLabel("还没选东西")
        self.lb_sel.setObjectName("Muted")
        row.addWidget(self.lb_sel, 1)
        self.btn_save = QPushButton("保存结果…")
        self.btn_save.setToolTip(
            "把这次找到的清单存成一个文件（.pcirc）。\n"
            "整卷扫几小时的结果关掉就没了 —— 存下来下次直接打开看、接着恢复，不用重扫。")
        self.btn_save.clicked.connect(self.save_catalog)
        row.addWidget(self.btn_save)
        self.btn_load = QPushButton("打开结果…")
        self.btn_load.setToolTip("打开之前存的扫描结果")
        self.btn_load.clicked.connect(self.open_catalog)
        row.addWidget(self.btn_load)
        self.btn_old = QPushButton("看看有没有「以前的版本」")
        self.btn_old.setToolTip("系统还原点 / 文件历史留下的快照。有的话用资源管理器直接还原最省事")
        self.btn_old.clicked.connect(self.show_shadow_hint)
        row.addWidget(self.btn_old)
        self.btn_pick_safe = QPushButton("勾上可恢复的")
        self.btn_pick_safe.setToolTip("把「还在回收站 / 应该能完整恢复」的都勾上，其它不勾")
        self.btn_pick_safe.clicked.connect(self.check_safe)
        row.addWidget(self.btn_pick_safe)
        self.btn_restore = QPushButton("恢复到…")
        self.btn_restore.setObjectName("Primary")
        self.btn_restore.setEnabled(False)
        self.btn_restore.clicked.connect(self.start_restore)
        row.addWidget(self.btn_restore)
        return row

    # ───────────── 结果存档（一次几小时的扫描不该白做） ─────────────
    def save_catalog(self):
        if not self._items:
            QMessageBox.information(self, "还没有结果", "先扫一次，有结果了才能保存")
            return
        folder = self._target or self._default_image_dir()
        path, _f = QFileDialog.getSaveFileName(
            self, "把这份结果存到哪里",
            catalog.default_path(folder, self._letter or self._image_letter),
            "扫描结果 (*.pcirc);;所有文件 (*.*)")
        if not path:
            return
        try:
            path = catalog.save(path, self._items, getattr(self, "_stats", {}),
                                meta={"mode": self._mode, "letter": self._letter,
                                      "image": os.path.basename(self._image or "")})
        except OSError as exc:
            QMessageBox.warning(self, "存不下来", f"{exc}")
            return
        self.info.setText(f"结果已存到 {os.path.basename(path)}"
                          "（以后用「打开结果…」直接看，不用重扫）")

    def open_catalog(self):
        if self.is_busy():
            return
        path, _f = QFileDialog.getOpenFileName(
            self, "打开之前存的扫描结果", self._default_image_dir(),
            "扫描结果 (*.pcirc);;所有文件 (*.*)")
        if not path:
            return
        try:
            items, stats, info = catalog.load(path)
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "打不开", str(exc))
            return
        meta = info.get("meta") or {}
        if meta.get("image"):
            self._set_image("")     # 看的是存档，不该同时挂着「正在扫某份镜像」的状态
        self._on_found({"mode": meta.get("mode") or "mft", "items": items,
                        "stats": dict(stats, truncated=False)})
        self.info.setText(f"已打开 {os.path.basename(path)}"
                          f"（存于 {info.get('saved') or '未知时间'}）　共 {len(items)} 条")

    def check_safe(self):
        """把能恢复的都勾上（多了先确认一次：别让人一点就复制几百个文件出去）。"""
        # 必须按 _shown 的下标来勾：表格的行对应的是「筛选后」的列表，
        # 用 _items 的下标去勾，一加筛选就会勾到别人头上（原来就是这么错的）。
        # 也不要勾 unverified（还没核对内容的）：勾错了等于让用户复制一堆可能坏的文件。
        idx = [i for i, it in enumerate(self._shown or [])
               if it.get("confidence") in ("recycle", "good")]
        if not idx:
            QMessageBox.information(self, "没有可恢复的",
                                    "列表里没有标着「还在回收站 / 应该能完整恢复」的条目")
            return
        if len(idx) > 50 and QMessageBox.question(
                self, "确认勾选",
                f"会把 {len(idx)} 个条目标成选中，之后点「恢复到…」就要复制这么多文件。\n"
                "确定要全勾上吗？") != QMessageBox.Yes:
            return
        for i in idx:
            self.table.set_row_checked(i, True)
        if self.btn_view.isChecked():
            self._rebuild_tree(self._shown)

    # ───────────── 盘符 ─────────────
    def _load_volumes(self):
        self._set_image("")               # 点「刷新」= 回到真实盘
        cur = self._letter
        self.cb_vol.blockSignals(True)
        self.cb_vol.clear()
        vols = recovery.volumes()
        for v in vols:
            total = v["total"] / (1024 ** 3)
            free = v["free"] / (1024 ** 3)
            kind = "U 盘/移动盘" if v["removable"] else ("系统盘" if v["letter"] == "C:" else "本机磁盘")
            label = f"{v['letter']}  {v['label'] or kind}  {total:.0f}GB（剩 {free:.0f}GB）"
            if not v["is_ntfs"] and v["fs"] != "NTFS":
                label += f"  ·{v['fs']}，仅能看回收站"
            self.cb_vol.addItem(label, v["letter"])
        self.cb_vol.blockSignals(False)
        if cur:
            i = self.cb_vol.findData(cur)
            if i >= 0:
                self.cb_vol.setCurrentIndex(i)
        self._on_vol(self.cb_vol.currentIndex())

    def _on_vol(self, _idx):
        self._letter = self.cb_vol.currentData() or ""
        if self._letter:
            self.info.setText(f"已选 {self._letter}　还没开始找")
        if self._image:
            return                      # 看镜像时不判断真实盘的格式（镜像自己有一套）
        self._probe_fs(self._letter)

    def _probe_fs(self, letter):
        """选盘后立刻看一眼是什么文件系统。

        为什么不等扫描时报错：以前选到 exFAT 的 U 盘，要点「开始查找」、等一会儿，
        才收到一句「不是 NTFS」—— 用户既不知道原因，也不知道下一步做什么。
        这里只读 2 个扇区（几毫秒），提前把用不上的方式灰掉、把原因说清。
        """
        if not letter:
            self._apply_fs("", "")
            return
        try:
            fs = recovery.probe_volume(letter)
        except Exception as exc:                # noqa: BLE001
            self._apply_fs("", "")
            self.info.setText(f"已选 {letter}　（{exc}）")
            return
        kind = fs.get("kind") or ""
        if kind == "denied":
            # 没管理员权限：判断不了格式，但不该把按钮都灰掉（回收站那条路照常能走）
            self._apply_fs("", "")
            self.info.setText(f"已选 {letter}　（判断格式要管理员权限，不影响先看回收站）")
            return
        self._apply_fs(kind, fs.get("hint") or "")

    # 只能「按文件类型找」的格式：连目录项/记录表都没法解析
    _ONLY_CARVE = ("refs", "apfs", "ext", "zero", "mbr", "unknown")
    # 能扫「已删除文件」的格式：NTFS 走 MFT，FAT/exFAT 走目录项（4.14.0 起）
    _CAN_SCAN = ("ntfs", "exfat", "fat32", "fat")

    def _apply_fs(self, kind, hint=""):
        """只调提示文字和按钮状态。

        以前这里要把 4 个「方式」单选按格式灰掉，现在方式没了 —— 逻辑简化成：
        加密盘直接拦住；其余都是「点按钮就行」，只是措辞不同。
        """
        self._fs_kind = kind or ""
        self._fs_hint = hint or ""
        kind = self._fs_kind
        if kind == "bitlocker":
            self.chk_deep.setEnabled(False)
            self.chk_deep.setChecked(False)
            self.btn_scan.setEnabled(False)     # 加密盘扫了也只有密文，别让人白等
            self.lb_hint.setText("这块盘是加密的：先解锁，再回来找"
                                 "（怎么解锁点右边「为什么？」）")
            self.btn_why.show()
            return
        self.btn_scan.setEnabled(True)
        self.chk_deep.setEnabled(True)
        if kind in self._ONLY_CARVE:
            self.btn_scan.setText("按文件类型找")
            self.lb_hint.setText(
                f"这块盘是 {recovery.boot_label(kind)} 格式：文件名和目录都读不出来，"
                "只能按内容捞（找回的放到目标目录，名字是程序起的）")
        elif kind in ("exfat", "fat32", "fat"):
            self.btn_scan.setText("开始查找")
            self.lb_hint.setText(
                f"这块盘是 {recovery.boot_label(kind)} 格式：点「开始查找」就行 —— "
                "会自动看回收站和已删除的文件（FAT 系的名字首字符可能是 _）")
        elif kind == "ntfs":
            self.btn_scan.setText("开始查找")
            self.lb_hint.setText("点「开始查找」就行 —— 会自动看回收站、已删除的记录，"
                                 "没找到再往下深挖")
        elif kind == "unknown":
            self.btn_scan.setText("按文件类型找")
            self.lb_hint.setText("这块盘的格式认不出来 —— 只能按内容捞，找不回原来的名字")
        else:
            self.btn_scan.setText("开始查找")
            self.lb_hint.setText("点「开始查找」就行")
        if kind == "ntfs":
            self.btn_why.hide()
        else:
            self.btn_why.show()

    def _show_fs_why(self):
        if not self._fs_hint:
            return
        QMessageBox.information(self, "这块盘为什么用不了那些方式", self._fs_hint)

    @staticmethod
    def _image_boot_kind(path, base=0):
        """看镜像里「卷首」是哪种文件系统（镜像没有盘符，不能靠 probe_volume）。

        `base` 非 0 时看的是分区起点那个扇区 —— 整盘镜像的 0 偏移是分区表，
        按 0 判断会得到「mbr」，界面就会把四种方式全灰掉。
        """
        try:
            with open(path, "rb") as fh:
                fh.seek(base)
                head = fh.read(512)
                fh.seek(base + 1024)
                ext = fh.read(2)
        except OSError:
            return "unknown"
        if len(head) < 512:
            return "unknown"
        return recovery.boot_kind(head, ext)

    # ───────────── 查找 ─────────────
    def _mode_key(self):
        """现在只有两种可能：能解析就自动找，解析不了就只能按文件类型捞。

        「回收站 / 已删除 / 格式化残留」的区分已经交给 `RecoveryScanTask(mode="auto")`，
        界面上不再让人选。
        """
        return "carve" if self._fs_kind in self._ONLY_CARVE else "auto"

    def start_scan(self):
        """一个按钮干完所有事。

        不再问「文件是进回收站了、删了、还是格式化了」—— 用户不记得，也不该被问。
        后台按「回收站 → 已删除记录 →（必要时）格式化残留」自动跑，结果合并去重。
        """
        # 换了一块盘/一份镜像再扫：上一条的预览不能再留着（内容根本不是这块盘上的）
        self.preview.clear()
        self.preview.hide()
        self._pv_hits.clear()
        if self.is_busy():
            return
        letter = self._letter
        if self._image:
            letter = self._image_letter or "镜像"
        if not letter:
            QMessageBox.information(self, "先选一块盘", "上面选一下要恢复哪块盘")
            return
        # 结果都来自卷扫描（回收站条目靠 $I/$R 文件、其余靠 runs），导出统一走这条路。
        # 以前按模式分，现在只剩「能解析」和「按类型捞」两种，后者不经过这里。
        #
        # ⚠️ 这里原来写死成 mode = "mft"（4.17.0 的回归）：界面说「会自动看回收站、
        # 已删除记录，没找到再往下深挖」，实际只扫了 MFT —— 回收站里明明躺着的文件
        # 一个都不显示，这就是「效果不如市面工具」最直接的一条。必须走 _mode_key()。
        mode = self._mode_key()
        target = None
        if mode == "carve":
            # 按类型找是「边找边写」，所以得先定好放哪儿
            target = self._ask_target(letter)
            if not target:
                return
            self._target = target
        deep = bool(self.chk_deep.isChecked())
        if mode in ("auto", "mft", "raw") and not is_admin() and not self._image:
            # 不硬拦：非管理员也还能看回收站（第一步），只是扫不到已删除记录。
            # 与其让人卡在一个看不懂的「需要管理员权限」弹窗，不如跑一遍再告诉他。
            self.info.setText("没有管理员权限：这次只有回收站能看")

        from .tasks import RecoveryScanTask
        self.btn_scan.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.btn_restore.setEnabled(False)
        self.pb.setRange(0, 0)
        self.pb.show()
        if mode == "auto":
            self.info.setText("正在查找（会自动看回收站、已删除记录）…")
        elif mode == "carve":
            self.info.setText("正在按文件类型找…")
        else:
            self.info.setText("正在查找…")
        if deep:
            self.info.setText("正在深挖：会比平时慢很多（几百 GB 可能几小时），随时可停")
        task = self._hold(RecoveryScanTask(mode, letter, target, deep=deep,
                                          image=self._image or None,
                                          image_base=self._image_base,
                                          groups=[self.cb_group.currentData()],
                                          parent=self))
        task.progress.connect(self._on_progress)
        task.failed.connect(self._on_fail)
        task.done.connect(self._on_found)
        task.finished.connect(self._on_finished)
        task.start()

    def stop_scan(self):
        if self._task is not None and hasattr(self._task, "stop"):
            self._task.stop()
            self.info.setText("正在停…")

    def _on_progress(self, i, n, text):
        if n:
            self.pb.setRange(0, n)
            self.pb.setValue(min(i, n))
            pct = i * 100 // n if n else 0
            self.info.setText(f"{text}　{pct}%")
        else:
            self.info.setText(text)

    def _on_fail(self, msg):
        self.info.setText("查找失败：" + msg.splitlines()[-1])
        tail = ""
        if "NTFS" in msg or "不是 FAT" in msg:
            tail = ("\n\n这块盘的文件系统跟预期对不上（可能被格式化过、或者是加密盘）。\n"
                    "可以试「按文件类型找」——它不看文件系统，只按内容找（找不回原名）。")
        QMessageBox.warning(self, "查找失败", msg + tail)

    def _on_finished(self):
        self.pb.hide()
        # 加密盘扫不了：任务结束时别把「开始查找」又点亮了
        self.btn_scan.setEnabled(self._fs_kind != "bitlocker")
        self.btn_stop.setEnabled(False)
        self.btn_image.setEnabled(True)
        self.btn_open_img.setEnabled(True)

    def _on_found(self, payload):
        mode = payload.get("mode")
        items = payload.get("items") or []
        stats = payload.get("stats") or {}
        self._items = items
        self._stats = stats
        if mode == "carve":
            blind = bool(stats.get("blind"))
            # 按类型找的结果直接写进目标目录，不进列表 —— 把别的视图也清干净，
            # 否则切换到「按目录看」还挂着上一次的旧结果，很误导。
            self._shown = []
            self.tree.hide()
            self.bar_filter.hide()
            extra = ("。这块盘不是 NTFS，工具不知道哪些区域还空着，"
                     "所以抠出来的东西里可能有现在还好好放着的文件（重复品），自己挑"
                     if blind else "")
            by_kind = stats.get("by_kind") or {}
            detail = "、".join(
                f"{recovery.CARVE_LABEL.get(k, k)} {v.get('n', 0)}"
                for k, v in sorted(by_kind.items(), key=lambda kv: -kv[1].get("n", 0))[:8])
            weak = sum(v.get("weak", 0) for v in by_kind.values())
            frag = sum(v.get("fragment", 0) for v in by_kind.values())
            tail = (f"。扫了 {stats.get('scanned', 0) / (1024 ** 3):.1f}GB，"
                    f"{stats.get('elapsed', 0):.0f} 秒（{stats.get('speed', 0)}MB/s）")
            if stats.get("truncated"):
                tail += "，没扫完就停了（可以再点一次接着找别的区域）"
            if frag:
                tail += (f"，其中 {frag} 个是「碎片」—— 文件在盘上被拆成了几段，"
                         "已经尽量拼回去（中间缺的那一小段按空白补，能打开但那一小段是花的）")
            if weak:
                tail += f"，其中 {weak} 个只找到半截（这类格式没有结束标记）"
            self.table.set_check_rows([], [])
            self.table.hide()
            self.empty.set_texts(
                f"按文件类型找回 {len(items)} 个，已经写到你选的目录",
                (f"位置：{self._target}　名字是程序起的（jpg_0001.jpg 这种），"
                 "原文件名和目录找不回来了" + tail + ("。" + detail if detail else "")
                 + extra))
            self.empty.show()
            self.empty.setVisible(True)
            self.info.setText(f"按类型找回 {len(items)} 个文件 → {self._target}")
            if items:
                QMessageBox.information(
                    self, "找完了",
                    f"找回 {len(items)} 个文件，已保存到：\n{self._target}\n\n"
                    "名字是程序按序号起的，内容可能需要逐个打开确认完整性。"
                    + (f"\n\n注意：这块盘是 {recovery.boot_label(stats.get('fs') or '')}"
                       "格式，工具不知道哪些区域还空着，抠出来的是「看起来像文件」的内容，"
                       "里面可能混着现在还正常放着的文件。" if blind else ""))
            return

        # 列表内容交给 _apply_filter()：它会按当前筛选条件（类型/时间/关键字）
        # 决定显示哪些，并保住已经勾上的条目。
        self._fresh = True
        self._view_limit = VIEW_STEP
        self._apply_filter()
        self.table.setVisible(bool(items))
        self.empty.setVisible(not items)
        if not items:
            if (stats.get("zero") or {}).get("verdict") in ("zeros", "erased",
                                                              "mostly_zeros"):
                z = stats["zero"]
                ratio = max(z.get("zero_ratio") or 0, z.get("ff_ratio") or 0)
                kind = "0xFF" if z.get("verdict") == "erased" else "0x00"
                self.empty.set_texts(
                    "这块盘的空闲区读出来基本全是 0",
                    f"抽了 {z.get('sampled', 0) / 2 ** 20:.0f}MB 空闲区，"
                    f"{ratio * 100:.1f}% 是 {kind}。\n"
                    "这说明释放过的块已经被擦掉了（SSD 的 TRIM 真落地到闪存就是这样），"
                    "软件层面读不回来，换什么工具都一样。\n"
                    "还能救的是「名字」：勾上「找得更彻底」再试，变更日志里往往还留着文件名。")
            else:
                hint = ("已经自动看过回收站、已删除记录"
                        + ("，也深挖了格式化残留" if stats.get("deep_ran") else "")
                        + "。")
                self.empty.set_texts(
                    "这块盘上没找到可恢复的记录",
                    hint + "\n\n还能试的：勾上「找得更彻底」再找我一遍；"
                    "或者用上面的「按文件类型找」按内容硬捞（找不回原名）。\n"
                    "如果这块盘是 SSD 且被 TRIM 过，数据在物理层面已经没了。")
        if mode == "auto":
            stages = stats.get("stages") or []
            parts = [f"{name} {n} 项" for name, n in stages if n]
            if not items:
                # 空结果时别写「找到 0 项（共 0 项）」这种绕的话，大白话说清就行
                self.info.setText("已经找过一遍，没有结果"
                                  + (f"（{'，'.join(parts)}）" if parts else ""))
                return
            deep_txt = ""
            if stats.get("deep_ran"):
                deep_txt = ("　已深挖格式化残留" if stats.get("deep_wanted")
                            else "　常规扫描没找到什么，已自动深挖")
            warn = stats.get("warn")
            cands = stats.get("candidates") or 0
            more = ""
            if cands > len(items):
                more = f"　共认出 {cands} 条，这里按时间从新到旧列了 {len(items)} 条"
            if len(items) > VIEW_STEP:
                more += (f"　列表先摆最新的 {VIEW_STEP} 条，"
                         "点上方的「多看」可以一批批往下翻到全部")
            unv = stats.get("unverified") or 0
            if unv > 0:
                more += f"　其中 {unv} 条还没核对内容（点开哪条就核对哪条）"
            self.info.setText(
                f"找到 {len(items)} 项（{'，'.join(parts)}）{deep_txt}"
                + more
                + (f"　⚠️ {warn}" if warn else "")
                + ("　时间到了先停，结果不全，可以再点一次"
                   if stats.get("truncated") else ""))
        elif mode == "recycle":
            self.info.setText(f"回收站里 {len(items)} 项，勾选后点「恢复到…」")
        elif mode == "raw":
            # 小盘（U 盘 / 虚拟盘）用 GB 会四舍五入成「0GB」，看着像没扫
            scanned_n = stats.get("scanned", 0)
            span_n = stats.get("span", 0)
            scanned = (f"{scanned_n / (1024 ** 3):.2f}GB" if scanned_n >= 1 << 30
                       else f"{scanned_n / (1024 ** 2):.0f}MB")
            span = (f"{span_n / (1024 ** 3):.2f}GB" if span_n >= 1 << 30
                    else f"{span_n / (1024 ** 2):.0f}MB")
            extra = ("　（时间到了先停，结果不全；可以再点一次接着找）"
                     if stats.get("truncated") else "")
            unv = stats.get("unverified") or 0
            if unv > 0:
                extra += f"　其中 {unv} 条还没核对内容（点开哪条就核对哪条）"
            if len(items) > VIEW_STEP:
                extra += (f"　列表先摆 {VIEW_STEP} 条，"
                          "点上方的「多看」可以一批批往下翻到全部")
            mode_txt = "整卷扫" if stats.get("whole_disk") else "只扫空闲区"
            live_txt = (f"；剔掉活文件 {stats.get('live_dropped', 0)} 条"
                        if stats.get("live_dropped") else "")
            self.info.setText(
                f"找到 {len(items)} 项（{mode_txt}，扫了 {scanned} / "
                f"待扫 {span}，旧记录 {stats.get('records', 0)} 条 / 目录索引 "
                f"{stats.get('indx_entries', 0)} 条 / 变更日志 "
                f"{stats.get('usn_records', 0)} 条（其中 {stats.get('from_usn', 0)} 个名字"
                f"用上了）；只有名字 {stats.get('name_only', 0)} 项{live_txt}）{extra}")
        else:
            extra = "（扫到一半就停了，结果不全，可以再点一次）" if stats.get("truncated") else ""
            cands = stats.get("candidates") or 0
            if cands > len(items):
                extra += f"（共认出 {cands} 条，这里按时间从新到旧列了 {len(items)} 条）"
            fs_txt = f"{stats['fs']}，" if stats.get("fs") else ""
            lossy = sum(1 for i in items if i.get("name_lossy"))
            lossy_txt = (f"；{lossy} 个名字的首字符是 Windows 删除时盖掉的，用 _ 占位"
                         if lossy else "")
            self.info.setText(
                f"找到 {len(items)} 项（{fs_txt}其中 {stats.get('good', 0)} 项"
                f"应该能完整恢复{lossy_txt}）{extra}")

    # ───────────── 镜像（先镜像，再反复扫） ─────────────
    def _default_image_dir(self):
        """默认把镜像放到「不和源盘同一个卷」的地方。"""
        src = (self._letter or "C:")[0].upper()
        for cand in ("E:////", "D:////", "C:////"):
            if cand[0] != src and os.path.isdir(cand):
                return cand
        return os.path.expanduser("~")

    def _set_image(self, path, letter="", base=0, part=None):
        self._image = path
        self._image_letter = letter or ""
        self._image_base = int(base or 0)
        self._image_part = part
        self.cb_vol.setEnabled(not path)
        if path:
            size = os.path.getsize(path) / (1024 ** 2) if os.path.isfile(path) else 0
            self.lb_src.setText(
                f"来源：镜像 {os.path.basename(path)}（{size:.0f} MB"
                + (f"，原盘 {self._image_letter}" if self._image_letter else "")
                + "）　点「刷新」回到真实盘")
            # 镜像里的文件系统可能跟当前盘符无关（比如打开的是别人做的 exFAT 镜像），
            # 所以单独判一次，别拿当前选中盘的结论套上去。
            kind = self._image_boot_kind(path, self._image_base)
            hint = recovery.boot_hint(kind, self._image_letter or None)
            self._apply_fs(kind, hint)
        else:
            self.lb_src.setText("")

    def start_image(self):
        """做整卷镜像：只读复制，支持断点续传。"""
        if self.is_busy():
            return
        letter = self._letter
        if not letter:
            QMessageBox.information(self, "先选一块盘", "上面选一下要镜像哪块盘")
            return
        if not is_admin():
            QMessageBox.warning(self, "需要管理员权限",
                                "读整块盘的原始数据需要管理员权限。\n\n"
                                "请关掉工具，右键「以管理员身份运行」再试。")
            return
        default = os.path.join(self._default_image_dir(), f"盘{letter[0]}_备份.pciimg")
        path, _flt = QFileDialog.getSaveFileName(
            self, "镜像保存到哪里（要放在别的盘）", default,
            "镜像文件 (*.pciimg);;所有文件 (*.*)")
        if not path:
            return
        if not path.lower().endswith(".pciimg"):
            path += ".pciimg"
        why = recovery.same_volume(letter, os.path.dirname(path) or ".")
        if why:
            QMessageBox.warning(
                self, "这个位置不行",
                why + "\n\n镜像必须放到别的盘：写在同一块盘上等于一边读一边写，"
                "既慢又可能把还没捞出来的数据盖掉。")
            return

        # 空间先算清楚：一整块 1T 的盘做镜像要 1T 空间。选错位置的话，
        # 会在写了几百 GB 之后才失败 —— 那才是最难受的，几十毫秒就能提前说。
        try:
            plan = recovery.image_plan(letter, path)
        except Exception as exc:                # noqa: BLE001
            QMessageBox.warning(self, "这块盘读不出来", str(exc))
            return
        if not plan.get("ok"):
            QMessageBox.warning(self, "这里放不下镜像", plan.get("why") or "空间不够")
            return

        info = recovery.image_info(path)
        if info and info.get("done"):
            if info.get("done") >= (info.get("total") or 0):
                QMessageBox.information(
                    self, "这个镜像已经做完了",
                    "这个文件已经是一份完整镜像了，可以直接点「打开已有镜像…」用它。")
                return
            if QMessageBox.question(
                    self, "接着上次写吗",
                    f"这个文件里有上次没做完的镜像（已写 "
                    f"{info['done'] / 2 ** 20:.0f} MB / "
                    f"{(info.get('total') or 0) / 2 ** 20:.0f} MB）。\n\n"
                    "要从未完成的位置继续吗？") != QMessageBox.Yes:
                return

        from .tasks import ImageTask
        self.btn_image.setEnabled(False)
        self.btn_open_img.setEnabled(False)
        self.btn_scan.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.pb.setRange(0, 1000)
        self.pb.setValue(0)
        self.pb.show()
        self.info.setText("正在做镜像（只读，不会改这块盘）…")
        task = self._hold(ImageTask(letter, path, parent=self))
        task.progress.connect(self._on_progress)
        task.failed.connect(self._on_image_fail)
        task.done.connect(self._on_image_done)
        task.finished.connect(self._on_finished)
        task.start()

    def _on_image_fail(self, msg):
        self.info.setText("镜像失败：" + msg.splitlines()[-1])
        QMessageBox.warning(self, "镜像失败", msg)

    def _on_image_done(self, st):
        mb = st.get("done", 0) / (1024 ** 2)
        bad = st.get("bad_bytes") or 0
        bad_count = st.get("bad_count") or 0
        if not st.get("complete"):
            tip = f"镜像先停在这里：已写 {mb:.0f} MB。下次选同一个文件会接着写"
            if bad:
                tip += f"（已跳过 {bad_count} 处读不出来的位置）"
            self.info.setText(tip)
            return
        extra = f"，跳过 {bad_count} 处坏块共 {bad / 2 ** 20:.1f} MB" if bad else ""
        self.info.setText(f"镜像完成：{os.path.basename(st['dest'])}"
                          f"（{mb:.0f} MB{extra}）")
        self._set_image(st["dest"], st.get("letter") or "")

        lines = [f"镜像文件：\n{st['dest']}\n",
                 f"大小 {mb:.0f} MB"
                 + (f"，其中 {bad_count} 处读不出来（共 {bad / 2 ** 20:.1f} MB）"
                    if bad else "，全部读完")]
        pre = st.get("smart") or {}
        if pre.get("level") in ("warn", "error"):
            lines.append(f"磁盘健康：{pre.get('text')}")
        if bad:
            lines.append("读不出来的位置清单在 "
                         f"{os.path.basename(recovery.badmap_path(st['dest']))}。"
                         "盘上已经出现读不出的扇区，别再往里写东西。")
        lines.append("\n现在就对这份镜像扫描吗？（扫镜像不再碰源盘，可以反复扫）")
        if QMessageBox.question(self, "镜像做好了", "\n".join(lines)) == QMessageBox.Yes:
            # 必须延后：此刻镜像任务的 finished 还没派发，is_busy() 仍为 True，
            # 直接调 start_scan() 会被它自己挡掉 —— 看起来就是「点了没反应」。
            QTimer.singleShot(300, self.start_scan)

    def open_image(self):
        """打开之前做的镜像，直接扫它。

        整盘镜像（dd / 移动硬盘盒直通 / E01 转出来的）在这里是常态：0 偏移放的是
        **分区表**，真正的卷在某个分区的起点。所以先看分区表 —— 有多个分区就让用户挑，
        分区表没了就提议按文件系统签名找一遍（只读，不写任何东西）。
        """
        if self.is_busy():
            return
        path, _flt = QFileDialog.getOpenFileName(
            self, "打开之前做的镜像", self._default_image_dir(),
            "镜像文件 (*.pciimg *.img *.dd *.raw *.bin *.vhd *.vhdx *.vmdk);;"
            "虚拟盘 (*.vhd *.vhdx *.vmdk);;所有文件 (*.*)")
        if not path:
            return
        info = recovery.image_info(path) or {}
        letter = info.get("letter") or ""

        base, part = 0, None
        try:
            layout = partitions.list_partitions(path)
        except Exception as exc:                # noqa: BLE001
            QMessageBox.warning(self, "这个文件打不开", str(exc))
            return
        usable = [p for p in layout.get("parts") or []
                  if p.get("fs") in ("ntfs", "exfat", "fat32", "fat")]
        if layout.get("scheme") in ("mbr", "gpt") and usable:
            labels = [
                f"第 {i + 1} 个分区　{p.get('fs') or '认不出'}　"
                f"{(p.get('size') or 0) / (1024 ** 3):.1f} GB　"
                f"（从 {(p.get('offset') or 0) / (1024 ** 2):.0f} MB 处开始）"
                for i, p in enumerate(usable)]
            pick = 0
            if len(usable) > 1:
                chosen, ok = QInputDialog.getItem(
                    self, "这是整块硬盘的镜像",
                    "这份镜像的 0 偏移是分区表，里面有几个分区。\n"
                    "选一个来扫（只读，不会改镜像）：", labels, 0, False)
                if not ok:
                    return
                pick = labels.index(chosen)
            part = usable[pick]
            base = int(part.get("offset") or 0)
        elif layout.get("scheme") in ("mbr", "gpt") and not usable:
            if not self._find_lost_parts(path, layout):
                return
            layout = partitions.list_partitions(path)
            usable = [p for p in layout.get("parts") or []
                      if p.get("fs") in ("ntfs", "exfat", "fat32", "fat")]
            if not usable:
                return
            part = usable[0]
            base = int(part.get("offset") or 0)

        try:
            probe, kind = recovery.open_image_volume(path, letter=letter or "镜像",
                                                     base=base, part=part)
            probe.close()
        except Exception as exc:                # noqa: BLE001
            QMessageBox.warning(self, "这个文件打不开",
                                f"{exc}\n\n"
                                "镜像得是**从卷的 0 偏移开始**的整卷拷贝，或者整块硬盘的镜像"
                                "（那样本工具会从分区表里找分区）。")
            return
        if not info:
            QMessageBox.information(
                self, "能打开，但没有进度信息",
                "这个文件不是本工具做的镜像（没有 .json 进度文件），"
                "扫描照常可以做，只是不能断点续传、原盘符也未知。")
        self._set_image(path, letter, base=base, part=part)
        vkind = getattr(probe, "label", "") or ""
        if vkind and vkind != "整盘镜像":
            # 用户给的是虚拟盘（VHD/VHDX/VMDK）：告诉他工具已经把格式解开了，
            # 免得他以为「我拿的是 .vhdx，你怎么当裸数据读」。
            self.lb_src.setText(self.lb_src.text() + f"　（已解开：{vkind}）")
        if base:
            self.lb_src.setText(self.lb_src.text() +
                                f"　用的是 {recovery.boot_label(kind)} 分区，"
                                f"从 {base / (1024 ** 2):.0f} MB 处开始")
        self.info.setText(f"已切到镜像：{os.path.basename(path)}　选好方式后点「开始查找」")

    def _find_lost_parts(self, path, layout):
        """分区表里没有可用分区时，问用户要不要按签名扫一遍。返回是否找到。"""
        if QMessageBox.question(
                self, "分区表里没有可用分区",
                (layout.get("note") or "读不出分区表") + "\n\n"
                "要不要按文件系统签名（NTFS / exFAT / ReFS）在整份镜像里找一遍？\n"
                "只读，不会改文件；几百 GB 大概几十秒。") != QMessageBox.Yes:
            return False
        self.info.setText("正在按签名找分区…")
        found = partitions.find_boot_sectors(path, progress=None)
        if not found:
            QMessageBox.warning(
                self, "没找到",
                "整份镜像里没找到任何 NTFS / exFAT / ReFS 的引导扇区。\n\n"
                "可能是：镜像本身是加密/压缩过的、分区被整段清零、或者这不是硬盘镜像。")
            return False
        names = [f"{recovery.boot_label(p['fs'])}　从 "
                 f"{p['offset'] / (1024 ** 2):.0f} MB 处开始" for p in found]
        chosen, ok = QInputDialog.getItem(
            self, "找到了这些分区", "按文件系统签名找到的分区（按位置排序）：",
            names, 0, False)
        if not ok:
            return False
        pick = found[names.index(chosen)]
        # 把找到的结果塞回 layout，调用方按正常流程打开
        layout["parts"] = [pick]
        layout["scheme"] = "found"
        return True

    # ───────────── 恢复 ─────────────
    def _ask_target(self, letter):
        path = QFileDialog.getExistingDirectory(
            self, "恢复出来的文件放到哪里（必须是别的盘）",
            self._target or os.path.expanduser("~"))
        if not path:
            return None
        why = recovery.check_target(letter, path)
        if why:
            QMessageBox.warning(self, "这个位置不行", why)
            return None
        self._target = path
        return path

    def start_restore(self):
        if self.is_busy():
            return
        items = self._checked_items()
        if not items:
            QMessageBox.information(self, "还没勾", "先在列表里勾上要恢复的文件")
            return
        # 勾选里可能有「解不了」的：只有名字、NTFS 压缩、EFS 加密、已被清零。
        # 这些一律不导出（导出的只会是打不开的文件或空文件），在这里一次说清原因。
        BLOCK = {
            "name_only": "只有名字，没有数据位置（记录已被覆盖）",
            "encrypted": "EFS 加密文件，本工具不能解密",
            "wiped": "数据区已被清零（多半是 TRIM），导出的只会是空文件",
        }
        counts = {}
        real = []
        for i in items:
            key = i.get("confidence")
            if key in BLOCK:
                counts[key] = counts.get(key, 0) + 1
            else:
                real.append(i)
        self._skipped = sum(counts.values())
        if not real:
            detail = "\n".join(f"· {BLOCK[k]}：{v} 项" for k, v in counts.items())
            QMessageBox.information(
                self, "这些都没法导出",
                f"勾的 {len(items)} 项里，没有一项能导出内容：\n\n{detail}\n\n"
                "「只有名字」的请用上面的「按文件类型找」按内容去捞；"
                "被清零/加密/压缩的，本工具确实做不到 —— 换工具也一样要先解决这一层。")
            return
        if counts:
            detail = "、".join(f"{BLOCK[k]} {v} 项" for k, v in counts.items())
            QMessageBox.information(
                self, "有 {} 项没法导出，已跳过".format(sum(counts.values())),
                f"{detail}。\n\n"
                "剩下的 {} 项照常导出。".format(len(real)))
        items = real
        mode = self._mode_key()
        target = self._ask_target(self._letter)
        if not target:
            return
        from .tasks import RecoveryRestoreTask
        self.btn_restore.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.pb.setRange(0, len(items))
        self.pb.setValue(0)
        self.pb.show()
        task = self._hold(RecoveryRestoreTask(mode, self._letter, items, target,
                                              image=self._image or None,
                                              image_base=self._image_base, parent=self))
        task.progress.connect(self._on_progress)
        task.failed.connect(self._on_fail)
        task.done.connect(self._on_restored)
        task.finished.connect(self._on_finished)
        task.start()

    def _on_restored(self, res):
        ok = res.get("ok") or []
        bad = res.get("bad") or []
        shaky = res.get("shaky") or []
        target = res.get("target")
        skip = getattr(self, "_skipped", 0)

        if bad:
            self.info.setText(f"写出 {len(ok)} 个，{len(bad)} 个失败 → {target}")
            detail = "\n".join(f"· {b['name']}：{b['why']}" for b in bad[:8])
            QMessageBox.warning(self, "有文件没恢复成功",
                                f"{len(bad)} 个失败：\n{detail}"
                                + ("\n…" if len(bad) > 8 else "")
                                + "\n\n失败多半是这些簇已经被新数据占用了。")
            return
        if not ok:
            return

        # 自检不通过的单独说：这些文件已经写出来了，但大小或文件头不对 ——
        # 不能混在「成功」里，否则用户会拿一个坏文件当备份。
        head = f"{len(ok)} 个文件已保存到：\n{target}\n\n"
        if shaky:
            self.info.setText(f"写出 {len(ok)} 个，其中 {len(shaky)} 个自检不通过 → {target}")
            detail = "\n".join(f"· {s['name']}：{s['why']}" for s in shaky[:8])
            QMessageBox.warning(
                self, f"{len(shaky)} 个文件可能不完整",
                head + f"其中 {len(shaky)} 个写出来之后自检没通过：\n{detail}"
                + ("\n…" if len(shaky) > 8 else "")
                + "\n\n这些文件**可能是坏的**（所在空间已被覆盖，或内容被清零）。"
                  "建议先打开看看，不要把唯一的备份托付给它们。")
            return
        self.info.setText(f"恢复了 {len(ok)} 个（自检通过）→ {target}")
        QMessageBox.information(
            self, "恢复完成",
            head
            + (f"另外 {skip} 项没法导出（只有名字 / 压缩 / 加密 / 已清零），已在导出前跳过。\n\n"
               if skip else "")
            + "这 {} 个的大小和文件头都对得上，但内容是否完好还得你自己打开确认。".format(len(ok)))


    # ───────────── 以前的版本 ─────────────
    def show_shadow_hint(self):
        copies = recovery.shadow_copies(self._letter or None)
        if copies:
            lines = [f"· {c['created']}　{c['device']}" for c in copies[:6]]
            QMessageBox.information(
                self, "找到「以前的版本」",
                "这块盘上有系统快照，直接用它最省事、最不容易出错：\n\n"
                + "\n".join(lines)
                + "\n\n用法：在资源管理器里右键那个文件夹（或整块盘）→ 属性 → "
                  "「以前的版本」→ 选一个时间点 → 打开或复制出来。")
        else:
            QMessageBox.information(
                self, "没有找到「以前的版本」",
                "这块盘没有系统还原点或文件历史快照（这台电脑可能没开系统保护）。\n\n"
                "以后想留一手：控制面板 → 系统 → 系统保护 → 打开（给系统盘留 5% 空间就够）。"
                "开了之后，误删/误改都能从「以前的版本」里直接拿回来。")

    # ───────────── 杂项 ─────────────
    # ───────────── 先看一眼：缩略图 / 内容预览 ─────────────
    def _current_pick(self):
        """当前选中的 (条目, 在 _shown 里的下标)。表格和目录树都走这里。"""
        if self.btn_view.isChecked():
            node = self.tree.currentItem()
            if node is None:
                return None, -1
            idx = node.data(0, Qt.UserRole)
            if isinstance(idx, int) and 0 <= idx < len(self._shown or []):
                return self._shown[idx], idx
            return None, -1
        row = self.table.currentRow()
        if row < 0:
            return None, -1
        return self.table.payload_at(row), row

    def _on_row_pick(self):
        if self.table.currentRow() >= 0:
            self.preview.show()
            self._pv_timer.start()

    def _on_tree_pick(self, cur, _prev):
        if cur is not None and isinstance(cur.data(0, Qt.UserRole), int):
            self.preview.show()
            self._pv_timer.start()

    def _load_preview(self):
        item, _idx = self._current_pick()
        if item is None:
            return
        cached = self._pv_hits.get(id(item))
        if cached is not None:
            self.preview.show_item(item, cached)
            return
        self.preview.show_loading(item)
        self._pv_token += 1
        job = PreviewJob(self._pv_token, item,
                         letter=self._letter or self._image_letter or "",
                         image=self._image or "", image_base=self._image_base)
        job.signals.done.connect(self._pv_on_loaded)
        QThreadPool.globalInstance().start(job)

    def _pv_on_loaded(self, token, item, info):
        # 按着方向键连翻的时候会有好几个请求同时在飞，只认最后一个
        if token != self._pv_token:
            return
        self._pv_hits[id(item)] = info
        if len(self._pv_hits) > 600:
            self._pv_hits.clear()
        cur, _idx = self._current_pick()
        if cur is not item:
            return
        self.preview.show_item(item, info)
        if item.get("path"):
            self._refresh_path_cell(item)

    def open_preview(self):
        """双击 / 「看大图…」：把这一条放大看，← → 能翻上下一个。"""
        item, idx = self._current_pick()
        if item is None:
            return
        dlg = PreviewDialog(self, self._shown or [item], max(idx, 0),
                            letter=self._letter or self._image_letter or "",
                            image=self._image or "", image_base=self._image_base)
        dlg.exec()

    def _on_counts(self, sel, total):
        self.lb_sel.setText(f"已勾 {sel} / {total}")
        self.btn_restore.setEnabled(sel > 0 and not self.is_busy())

    # ───────────── 筛选 / 目录树 / 勾选 ─────────────
    def _apply_filter(self, *_args):
        """按当前筛选条件重建列表（表格和目录树共用同一份结果）。

        勾选状态跟**条目对象**走，不跟行号走 —— 换个筛选条件重建表格时，
        已经勾上的东西不能默默被取消（用户会以为程序把勾选吃了）。
        """
        items = getattr(self, "_items", None) or []
        if not items:
            self.bar_filter.hide()
            self.preview.clear()
            self.preview.hide()
            return
        matched = catalog.filter_items(
            items,
            kind=self.cb_kind.currentData() or "",
            days=int(self.cb_time.currentData() or 0),
            keyword=self.ed_kw.text())
        # 盘里认出十几万条是常事。既不截断丢掉（用户找不到「更老的」那些），
        # 也不一次全摆进 QTableWidget（几万行建表要好几秒、滚动也卡）：
        # 先摆最新的一批，底部「多看 N 条」一批批往下加。
        self._matched = len(matched)
        shown = matched[:self._view_limit]
        self._shown = shown
        self.bar_filter.show()
        if self._matched > len(shown):
            self.lb_count.setText(
                f"显示前 {len(shown)} 条，共 {self._matched} 条（最新的在前）")
            self.btn_more.setText(f"多看 {VIEW_STEP} 条")
            self.btn_more.show()
        else:
            self.lb_count.setText(
                f"共 {len(items)} 条" if self._matched == len(items)
                else f"显示 {self._matched} / 共 {len(items)} 条")
            self.btn_more.hide()

        keep = {id(p) for p in self.table.checked_payloads()}
        rows, payloads = [], []
        for it in shown:
            conf = it.get("confidence") or ""
            # 只有名字的条目（USN / INDX）不知道大小，显示「0B」会被当成空文件
            unknown_size = (conf == "name_only" and not it.get("size"))
            rows.append([
                it.get("name") or "",
                ("—" if unknown_size
                 else (fb(it.get("size") or 0) if not it.get("is_dir") else "文件夹"),
                 it.get("size") or 0),
                self._path_text(it),
                it.get("deleted") or it.get("mtime") or "",
                recovery.CONFIDENCE.get(conf, conf),
            ])
            payloads.append(it)
        self.table.set_check_rows(rows, payloads, checked=False)
        for i, p in enumerate(shown):
            if id(p) in keep:
                self.table.set_row_checked(i, True)
        if getattr(self, "_fresh", False):
            # 新扫出来的：条数少（≤20）就替用户勾上能恢复的；多了一个都不勾 ——
            # 回收站里常躺着几百个旧文件，默认全勾着，点一下「恢复到…」就复制几百个出去。
            if len(items) <= 20:
                for i, it in enumerate(shown):
                    if it.get("confidence") in ("recycle", "good"):
                        self.table.set_row_checked(i, True)
            self._fresh = False
        if self.btn_view.isChecked():
            self._rebuild_tree(shown)
        elif self.table.currentRow() < 0:
            self.preview.clear()
            self.preview.hide()
        self._on_counts(len(self.table.checked_payloads()), len(shown))

    def _reset_view(self, *_args):
        """筛选条件变了：回到第一批（不然用户改完筛选还停在第 8 万条的位置）。"""
        self._view_limit = VIEW_STEP
        self._apply_filter()

    def _show_more(self):
        """再摆一批。已经摆到底就提示一句，别让按钮点着没反应。"""
        if self._view_limit >= self._matched:
            self.btn_more.hide()
            return
        self._view_limit += VIEW_STEP
        self._apply_filter()
        # 滚到新出现的第一条，用户才知道「更多」在哪儿
        first_new = max(0, self._view_limit - VIEW_STEP)
        if first_new < self.table.rowCount():
            self.table.scrollToItem(self.table.item(first_new, 1),
                                    QAbstractItemView.PositionAtTop)

    def _path_text(self, it):
        """表格里「原位置」这一格显示什么。

        扫描时为省时间，只有最新那批算了原路径（15 万条全算要 57 秒）。
        没算的这里说明白，别显示成空白让人以为「这个文件没有原位置」。
        """
        path = it.get("path") or ""
        if path:
            return path + (f"（另有 {len(it['links'])} 个硬链接）"
                           if it.get("links") else "")
        if isinstance(it.get("idx"), int) and it["idx"] > 0:
            return "（点这一行就能读出原位置）"
        return ""

    def _refresh_path_cell(self, item):
        """预览时顺手补出了原路径 → 把表格那一格也更新掉。"""
        for row, it in enumerate(self._shown or []):
            if it is item:
                cell = self.table.item(row, 3)      # 列：勾选/名称/大小/原位置…
                if cell is not None:
                    cell.setText(self._path_text(item))
                return

    def _toggle_view(self, on):
        """列表 / 按目录 二选一。

        切回列表时**必须把树里的勾选同步到表格** —— 不同步的话，用户在大树上
        勾了半个文件夹，一切回列表就全没了（看起来像程序把勾选吃了）。
        """
        if not on:
            checked = {id(p) for p in self._tree_checked_items()}
            for i, p in enumerate(self._shown or []):
                self.table.set_row_checked(i, id(p) in checked)
        self.btn_view.setText("看列表" if on else "按目录看")
        self.table.setVisible(not on and bool(self._shown))
        self.tree.setVisible(bool(on and self._shown))
        if on and self._shown:
            self._rebuild_tree(self._shown)
        self._on_counts(len(self._checked_items()), len(self._shown or []))

    def _rebuild_tree(self, items):
        """把结果按「原来的文件夹结构」摊成一棵树。

        几千条平铺在表里，同一个文件夹里的东西散落在各个位置，根本没法判断
        「这个文件夹是不是我想整体恢复的」。树视图解决的就是这个。
        """
        checked = {id(p) for p in self._checked_items()}
        self.tree.blockSignals(True)
        self.tree.clear()
        folders = {}
        for idx, it in enumerate(items):
            path = str(it.get("path") or "") or str(it.get("name") or "")
            parts = [p for p in path.split("\\") if p]
            if not parts:
                parts = [it.get("name") or "(未命名)"]
            parent = None
            acc = ""
            for part in parts[:-1]:
                acc = f"{acc}\\{part}" if acc else part
                node = folders.get(acc)
                if node is None:
                    node = QTreeWidgetItem([part, "", "", ""])
                    node.setFirstColumnSpanned(False)
                    if parent is None:
                        self.tree.addTopLevelItem(node)
                    else:
                        parent.addChild(node)
                    node.setExpanded(True)
                    folders[acc] = node
                parent = node
            conf = it.get("confidence") or ""
            size = ("文件夹" if it.get("is_dir")
                    else fb(it.get("size") or 0))
            leaf = QTreeWidgetItem([parts[-1], size,
                                    it.get("deleted") or it.get("mtime") or "",
                                    recovery.CONFIDENCE.get(conf, conf)])
            leaf.setFlags(leaf.flags() | Qt.ItemIsUserCheckable)
            leaf.setCheckState(0, Qt.Checked if id(it) in checked else Qt.Unchecked)
            leaf.setData(0, Qt.UserRole, idx)
            if parent is None:
                self.tree.addTopLevelItem(leaf)
            else:
                parent.addChild(leaf)
        self.tree.blockSignals(False)

    def _on_tree_check(self, node, _col):
        """父节点勾选联动子节点（勾一个文件夹 = 勾它下面全部）。"""
        state = node.checkState(0)
        self.tree.blockSignals(True)
        stack = [node]
        while stack:
            n = stack.pop()
            if n.childCount():
                for i in range(n.childCount()):
                    child = n.child(i)
                    child.setCheckState(0, state)
                    stack.append(child)
        self.tree.blockSignals(False)
        self._on_counts(len(self._checked_items()), len(self._shown))

    def _tree_checked_items(self):
        """树视图里勾上的条目（叶子节点才算，父节点只是分组）。"""
        out = []

        def walk(node):
            for i in range(node.childCount()):
                child = node.child(i)
                if child.childCount():
                    walk(child)
                elif child.checkState(0) == Qt.Checked:
                    out.extend(self._payload_at(child))

        for i in range(self.tree.topLevelItemCount()):
            top = self.tree.topLevelItem(i)
            if top.childCount():
                walk(top)
            elif top.checkState(0) == Qt.Checked:
                out.extend(self._payload_at(top))
        return out

    def _payload_at(self, node):
        """树节点 → `_shown` 里那份原始条目（按 id 比对勾选状态要靠它）。"""
        idx = node.data(0, Qt.UserRole)
        if isinstance(idx, int) and 0 <= idx < len(self._shown or []):
            return [self._shown[idx]]
        return []

    def _checked_items(self):
        """当前视图里勾上的条目（表格和树都能取）。"""
        if self.btn_view.isChecked():
            return self._tree_checked_items()
        return self.table.checked_payloads()
