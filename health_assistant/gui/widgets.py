"""health_assistant.gui.widgets — 通用界面组件

DataTable      统一的只读数据表（列宽策略 / 数值排序 / 右键复制 / 导出 CSV）
CheckTable     带勾选列的数据表（清理候选）
StatCard       顶部指标卡
Badge          状态徽标
BlockView      把 Result.blocks 渲染成一叠控件
FindingList    把结论（问题 + 影响 + 收益 + 命令）渲染成卡片
EmptyState     空态提示
"""

from __future__ import annotations

import csv
import os

from PySide6.QtCore import QEvent, QRectF, QSize, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QGuiApplication, QPainter, QPen
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QFileDialog, QFrame,
                               QGridLayout, QHBoxLayout, QHeaderView, QLabel,
                               QMenu, QMessageBox, QPlainTextEdit, QProgressBar,
                               QPushButton, QSizePolicy, QTableWidget,
                               QTableWidgetItem, QVBoxLayout, QWidget)

from .theme import C, SEV, SEV_LABEL, sev_bg, sev_border, sev_color


def show_error(parent, title, msg, summary=None):
    """统一的错误弹窗：首行给结论，调用栈折进「显示详细信息」（可 Ctrl+C 复制）。"""
    box = QMessageBox(parent)
    box.setIcon(QMessageBox.Critical)
    box.setWindowTitle(title)
    box.setText(summary or (msg.strip().splitlines() or [title])[-1])
    box.setInformativeText("点「显示详细信息」可看完整调用栈，Ctrl+C 可复制。")
    box.setDetailedText(msg.strip())
    box.setStandardButtons(QMessageBox.Ok)
    box.exec()

ALIGN = {"l": Qt.AlignLeft | Qt.AlignVCenter,
         "r": Qt.AlignRight | Qt.AlignVCenter,
         "c": Qt.AlignCenter,
         "lt": Qt.AlignLeft | Qt.AlignTop,
         "rt": Qt.AlignRight | Qt.AlignTop}


def _maybe_num(text):
    """把 "12.3" / "1,024" 这类文本转成可比较的数值，供点表头排序用。"""
    s = str(text).strip().replace(",", "").replace("%", "")
    try:
        return float(s)
    except ValueError:
        return str(text).lower()


class _Cell(QTableWidgetItem):
    def __init__(self, text, sortv=None, align="l"):
        super().__init__(str(text))
        self.sortv = _maybe_num(text) if sortv is None else sortv
        self.setTextAlignment(ALIGN.get(align, ALIGN["l"]) if isinstance(align, str) else align)

    def __lt__(self, other):
        a = self.sortv
        b = getattr(other, "sortv", None)
        if b is None:
            return str(a) < str(other.text())
        try:
            return a < b
        except TypeError:
            return str(a) < str(b)


class DataTable(QTableWidget):
    """只读数据表。

    columns: [(标题, 宽度, 对齐)]，宽度 >0 固定、0=按内容、-1=拉伸填充
    rows:    [[值, ...]]，值可为 str 或 (显示文本, 排序值)
    """

    def __init__(self, columns, parent=None, sortable=True, wrap=False):
        super().__init__(parent)
        self._cols = list(columns)
        self._wrap = wrap
        self.setColumnCount(len(self._cols))
        self.setHorizontalHeaderLabels([str(c[0]) for c in self._cols])
        self.setRowCount(0)
        self.setShowGrid(False)
        self.setWordWrap(bool(wrap))
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._on_menu)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.setSortingEnabled(False)
        self.setFocusPolicy(Qt.StrongFocus)

        hh = self.horizontalHeader()
        hh.setHighlightSections(False)
        hh.setDefaultAlignment(ALIGN["l"])
        hh.setFixedHeight(30)
        for i, spec in enumerate(self._cols):
            w = spec[1] if len(spec) > 1 else 0
            if w is None or w == 0:
                hh.setSectionResizeMode(i, QHeaderView.ResizeToContents)
            elif w < 0:
                hh.setSectionResizeMode(i, QHeaderView.Stretch)
            else:
                hh.setSectionResizeMode(i, QHeaderView.Fixed)
                self.setColumnWidth(i, int(w))
        vh = self.verticalHeader()
        vh.setVisible(False)
        vh.setDefaultSectionSize(26)
        vh.setSectionResizeMode(QHeaderView.ResizeToContents if wrap
                                else QHeaderView.Fixed)
        self._sortable = sortable
        self.extra_actions = []      # [(菜单文本, 回调)] 由页面注入，放在右键菜单顶部
        self.context_row = -1        # 最近一次右键的行号（-1 = 空白处）
        self.context_pos = None      # 右键点对应的 viewport 坐标

    def _align_of(self, c):
        align = self._cols[c][2] if len(self._cols[c]) > 2 else "l"
        if self._wrap:
            align = {"l": "lt", "r": "rt"}.get(align, align)
        return ALIGN.get(align, ALIGN["l"])

    # ---- 填充 ----
    def set_rows(self, rows, styles=None):
        """styles: {(行号, 列号): {"fg": 颜色, "bg": 颜色, "bold": True}}"""
        self.setUpdatesEnabled(False)
        self.setSortingEnabled(False)
        self.clearContents()
        self.setRowCount(len(rows))
        for r, row in enumerate(rows):
            for c in range(len(self._cols)):
                spec = row[c] if c < len(row) else ""
                align = self._align_of(c)
                if isinstance(spec, (tuple, list)) and len(spec) == 2:
                    cell = _Cell(spec[0], sortv=spec[1], align=align)
                else:
                    cell = _Cell("" if spec is None else spec, align=align)
                st = (styles or {}).get((r, c))
                if st:
                    if st.get("fg"):
                        cell.setForeground(QColor(st["fg"]))
                    if st.get("bg"):
                        cell.setBackground(QColor(st["bg"]))
                    if st.get("bold"):
                        f = cell.font()
                        f.setBold(True)
                        cell.setFont(f)
                if st and st.get("tip"):
                    cell.setToolTip(st["tip"])
                self.setItem(r, c, cell)
        self.setUpdatesEnabled(True)
        self.setSortingEnabled(bool(self._sortable))

    def set_tooltips(self, col, tips):
        for r, tip in enumerate(tips):
            it = self.item(r, col)
            if it is not None and tip:
                it.setToolTip(tip)

    # ---- 取值 ----
    def row_text(self, r, sep="\t"):
        out = []
        for c in range(len(self._cols)):
            it = self.item(r, c)
            out.append(it.text() if it else "")
        return sep.join(out)

    def all_text(self, sep="\t"):
        lines = ["\t".join(str(c[0]) for c in self._cols)]
        for r in range(self.rowCount()):
            lines.append(self.row_text(r, sep))
        return "\n".join(lines)

    def selected_text(self):
        rows = sorted({i.row() for i in self.selectedIndexes()})
        if not rows:
            return ""
        return "\n".join(self.row_text(r) for r in rows)

    # ---- 右键菜单 ----
    def _on_menu(self, pos):
        idx = self.indexAt(pos)
        self.context_row = idx.row() if idx.isValid() else -1
        self.context_pos = pos
        if idx.isValid() and idx.row() not in {i.row() for i in self.selectedIndexes()}:
            self.selectRow(idx.row())
        menu = QMenu(self)
        extras = list(getattr(self, "extra_actions", []) or [])
        for spec in extras:
            if isinstance(spec, str):                 # 图省事写成 "-" 也认
                label, cb, state = spec, None, True
            else:
                label, cb = spec[0], spec[1]
                state = spec[2] if len(spec) > 2 else True
            if label == "-":
                menu.addSeparator()
                continue
            # 第三项可以是「开菜单时才算」的状态：True=可点；字符串=不可点并把它当原因写进菜单项
            # （例：「删除到回收站…（系统目录或你的主目录本身，不能删）」）。不传就是恒可点。
            if callable(state):
                state = state()
            text = label if state is True else f"{label}（{state}）"
            act = menu.addAction(text)
            act.setEnabled(state is True)
            act.triggered.connect(lambda _checked=False, f=cb: f())
        last = extras[-1] if extras else None
        if last is not None and last != "-" and last[0] != "-":
            menu.addSeparator()
        act_cell = menu.addAction("复制单元格")
        act_row = menu.addAction("复制选中行")
        act_all = menu.addAction("复制整表")
        menu.addSeparator()
        act_csv = menu.addAction("导出为 CSV…")
        for a in (act_cell, act_row, act_all):
            a.setEnabled(self.rowCount() > 0)
        act_csv.setEnabled(self.rowCount() > 0)
        chosen = menu.exec(self.viewport().mapToGlobal(pos))
        if chosen is None:
            return
        clip = QGuiApplication.clipboard()
        if chosen is act_cell and idx.isValid():
            it = self.item(idx.row(), idx.column())
            clip.setText(it.text() if it else "")
        elif chosen is act_row:
            clip.setText(self.selected_text())
        elif chosen is act_all:
            clip.setText(self.all_text())
        elif chosen is act_csv:
            self.export_csv()

    def export_csv(self, default_name="export.csv"):
        path, _ = QFileDialog.getSaveFileName(self, "导出 CSV", default_name,
                                              "CSV 文件 (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8-sig", newline="") as fh:
                w = csv.writer(fh)
                w.writerow([str(c[0]) for c in self._cols])
                for r in range(self.rowCount()):
                    w.writerow([self.item(r, c).text() if self.item(r, c) else ""
                                for c in range(len(self._cols))])
        except OSError as exc:
            raise RuntimeError(f"写入失败: {exc}") from exc


class CheckTable(DataTable):
    """首列带勾选框的数据表。行数据存在首列 UserRole。"""

    def __init__(self, columns, parent=None):
        super().__init__([("", 34, "c")] + list(columns), parent, sortable=False)
        self._rows = []
        self.itemChanged.connect(self._on_item_changed)

    def set_check_rows(self, rows, payloads, checked=True):
        """rows: 显示行；payloads: 与 rows 等长的业务对象（挂在首列）。"""
        self._rows = list(payloads)
        self.blockSignals(True)          # 逐行 setItem 会触发上千次 itemChanged
        self.setUpdatesEnabled(False)
        self.clearContents()
        self.setRowCount(len(rows))
        for r, row in enumerate(rows):
            chk = QTableWidgetItem("")
            chk.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            chk.setCheckState(Qt.Checked if checked else Qt.Unchecked)
            chk.setData(Qt.UserRole, r)
            self.setItem(r, 0, chk)
            for c, spec in enumerate(row, start=1):
                align = self._align_of(c)
                if isinstance(spec, (tuple, list)) and len(spec) == 2:
                    cell = _Cell(spec[0], sortv=spec[1], align=align)
                else:
                    cell = _Cell("" if spec is None else spec, align=align)
                self.setItem(r, c, cell)
        self.setUpdatesEnabled(True)
        self.blockSignals(False)
        self._emit_counts()

    def _on_item_changed(self, item):
        if item.column() == 0:
            self._emit_counts()

    counts_changed = Signal(int, int)      # (已选数, 总数)

    def _emit_counts(self):
        self.counts_changed.emit(len(self.checked_payloads()), self.rowCount())

    def checked_payloads(self):
        out = []
        for r in range(self.rowCount()):
            it = self.item(r, 0)
            if it is None or it.checkState() != Qt.Checked:
                continue
            i = it.data(Qt.UserRole)
            if isinstance(i, int) and 0 <= i < len(self._rows):
                out.append(self._rows[i])
        return out

    def payload_at(self, row):
        """取某一行的业务对象（右键菜单用）。"""
        it = self.item(row, 0)
        if it is None:
            return None
        i = it.data(Qt.UserRole)
        if isinstance(i, int) and 0 <= i < len(self._rows):
            return self._rows[i]
        return None

    def append_check_rows(self, rows, payloads, checked=False):
        """往末尾追加行，不重建整张表（边扫边出结果时用）。

        重建一次十几万行要好几秒；追加一批只跟这一批的条数有关。
        首列 UserRole 里存的是**在 `self._rows` 里的下标**，所以必须先算出
        追加前的长度当基准，否则勾选会勾到别人身上。
        """
        if not rows:
            return
        base = len(self._rows)
        self._rows.extend(payloads)
        r0 = self.rowCount()
        self.blockSignals(True)
        self.setUpdatesEnabled(False)
        self.setRowCount(r0 + len(rows))
        for k, row in enumerate(rows):
            r = r0 + k
            chk = QTableWidgetItem("")
            chk.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            chk.setCheckState(Qt.Checked if checked else Qt.Unchecked)
            chk.setData(Qt.UserRole, base + k)
            self.setItem(r, 0, chk)
            for c, spec in enumerate(row, start=1):
                align = self._align_of(c)
                if isinstance(spec, (tuple, list)) and len(spec) == 2:
                    cell = _Cell(spec[0], sortv=spec[1], align=align)
                else:
                    cell = _Cell("" if spec is None else spec, align=align)
                self.setItem(r, c, cell)
        self.setUpdatesEnabled(True)
        self.blockSignals(False)
        self._emit_counts()

    def set_row_checked(self, row, on=True):
        it = self.item(row, 0)
        if it is not None:
            it.setCheckState(Qt.Checked if on else Qt.Unchecked)

    def set_all_checked(self, on):
        state = Qt.Checked if on else Qt.Unchecked
        for r in range(self.rowCount()):
            it = self.item(r, 0)
            if it is not None:
                it.setCheckState(state)


class Badge(QLabel):
    """小状态标签。"""

    def __init__(self, text="", sev="info", parent=None):
        super().__init__(text, parent)
        self.set_sev(sev)
        self.setAlignment(Qt.AlignCenter)

    def set_sev(self, sev):
        fg, bg, bd = SEV.get(sev, SEV["info"])
        self.setStyleSheet(
            f"color:{fg}; background:{bg}; border:1px solid {bd};"
            f"border-radius:9px; padding:1px 9px; font-size:11px;")


class StatCard(QFrame):
    """指标卡：标题 / 大数值 / 副标题。"""

    def __init__(self, title, value="—", sub="", parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(2)
        self.lb_title = QLabel(title)
        self.lb_title.setObjectName("CardTitle")
        self.lb_value = QLabel(value)
        self.lb_value.setObjectName("CardValue")
        self.lb_sub = QLabel(sub)
        self.lb_sub.setObjectName("CardSub")
        lay.addWidget(self.lb_title)
        lay.addWidget(self.lb_value)
        lay.addWidget(self.lb_sub)
        self.setMinimumWidth(150)

    def set_value(self, value, sub=None, color=None):
        self.lb_value.setText(str(value))
        if color:
            self.lb_value.setStyleSheet(f"color:{color};")
        if sub is not None:
            self.lb_sub.setText(str(sub))


class EmptyState(QWidget):
    """居中的空态提示。

    注意布局：不能给 QVBoxLayout 设 AlignCenter、也不能给 label 加 AlignHCenter ——
    那会让 QLabel 不按整行宽排版、按很窄的 sizeHint 截字（3.5.1/3.5.2 各踩一次）。
    label 必须占满行宽、文字自身居中，垂直居中用上下 stretch。
    """

    def __init__(self, title="", hint="", parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setSpacing(6)
        lay.addStretch(1)
        self.lb_title = QLabel(title)
        self.lb_title.setObjectName("H2")
        self.lb_title.setAlignment(Qt.AlignCenter)
        self.lb_title.setWordWrap(True)
        lay.addWidget(self.lb_title)
        self.lb_hint = QLabel(hint)
        self.lb_hint.setObjectName("Muted")
        self.lb_hint.setAlignment(Qt.AlignCenter)
        self.lb_hint.setWordWrap(True)
        self.lb_hint.setContentsMargins(60, 0, 60, 0)   # 别贴边，留白靠边距
        lay.addWidget(self.lb_hint)
        lay.addStretch(1)

    def set_texts(self, title, hint=""):
        """空态文案随状态变（检查前 / 检查中 / 一切正常 / 搜索无结果）。"""
        self.lb_title.setText(title)
        self.lb_hint.setText(hint)
        self.lb_hint.setVisible(bool(hint))


def hline():
    f = QFrame()
    f.setFrameShape(QFrame.HLine)
    f.setStyleSheet(f"color:{C['border']}; background:{C['border']}; max-height:1px;")
    return f


def _drop(w):
    """立刻从父控件摘掉再排队销毁 —— 只 deleteLater() 会在下一帧前继续绘制，
    切检查项时会看到新旧内容叠在一起。"""
    if w is None:
        return
    w.hide()
    w.setParent(None)
    w.deleteLater()


class BarsWidget(QWidget):
    """Bars 块：标签 + 进度条 + 数值。"""

    def __init__(self, rows, parent=None):
        super().__init__(parent)
        grid = QGridLayout(self)
        grid.setContentsMargins(0, 2, 0, 2)
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(3)
        grid.setColumnStretch(1, 1)
        for i, (label, value, ratio) in enumerate(rows):
            lb = QLabel(label)
            lb.setFixedWidth(170)
            bar = QProgressBar()
            bar.setRange(0, 1000)
            bar.setValue(max(0, min(1000, int(ratio * 1000))))
            bar.setFixedHeight(9)
            lb_v = QLabel(value)
            lb_v.setObjectName("Muted")
            lb_v.setFixedWidth(92)
            lb_v.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            grid.addWidget(lb, i, 0)
            grid.addWidget(bar, i, 1)
            grid.addWidget(lb_v, i, 2)


class BlockView(QWidget):
    """把 Result.blocks（kv / table / text / bars）渲染成一叠控件。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(0, 0, 0, 0)
        self.lay.setSpacing(10)
        self.lay.addStretch(1)

    def clear(self):
        while self.lay.count() > 1:
            item = self.lay.takeAt(0)
            _drop(item.widget())

    def render(self, blocks):
        self.clear()
        for blk in blocks or []:
            w = self._make(blk)
            if w is not None:
                self.lay.insertWidget(self.lay.count() - 1, w)

    def _make(self, blk):
        kind = blk.get("type")
        if kind == "kv":
            tb = DataTable([("项目", 190, "l"), ("值", -1, "l")], sortable=False)
            tb.set_rows([[k, v] for k, v in blk.get("rows", [])])
            tb.setMinimumHeight(min(26 * len(blk.get("rows", [])) + 32, 330))
            tb.setMaximumHeight(min(26 * len(blk.get("rows", [])) + 34, 330))
            return tb
        if kind == "table":
            headers = blk.get("headers") or []
            aligns = blk.get("aligns") or ["l"] * len(headers)
            cols = []
            for i, h in enumerate(headers):
                cols.append((h, 0 if i < len(headers) - 1 else -1, aligns[i]))
            tb = DataTable(cols, sortable=False)
            tb.set_rows(blk.get("rows") or [])
            n = len(blk.get("rows") or [])
            tb.setMinimumHeight(min(26 * n + 34, 430))
            return tb
        if kind == "text":
            ed = QPlainTextEdit()
            ed.setReadOnly(True)
            ed.setPlainText(blk.get("text") or "")
            lines = (blk.get("text") or "").count("\n") + 1
            ed.setFixedHeight(min(max(38, lines * 18 + 12), 240))
            return ed
        if kind == "bars":
            return BarsWidget(blk.get("rows") or [])
        return None


class FindingCard(QFrame):
    """一条结论：状态 + 文字 + 影响/收益 + 可复制命令。"""

    def __init__(self, f, parent=None):
        super().__init__(parent)
        sev = f.get("severity", "info")
        self.setObjectName("Card")
        self.setStyleSheet(
            f"#Card{{border:1px solid {sev_border(sev)}; border-left:3px solid {sev_color(sev).name()};"
            f"border-radius:6px; background:{sev_bg(sev)};}}")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 9, 12, 9)
        lay.setSpacing(5)

        head = QHBoxLayout()
        head.setSpacing(8)
        badge = Badge(SEV_LABEL.get(sev, sev), sev)
        badge.setFixedHeight(20)
        head.addWidget(badge, 0, Qt.AlignTop)
        txt = QLabel(f.get("text", ""))
        txt.setWordWrap(True)
        txt.setStyleSheet(f"color:{C['text']}; font-weight:600;")
        head.addWidget(txt, 1)
        lay.addLayout(head)

        meta = []
        if f.get("impact"):
            meta.append(f"影响：{f['impact']}")
        if f.get("gain"):
            meta.append(f"收益：{f['gain']}")
        if meta:
            lb = QLabel("　·　".join(meta))
            lb.setWordWrap(True)
            lb.setStyleSheet(f"color:{C['muted']}; font-size:12px;")
            lay.addWidget(lb)

        if f.get("fix"):
            # 命令原文对普通使用者是干扰，只给一个复制按钮（悬停可预览），
            # 复制后发给 IT 处理；技术人员把鼠标放上去就能看到命令。
            row = QHBoxLayout()
            row.setSpacing(6)
            btn = QPushButton("复制处理命令")
            btn.setToolTip(str(f["fix"]))
            btn.clicked.connect(lambda: QGuiApplication.clipboard().setText(f["fix"]))
            row.addWidget(btn)
            row.addStretch(1)
            lay.addLayout(row)


class FindingList(QWidget):
    """一叠结论卡片。右键某张卡片会发出 item_menu(finding, 全局坐标)。"""

    item_menu = Signal(object, object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(0, 0, 0, 0)
        self.lay.setSpacing(8)

    def clear(self):
        while self.lay.count():
            item = self.lay.takeAt(0)
            _drop(item.widget())

    def render(self, findings):
        self.clear()
        for f in findings or []:
            card = FindingCard(f)
            card.setContextMenuPolicy(Qt.CustomContextMenu)
            card.customContextMenuRequested.connect(
                lambda pos, ff=f, w=card: self.item_menu.emit(ff, w.mapToGlobal(pos)))
            self.lay.addWidget(card)



# ────────────────── 忙碌遮罩（转圈，挡住整窗点击） ──────────────────

class BusyOverlay(QWidget):
    """盖住整个窗口的半透明遮罩 + 中心转圈。

    为什么不用 QProgressBar 的忙碌态：那只是一条细线，用户分不清"在忙"还是"卡死了"，
    而且照样能点别的按钮。这里盖一层，点到哪都进不来，中间明确写"正在扫描"。
    宿主窗口尺寸变化时跟着铺满（eventFilter）。
    """

    def __init__(self, parent):
        super().__init__(parent)
        self.setObjectName("BusyOverlay")
        self.setCursor(Qt.BusyCursor)
        self.setFocusPolicy(Qt.StrongFocus)      # 抢焦点，别让空格/回车激活后面的按钮
        self._angle = 0
        self._text = ""
        self._sub = ""
        self._timer = QTimer(self)
        # 60ms（约 16fps）时整窗重绘一次半透明底 + 圆角卡片，光这个在 1460×920 上
        # 就要吃掉几个点的 CPU（扫描时看着风扇转）。4.6.0 起：10fps + 只重绘转圈那一小块。
        self._timer.setInterval(100)
        self._timer.timeout.connect(self._tick)
        parent.installEventFilter(self)
        self.hide()

    # ---- 生命周期 ----
    def start(self, text, sub=""):
        self._text, self._sub = str(text), str(sub)
        par = self.parentWidget()
        if par is not None:
            self.setGeometry(par.rect())
        self.raise_()
        self.show()
        self.setFocus(Qt.OtherFocusReason)
        if not self._timer.isActive():
            self._timer.start()

    def stop(self):
        self._timer.stop()
        self.hide()

    def is_busy(self):
        return self._timer.isActive()

    def _tick(self):
        self._angle = (self._angle + 30) % 360
        # 只把这个圆的范围标脏：半透明底和文字都不用重画
        self.update(self._spin_box().toAlignedRect().adjusted(-8, -8, 8, 8))

    def _spin_box(self):
        """转圈那个方框（widget 坐标）。绘制和局部重绘都用它，别算两遍。"""
        card = QRectF(0, 0, 340, 148)
        card.moveCenter(QRectF(self.rect()).center())
        r = 16
        return QRectF(card.center().x() - r, card.top() + 30, r * 2, r * 2)

    def eventFilter(self, obj, ev):
        if obj is self.parentWidget() and ev.type() == QEvent.Resize and self.isVisible():
            self.setGeometry(self.parentWidget().rect())
        return False

    # ---- 绘制 ----
    def paintEvent(self, _ev):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.fillRect(self.rect(), QColor(243, 245, 248, 210))

        card = QRectF(0, 0, 340, 148)
        card.moveCenter(QRectF(self.rect()).center())
        p.setPen(QPen(QColor(C["border"]), 1))
        p.setBrush(QColor(C["panel"]))
        p.drawRoundedRect(card, 12, 12)

        box = self._spin_box()
        p.setBrush(Qt.NoBrush)
        p.setPen(QPen(QColor(C["border_soft"]), 4))
        p.drawEllipse(box)
        p.setPen(QPen(QColor(C["accent"]), 4, Qt.SolidLine, Qt.RoundCap))
        p.drawArc(box, int(-self._angle * 16), int(-100 * 16))   # 100° 的一段弧

        f = QFont(self.font())
        f.setPointSizeF(11.0)
        f.setBold(True)
        p.setFont(f)
        p.setPen(QColor(C["text"]))
        p.drawText(QRectF(card.left(), card.top() + 76, card.width(), 26),
                   Qt.AlignCenter, self._text)
        if self._sub:
            f2 = QFont(self.font())
            f2.setPointSizeF(9.0)
            p.setFont(f2)
            p.setPen(QColor(C["muted"]))
            p.drawText(QRectF(card.left() + 16, card.top() + 104, card.width() - 32, 34),
                       Qt.AlignHCenter | Qt.AlignTop | Qt.TextWordWrap, self._sub)
        p.end()

    # 覆盖层自己吃掉所有鼠标事件（默认命中即不传给下层），这里显式再挡一次
    def mousePressEvent(self, ev):
        ev.accept()

    def mouseReleaseEvent(self, ev):
        ev.accept()

    def mouseDoubleClickEvent(self, ev):
        ev.accept()

    def wheelEvent(self, ev):
        ev.accept()


def window_busy(widget, text=None, sub=""):
    """在 widget 所在的顶层窗口正中间显示 / 关闭转圈遮罩。

    text=None 表示关闭。遮罩按窗口懒创建，一个窗口只建一个。
    """
    win = widget.window()
    ov = getattr(win, "_busy_overlay", None)
    if ov is None:
        ov = BusyOverlay(win)
        win._busy_overlay = ov
    if text:
        ov.start(text, sub)
    else:
        ov.stop()
    return ov
