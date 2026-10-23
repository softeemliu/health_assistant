"""health_assistant.gui.netfix_panel — 网络修复面板（IT 网管视角）

3.5.4 起不再弹独立窗口：这个面板直接嵌在「网络」页签里（主窗口内完成），
入口是页面上的「开始检查网络」按钮或工具条的「修复网络」按钮。

点开始即后台逐条检索（网卡与驱动 → IP/网关 → 出口 → DNS → 代理 → 协议栈 →
时间），每查完一层立刻把这一层的结论显示出来，然后逐条给出处置。

三条铁律（和网管排查一样）：
1. 先说依据再说结论 —— 每条结论都能展开看它凭什么这么说；
2. 能代跑的只代跑幂等、不改配置的命令（safe）；会改配置/短暂断网的逐条确认（caution）；
   要重启或有判断成本的只给命令（manual），绝不代跑；
3. 公司管控机上写着「改之前先问 IT」，避免用户改完被策略覆盖还以为工具失灵。
"""

from __future__ import annotations

import time

from PySide6.QtCore import Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (QDialog, QHBoxLayout, QLabel, QMessageBox,
                               QPlainTextEdit, QProgressBar, QPushButton,
                               QVBoxLayout, QWidget)

from ..core import cli_cmd
from ..netfix import SEV_ORDER
from .theme import C, SEV, SEV_LABEL, sev_color
from .widgets import DataTable, show_error

RISK_LABEL = {"safe": "可直接修", "caution": "需确认", "manual": "手工执行"}


class NetFixPanel(QWidget):
    """网络问题清单 → 右键/按钮逐条修复（嵌在「网络」页签里，不弹窗）。

    表格列：级别 / 分层 / 问题 / 结论依据 / 处置 / 风险
    """

    changed = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._issues = []
        self._passed = []
        self._data = None
        self._task = None

        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(9)

        self.lb_head = QLabel(
            "点「开始逐条检索」，按 网卡与驱动 → IP/网关 → 出口 → DNS → 代理 → "
            "协议栈 → 时间 一层一层查，每查完一层立刻出这一层的结论")
        self.lb_head.setObjectName("Muted")
        self.lb_head.setWordWrap(True)
        lay.addWidget(self.lb_head)

        self.pb = QProgressBar()
        self.pb.setRange(0, 7)
        self.pb.setValue(0)
        self.pb.setFixedHeight(4)
        self.pb.hide()                # 未开始检索时不转圈，避免看着像卡住
        lay.addWidget(self.pb)

        self.table = DataTable([
            ("级别", 66, "c"),
            ("分层", 74, "c"),
            ("问题", 320, "l"),
            ("结论依据", -1, "l"),
            ("处置", 200, "l"),
            ("风险", 84, "c"),
        ])
        self.table.setToolTip("右键任意一行：修复这条 / 复制命令 / 看完整依据")
        self.table.extra_actions = [
            ("修复这一条", self.fix_current),
            ("复制修复命令", self.copy_cmd),
            ("-", None),
            ("复制这条诊断（Markdown）", self.copy_issue),
            ("查看完整依据", self.show_detail),
        ]
        self.table.itemDoubleClicked.connect(lambda _it: self.show_detail())
        lay.addWidget(self.table, 1)

        bar = QHBoxLayout()
        bar.setSpacing(8)
        self.btn_safe = QPushButton("一键修复可自动处理项")
        self.btn_safe.setObjectName("Primary")
        self.btn_safe.setEnabled(False)
        self.btn_safe.setToolTip("只执行幂等、不改配置的命令（如清空 DNS 缓存）")
        self.btn_safe.clicked.connect(self.fix_safe)
        self.btn_start = QPushButton("开始逐条检索")
        self.btn_start.setObjectName("Primary")
        self.btn_start.setToolTip("按 网卡/驱动 → IP/网关 → 出口 → DNS → 代理 → 协议栈 → 时间\n"
                                  "一层一层查，每查完一层立刻出这一层的结论")
        self.btn_start.clicked.connect(self.scan)
        self.btn_fix = QPushButton("修复选中项")
        self.btn_fix.setEnabled(False)
        self.btn_fix.clicked.connect(self.fix_selected)
        self.btn_copy = QPushButton("复制全部结论")
        self.btn_copy.setEnabled(False)
        self.btn_copy.clicked.connect(self.copy_all)

        self.lb_tail = QLabel("")
        self.lb_tail.setObjectName("Muted")
        self.lb_tail.setWordWrap(True)
        for w in (self.btn_start, self.btn_safe, self.btn_fix, self.btn_copy):
            bar.addWidget(w)
        bar.addStretch(1)
        lay.addLayout(bar)
        lay.addWidget(self.lb_tail)

    # ---- 诊断 ----
    def scan(self):
        from .tasks import NetDiagTask
        self._issues = []
        self._passed = []
        self._data = None
        self.table.set_rows([], {})
        self.pb.setRange(0, 7)
        self.pb.setValue(0)
        self.pb.show()
        self.btn_start.setText("重新逐条检索")
        self._busy(True)
        self.lb_head.setText("开始逐条检索：网卡与驱动 → IP/网关 → 出口 → DNS → 代理 → 协议栈 → 时间…")
        self.lb_tail.setText("")
        task = NetDiagTask(parent=self)
        self._task = task
        task.stage.connect(self._on_stage)
        task.partial.connect(self._on_partial)
        task.done.connect(self._on_scan)
        task.failed.connect(self._on_fail)
        task.finished.connect(self._clear_task)
        task.start()

    def _on_stage(self, i, n, label):
        self.pb.setRange(0, n)
        self.pb.setValue(max(0, i - 1))
        self.lb_head.setText(f"正在检索 {i}/{n}：{label}…"
                             + (f"（已发现 {len(self._issues)} 条）" if self._issues else ""))

    def _on_partial(self, part):
        """每查完一层就把这一层的结论追加进表，不必等全部查完。"""
        new = part.get("issues") or []
        passed = part.get("passed") or []
        self._passed.extend(passed)
        if new:
            self._issues.extend(new)
            self._fill()
        if passed:
            # 大多数层是「没问题」，不写一行的话用户只能看着进度条发呆
            self.lb_tail.setText(f"已通过 {len(self._passed)} 项检查：{passed[-1]}")

    def _on_scan(self, res):
        self._busy(False)
        self._issues = res.get("issues") or self._issues
        self._passed = res.get("passed") or self._passed
        self._data = res.get("data")
        self._fill()
        n = self.pb.maximum()
        self.pb.setValue(n if not res.get("stopped") else res.get("steps_done", 0))
        self.lb_head.setText(res.get("summary", ""))
        passed = self._passed or []
        tail = "已通过的检测：" + "；".join(passed[:8]) if passed else ""
        if self._data and not self._data.get("admin"):
            tail += ("\n当前不是管理员，标记为「需管理员」的修复会被拦下 —— "
                     f"需要时用管理员身份跑：{cli_cmd()}")
        self.lb_tail.setText(tail.strip())

    def _on_fail(self, msg):
        self._busy(False)
        self.lb_head.setText("诊断失败，详见弹窗")
        show_error(self, "网络诊断失败", msg, summary="诊断过程中出错，详见下方调用栈。")

    def _clear_task(self):
        # 只收拾「当前这个」任务：_on_fixed 里会紧接着起一轮新诊断，
        # 那时 self._task 已经指向新任务，旧任务这时才发 finished ——
        # 不做判断就会把新任务的引用清成 None（线程被回收 → 崩）。
        if self.sender() is not None and self.sender() is not self._task:
            return
        self._task = None
        self._busy(False)

    def _busy(self, on):
        self.pb.setVisible(on)
        self.btn_start.setEnabled(not on)
        self._sync_buttons()

    def stop(self):
        """主窗口关闭 / 离开页面时调用：让采集线程收手，别在后台空跑完 7 层。"""
        task = self._task
        if task is not None and hasattr(task, "stop"):
            task.stop()

    def _sync_buttons(self):
        """按钮可用性只看当前结论：没有对应级别的条目就别亮着。

        注意不能「扫完就统统启用」—— 之前 _clear_task 里的一句 blanket 启用
        会让「一键修复（0）」这种空按钮变成可点，点了弹个没内容的确认框。
        """
        busy = self._task is not None
        n_safe = sum(1 for i in self._issues if i.get("risk") == "safe")
        n_fixable = sum(1 for i in self._issues if i.get("risk") in ("safe", "caution"))
        self.btn_safe.setEnabled(not busy and n_safe > 0)
        self.btn_fix.setEnabled(not busy and n_fixable > 0)
        self.btn_copy.setEnabled(not busy and bool(self._issues))

    # ---- 表格 ----
    def _fill(self):
        rows, styles = [], {}
        for i, it in enumerate(self._issues):
            sev = it.get("severity", "info")
            ev = "；".join(it.get("evidence") or [])
            fix = it.get("fix_label") or ""
            if not fix and it.get("fix_kind") == "manual":
                fix = "按给出的命令手工执行"
            rows.append([
                (SEV_LABEL.get(sev, sev), SEV_ORDER.get(sev, 9)),
                it.get("area", ""),
                it.get("title", ""),
                ev,
                fix,
                RISK_LABEL.get(it.get("risk"), "—"),
            ])
            fg = sev_color(sev)
            styles[(i, 0)] = {"fg": fg, "bold": True, "bg": SEV[sev][1]}
            styles[(i, 2)] = {"bold": True, "tip": it.get("title", "")}
            styles[(i, 3)] = {"tip": ev}
            styles[(i, 4)] = {"tip": (it.get("fix_text") or fix)}
            if it.get("risk") == "manual":
                styles[(i, 5)] = {"fg": C["muted"]}
        self.table.set_rows(rows, styles)
        n_safe = sum(1 for i in self._issues if i.get("risk") == "safe")
        self.btn_safe.setText(f"一键修复可自动处理项（{n_safe}）")
        self._sync_buttons()

    # ---- 选行 / 右键 ----
    def _row(self, row=None):
        if row is None:
            row = getattr(self.table, "context_row", -1)
        if row is None or row < 0 or row >= len(self._issues):
            return None
        return self._issues[row]

    def fix_current(self):
        it = self._row()
        if it is None:
            QMessageBox.information(self, "先选一行", "请在一行结论上右键。")
            return
        self._run([it])

    def fix_selected(self):
        picked = []
        seen = set()
        for idx in self.table.selectionModel().selectedRows():
            r = idx.row()
            if 0 <= r < len(self._issues) and r not in seen:
                seen.add(r)
                picked.append(self._issues[r])
        if not picked:
            picked = [i for i in self._issues if i.get("risk") in ("safe", "caution")]
        if not picked:
            QMessageBox.information(self, "没有可修复项",
                                    "这一轮没有能由工具执行的修复，按给出的命令手工处理即可。")
            return
        self._run(picked)

    def fix_safe(self):
        picked = [i for i in self._issues if i.get("risk") == "safe"]
        if not picked:
            QMessageBox.information(self, "没有可自动处理的项",
                                    "这一轮没有「幂等、不改配置」的修复。")
            return
        self._run(picked, auto=True)

    def copy_cmd(self):
        it = self._row()
        if it is None:
            return
        text = it.get("fix_text") or (it.get("fix_cmd") and " ".join(it["fix_cmd"])) or ""
        if not text:
            QMessageBox.information(self, "没有命令", "这条是人工处置项，没有可执行命令。")
            return
        QGuiApplication.clipboard().setText(text)
        self.lb_tail.setText("命令已复制到剪贴板")

    def _md(self, it):
        lines = [f"[{SEV_LABEL.get(it.get('severity'), '?')}] [{it.get('area')}] {it.get('title')}"]
        lines += ["  依据：" + e for e in (it.get("evidence") or [])]
        if it.get("impact"):
            lines.append("  影响：" + it["impact"])
        if it.get("fix_text"):
            lines.append("  处置：" + it.get("fix_label", ""))
            lines += ["    " + l for l in it["fix_text"].splitlines()]
        if it.get("reboot"):
            lines.append("  注意：执行后需要重启")
        return "\n".join(lines)

    def copy_issue(self):
        it = self._row()
        if it is None:
            return
        QGuiApplication.clipboard().setText(self._md(it))
        self.lb_tail.setText("这条诊断已复制为 Markdown")

    def copy_all(self):
        if not self._issues:
            return
        head = [f"# 网络检查  {time.strftime('%Y-%m-%d %H:%M')}",
                f"结论：{self.lb_head.text()}", ""]
        body = [self._md(it) for it in self._issues]
        QGuiApplication.clipboard().setText("\n\n".join(head + body))
        self.lb_tail.setText("全部结论已复制为 Markdown")

    def show_detail(self):
        it = self._row()
        if it is None:
            return
        d = self._data or {}
        extra = []
        if d:
            extra.append("—— 采集到的实况 ——")
            for a in (d.get("adapters") or []):
                extra.append(f"  网卡 {a['name']}：IP {', '.join(a['ip']) or '-'}　"
                             f"网关 {', '.join(a['gateway']) or '-'}　"
                             f"DNS {', '.join(a['dns']) or '-'}　"
                             f"状态 {a['state']}")
            if d.get("drivers"):
                extra.append("  —— 网卡驱动 ——")
                pnp = {(p.get("desc") or "").lower(): p for p in (d.get("pnp") or [])}
                for dv in d["drivers"][:8]:
                    p = pnp.get((dv.get("desc") or "").lower()) or {}
                    extra.append(f"    {dv.get('desc', '')[:36]}："
                                 f"{dv.get('version') or '-'} / "
                                 f"{dv.get('provider') or '-'} / "
                                 f"连接名 {dv.get('friendly') or '-'} / "
                                 f"状态 {p.get('status') or '-'}")
            if d.get("ping"):
                extra.append("  ping：" + "　".join(
                    f"{k}={'通' if v.get('ok') else '不通'}"
                    + (f"({v['avg']:.0f}ms)" if v.get("avg") else "")
                    for k, v in d["ping"].items()))
            if d.get("dns"):
                extra.append("  解析：" + "　".join(
                    f"{k}={'OK' if v.get('ok') else v.get('err', '')[:20]}"
                    for k, v in d["dns"].items()))
            px = d.get("proxy") or {}
            extra.append(f"  代理：WinINET 启用={px.get('enable')} "
                         f"服务器={px.get('server') or '-'}　PAC={px.get('pac') or '-'}　"
                         f"WinHTTP={px.get('winhttp') or '直连'}")
            if px.get("env"):
                extra.append("  环境变量：" + "　".join(f"{k}={v}" for k, v in px["env"].items()))
            if d.get("mtu"):
                extra.append(f"  MTU：{d['mtu'].get('detail')}")
            if d.get("firewall"):
                extra.append("  防火墙：" + "　".join(f"{p}={v}" for p, v in d["firewall"]))
            if d.get("passed"):
                pass
        text = self._md(it) + "\n\n" + "\n".join(extra)

        dlg = QDialog(self)
        dlg.setWindowTitle(it.get("title", "")[:60])
        dlg.resize(820, 560)
        v = QVBoxLayout(dlg)
        box = QPlainTextEdit(text)
        box.setReadOnly(True)
        v.addWidget(box, 1)
        row = QHBoxLayout()
        row.addStretch(1)
        b = QPushButton("复制")
        b.clicked.connect(lambda: QGuiApplication.clipboard().setText(box.toPlainText()))
        row.addWidget(b)
        ok = QPushButton("关闭")
        ok.clicked.connect(dlg.accept)
        row.addWidget(ok)
        v.addLayout(row)
        dlg.exec()

    # ---- 执行修复 ----
    def _run(self, items, auto=False):
        if self._task is not None or not items:
            return
        runnable = [i for i in items if i.get("fix_kind") in ("cmd", "action")]
        manual = [i for i in items if i.get("fix_kind") == "manual"]
        if not runnable:
            if manual:
                QMessageBox.information(
                    self, "这些需要手工处理",
                    "以下几条涉及重启或需要你判断参数，工具不代跑：\n\n"
                    + "\n".join(f"· {i['title']}" for i in manual[:8])
                    + "\n\n右键「复制修复命令」，按里面的步骤操作。")
            return

        listing = []
        for i in runnable:
            cmd = i.get("fix_text") or " ".join(i.get("fix_cmd") or [])
            listing.append(f"· {i['title']}\n     {cmd}")
            if i.get("reboot"):
                listing.append("     （执行后需要重启）")
        warn = QMessageBox(self)
        warn.setIcon(QMessageBox.Warning)
        warn.setWindowTitle("确认修复")
        warn.setText(f"将执行 {len(runnable)} 条修复：\n\n" + "\n".join(listing))
        if auto:
            warn.setInformativeText("这些都是幂等操作（不改配置、可随时重跑），确认继续？")
        else:
            warn.setInformativeText("标着「需确认」的会改动配置或短暂断网，确认继续？")
        warn.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        warn.setDefaultButton(QMessageBox.No)
        warn.button(QMessageBox.Yes).setText("执行")
        warn.button(QMessageBox.No).setText("取消")
        if warn.exec() != QMessageBox.Yes:
            return

        from .tasks import NetFixTask
        self._busy(True)
        self.lb_tail.setText("正在执行修复…")
        task = NetFixTask(runnable, parent=self)
        self._task = task
        task.log.connect(self.lb_tail.setText)
        task.done.connect(self._on_fixed)
        task.failed.connect(self._on_fail)
        task.finished.connect(self._clear_task)
        task.start()

    def _on_fixed(self, results):
        self._busy(False)
        ok = [r for r in results if r["res"].get("ok")]
        bad = [r for r in results if not r["res"].get("ok")]
        lines = [f"执行 {len(results)} 条：成功 {len(ok)}，失败/跳过 {len(bad)}", ""]
        for r in results:
            mark = "✓" if r["res"].get("ok") else "×"
            lines.append(f"{mark} {r['issue']['title'][:40]}")
            lines.append("    " + (r["res"].get("msg") or "")[:160])
        if bad:
            lines.append("")
            lines.append("失败的多半是权限或策略限制：用管理员身份重开 health_assistant.cmd 再试；"
                         "公司管控机上请先问 IT。")
        lines.append("")
        lines.append("修完建议点「重新诊断」确认效果。")
        QMessageBox.information(self, "修复结果", "\n".join(lines))
        self.lb_tail.setText(f"修复完成：成功 {len(ok)} / 失败 {len(bad)}")
        if ok:
            self.changed.emit()
        self.scan()
