"""health_assistant.gui.window — 主窗口

主界面按「普通使用者（行政等非技术岗）」设计：
· 八个页签：体检结果 / 清理空间 / 网络 / 进程 / 监听端口 / 密码与账号 / FTP / 数据恢复
  （只有「体检结果」开机就建，其余第一次点开才建 —— 见 PAGE_SPECS）。
  子模块入口就是页签本身 —— 早期那排「常用工具」按钮与页签重复，3.5.5 已删除；
· 3.7.2 起去掉「跳板机」页（安全考虑：不再在本工具里保存第三方系统账号密码，
  也不再内嵌 WebEngine 存会话 cookie）；
· 标题栏只有 开始检查 / 停止 / 保存报告 / 更多，没有范围选择和 JSON 导出。

底部状态栏（进度 + 提示）。运行日志不占界面：所有消息逐行落盘
（%LOCALAPPDATA%\\health_assistant\\gui.log），界面只在状态栏闪一条提示。
"""

from __future__ import annotations

import gc
import os
import platform
import time

from PySide6.QtCore import QPoint, Qt, QTimer
from PySide6.QtGui import QAction, QColor, QFont, QIcon, QPainter, QPixmap
from PySide6.QtWidgets import (QApplication, QFileDialog, QHBoxLayout,
                               QLabel, QMainWindow, QMenu, QMessageBox,
                               QProgressBar, QPushButton, QTabWidget,
                               QVBoxLayout, QWidget)

from .. import __version__, checks, render                     # noqa: F401 导入即注册
from ..core import BASE_DIR, get_checks, load_config
from ..legacy import purge_legacy_secrets
from .pages import (CleanPage, CredsPage, DetailPage, FtpPage, NetHelpPage,
                    PortsPage, ProcsPage, RecoveryPage)
from .tasks import InspectTask, meta_info
from .theme import C, SEV, apply_theme
from . import single

# 3.5.4 起所有子模块都是主窗口里的页签，不再弹独立窗口
# （用户要求：进程、修复网络等直接在一个窗口里完成）。
# 3.7.2 起「跳板机」页已移除（安全考虑）。
# 4.1.0 起多一个「FTP」页（文件传输工具），页签共 7 个。
TAB_DETAIL, TAB_CLEAN, TAB_NET, TAB_PROCS, TAB_PORTS, TAB_CREDS, TAB_FTP, \
    TAB_RECOVER = range(8)

# 页签清单：key、显示名、页面类。**只有第一个开机就建**，其余第一次点开才建。
# 为什么这么改（4.6.0，用户反馈「内存和 CPU 消耗蛮大」）：
# 七页全在构造时建好，等于每次启动都把 7 页的控件、样式、数据摆一遍；
# 实测多花 ~0.3s、多占 ~20MB 常驻内存，而多数人只会看体检页。
# 页签文字、顺序、位置全不变，只是内容按需生成，观感一致。
PAGE_SPECS = (
    ("detail", "体检结果", DetailPage),
    ("clean", "清理空间", CleanPage),
    ("net", "网络", NetHelpPage),
    ("procs", "进程", ProcsPage),
    ("ports", "监听端口", PortsPage),
    ("creds", "密码与账号", CredsPage),
    ("ftp", "FTP", FtpPage),
    ("recover", "数据恢复", RecoveryPage),
)
_PAGE_META = {k: (n, c) for k, n, c in PAGE_SPECS}
_PAGE_INDEX = {k: i for i, (k, _n, _c) in enumerate(PAGE_SPECS)}
TAB_KEY = {i: k for i, (k, _n, _c) in enumerate(PAGE_SPECS)}

PAGE_OF = {"procs": TAB_PROCS, "ports": TAB_PORTS, "creds": TAB_CREDS,
           "netfix": TAB_NET, "clean": TAB_CLEAN, "clean_slim": TAB_CLEAN,
           "mem_boost": TAB_PROCS, "startup": TAB_PROCS, "disk_use": TAB_CLEAN,
           "recover": TAB_RECOVER, "detail": TAB_DETAIL}

PAGE_HINT = {
    "procs": "这一页是技术向的：看现在跑着哪些程序、各占多少 CPU / 内存",
    "ports": "这一页是技术向的：看哪些程序在对外开端口",
    "creds": "这一页含明文密码：看完记得关掉，别截图外发",
    "clean_slim": "已切到「系统盘瘦身」并开始扫描：只勾了删了肯定没影响的那几类",
    "mem_boost": "已打开「内存加速」：占用高的进程默认勾上，释放的是物理内存占用，进程不会退出",
    "startup": "已打开「开机自启项」：停用只是让它在开机时不启动，随时能恢复",
    "disk_use": "已打开「空间去哪了」：一层层往下钻，看空间到底被谁占了",
}


class RunLog:
    """运行日志的落点（界面里已经没有日志页了）。

    写 %LOCALAPPDATA%\\health_assistant\\gui.log，超过 1MB 就滚成 gui.log.1；
    写不进去也不会影响界面，静默放弃即可。
    """

    def __init__(self, path=None):
        base = path or os.path.join(
            os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"),
            "health_assistant", "gui.log")
        self.path = base
        try:
            os.makedirs(os.path.dirname(base), exist_ok=True)
            if os.path.exists(base) and os.path.getsize(base) > 1024 * 1024:
                os.replace(base, base + ".1")
        except OSError:
            self.path = None

    def append(self, text):
        if not self.path:
            return
        try:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {text}\n")
        except OSError:
            self.path = None



def app_icon():
    """窗口 / 任务栏图标。

    优先用项目根目录的 health_assistant.ico（多尺寸帧，任务栏和 Alt-Tab 更清晰，
    由 tools/make_icon.py 生成）；找不到就现画一个，不依赖外部资源也能跑。
    """
    ico = os.path.join(BASE_DIR, "health_assistant.ico")
    if os.path.isfile(ico):
        icon = QIcon(ico)
        if not icon.isNull():
            return icon

    pm = QPixmap(64, 64)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing, True)
    p.setBrush(QColor(C["accent"]))
    p.setPen(Qt.NoPen)
    p.drawRoundedRect(2, 2, 60, 60, 14, 14)
    p.setPen(QColor("#ffffff"))
    f = QFont("Microsoft YaHei UI", 26)
    f.setBold(True)
    p.setFont(f)
    p.drawText(pm.rect(), Qt.AlignCenter, "巡")
    p.end()
    return QIcon(pm)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.cfg, self.cfg_src = load_config(None)
        self._task = None
        self._items = []
        self._done_payload = None
        self.log = RunLog()
        self._pages = {}                # key → 已建好的页面（懒建，见 _build_page）
        self._building_page = False

        self.setWindowTitle("健康助手")
        self.setWindowIcon(app_icon())
        self.resize(1460, 920)
        self.setMinimumSize(1180, 720)

        self._build()
        # 启动阶段建的这些控件、字体、样式表基本活到关闭，把它们移出 GC 的分代扫描：
        # 之后每次年轻代回收都要把这几万个对象摸一遍，纯属浪费 CPU。
        gc.collect()
        gc.freeze()
        QTimer.singleShot(500, self.start_inspect)

    # ───────────────────────── 页面（懒建） ─────────────────────────
    def _build_page(self, key):
        """建（或取回）某个页签的页面。返回页面对象；构造过程中重入则返回 None。"""
        page = self._pages.get(key)
        if page is not None:
            return page
        meta = _PAGE_META.get(key)
        if meta is None or self._building_page:
            return None
        name, cls = meta
        idx = _PAGE_INDEX[key]
        self._building_page = True
        try:
            page = cls(self.cfg)
            page.notify.connect(self._on_notify)
            # 页面内容统一离页签条 10px：页签的蓝色下划线和页面里第一个
            # 蓝色按钮贴在一起会连成一片（看着像按钮多了条蓝边）。
            lay = page.layout()
            if lay is not None:
                m = lay.contentsMargins()
                lay.setContentsMargins(m.left(), m.top() + 10, m.right(), m.bottom())
            self._pages[key] = page
            old = self.tabs.widget(idx)
            was_current = self.tabs.currentIndex() == idx
            self.tabs.blockSignals(True)          # 别在换控件时再触发一轮 currentChanged
            self.tabs.removeTab(idx)
            self.tabs.insertTab(idx, page, name)
            if was_current:
                # 只在「用户正看着这个占位符」时把当前页重新指向真页面；
                # 纯粹因为别人拿了一下属性（self.procs）就跳页签是不对的。
                self.tabs.setCurrentIndex(idx)
            self.tabs.blockSignals(False)
            if old is not None:
                old.deleteLater()
            return page
        finally:
            self._building_page = False

    # 属性写法沿用原来的 self.clean / self.procs …，外部代码一行都不用改
    @property
    def detail(self):
        return self._build_page("detail")

    @property
    def clean(self):
        return self._build_page("clean")

    @property
    def net(self):
        return self._build_page("net")

    @property
    def procs(self):
        return self._build_page("procs")

    @property
    def ports(self):
        return self._build_page("ports")

    @property
    def creds(self):
        return self._build_page("creds")

    @property
    def ftp(self):
        return self._build_page("ftp")

    @property
    def recover(self):
        return self._build_page("recover")

    # ───────────────────────── 单实例：被叫醒 ─────────────────────────
    def activate_window(self):
        """第二个实例双击 exe 时，把已经开着的这个窗口叫到前面来。"""
        if self.isMinimized():
            self.setWindowState(self.windowState() & ~Qt.WindowMinimized)
        self.show()
        self.raise_()
        self.activateWindow()
        try:
            hwnd = int(self.winId())
        except Exception:                       # noqa: BLE001
            hwnd = 0
        if hwnd and os.name == "nt":
            try:
                import ctypes
                u32 = ctypes.WinDLL("user32")
                u32.ShowWindow(ctypes.c_void_p(hwnd), 9)          # SW_RESTORE
                u32.SetForegroundWindow(ctypes.c_void_p(hwnd))
                u32.GetForegroundWindow.restype = ctypes.c_void_p
                if (u32.GetForegroundWindow() or 0) != hwnd:
                    # 前台锁抢不过别的程序：闪任务栏，至少让人看见它在哪
                    single.flash_taskbar(hwnd)
            except Exception:                   # noqa: BLE001
                pass
        try:
            self.lb_status.setText("已经有一个「健康助手」在运行，已切到这个窗口")
        except Exception:                       # noqa: BLE001
            pass

    # ───────────────────────── 构建界面 ─────────────────────────
    def _build(self):
        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_header())

        body = QWidget()
        bl = QVBoxLayout(body)
        bl.setContentsMargins(14, 10, 14, 8)
        bl.setSpacing(8)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)

        # 七个页签全在主窗口里 —— 进程 / 端口 / 凭据 / FTP 都不弹独立窗口。
        # 4.6.0 起先只放占位控件，点开哪一个才建哪一个（见 _build_page）。
        for _key, name, _cls in PAGE_SPECS:
            self.tabs.addTab(QWidget(), name)
        self._build_page("detail")

        self.detail.goto_page.connect(self._goto_page)
        self.tabs.currentChanged.connect(self._on_tab)

        bl.addWidget(self.tabs, 1)
        root.addWidget(body, 1)
        self.setCentralWidget(central)

        # 状态栏
        self.pb = QProgressBar()
        self.pb.setFixedWidth(220)
        self.pb.setFixedHeight(6)
        self.pb.hide()
        self.lb_status = QLabel("就绪")
        self.lb_status.setObjectName("Muted")
        self.lb_right = QLabel(f"v{__version__}")
        self.lb_right.setObjectName("Faint")
        self.statusBar().addWidget(self.lb_status, 1)
        self.statusBar().addPermanentWidget(self.pb)
        self.statusBar().addPermanentWidget(self.lb_right)
        self.statusBar().setSizeGripEnabled(False)

        self.log.append(f"配置来源：{self.cfg_src or '内置默认值'}")
        # 状态栏的 lb_right 建好之后才能挂 meta 提示（_refresh_meta 内部会写它）
        self._refresh_meta()

    def _on_notify(self, text):
        """页面动作提示：写日志文件，状态栏闪 5 秒（不再有日志页）。"""
        self.log.append(text)
        self.statusBar().showMessage(str(text).replace("\n", " "), 5000)

    def _build_header(self):
        head = QWidget()
        head.setObjectName("Header")
        head.setFixedHeight(56)
        lay = QHBoxLayout(head)
        lay.setContentsMargins(16, 8, 16, 8)
        lay.setSpacing(12)

        # 左边原来那两行「本机巡检 DESKTOP-xxx / Windows 10 · 用户 Administrator」
        # 4.0.2 按用户要求整块去掉：机器名和系统版本对普通使用者没有信息量，
        # 而报告里本来就带着这些；需要时把鼠标停到右下角版本号上还能看到。
        lay.addStretch(1)

        # 「范围」下拉去掉了 —— 普通使用者不会挑检查范围，全查就好；
        # 技术人员有命令行（health_assistant.cmd run <范围>）。
        self.btn_start = QPushButton("开始检查")
        self.btn_start.setObjectName("Primary")
        self.btn_start.setMinimumWidth(96)
        self.btn_start.clicked.connect(self.start_inspect)
        lay.addWidget(self.btn_start)

        self.btn_stop = QPushButton("停止")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_inspect)
        lay.addWidget(self.btn_stop)

        # 保存报告一步到位（发给 IT 看的 Markdown）；原始数据收进「更多工具」
        self.btn_export = QPushButton("保存报告")
        self.btn_export.setEnabled(False)
        self.btn_export.setToolTip("把检查结果存成一个文件，发给 IT 就行")
        self.btn_export.clicked.connect(lambda: self.export("md"))
        lay.addWidget(self.btn_export)

        # 进程 / 端口 / 凭据已经在下面工具条上直接摆出来了，这里只留技术向的杂项
        self.btn_tools = QPushButton("更多 ▾")
        menu = QMenu(self)
        menu.addAction("导出原始数据（JSON，给 IT）", lambda: self.export("json"))
        menu.addAction("打开配置文件夹", self._open_cfg_dir)
        menu.addSeparator()
        menu.addAction("打开运行日志文件", self._open_log)
        self._tools_menu = menu
        self.btn_tools.clicked.connect(self._show_tools_menu)
        lay.addWidget(self.btn_tools)

        return head

    def _show_tools_menu(self):
        self._tools_menu.exec(
            self.btn_tools.mapToGlobal(QPoint(0, self.btn_tools.height() + 4)))

    def _refresh_meta(self):
        """机器名 / 系统 / 用户不再摆在顶部，收进右下角版本号的悬停提示。"""
        m = meta_info()
        os_short = f"{platform.system()} {platform.release()}"
        self._meta_tip = f"{m['host']}　·　{os_short}　·　用户 {m['user']}"
        self._update_right_tip()

    def _update_right_tip(self):
        tip = getattr(self, "_meta_tip", "")
        if self.cfg_src:
            tip = f"{tip}\n配置文件：{self.cfg_src}"
        self.lb_right.setToolTip(tip)

    def _open_log(self):
        path = self.log.path
        if not path or not os.path.isfile(path):
            QMessageBox.information(self, "运行日志", "日志文件还没生成。")
            return
        try:
            os.startfile(path)
        except Exception as exc:
            QMessageBox.information(self, "运行日志", f"{path}\n\n{exc}")

    def _open_cfg_dir(self):
        base = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "health_assistant")
        try:
            os.makedirs(base, exist_ok=True)
            os.startfile(base)
        except Exception as exc:
            QMessageBox.information(self, "配置文件夹", f"{base}\n\n{exc}")

    # ───────────────────────── 页签 ─────────────────────────
    def _on_tab(self, idx):
        """切页签时懒加载：页面第一次进来才建，数据第一次进来才读。"""
        if self._building_page:
            return
        key = TAB_KEY.get(idx)
        if key is None:
            return
        page = self._build_page(key)          # 就是当前页，通常是已建好的
        if page is None:
            return
        if key == "procs" and not page._rows:
            page.reload()
        elif key == "ports" and not page._rows:
            page.reload()
        elif key == "creds":
            page._ensure()

    # ───────────────────────── 巡检 ─────────────────────────
    def start_inspect(self):
        if self._task is not None and self._task.isRunning():
            return
        targets = get_checks(None, include_disabled=self.cfg.get("disabled") or [])
        if not targets:
            QMessageBox.information(self, "没有可执行的检查项",
                                    "配置里可能把检查项都禁用了，检查 config.json")
            return

        self._items = []
        self._done_payload = None
        self.detail.prepare(targets)
        self.detail.set_running(True)
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.btn_export.setEnabled(False)
        self.pb.setRange(0, 0)
        self.pb.show()
        self.lb_status.setText(f"正在检查：0/{len(targets)}")
        self.log.append(f"开始巡检 {len(targets)} 项")

        plugin_dirs = list(self.cfg.get("plugin_dirs") or [])
        default_plugins = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "plugins")
        if os.path.isdir(default_plugins):
            plugin_dirs.append(default_plugins)

        task = InspectTask(self.cfg, selector=None, plugin_dirs=plugin_dirs, parent=self)
        self._task = task
        task.item.connect(self._on_item)
        task.progress.connect(self._on_progress)
        task.log.connect(self.log.append)
        task.done.connect(self._on_done)
        task.failed.connect(self._on_failed)
        task.finished.connect(self._on_finished)
        task.start()

    def stop_inspect(self):
        if self._task is not None:
            self._task.stop()
            self.btn_stop.setEnabled(False)
            self.lb_status.setText("正在停止…（当前检查项执行完即停）")

    def _on_item(self, d):
        self._items.append(d)
        self.detail.upsert(d)

    def _on_progress(self, i, n, text):
        if n:
            self.pb.setRange(0, n)
            self.pb.setValue(i)
        self.lb_status.setText(f"{text}　{i}/{n}")

    def _on_failed(self, msg):
        self.detail.set_running(False)
        self.lb_status.setText("巡检失败：" + msg.splitlines()[-1])
        self.log.append("[巡检失败] " + msg)
        QMessageBox.critical(self, "巡检失败", msg)

    def _on_done(self, payload):
        self._done_payload = payload
        self.btn_export.setEnabled(True)
        self.detail.set_running(False)
        s = payload["summary"]
        todo = payload["plan"].get("count", 0)
        secs = s.get("elapsed_sec", 0)
        if todo:
            self.lb_status.setText(f"检查完成：发现 {todo} 件要处理的事，用时 {secs:.0f} 秒")
        else:
            self.lb_status.setText(
                f"检查完成：一切正常（{s.get('total', 0)} 项检查，用时 {secs:.0f} 秒）")
        self.log.append(
            f"巡检完成：{s.get('total', 0)} 项 / 用时 {secs:.1f}s / 待处理 {todo} 条")
        self.lb_right.setText(f"v{__version__}　{time.strftime('%H:%M:%S')}")

    def _on_finished(self):
        self._task = None
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.pb.hide()

    def _goto_page(self, key):
        """明细页右键「跳到…」：统一切页签（不再弹窗口）。"""
        idx = PAGE_OF.get(key)
        if idx is None:
            return
        # 先把它建出来再切：切过去的瞬间页面必须已经是完整的
        self._build_page(TAB_KEY.get(idx, "detail"))
        self.tabs.setCurrentIndex(idx)
        self._on_tab(idx)
        if key == "clean_slim":
            # 从体检页直接进瘦身：切模式 + 立刻开扫，省掉「再点一次扫描」
            self.clean.enter_slim()
        elif key == "mem_boost":
            # 内存告警时一键到「内存加速」，不用自己找进程页
            self.procs.open_mem_boost()
        elif key == "startup":
            # 开机自启项告警时一键到管理窗口
            self.procs.open_startup()
        elif key == "disk_use":
            # 「空间去哪了」：从体检页/清理页直接钻进目录体积视图
            self.clean.open_disk_use()
        name = self.tabs.tabText(idx)
        if key in PAGE_HINT:
            self.lb_status.setText(PAGE_HINT[key])
        else:
            self.lb_status.setText(f"已切到「{name}」")

    # ───────────────────────── 导出 ─────────────────────────
    def export(self, fmt="json"):
        payload = self._done_payload
        if not payload:
            QMessageBox.information(self, "还没有结果", "先执行一次巡检再导出")
            return
        stamp = time.strftime("%Y%m%d-%H%M%S")
        host = payload["meta"].get("host", "pc")
        ext = "json" if fmt == "json" else "md"
        path, _ = QFileDialog.getSaveFileName(
            self, "导出报告", f"health_assistant-{host}-{stamp}.{ext}",
            "JSON 文件 (*.json)" if fmt == "json" else "Markdown 文件 (*.md)")
        if not path:
            return
        try:
            fn = render.render_json if fmt == "json" else render.render_markdown
            text = fn(payload["meta"], payload["pairs"], payload["summary_obj"])
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        except Exception as exc:
            QMessageBox.critical(self, "导出失败", f"{type(exc).__name__}: {exc}")
            return
        self.log.append(f"已导出报告：{path}")
        QMessageBox.information(self, "导出完成", path)

    # ───────────────────────── 关闭 ─────────────────────────
    def closeEvent(self, ev):
        # 只碰已经建过的页面：没建过的页面没有线程、没有 socket，不用管
        net = self._pages.get("net")
        if net is not None:
            net.stop()                # 网络逐条检索的线程先收手
        ftp = self._pages.get("ftp")
        if ftp is not None:
            ftp.shutdown()            # FTP：停传输 + 断开连接（别把 socket 留着）
        for page in list(self._pages.values()):
            t = getattr(page, "_task", None)
            if t is not None and t.isRunning():
                if hasattr(t, "stop"):
                    t.stop()
                t.quit()
                t.wait(2000)
        if self._task is not None and self._task.isRunning():
            self._task.stop()
            self._task.wait(3000)
        super().closeEvent(ev)


def run(argv=None):
    """GUI 入口。"""
    import sys
    # 3.7.2 起不再用 QtWebEngine（跳板机页已移除），
    # 也就不必再设 AA_ShareOpenGLContexts。
    app = QApplication(sys.argv if argv is None else list(argv))
    app.setApplicationName("health_assistant")
    # 显示名和窗口标题保持一致，否则 Qt 会把显示名再拼一遍到标题栏末尾
    # （之前窗口标题是「本机巡检 · health_assistant 4.0.1 · 本机巡检」就是这么来的）
    app.setApplicationDisplayName("健康助手")
    app.setWindowIcon(app_icon())
    apply_theme(app)

    # ── 只允许一个界面实例（4.6.0）──
    # 第二个实例不弹窗、不建界面，只负责把第一个窗口叫到前面然后自己退出；
    # 这样连点两下 exe 不会出现两个界面同时巡检、抢同一份日志和配置。
    guard = single.Guard()
    if not guard.acquire():
        single.allow_other_foreground()
        ok = guard.notify()
        if not ok:
            # 对方可能刚起来还没开始听门铃，给它一点时间再来一次
            time.sleep(1.2)
            ok = guard.notify()
        if ok:
            return 0
        QMessageBox.information(
            None, "健康助手已经在运行",
            "这台电脑上已经有一个「健康助手」在跑，但没能把它叫到前面来。\n\n"
            "请到任务栏或按 Alt+Tab 找一下。如果实在找不到，"
            "就在任务管理器里结束「健康助手」，再重新打开。")
        return 0

    # 升级上来的机器上可能还留着旧版存过的第三方账号密码 / 会话 cookie，先清掉
    purge_legacy_secrets()
    win = MainWindow()
    guard.listen(win.activate_window)
    win.show()
    try:
        return app.exec()
    finally:
        guard.release()
