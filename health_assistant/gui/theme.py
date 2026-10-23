"""health_assistant.gui.theme — 配色、字体与 QSS

浅色专业风：中性灰底 + 白卡片 + 单一蓝色强调，状态色只用于文字与左侧色条，
避免整屏高饱和。所有颜色集中在 C 里，页面只引用常量。
"""

from __future__ import annotations

from PySide6.QtGui import QColor, QFont, QPalette
from PySide6.QtWidgets import QApplication

# ── 基础色 ──
C = {
    "bg": "#f3f5f8",          # 窗口底色
    "panel": "#ffffff",       # 卡片 / 表格底
    "panel_alt": "#fafbfc",   # 斑马纹
    "border": "#e0e5ec",
    "border_soft": "#edf0f4",
    "text": "#1f2733",
    "muted": "#6b7688",
    "faint": "#98a2b3",
    "accent": "#2563eb",
    "accent_soft": "#e8f0fe",
    "sel": "#dbe7fd",
}

# ── 状态色（文字 / 背景 / 边框） ──
SEV = {
    "ok":    ("#15803d", "#e9f6ee", "#bfe5cd"),
    "info":  ("#5b6b82", "#eef1f6", "#dde3ec"),
    "warn":  ("#a55a06", "#fdf3e3", "#f2d9ad"),
    "error": ("#c02626", "#fdecec", "#f5c4c4"),
}
SEV_LABEL = {"ok": "正常", "info": "信息", "warn": "警告", "error": "异常"}

FONT_FAMILY = "Microsoft YaHei UI"
FONT_FALLBACK = "Microsoft YaHei, Segoe UI, Arial"


def sev_color(sev: str) -> QColor:
    return QColor(SEV.get(sev, SEV["info"])[0])


def sev_bg(sev: str) -> str:
    return SEV.get(sev, SEV["info"])[1]


def sev_border(sev: str) -> str:
    return SEV.get(sev, SEV["info"])[2]


QSS = f"""
QWidget {{
    color: {C['text']};
    font-family: {FONT_FALLBACK};
    font-size: 13px;
}}
QMainWindow, QDialog {{ background: {C['bg']}; }}

/* ── 顶部标题栏 ── */
#Header {{
    background: {C['panel']};
    border-bottom: 1px solid {C['border']};
}}
#HeaderTitle {{ font-size: 15px; font-weight: 600; }}
#HeaderMeta  {{ color: {C['muted']}; font-size: 12px; }}
#HeaderHost  {{ font-size: 13px; font-weight: 600; color: {C['text']}; }}

/* ── 卡片 ── */
#Card {{
    background: {C['panel']};
    border: 1px solid {C['border']};
    border-radius: 8px;
}}
#CardValue {{ font-size: 22px; font-weight: 600; }}
#CardTitle {{ color: {C['muted']}; font-size: 12px; }}
#CardSub   {{ color: {C['faint']}; font-size: 11px; }}
#H1 {{ font-size: 16px; font-weight: 600; }}
#H2 {{ font-size: 14px; font-weight: 600; }}
#Muted {{ color: {C['muted']}; }}
#Faint {{ color: {C['faint']}; font-size: 12px; }}

/* ── 按钮 ── */
QPushButton {{
    background: {C['panel']};
    border: 1px solid {C['border']};
    border-radius: 6px;
    padding: 5px 14px;
    min-height: 20px;
}}
QPushButton:hover {{ background: #f7f9fc; border-color: #cfd8e3; }}
QPushButton:pressed {{ background: #eef2f7; }}
QPushButton:disabled {{ color: {C['faint']}; background: #f5f6f8; border-color: {C['border_soft']}; }}
QPushButton#Primary {{
    background: {C['accent']}; border-color: {C['accent']}; color: #ffffff; font-weight: 600;
}}
QPushButton#Primary:hover {{ background: #1d4fd8; border-color: #1d4fd8; }}
QPushButton#Primary:disabled {{ background: #a9c0f2; border-color: #a9c0f2; color: #f0f4ff; }}
QPushButton#Danger {{ color: {SEV['error'][0]}; border-color: {SEV['error'][2]}; }}
QPushButton#Danger:hover {{ background: {SEV['error'][1]}; }}

/* ── 状态筛选胶囊（明细页） ── */
QPushButton[chip="true"] {{
    border-radius: 13px;
    padding: 3px 12px;
    min-height: 18px;
    font-size: 12px;
    color: {C['muted']};
    background: {C['panel']};
}}
QPushButton[chip="true"]:hover {{ background: #f4f7fb; color: {C['text']}; }}
QPushButton[chip="true"]:checked {{
    background: {C['accent_soft']};
    border-color: {C['accent']};
    color: {C['accent']};
    font-weight: 600;
}}

/* ── 模式切换（清理页：常规清理 / 系统盘瘦身） ── */
/* 选中态用「实心蓝 + 白字」，不选的是「白底灰字」—— 之前用浅蓝底 + 蓝字，
   对比太弱，用户看不出到底点了哪个（3.8.3 反馈）。 */
QPushButton[mode="true"] {{
    padding: 6px 20px;
    min-height: 24px;
    font-weight: 600;
    color: {C['muted']};
    background: {C['panel']};
}}
QPushButton[mode="true"]:hover {{ background: #f4f7fb; color: {C['text']}; border-color: #cfd8e3; }}
QPushButton[mode="true"]:checked {{
    background: {C['accent']};
    border-color: {C['accent']};
    color: #ffffff;
}}
QPushButton[mode="true"]:checked:hover {{
    background: #1d4fd8;
    border-color: #1d4fd8;
    color: #ffffff;
}}
QPushButton[mode="true"]:checked:disabled {{
    background: #a9c0f2;
    border-color: #a9c0f2;
    color: #ffffff;
}}
QPushButton[mode="true"][seg="first"] {{
    border-top-right-radius: 0;
    border-bottom-right-radius: 0;
}}
QPushButton[mode="true"][seg="last"] {{
    border-top-left-radius: 0;
    border-bottom-left-radius: 0;
}}

/* ── 输入 ── */
QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox {{
    background: {C['panel']};
    border: 1px solid {C['border']};
    border-radius: 6px;
    padding: 4px 8px;
    min-height: 20px;
    selection-background-color: {C['sel']};
    selection-color: {C['text']};
}}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus {{
    border-color: {C['accent']};
}}
QComboBox::drop-down {{ border: none; width: 18px; }}
QComboBox QAbstractItemView {{
    background: {C['panel']};
    border: 1px solid {C['border']};
    selection-background-color: {C['sel']};
    selection-color: {C['text']};
    outline: none;
}}
QCheckBox {{ spacing: 6px; }}

/* ── 分页 ── */
/* 页签条和页面内容必须分成两层：
   选中页签的蓝色下划线和页面里「常规清理」的蓝色实心按钮原来贴在一起
   （零间距），蓝色连成一片，看着像按钮顶上多长了一条蓝边（4.0.1 反馈
   「很诡异」）。现在页签条自带一条通栏细线收尾，页面内容再往下留 10px，
   下划线就只属于页签，不会和按钮串味。 */
QTabWidget::pane {{
    border: none;
    background: transparent;
}}
QTabBar {{
    background: transparent;
    border-bottom: 1px solid {C['border']};
}}
QTabBar::tab {{
    background: transparent;
    border: none;
    border-bottom: 2px solid transparent;
    padding: 8px 16px;
    margin-right: 2px;
    color: {C['muted']};
}}
QTabBar::tab:hover {{ color: {C['text']}; }}
QTabBar::tab:selected {{
    color: {C['accent']};
    border-bottom: 2px solid {C['accent']};
    font-weight: 600;
}}
QTabBar::tab:disabled {{ color: {C['faint']}; }}

/* ── 表格 ── */
QTableWidget, QTableView {{
    background: {C['panel']};
    alternate-background-color: {C['panel_alt']};
    border: 1px solid {C['border']};
    border-radius: 8px;
    gridline-color: {C['border_soft']};
    selection-background-color: {C['sel']};
    selection-color: {C['text']};
    outline: none;
}}
QTableWidget::item, QTableView::item {{ padding: 3px 6px; }}
QHeaderView::section {{
    background: #f7f9fc;
    color: {C['muted']};
    border: none;
    border-bottom: 1px solid {C['border']};
    border-right: 1px solid {C['border_soft']};
    padding: 6px 8px;
    font-weight: 600;
}}
QHeaderView::section:last {{ border-right: none; }}
QTableCornerButton::section {{ background: #f7f9fc; border: none; }}

/* ── 列表（检查项） ── */
QListWidget {{
    background: {C['panel']};
    border: 1px solid {C['border']};
    border-radius: 8px;
    outline: none;
    padding: 4px;
}}
QListWidget::item {{
    padding: 6px 8px;
    border-radius: 5px;
    color: {C['text']};
}}
QListWidget::item:hover {{ background: #f4f7fb; }}
QListWidget::item:selected {{ background: {C['accent_soft']}; color: {C['text']}; }}

/* ── 文本区 ── */
QPlainTextEdit, QTextBrowser {{
    background: {C['panel']};
    border: 1px solid {C['border']};
    border-radius: 8px;
    padding: 6px;
    selection-background-color: {C['sel']};
    selection-color: {C['text']};
}}
QPlainTextEdit#Console {{
    font-family: Consolas, {FONT_FALLBACK};
    font-size: 12px;
}}

/* ── 滚动条 ── */
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{
    background: #cbd4e1; border-radius: 5px; min-height: 28px;
}}
QScrollBar::handle:vertical:hover {{ background: #b3bfd0; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:horizontal {{
    background: #cbd4e1; border-radius: 5px; min-width: 28px;
}}
QScrollBar::handle:horizontal:hover {{ background: #b3bfd0; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}

/* ── 状态栏 / 工具条 ── */
QStatusBar {{ background: {C['panel']}; border-top: 1px solid {C['border']}; color: {C['muted']}; }}
QStatusBar::item {{ border: none; }}
QToolBar {{ background: transparent; border: none; spacing: 6px; }}
QSplitter::handle {{ background: transparent; }}
QSplitter::handle:horizontal {{ width: 10px; }}
QSplitter::handle:vertical {{ height: 10px; }}

/* ── 进度 ── */
QProgressBar {{
    background: {C['border_soft']};
    border: none;
    border-radius: 3px;
    height: 6px;
    text-align: center;
    color: transparent;
}}
QProgressBar::chunk {{ background: {C['accent']}; border-radius: 3px; }}

QMenu {{
    background: {C['panel']};
    border: 1px solid {C['border']};
    border-radius: 6px;
    padding: 4px;
}}
QMenu::item {{ padding: 6px 22px 6px 14px; border-radius: 4px; }}
QMenu::item:selected {{ background: {C['accent_soft']}; }}
QMenu::separator {{ height: 1px; background: {C['border_soft']}; margin: 4px 8px; }}

QScrollArea {{ background: transparent; border: none; }}
QScrollArea > QWidget > QWidget {{ background: transparent; }}
"""


def apply_theme(app: QApplication):
    """Fusion 风格 + 调色板 + QSS，保证在浅色/深色系统上观感一致。"""
    app.setStyle("Fusion")

    font = QFont(FONT_FAMILY, 9)
    font.setStyleStrategy(QFont.PreferAntialias)
    app.setFont(font)

    pal = QPalette()
    pal.setColor(QPalette.Window, QColor(C["bg"]))
    pal.setColor(QPalette.Base, QColor(C["panel"]))
    pal.setColor(QPalette.AlternateBase, QColor(C["panel_alt"]))
    pal.setColor(QPalette.Text, QColor(C["text"]))
    pal.setColor(QPalette.WindowText, QColor(C["text"]))
    pal.setColor(QPalette.ButtonText, QColor(C["text"]))
    pal.setColor(QPalette.Highlight, QColor(C["sel"]))
    pal.setColor(QPalette.HighlightedText, QColor(C["text"]))
    pal.setColor(QPalette.ToolTipBase, QColor("#ffffff"))
    pal.setColor(QPalette.ToolTipText, QColor(C["text"]))
    app.setPalette(pal)

    app.setStyleSheet(QSS)
