"""health_assistant.gui — PySide6 桌面应用入口

    python -m health_assistant.gui         # 或 python health_assistant_app.py（自动挑解释器）
"""

from __future__ import annotations

__all__ = ["run", "MainWindow"]


def run(argv=None):
    from .window import run as _run
    return _run(argv)


def __getattr__(name):
    """延迟导入 MainWindow，避免 import health_assistant.gui 时就要求装好 PySide6。"""
    if name == "MainWindow":
        from .window import MainWindow
        return MainWindow
    raise AttributeError(name)
