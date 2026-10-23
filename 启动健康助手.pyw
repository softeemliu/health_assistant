"""双击启动（无黑框版）

`.pyw` 由 pythonw.exe 打开，进程本身不申请控制台窗口，所以双击之后
不会先闪一个 DOS 窗口。逻辑全部复用 health_assistant_app（含「哪个解释器装了
PySide6」的自检与自动换解释器）。

用法：双击本文件（唯一的日常入口）。
      tools/启动健康助手-控制台.bat 只留给计划任务/命令行，双击它一定会闪 cmd 窗口。
"""

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import health_assistant_app  # noqa: E402

if __name__ == "__main__":
    sys.exit(health_assistant_app.main())
