"""
health_assistant — Windows 本机巡检应用

图形界面（主入口）:
    双击 健康助手.exe                    # 打包版，免装 Python（dist/ 下）
    双击 启动巡检.pyw                    # 源码运行（不弹黑窗）
命令行（下面的 health_assistant = 项目根目录的 health_assistant.cmd，任意目录用绝对路径）:
    health_assistant                 # 全量巡检（文本，只列要处理的事）
    health_assistant --full          # 连正常项明细一起展开
    health_assistant system          # 只跑某个分组
    health_assistant profile         # 用户目录 / AppData / 点目录梳理
    health_assistant security --mask    # 账号/FTP 密码打码（默认明文）
    health_assistant port --all      # 端口 + 进程 + 启动参数
    health_assistant proc 1234       # 单进程详情（PID 或进程名）
    health_assistant kill --port 8080    # 终止占用端口的进程
    health_assistant clean           # 扫描系统盘残留 / 用户目录缓存（只读）
    health_assistant clean --yes     # 移到回收站
    health_assistant startup         # 开机自启项（--disable 名称 / --enable 名称 / --undo）
    health_assistant du C:\\          # 看空间去哪了（只统计，不删）
    health_assistant smart           # 硬盘健康（SMART / 磨损 / 温度 / 通电时间，只读）
    health_assistant mem             # 内存总览（--trim 释放 / --purge 清待机缓存）
    health_assistant lock "C:\\x"     # 查谁占着文件（--close 请它退出 / --kill 强制结束）
    health_assistant --format md --out report.md
    health_assistant list            # 查看所有已注册检查项

注意: `python -m health_assistant` 只在项目根目录下有效（包没有装进 site-packages）；
      在任意目录要用 health_assistant.cmd，这也正是报告里 fix 命令采用的形式。

扩展:
    在 plugins/ 下新建 .py，用 @check 装饰一个 func(ctx) -> Result 即可被自动发现

写检查项时，用 Result.add() 的结构化参数把结论变成可执行待办：
    res.add(Severity.WARN, "缓存占 12.7GB",
            impact="删了会自动重建，不影响设置",      # 不处理会怎样
            fix=cli_cmd("clean", "--kind", "profile", "--yes"),   # 提成绝对入口，粘贴即执行
            gain="释放 12.7GB", save_bytes=13613123567)           # 收益（字节用于合计）

fix 里不要写 `# 注释`：用户整行粘到 cmd 里会被当成参数，直接报错。
"""

from .core import (ActionPlan, Bars, Check, Context, Finding, Kind, KV,
                   REGISTRY, Result, Severity, Table, Text, check, cli_cmd,
                   get_checks, load_config)
from .runner import load_plugins, run_checks

__version__ = "4.19.0"
__all__ = [
    "check", "Result", "Severity", "Kind", "Finding", "KV", "Table", "Text", "Bars",
    "ActionPlan", "Check", "REGISTRY", "get_checks", "Context", "load_config",
    "cli_cmd",
    "run_checks", "load_plugins", "__version__",
]
