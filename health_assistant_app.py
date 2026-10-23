"""启动器（源码运行 + 打包后运行共用这一个入口）

两种身份：

1. **源码运行**（双击「启动巡检.pyw」/ `python health_assistant_app.py`）
   PATH 里的 `python` 未必是装了 PySide6 的那个解释器（本机 C:\\Python3 才是），
   所以这里先自检：当前解释器能 import PySide6 就直接跑；否则依次探测候选解释器，
   找到合适的再用它重新拉起 ``python -m health_assistant.gui``。

2. **打包后的 EXE**（PyInstaller 冻结，``sys.frozen`` 为真）
   解释器已经在 EXE 里了，绝不能再走上面的「探测解释器 + 换 pythonw 重开」——
   那条路会把 ``sys.executable``（就是 EXE 自己）当成 python 再跑一遍，无限递归。
   冻结后直接进 ``health_assistant.gui.run()``；带参数时按命令行模式跑（见 `_frozen_cli`）。

用法：
    双击「健康助手.exe」               # 日常入口，无控制台窗口
    "健康助手.exe" smart               # 命令行模式（输出在控制台/重定向文件里）
    python health_assistant_app.py           # 源码调试
"""

from __future__ import annotations

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
FROZEN = bool(getattr(sys, "frozen", False))


# ───────────────────────── 冻结版：命令行模式 ─────────────────────────

def _ensure_console():
    """给冻结版的命令行模式找个能输出的地方。

    窗口程序（--windowed）默认没有控制台，按这个顺序找：
      1. **已被重定向到文件/管道** → 原样保留，一个字都不动（最要紧的是这条，
         否则 `健康助手.exe list > 结果.txt` 会把重定向抢掉）。
      2. 从 cmd 里跑 → AttachConsole 挂到父进程的控制台；一次性打包时父进程是
         自己的引导程序（没有控制台），挂不上，继续往下。
      3. 都拿不到 → AllocConsole 新开一个窗口，至少别把结果吞掉。

    代码页统一设 65001，否则中文在 936 下会花屏。
    """
    if os.name != "nt":
        return
    import ctypes

    k32 = ctypes.windll.kernel32
    try:
        k32.AttachConsole(-1)                 # ATTACH_PARENT_PROCESS
    except Exception:
        pass
    k32.SetConsoleOutputCP(65001)
    k32.SetConsoleCP(65001)

    def reopen(name, mode):
        try:
            return open(name, mode, encoding="utf-8", errors="replace", buffering=1)
        except OSError:
            return None

    def ok(s, attr):
        try:
            return s is not None and not s.closed and hasattr(s, attr)
        except Exception:
            return False

    need = [("stdout", "CONOUT$", "w"), ("stderr", "CONOUT$", "w")]
    if any(not ok(getattr(sys, n, None), "write") for n, _f, _m in need):
        if not k32.GetConsoleWindow() and not k32.AllocConsole():
            return                        # 连控制台都开不出来：输出就没了，但不崩
    for name, dev, mode in need:
        if not ok(getattr(sys, name, None), "write"):
            stream = reopen(dev, mode)
            if stream is not None:
                setattr(sys, name, stream)
    if not ok(getattr(sys, "stdin", None), "read"):
        stream = reopen("CONIN$", "r")
        if stream is not None:
            sys.stdin = stream


def _frozen_cli(argv):
    """冻结后带参数运行 = 命令行模式（``健康助手.exe list`` 这种）。"""
    _ensure_console()
    try:
        from health_assistant.cli import main as cli_main
        return cli_main(argv)
    except SystemExit as exc:
        return exc.code or 0
    except Exception as exc:                  # noqa: BLE001 — 崩了也要留在窗口里看得到
        print(f"出错了：{type(exc).__name__}: {exc}")
        return 1


def _quiet():
    """隐藏子进程控制台窗口（GUI 进程没有控制台，子进程会自己新开黑框）。"""
    if os.name != "nt":
        return {}
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0
    return {"creationflags": 0x08000000, "startupinfo": si}


def _windowless(exe):
    """把 python.exe 换成同目录的 pythonw.exe —— 子进程连控制台都不申请。"""
    if os.name != "nt" or not exe.lower().endswith("python.exe"):
        return exe
    candidate = exe[:-len("python.exe")] + "pythonw.exe"
    return candidate if os.path.isfile(candidate) else exe


def _candidates():
    """按「最可能装了 PySide6」的顺序给出解释器候选。"""
    out = [sys.executable]
    if os.name == "nt":
        out.append(r"C:\Python3\python.exe")
        for base in (os.environ.get("LOCALAPPDATA", ""),
                     os.environ.get("ProgramFiles", ""),
                     os.environ.get("ProgramFiles(x86)", "")):
            if not base:
                continue
            pdir = os.path.join(base, "Programs", "Python")
            if os.path.isdir(pdir):
                for name in sorted(os.listdir(pdir), reverse=True):
                    exe = os.path.join(pdir, name, "python.exe")
                    if os.path.isfile(exe):
                        out.append(exe)
        for name in ("python", "python3"):
            out.append(name)
    else:
        out.append("/usr/bin/python3")

    seen, uniq = set(), []
    for c in out:
        key = os.path.normcase(c)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(c)
    return uniq


def _has_pyside(exe):
    try:
        r = subprocess.run([exe, "-c", "import PySide6"],
                           capture_output=True, timeout=30, **_quiet())
        return r.returncode == 0
    except Exception:
        return False


def main():
    # 改名前后的配置目录迁移（幂等、只复制不删）。放在最前面：
    # GUI / CLI / 冻结版都要走，晚一步就可能读到空配置或看不到历史台账。
    try:
        from health_assistant.core import migrate_legacy_dirs
        migrate_legacy_dirs()
    except Exception as exc:                       # noqa: BLE001
        print(f"[提示] 旧目录迁移跳过：{exc}", file=sys.stderr)

    # 冻结后不许再走「探测解释器」那条路（sys.executable 就是 EXE 自己，会自己拉自己）
    if FROZEN:
        if len(sys.argv) > 1:
            return _frozen_cli(sys.argv[1:])
        from health_assistant.gui import run
        return run()

    if _has_pyside(sys.executable):
        from health_assistant.gui import run
        return run()

    for exe in _candidates()[1:]:
        if os.path.sep in exe and not os.path.isfile(exe):
            continue
        if not _has_pyside(exe):
            continue
        print(f"使用解释器：{exe}")
        # 用 pythonw 重新拉起：换解释器时也不会多出一个黑窗口
        return subprocess.call([_windowless(exe), "-m", "health_assistant.gui"],
                               cwd=ROOT, **_quiet())

    print("未找到安装 PySide6 的 Python 解释器。", file=sys.stderr)
    print("安装命令示例：", file=sys.stderr)
    print("    C:\\Python3\\python.exe -m pip install PySide6 psutil", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
