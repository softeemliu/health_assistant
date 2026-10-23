"""health_assistant.gui.single — 只允许一个界面实例在跑（4.6.0）

用户要求：「增加一个限制，只能运行一个实例」。

为什么这道闸只装在**界面**入口（``window.run()``）上，不装在 exe 入口：
命令行模式（``健康助手.exe list`` / ``clean --yes``）不建窗口、不抢任何文件，
前台和它同时跑没有任何冲突。把命令行也挡掉，只会让「界面开着就导不出报告」。

两道机制各管一件事：

* **命名互斥体**判「有没有人在跑」。进程退出（包括崩溃、被任务管理器结束）时
  由内核自动释放，不存在锁文件残留 —— 用 ``.lock`` 文件的老办法崩溃一次就再也
  打不开了。名字用 ``Local\\`` 前缀 + 用户名：同一台机器上多个远程桌面会话（不同
  用户）各开各的，互不影响。
* **本地套接字**让第二个实例把话带给第一个：「把窗口叫到前面来」。用户双击 exe
  的预期是「看到那个窗口」，不是「什么都没发生」。

设计原则：**机制失效不许拒绝服务**。互斥体创建失败（权限、非 Windows）、
管道连不上（对方卡死），一律退回「照常启动一个」，最坏是开了两个窗口，
而不是打不开。
"""

from __future__ import annotations

import os
import sys

__all__ = ["Guard", "mutex_name", "pipe_name"]

_MUTEX_TMPL = "Local\\health_assistant-gui-%s"
_PIPE_TMPL = "health_assistant-gui-%s"

_ERROR_ALREADY_EXISTS = 183


def _tag():
    """互斥体/管道名的用户后缀：换用户、换会话互不干扰。"""
    who = (os.environ.get("USERNAME") or os.environ.get("USER") or "user").lower()
    keep = "".join(ch for ch in who if ch.isalnum() or ch in "-_")
    return keep or "user"


def mutex_name():
    return _MUTEX_TMPL % _tag()


def pipe_name():
    return _PIPE_TMPL % _tag()


class Guard:
    """单实例闸门：先抢名字，再决定是自己当老大还是叫醒老大。"""

    def __init__(self):
        self._mutex = None
        self._server = None

    # ───────────── 抢名字 ─────────────
    def acquire(self) -> bool:
        """拿到锁返回 True；已经有人在跑返回 False（**并用不着**继续建界面）。

        非 Windows / 调用失败 → 也返回 True（见模块注释：失效不拒绝服务）。
        """
        if os.name != "nt":
            return True
        try:
            import ctypes
            from ctypes import wintypes

            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
            k32.CreateMutexW.restype = wintypes.HANDLE
            h = k32.CreateMutexW(None, False, mutex_name())
            if not h:
                return True                     # 建不出来就别挡人
            if ctypes.get_last_error() == _ERROR_ALREADY_EXISTS:
                k32.CloseHandle(h)
                return False
            self._mutex = h
            return True
        except Exception:                       # noqa: BLE001
            return True

    # ───────────── 叫醒老大 ─────────────
    def notify(self, timeout_ms=3000) -> bool:
        """把「快把窗口提上来」递给已经在跑的那个。成功（它应答了）返回 True。"""
        try:
            from PySide6.QtNetwork import QLocalSocket
        except Exception:                       # noqa: BLE001
            return False
        sock = QLocalSocket()
        sock.connectToServer(pipe_name())
        if not sock.waitForConnected(min(timeout_ms, 1500)):
            return False
        sock.write(b"activate\n")
        if not sock.waitForBytesWritten(1000):
            return False
        sock.waitForReadyRead(timeout_ms)       # 等它回一句 ok
        ack = bytes(sock.readAll())
        sock.disconnectFromServer()
        return ack.startswith(b"ok")

    # ───────────── 当老大：听门铃 ─────────────
    def listen(self, on_activate) -> bool:
        """开始监听第二个实例的敲门声。on_activate() 在**主线程**里被调用。"""
        try:
            from PySide6.QtNetwork import QLocalServer
        except Exception:                       # noqa: BLE001
            return False
        try:
            server = QLocalServer()
            server.setSocketOptions(QLocalServer.UserAccessOption)
            # 上一个实例崩溃时可能留下同名管道（Windows 上一般随进程消失，保险起见）
            QLocalServer.removeServer(pipe_name())
            if not server.listen(pipe_name()):
                return False
            server.newConnection.connect(lambda: self._on_conn(on_activate))
            self._server = server
            return True
        except Exception:                       # noqa: BLE001
            return False

    def _on_conn(self, on_activate):
        server = self._server
        if server is None:
            return
        while server.hasPendingConnections():
            conn = server.nextPendingConnection()
            if conn is None:
                continue
            conn.readyRead.connect(lambda c=conn: self._read(c, on_activate))
            # 有的客户端写完就等，不等 readyRead 也能读到（管道已缓存）
            self._read(conn, on_activate)

    @staticmethod
    def _read(conn, on_activate):
        try:
            data = bytes(conn.readAll())
        except Exception:                       # noqa: BLE001
            data = b""
        if data.strip().startswith(b"activate"):
            try:
                on_activate()
            except Exception:                   # noqa: BLE001
                pass
            try:
                conn.write(b"ok\n")
                conn.flush()
                conn.waitForBytesWritten(500)
                conn.disconnectFromServer()
            except Exception:                   # noqa: BLE001
                pass

    # ───────────── 收尾 ─────────────
    def release(self):
        try:
            if self._server is not None:
                self._server.close()
                self._server = None
        except Exception:                       # noqa: BLE001
            pass
        try:
            if self._mutex and os.name == "nt":
                import ctypes
                ctypes.WinDLL("kernel32").CloseHandle(ctypes.c_void_p(self._mutex))
                self._mutex = None
        except Exception:                       # noqa: BLE001
            pass


def allow_other_foreground():
    """放开前台锁（第二个实例发出请求前调一次）。

    Windows 默认不允许后台进程把窗口抢到前台；``AllowSetForegroundWindow``
    把「提窗权限」交给下一个 SetForegroundWindow 的调用者，失败也无所谓 ——
    下面还有「闪任务栏」兜底。
    """
    if os.name != "nt":
        return
    try:
        import ctypes
        ctypes.WinDLL("user32").AllowSetForegroundWindow(-1)   # ASFW_ANY
    except Exception:                       # noqa: BLE001
        pass


def flash_taskbar(hwnd):
    """窗口提不到最前时闪一下任务栏，至少让用户知道它在哪（Windows 专用）。"""
    if os.name != "nt" or not hwnd:
        return False
    try:
        import ctypes
        from ctypes import wintypes

        class FLASHWINFO(ctypes.Structure):
            _fields_ = [("cbSize", wintypes.UINT), ("hwnd", wintypes.HWND),
                        ("dwFlags", wintypes.DWORD), ("uCount", wintypes.UINT),
                        ("dwTimeout", wintypes.DWORD)]

        FLASHW_ALL, FLASHW_TIMERNOFG = 3, 12
        info = FLASHWINFO(ctypes.sizeof(FLASHWINFO), wintypes.HWND(hwnd),
                          FLASHW_ALL | FLASHW_TIMERNOFG, 5, 0)
        return bool(ctypes.WinDLL("user32").FlashWindowEx(ctypes.byref(info)))
    except Exception:                       # noqa: BLE001
        return False


if __name__ == "__main__":                  # 手工验一下名字（开发用）
    print("mutex:", mutex_name(), " pipe:", pipe_name(), " tag:", _tag())
    sys.exit(0)
