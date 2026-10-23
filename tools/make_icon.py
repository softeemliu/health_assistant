"""生成 health_assistant.ico（快捷方式图标）。

Qt 的 ICO 插件是只读的，直接把 Pixmap 存成 .ico 会失败，所以这里自己拼 ICO 容器：
每帧按 PNG 编码后塞进 ICONDIR 里（Vista 以后都支持 PNG 帧）。

用法：C:\\Python3\\python.exe tools\\make_icon.py
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtCore import QBuffer, QByteArray, Qt          # noqa: E402
from PySide6.QtGui import QColor, QFont, QPainter, QPixmap  # noqa: E402
from PySide6.QtWidgets import QApplication                  # noqa: E402

from health_assistant.gui.theme import C                            # noqa: E402

SIZES = (16, 24, 32, 48, 64, 128, 256)


def draw(size):
    """画一帧：圆角蓝底 + 白色「巡」。"""
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing, True)
    p.setBrush(QColor(C["accent"]))
    p.setPen(Qt.NoPen)
    rad = max(1, round(size * 0.18))
    p.drawRoundedRect(0, 0, size, size, rad, rad)
    p.setPen(QColor("#ffffff"))
    f = QFont("Microsoft YaHei UI")
    f.setPixelSize(max(8, round(size * 0.62)))
    f.setBold(True)
    p.setFont(f)
    p.drawText(pm.rect(), Qt.AlignCenter, "巡")
    p.end()
    return pm


def png_bytes(pm):
    """把 Pixmap 编成 PNG 字节。

    注意：QBuffer 必须挂在持久的 QByteArray 上。写成 QBuffer(QByteArray())
    时那个临时对象会被回收，PySide6 里直接段错误（踩过）。
    """
    ba = QByteArray()
    buf = QBuffer(ba)
    buf.open(QBuffer.WriteOnly)
    pm.save(buf, "PNG")
    buf.close()
    return bytes(ba)


def main():
    app = QApplication.instance() or QApplication(sys.argv)   # QPixmap 需要 GUI 应用对象
    frames = [(s, png_bytes(draw(s))) for s in SIZES]

    head = struct.pack("<HHH", 0, 1, len(frames))             # reserved / type=icon / count
    offset = 6 + 16 * len(frames)
    entries, blobs = b"", b""
    for size, data in frames:
        # ICONDIRENTRY: w, h, colors, reserved, planes, bpp, size, offset
        entries += struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32,
                               len(data), offset)
        blobs += data
        offset += len(data)

    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "health_assistant.ico")
    with open(out, "wb") as fh:
        fh.write(head + entries + blobs)
    print(f"已生成 {out}（{len(frames)} 帧，{os.path.getsize(out)} 字节）")
    return app


if __name__ == "__main__":
    main()
