"""health_assistant.gui.preview_ui — 恢复结果的预览面板与大图窗口

拆出来单独一个文件，是因为 pages.py 已经六千多行，而且这套东西两边都要用
（列表选中、按目录选中的树、大图窗口）。

读盘全部在后台线程做：从镜像或慢盘上读 24MB 有可能要几百毫秒，
放在界面线程会卡住拖选。回来时用 token 比对，晚到的旧结果直接丢掉 ——
用户按着方向键快速翻的时候，不能出现「显示的是上一条的内容」。
"""

from __future__ import annotations

from PySide6.QtCore import (QBuffer, QByteArray, QIODevice, QObject, QRect,
                            QSize, Qt, QRunnable, QThreadPool, Signal)
from PySide6.QtGui import QColor, QFont, QImage, QImageReader, QPainter, QPixmap
from PySide6.QtWidgets import (QDialog, QFrame, QHBoxLayout, QLabel,
                               QPlainTextEdit, QPushButton, QSizePolicy,
                               QVBoxLayout, QWidget)

from .. import preview, recovery
from .theme import C, SEV

THUMB = 132          # 缩略图边长（面板用）
BIG_MAX = 1400       # 大图窗口里解码的最大边长（再大只是白占内存）


def fb(n):
    """字节数 → 人话（和 pages.py 里的 fb 一个口径，但这里不能反向 import）。"""
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "—"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def decode_image(data, max_px=0):
    """从内存解码图片；`max_px` 给了就按比例缩到这么大再解码。

    先 setScaledSize 再 read，比「解出原图再缩」省一个数量级的内存 ——
    手机照片 4032×3024 解成全尺寸要 36MB，缩到 240px 只要几百 KB。
    """
    if not data:
        return QImage()
    buf = QBuffer()
    buf.setData(QByteArray(data))
    buf.open(QIODevice.ReadOnly)
    reader = QImageReader(buf)
    reader.setAutoTransform(True)
    if max_px:
        size = reader.size()
        if size.isValid() and size.width() > 0:
            reader.setScaledSize(size.scaled(max_px, max_px, Qt.KeepAspectRatio))
    img = reader.read()
    buf.close()
    return img


def _placeholder(text, size=THUMB, tone=None):
    """没有图的时候画一个方块，写两个字上去（比空白强，也比画图标诚实）。"""
    pm = QPixmap(size, size)
    pm.fill(QColor(tone or C["panel_alt"]))
    p = QPainter(pm)
    p.setPen(QColor(C["faint"]))
    f = QFont()
    f.setPointSize(9)
    p.setFont(f)
    p.drawText(QRect(0, 0, size, size), Qt.AlignCenter, text)
    p.end()
    return pm


def _verdict_style(match):
    if match is True:
        return SEV["ok"][0]
    if match is False:
        return SEV["warn"][0]
    return C["muted"]


# ───────────────────────── 后台读（不卡界面）─────────────────────────

class _JobSignals(QObject):
    done = Signal(int, object, object)      # (token, item, 描述 dict)


class PreviewJob(QRunnable):
    """在后台按需打开卷 → 读头部 → 认出类型 → 关卷。

    每次自己开卷是有意的：页面上的结果可能来自镜像、也可能来自另一块盘，
    缓存一个长驻的卷对象得管它的生命周期，还不如开一次（几十毫秒，在后台）。
    """

    def __init__(self, token, item, letter="", image="", image_base=0):
        super().__init__()
        self.token = token
        self.item = item
        self.letter = letter
        self.image = image
        self.image_base = image_base
        self.signals = _JobSignals()

    def run(self):
        vol = None
        try:
            # 能直接读文件的（回收站原件 / 已导出的）就不要开卷：省一次读盘，
            # 也不会因为没权限/盘被占用而看不了本来能看的东西。
            if preview.needs_volume(self.item):
                if self.image:
                    vol, _kind = recovery.open_image_volume(
                        self.image, letter=self.letter or "镜像",
                        base=self.image_base)
                elif self.letter:
                    vol, _kind = recovery.open_volume(self.letter)
            # 扫描时为省时间没算的原路径，这会儿卷已经打开了，顺手补上
            #（表格那一格由页面在收到结果后刷新）
            if vol is not None:
                recovery.fill_path(vol, self.item)
            info = preview.describe(vol, self.item)
        except Exception as exc:                    # noqa: BLE001
            info = {"kind": "error", "label": "读不出来", "match": None,
                    "detail": "", "image": b"", "text": None, "names": [],
                    "size": int(self.item.get("size") or 0),
                    "match_text": f"读这块盘的时候出错了：{exc}"}
        finally:
            if vol is not None:
                try:
                    vol.close()
                except Exception:                   # noqa: BLE001
                    pass
        self.signals.done.emit(self.token, self.item, info)


# ───────────────────────── 面板（列表下方那一条）─────────────────────────

class PreviewPane(QFrame):
    """选中一行就显示：缩略图 + 「这是什么、能不能打开」。双击看大图。"""

    open_big = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.setFixedHeight(THUMB + 26)
        self._info = None
        self._item = None

        h = QHBoxLayout(self)
        h.setContentsMargins(10, 10, 10, 10)
        h.setSpacing(12)

        self.thumb = QLabel()
        self.thumb.setFixedSize(THUMB, THUMB)
        self.thumb.setAlignment(Qt.AlignCenter)
        self.thumb.setStyleSheet(
            f"background:{C['panel_alt']}; border:1px solid {C['border_soft']};"
            f"border-radius:6px;")
        h.addWidget(self.thumb)

        v = QVBoxLayout()
        v.setSpacing(4)
        v.addStretch(1)
        self.t_name = QLabel("")
        f = self.t_name.font()
        f.setBold(True)
        f.setPointSize(f.pointSize() + 1)
        self.t_name.setFont(f)
        self.t_name.setWordWrap(True)
        v.addWidget(self.t_name)

        self.t_verdict = QLabel("")
        self.t_verdict.setWordWrap(True)
        v.addWidget(self.t_verdict)

        self.t_meta = QLabel("")
        self.t_meta.setObjectName("Muted")
        self.t_meta.setWordWrap(True)
        v.addWidget(self.t_meta)

        self.t_extra = QLabel("")
        self.t_extra.setObjectName("Faint")
        self.t_extra.setWordWrap(True)
        v.addWidget(self.t_extra)
        v.addStretch(1)
        h.addLayout(v, 1)

        right = QVBoxLayout()
        right.setSpacing(4)
        right.addStretch(1)
        self.btn_big = QPushButton("看大图…")
        self.btn_big.setToolTip("双击这一行也能打开（打开后可以用 ← → 翻上下一个）")
        self.btn_big.clicked.connect(self.open_big.emit)
        right.addWidget(self.btn_big)
        self.t_hint = QLabel("双击看大图")
        self.t_hint.setObjectName("Faint")
        self.t_hint.setAlignment(Qt.AlignRight)
        right.addWidget(self.t_hint)
        right.addStretch(1)
        h.addLayout(right)

        self.clear()

    def mouseDoubleClickEvent(self, event):          # noqa: N802
        if self._item is not None:
            self.open_big.emit()
        super().mouseDoubleClickEvent(event)

    def clear(self):
        self._info = None
        self._item = None
        self.thumb.setPixmap(_placeholder("还没选中\n哪一条"))
        self.t_name.setText("")
        self.t_verdict.setText("")
        self.t_meta.setText("")
        self.t_extra.setText("")
        self.btn_big.setEnabled(False)
        self.t_hint.setText("")

    def show_loading(self, item):
        """先给个「正在看…」，别让面板空着让人以为没反应。"""
        self._item = item
        self.thumb.setPixmap(_placeholder("正在看…"))
        self.t_name.setText(str(item.get("name") or ""))
        self.t_verdict.setText("正在读它的开头…")
        self.t_verdict.setStyleSheet(f"color:{C['muted']};")
        self.t_meta.setText(fb(item.get("size") or 0))
        self.t_extra.setText("")
        self.btn_big.setEnabled(False)
        self.t_hint.setText("")

    def show_item(self, item, info):
        self._item = item
        self._info = info
        name = str(item.get("name") or "")
        self.t_name.setText(name)

        verdict = info.get("match_text") or ""
        self.t_verdict.setText(verdict)
        self.t_verdict.setStyleSheet(f"color:{_verdict_style(info.get('match'))};")

        bits = []
        if info.get("label"):
            bits.append(info["label"])
        if info.get("detail"):
            bits.append(info["detail"])
        size = info.get("size") or item.get("size") or 0
        if size and not item.get("is_dir"):
            bits.append(fb(size))
        when = item.get("deleted") or item.get("mtime") or ""
        if when:
            bits.append(when)
        self.t_meta.setText("　·　".join(bits))

        extra = ""
        names = info.get("names") or []
        if names:
            extra = "里面是：" + "、".join(names[:4]) + ("…" if len(names) > 4 else "")
        if info.get("text"):
            first = [ln for ln in info["text"].split("\n") if ln.strip()][:1]
            if first:
                extra = "第一行：" + first[0].strip()[:80]
        self.t_extra.setText(extra)

        # 缩略图
        img = QImage()
        if info.get("image"):
            img = decode_image(info["image"], THUMB * 2)
        if not img.isNull():
            self.thumb.setPixmap(QPixmap.fromImage(img).scaled(
                THUMB, THUMB, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        else:
            hint = {"image": "没能解码\n（可能只有半截）"}.get(info.get("kind"), "")
            label = (info.get("label") or "文件")
            self.thumb.setPixmap(_placeholder(hint or label[:10]))

        self.btn_big.setEnabled(True)
        self.t_hint.setText("双击看大图")


# ───────────────────────── 大图 / 大文本窗口 ─────────────────────────

class PreviewDialog(QDialog):
    """把一条恢复结果放大看。← → 在列表里翻上/下一条，Esc 关掉。"""

    def __init__(self, parent, items, index, letter="", image="", image_base=0):
        super().__init__(parent)
        self.setWindowTitle("看看内容")
        self.resize(940, 720)
        self._items = list(items)
        self._idx = max(0, min(index, len(self._items) - 1))
        self._letter = letter
        self._image = image
        self._image_base = image_base
        self._token = 0
        self._img = QImage()
        self._info = None
        self._busy = False

        v = QVBoxLayout(self)
        v.setContentsMargins(12, 10, 12, 10)
        v.setSpacing(8)

        top = QHBoxLayout()
        self.t_title = QLabel("")
        f = self.t_title.font()
        f.setBold(True)
        f.setPointSize(f.pointSize() + 1)
        self.t_title.setFont(f)
        top.addWidget(self.t_title, 1)
        self.t_pos = QLabel("")
        self.t_pos.setObjectName("Faint")
        top.addWidget(self.t_pos)
        v.addLayout(top)

        self.t_verdict = QLabel("")
        self.t_verdict.setWordWrap(True)
        v.addWidget(self.t_verdict)

        self.stage = QLabel()
        self.stage.setAlignment(Qt.AlignCenter)
        self.stage.setMinimumSize(400, 300)
        self.stage.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.stage.setStyleSheet(
            f"background:{C['panel']}; border:1px solid {C['border_soft']};"
            f"border-radius:6px;")
        v.addWidget(self.stage, 1)

        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        self.text.hide()
        v.addWidget(self.text, 1)

        bottom = QHBoxLayout()
        self.btn_prev = QPushButton("← 上一个")
        self.btn_prev.clicked.connect(lambda: self.step(-1))
        bottom.addWidget(self.btn_prev)
        self.btn_next = QPushButton("下一个 →")
        self.btn_next.clicked.connect(lambda: self.step(1))
        bottom.addWidget(self.btn_next)
        bottom.addStretch(1)
        self.t_meta = QLabel("")
        self.t_meta.setObjectName("Muted")
        bottom.addWidget(self.t_meta)
        bottom.addStretch(1)
        btn_close = QPushButton("关掉")
        btn_close.clicked.connect(self.accept)
        bottom.addWidget(btn_close)
        v.addLayout(bottom)

        self._load()

    # -- 翻页 --
    def step(self, delta):
        if self._busy:
            return
        new = self._idx + delta
        if 0 <= new < len(self._items):
            self._idx = new
            self._load()

    def keyPressEvent(self, event):                 # noqa: N802
        key = event.key()
        if key in (Qt.Key_Left, Qt.Key_PageUp):
            self.step(-1)
        elif key in (Qt.Key_Right, Qt.Key_PageDown):
            self.step(1)
        elif key == Qt.Key_Escape:
            self.reject()
        else:
            super().keyPressEvent(event)

    def resizeEvent(self, event):                   # noqa: N802
        super().resizeEvent(event)
        self._paint()

    # -- 读一条 --
    def _load(self):
        item = self._items[self._idx]
        self.t_title.setText(str(item.get("name") or ""))
        self.t_pos.setText(f"第 {self._idx + 1} / {len(self._items)} 个")
        self.btn_prev.setEnabled(self._idx > 0)
        self.btn_next.setEnabled(self._idx < len(self._items) - 1)
        self.t_verdict.setText("正在读它的开头…")
        self.t_verdict.setStyleSheet(f"color:{C['muted']};")
        self.t_meta.setText(fb(item.get("size") or 0))
        self._img = QImage()
        self.text.hide()
        self.stage.show()
        self.stage.setText("正在读…")
        self._busy = True

        self._token += 1
        job = PreviewJob(self._token, item, self._letter, self._image,
                         self._image_base)
        job.signals.done.connect(self._on_loaded)
        QThreadPool.globalInstance().start(job)

    def _on_loaded(self, token, item, info):
        if token != self._token:
            return                                      # 晚到的旧结果，丢掉
        self._busy = False
        self._info = info
        self.t_verdict.setText(info.get("match_text") or "")
        self.t_verdict.setStyleSheet(f"color:{_verdict_style(info.get('match'))};")
        bits = [info.get("label") or "", info.get("detail") or "",
                fb(info.get("size") or 0)]
        self.t_meta.setText("　·　".join([b for b in bits if b]))

        if info.get("image"):
            self._img = decode_image(info["image"], BIG_MAX)
        if not self._img.isNull():
            self.text.hide()
            self.stage.show()
            self._paint()
            return
        if info.get("text"):
            self.stage.hide()
            self.text.show()
            self.text.setPlainText(info["text"])
            return
        self.stage.show()
        self.text.hide()
        self.stage.setPixmap(QPixmap())
        names = info.get("names") or []
        msg = [info.get("match_text") or "", ""]
        if names:
            msg.append("里面有：")
            msg.extend("  " + n for n in names[:8])
        elif info.get("kind") in preview.MEDIA_KINDS:
            msg.append("视频/音频没法在这里播放，"
                       "上面写的时长和分辨率是从文件头读出来的。")
        elif info.get("image"):
            msg.append("这张图没能解码：可能只找到半截，或者这种格式 Qt 解不了。")
        else:
            msg.append("这类文件没有图片预览，只看类型和大小。")
        self.stage.setText("\n".join(m for m in msg if m is not None).strip())

    def _paint(self):
        if self._img.isNull():
            return
        area = self.stage.size()
        if area.width() < 20 or area.height() < 20:
            return
        pm = QPixmap.fromImage(self._img).scaled(
            area.width() - 12, area.height() - 12,
            Qt.KeepAspectRatio, Qt.SmoothTransformation)
        self.stage.setPixmap(pm)
