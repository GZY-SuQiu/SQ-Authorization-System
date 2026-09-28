from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from . import theme


def set_variant(widget: QWidget, variant: str) -> QWidget:
    widget.setProperty("variant", variant)
    widget.style().unpolish(widget)
    widget.style().polish(widget)
    return widget


def make_button(text: str, variant: str = "default", on_click=None) -> QPushButton:
    btn = QPushButton(text)
    btn.setCursor(Qt.PointingHandCursor)
    if variant != "default":
        set_variant(btn, variant)
    if on_click is not None:
        btn.clicked.connect(on_click)
    return btn


class Card(QFrame):
    def __init__(self, parent: QWidget | None = None, padding: int = 18, spacing: int = 12):
        super().__init__(parent)
        self.setObjectName("Card")
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(padding, padding, padding, padding)
        self.body.setSpacing(spacing)


class StatCard(QFrame):
    def __init__(self, label: str, value: str = "0", accent: str = theme.PRIMARY, parent=None):
        super().__init__(parent)
        self.setObjectName("StatCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(4)

        self.value_label = QLabel(value)
        self.value_label.setObjectName("StatValue")
        self.value_label.setStyleSheet(f"color: {accent};")

        self.text_label = QLabel(label)
        self.text_label.setObjectName("StatLabel")

        layout.addWidget(self.value_label)
        layout.addWidget(self.text_label)

    def set_value(self, value) -> None:
        self.value_label.setText(str(value))


class PageHeader(QWidget):
    def __init__(self, title: str, subtitle: str = "", parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        title_label = QLabel(title)
        title_label.setObjectName("Title")
        layout.addWidget(title_label)
        if subtitle:
            sub = QLabel(subtitle)
            sub.setObjectName("Subtitle")
            layout.addWidget(sub)


def divider() -> QFrame:
    line = QFrame()
    line.setObjectName("Divider")
    line.setFrameShape(QFrame.HLine)
    line.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
    return line


def field(label: str, widget: QWidget) -> QWidget:
    box = QWidget()
    layout = QVBoxLayout(box)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(6)
    lab = QLabel(label)
    lab.setObjectName("Muted")
    layout.addWidget(lab)
    layout.addWidget(widget)
    return box


def hbox(*widgets, spacing: int = 10, margins: tuple = (0, 0, 0, 0)) -> QWidget:
    box = QWidget()
    layout = QHBoxLayout(box)
    layout.setContentsMargins(*margins)
    layout.setSpacing(spacing)
    for w in widgets:
        layout.addWidget(w)
    return box


class Toast(QLabel):
    COLORS = {
        "success": theme.SUCCESS,
        "error": theme.DANGER,
        "warning": theme.WARNING,
        "info": theme.PRIMARY,
    }

    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self.setObjectName("Toast")
        self.setAlignment(Qt.AlignCenter)
        self.setWordWrap(True)
        self.setMinimumWidth(240)
        self.setMaximumWidth(520)
        self.hide()
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.hide)

    def show_message(self, message: str, kind: str = "info", msec: int = 3000) -> None:
        color = self.COLORS.get(kind, theme.PRIMARY)
        self.setStyleSheet(
            f"#Toast {{ background: {color}; color: #FFFFFF; border-radius: 10px;"
            f" padding: 12px 20px; font-weight: 600; }}"
        )
        self.setText(message)
        self.adjustSize()
        parent = self.parentWidget()
        if parent:
            x = (parent.width() - self.width()) // 2
            self.move(max(12, x), 20)
            self.raise_()
        self.show()
        self._timer.start(msec)


def confirm(parent: QWidget, title: str, text: str) -> bool:
    box = QMessageBox(parent)
    box.setWindowTitle(title)
    box.setText(text)
    box.setIcon(QMessageBox.Question)
    box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
    box.button(QMessageBox.Yes).setText("确定")
    box.button(QMessageBox.No).setText("取消")
    return box.exec() == QMessageBox.Yes


def info(parent: QWidget, text: str, title: str = "提示") -> None:
    box = QMessageBox(parent)
    box.setWindowTitle(title)
    box.setText(text)
    box.setIcon(QMessageBox.Information)
    box.setStandardButtons(QMessageBox.Ok)
    box.button(QMessageBox.Ok).setText("知道了")
    box.exec()


def error(parent: QWidget, text: str, title: str = "错误") -> None:
    box = QMessageBox(parent)
    box.setWindowTitle(title)
    box.setText(text)
    box.setIcon(QMessageBox.Critical)
    box.setStandardButtons(QMessageBox.Ok)
    box.button(QMessageBox.Ok).setText("知道了")
    box.exec()
