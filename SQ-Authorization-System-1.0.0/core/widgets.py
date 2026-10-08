from PySide6.QtCore import QEvent, Qt, QTimer
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QTableWidget,
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


class StatusBadge(QLabel):
    TONES = {
        "neutral": (theme.TEXT_MUTED, theme.SURFACE_STRONG),
        "info": (theme.PRIMARY, theme.PRIMARY_SOFT),
        "success": (theme.SUCCESS, theme.SUCCESS_SOFT),
        "warning": (theme.WARNING, theme.WARNING_SOFT),
        "error": (theme.DANGER, theme.DANGER_SOFT),
        "frozen": (theme.FROZEN, theme.FROZEN_SOFT),
    }

    def __init__(self, text: str = "", kind: str = "neutral", parent=None):
        super().__init__(parent)
        self.setAlignment(Qt.AlignCenter)
        self.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Fixed)
        self.set_state(text, kind)

    def set_state(self, text: str, kind: str = "neutral") -> None:
        color, background = self.TONES.get(kind, self.TONES["neutral"])
        self.setText(text)
        self.setStyleSheet(
            f"color: {color}; background: {background}; border: 1px solid {color}33;"
            "border-radius: 7px; padding: 4px 10px; font-weight: 600;"
        )


class StatGrid(QWidget):
    def __init__(self, cards, columns: int = 4, min_card_width: int = 150, parent=None):
        super().__init__(parent)
        self.cards = list(cards)
        self.max_columns = max(1, columns)
        self.min_card_width = max(120, min_card_width)
        self._columns = 0
        self.grid = QGridLayout(self)
        self.grid.setContentsMargins(0, 0, 0, 0)
        self.grid.setHorizontalSpacing(14)
        self.grid.setVerticalSpacing(12)
        self._rebuild(self.max_columns)

    def _rebuild(self, columns: int) -> None:
        columns = max(1, min(columns, self.max_columns, len(self.cards) or 1))
        if columns == self._columns:
            return
        while self.grid.count():
            item = self.grid.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(self)
        for index, card in enumerate(self.cards):
            self.grid.addWidget(card, index // columns, index % columns)
        for column in range(self.max_columns):
            self.grid.setColumnStretch(column, 1 if column < columns else 0)
        self._columns = columns

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        columns = max(1, self.width() // self.min_card_width)
        self._rebuild(columns)


class EmptyHint(QLabel):
    """Centered "no data" label that floats over an empty table viewport."""

    def __init__(self, table: QTableWidget):
        super().__init__(table.viewport())
        self._table = table
        self.setObjectName("EmptyHint")
        self.setAlignment(Qt.AlignCenter)
        self.setWordWrap(True)
        self.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        self.setStyleSheet(f"color: {theme.TEXT_MUTED}; background: transparent;")
        table.viewport().installEventFilter(self)

    def eventFilter(self, obj, event):
        # 表被销毁时仍可能收到残留事件，异常必须就地吞掉。
        try:
            if obj is self._table.viewport() and event.type() == QEvent.Resize:
                self.setGeometry(self._table.viewport().rect())
        except Exception:
            pass
        return super().eventFilter(obj, event)


def set_empty_text(table: QTableWidget, text: str = "暂无数据") -> None:
    table.setProperty("emptyText", text)
    hint = getattr(table, "_empty_hint", None)
    if hint is not None:
        hint.setText(text)


def sync_empty_hint(table: QTableWidget) -> None:
    """Show or hide the placeholder overlay according to the current row count."""
    try:
        hint = getattr(table, "_empty_hint", None)
        if table.rowCount() == 0:
            if hint is None:
                hint = EmptyHint(table)
                table._empty_hint = hint
            hint.setText(table.property("emptyText") or "暂无数据")
            hint.setGeometry(table.viewport().rect())
            hint.show()
            hint.raise_()
        elif hint is not None:
            hint.hide()
    except RuntimeError:
        # The C++ widget went away before the deferred call ran.
        return


def prepare_table(table: QTableWidget) -> None:
    table.setAlternatingRowColors(True)
    table.setShowGrid(False)
    table.setWordWrap(False)
    table.setTextElideMode(Qt.ElideRight)
    table.verticalHeader().setDefaultSectionSize(40)
    table.setCornerButtonEnabled(False)
    table.setSelectionBehavior(QAbstractItemView.SelectRows)
    table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
    table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
    table.setFocusPolicy(Qt.StrongFocus)
    header = table.horizontalHeader()
    header.setHighlightSections(False)
    header.setMinimumSectionSize(56)
    header.setSectionsClickable(True)
    # fill_table() sets the row count right after this call, so the overlay
    # is refreshed once the current event loop iteration completes.
    QTimer.singleShot(0, lambda t=table: sync_empty_hint(t))




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
        self.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        self.hide()
        # 先记锚点再装过滤器：安装后立刻到达的 Show/Resize 事件会在
        # _anchor 尚未赋值时访问它，Qt 只能把异常打到控制台。
        self._anchor = parent
        parent.installEventFilter(self)
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.hide)

    def eventFilter(self, obj, event):
        # Keep the toast horizontally centered when the host window resizes
        # instead of relying on every window to override resizeEvent().
        try:
            anchor = getattr(self, "_anchor", None)
            if obj is anchor and event.type() in (QEvent.Resize, QEvent.Show):
                if self.isVisible():
                    self._reposition()
        except Exception:
            pass
        return super().eventFilter(obj, event)

    def _reposition(self) -> None:
        parent = self.parentWidget()
        if parent is None:
            return
        self.move(max(12, (parent.width() - self.width()) // 2), 20)

    def show_message(self, message: str, kind: str = "info", msec: int = 3000) -> None:
        color = self.COLORS.get(kind, theme.PRIMARY)
        self.setStyleSheet(
            f"#Toast {{ background: {color}; color: #FFFFFF; border-radius: 10px;"
            f" padding: 12px 20px; font-weight: 600; }}"
        )
        self.setText(message)
        self.adjustSize()
        self._reposition()
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
