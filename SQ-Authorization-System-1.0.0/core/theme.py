"""Global light theme for every PySide6 front-end.

The QSS below is intentionally explicit. Qt's platform styles (``windows11``,
``windowsvista``, ``fusion``) draw their own chrome for any widget the
stylesheet does not mention, which is how stray separators and heavy splitter
handles leak into the UI. Every structural widget this project relies on is
therefore styled here instead of being left to the native style.
"""

import tempfile
from pathlib import Path

PRIMARY = '#2F6BFF'
PRIMARY_HOVER = '#1E5BEF'
PRIMARY_PRESSED = '#1749C7'
PRIMARY_SOFT = '#EEF4FF'
PRIMARY_BORDER = '#D7E2FF'

BG = '#FFFFFF'
SURFACE = '#F7F9FC'
SURFACE_STRONG = '#F2F5FA'
SURFACE_HOVER = '#EDF1F9'
BORDER = '#E3E8F0'
BORDER_STRONG = '#D2DAE8'
BORDER_HOVER = '#BFC9DA'

TEXT = '#1D2330'
TEXT_SOFT = '#5B6478'
TEXT_MUTED = '#7C8799'
TEXT_DISABLED = '#AAB3C2'

SUCCESS = '#168A4A'
SUCCESS_SOFT = '#EAF8F0'
WARNING = '#B76E00'
WARNING_SOFT = '#FFF6E6'
DANGER = '#D92D20'
DANGER_SOFT = '#FEF0EF'
DANGER_BORDER = '#F1B8B3'
FROZEN = '#6941C6'
FROZEN_SOFT = '#F3EFFF'
INFO = '#2F6BFF'

# A splitter handle sits between two cards. When the handle has no rule Qt
# paints a solid block of native chrome (up to #EFEFEF with the Windows 11
# style) that spans the full height and reads as a thick vertical bar. The
# width is fixed here and the fill stays transparent until it is hovered.
SPLITTER_HANDLE_WIDTH = 10

FONT_FAMILIES = [
    'Microsoft YaHei UI',
    'Microsoft YaHei',
    'Segoe UI',
    'PingFang SC',
    'Noto Sans CJK SC',
    'sans-serif',
]

MONO_FAMILIES = [
    'Cascadia Mono',
    'Consolas',
    'JetBrains Mono',
    'DejaVu Sans Mono',
    'monospace',
]

# Qt stops drawing a widget's own glyph as soon as one of its sub-controls is
# styled, so combo arrows, checkbox ticks and sort indicators must be supplied
# as images. They are painted once at startup rather than shipped as assets.
_ICON_DIR = Path(tempfile.gettempdir()) / 'sq-authorization-theme'


def _icon(name: str) -> str:
    return (_ICON_DIR / name).as_posix()


def _ensure_icons() -> None:
    """Paint the small control glyphs the stylesheet refers to."""
    from PySide6.QtCore import QPointF, Qt
    from PySide6.QtGui import (
        QColor,
        QPainter,
        QPainterPath,
        QPen,
        QPixmap,
        QPolygonF,
    )

    _ICON_DIR.mkdir(parents=True, exist_ok=True)

    def canvas(width: int, height: int):
        pixmap = QPixmap(width, height)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing, True)
        return pixmap, painter

    # White tick, drawn on the primary-blue checked background.
    pixmap, painter = canvas(16, 16)
    pen = QPen(QColor('#FFFFFF'))
    pen.setWidthF(2.0)
    pen.setCapStyle(Qt.RoundCap)
    pen.setJoinStyle(Qt.RoundJoin)
    painter.setPen(pen)
    path = QPainterPath(QPointF(3.6, 8.4))
    path.lineTo(QPointF(6.7, 11.6))
    path.lineTo(QPointF(12.4, 4.6))
    painter.drawPath(path)
    painter.end()
    pixmap.save(_icon('check.png'), 'PNG')

    # Combo chevrons, spin-box arrows and header sort markers share one shape.
    for name, points in (
        ('arrow_down.png', [(0.6, 1.0), (9.4, 1.0), (5.0, 5.4)]),
        ('arrow_up.png', [(0.6, 5.0), (9.4, 5.0), (5.0, 0.6)]),
    ):
        pixmap, painter = canvas(10, 6)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor('#7C8799'))
        painter.drawPolygon(QPolygonF([QPointF(x, y) for x, y in points]))
        painter.end()
        pixmap.save(_icon(name), 'PNG')

APP_QSS = f"""
* {{
    font-size: 13px;
    color: {TEXT};
    outline: none;
}}
QMainWindow, QDialog, QWidget#Root {{
    background: {BG};
}}
QWidget#Transparent {{
    background: transparent;
}}
/* 滚动内容层：不能透底，否则深色系统主题下滚动会露出黑带。 */
QWidget#ScrollBody {{
    background: {BG};
}}

/* ---------------------------------------------------------------- chrome */
QFrame#Sidebar {{
    background: {SURFACE};
    border: none;
    border-right: 1px solid {BORDER};
}}
QFrame#Card {{
    background: {BG};
    border: 1px solid {BORDER};
    border-radius: 8px;
}}
QFrame#StatCard {{
    background: {BG};
    border: 1px solid {BORDER};
    border-radius: 8px;
}}
QFrame#Divider {{
    background: {BORDER};
    border: none;
    max-height: 1px;
    min-height: 1px;
}}

/* ------------------------------------------------------------ typography */
QLabel#Brand {{
    font-size: 16px;
    font-weight: 700;
    color: {PRIMARY};
}}
QLabel#Title {{
    font-size: 20px;
    font-weight: 600;
}}
QLabel#Subtitle {{
    color: {TEXT_MUTED};
    font-size: 12px;
}}
QLabel#SectionTitle {{
    font-size: 14px;
    font-weight: 600;
}}
QLabel#StatValue {{
    font-size: 26px;
    font-weight: 700;
}}
QLabel#StatLabel {{
    color: {TEXT_MUTED};
    font-size: 12px;
}}
QLabel#Muted {{
    color: {TEXT_MUTED};
}}
QLabel#Success {{ color: {SUCCESS}; font-weight: 600; }}
QLabel#Warning {{ color: {WARNING}; font-weight: 600; }}
QLabel#Danger  {{ color: {DANGER}; font-weight: 600; }}
QLabel#KeyText {{
    font-family: "Cascadia Mono", "Consolas", monospace;
    font-size: 14px;
    letter-spacing: 1px;
}}
QLabel#RoleBadge {{
    background: {PRIMARY_SOFT};
    color: {PRIMARY};
    border: 1px solid {PRIMARY_BORDER};
    border-radius: 6px;
    padding: 3px 8px;
    font-size: 11px;
    font-weight: 600;
}}
QLabel#NavLabel {{
    color: {TEXT_MUTED};
    font-size: 11px;
    font-weight: 600;
    padding: 2px 8px;
}}

/* --------------------------------------------------------------- buttons */
QPushButton {{
    background: {BG};
    border: 1px solid {BORDER_STRONG};
    border-radius: 8px;
    padding: 8px 16px;
    color: {TEXT};
}}
QPushButton:hover {{ background: {SURFACE_STRONG}; border-color: {BORDER_HOVER}; }}
QPushButton:pressed {{ background: #E8EEFA; }}
QPushButton:focus {{ border-color: {PRIMARY}; }}
QPushButton:disabled {{ color: {TEXT_DISABLED}; background: #F5F7FB; border-color: {BORDER}; }}
QPushButton[variant="primary"] {{
    background: {PRIMARY};
    border: 1px solid {PRIMARY};
    color: #FFFFFF;
    font-weight: 600;
}}
QPushButton[variant="primary"]:hover {{ background: {PRIMARY_HOVER}; border-color: {PRIMARY_HOVER}; }}
QPushButton[variant="primary"]:pressed {{ background: {PRIMARY_PRESSED}; border-color: {PRIMARY_PRESSED}; }}
QPushButton[variant="primary"]:disabled {{ background: #A9C1FF; border-color: #A9C1FF; color: #FFFFFF; }}
QPushButton[variant="danger"] {{ background: {BG}; border: 1px solid {DANGER_BORDER}; color: {DANGER}; }}
QPushButton[variant="danger"]:hover {{ background: {DANGER_SOFT}; border-color: #ED9B94; }}
QPushButton[variant="danger"]:pressed {{ background: #FCE3E1; }}
QPushButton[variant="danger"]:disabled {{ color: #E7B4B0; border-color: #F6DCDA; background: #FEF7F7; }}
QPushButton[variant="ghost"] {{ background: transparent; border: 1px solid transparent; color: {TEXT_SOFT}; }}
QPushButton[variant="ghost"]:hover {{ background: {SURFACE_STRONG}; border-color: transparent; color: {TEXT}; }}
QPushButton[variant="ghost"]:pressed {{ background: #E8EEFA; }}
QPushButton#NavButton {{
    text-align: left;
    padding: 10px 14px;
    border-radius: 8px;
    border: 1px solid transparent;
    color: {TEXT_SOFT};
    font-weight: 500;
}}
QPushButton#NavButton:hover {{ background: {SURFACE_HOVER}; }}
QPushButton#NavButton:checked {{
    background: {PRIMARY_SOFT};
    color: {PRIMARY};
    border-color: {PRIMARY_BORDER};
    font-weight: 600;
}}
QToolButton {{
    background: {BG};
    border: 1px solid {BORDER_STRONG};
    border-radius: 8px;
    padding: 8px 14px;
    color: {TEXT};
}}
QToolButton:hover {{ background: {SURFACE_STRONG}; border-color: {BORDER_HOVER}; }}
QToolButton:pressed, QToolButton:open {{ background: #E8EEFA; border-color: {BORDER_HOVER}; }}
QToolButton:disabled {{ color: {TEXT_DISABLED}; background: #F5F7FB; border-color: {BORDER}; }}
QToolButton::menu-indicator {{ image: none; width: 0px; }}

/* ----------------------------------------------------------------- menus */
QMenu {{
    background: {BG};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 5px;
}}
QMenu::item {{ padding: 8px 28px 8px 12px; border-radius: 6px; color: {TEXT}; }}
QMenu::item:selected {{ background: {PRIMARY_SOFT}; color: {PRIMARY}; }}
QMenu::item:disabled {{ color: {TEXT_DISABLED}; }}
QMenu::separator {{ height: 1px; background: {BORDER}; margin: 5px 8px; }}

/* ---------------------------------------------------------------- inputs */
QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox, QPlainTextEdit, QTextEdit {{
    background: {BG};
    border: 1px solid {BORDER_STRONG};
    border-radius: 8px;
    padding: 8px 12px;
    selection-background-color: {PRIMARY};
    selection-color: #FFFFFF;
}}
QLineEdit:hover, QComboBox:hover, QSpinBox:hover, QDoubleSpinBox:hover {{
    border-color: {BORDER_HOVER};
}}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus,
QDoubleSpinBox:focus, QPlainTextEdit:focus, QTextEdit:focus {{
    border: 1px solid {PRIMARY};
}}
QLineEdit:disabled, QSpinBox:disabled, QDoubleSpinBox:disabled,
QComboBox:disabled, QPlainTextEdit:disabled, QTextEdit:disabled {{
    background: #F5F7FB;
    color: #9AA3B2;
}}
QLineEdit[readOnly="true"], QPlainTextEdit[readOnly="true"], QTextEdit[readOnly="true"] {{
    background: {SURFACE};
}}
QComboBox::drop-down {{ border: none; width: 26px; }}
QComboBox::down-arrow {{ image: url("{_icon('arrow_down.png')}"); width: 10px; height: 6px; }}
QComboBox::down-arrow:disabled {{ image: none; }}
QSpinBox, QDoubleSpinBox {{ padding-right: 20px; }}
QSpinBox::up-button, QDoubleSpinBox::up-button {{
    subcontrol-origin: border;
    subcontrol-position: top right;
    width: 20px;
    border: none;
    border-left: 1px solid {BORDER};
    background: {SURFACE};
    border-top-right-radius: 8px;
}}
QSpinBox::down-button, QDoubleSpinBox::down-button {{
    subcontrol-origin: border;
    subcontrol-position: bottom right;
    width: 20px;
    border: none;
    border-left: 1px solid {BORDER};
    border-top: 1px solid {BORDER};
    background: {SURFACE};
    border-bottom-right-radius: 8px;
}}
QSpinBox::up-button:hover, QDoubleSpinBox::up-button:hover,
QSpinBox::down-button:hover, QDoubleSpinBox::down-button:hover {{
    background: {SURFACE_HOVER};
}}
QSpinBox::up-arrow, QDoubleSpinBox::up-arrow {{
    image: url("{_icon('arrow_up.png')}");
    width: 10px;
    height: 6px;
}}
QSpinBox::down-arrow, QDoubleSpinBox::down-arrow {{
    image: url("{_icon('arrow_down.png')}");
    width: 10px;
    height: 6px;
}}
QComboBox QAbstractItemView {{
    border: 1px solid {BORDER};
    border-radius: 8px;
    background: {BG};
    selection-background-color: {PRIMARY_SOFT};
    selection-color: {PRIMARY};
    padding: 4px;
}}

/* --------------------------------------------------------------- toggles */
QCheckBox, QRadioButton {{ spacing: 8px; padding: 2px; }}
QCheckBox::indicator, QRadioButton::indicator {{
    width: 16px;
    height: 16px;
    border: 1px solid {BORDER_STRONG};
    background: {BG};
}}
QCheckBox::indicator {{ border-radius: 4px; }}
QRadioButton::indicator {{ border-radius: 8px; }}
QCheckBox::indicator:hover, QRadioButton::indicator:hover {{ border-color: {PRIMARY}; }}
QCheckBox::indicator:checked {{
    background: {PRIMARY};
    border-color: {PRIMARY};
    image: url("{_icon('check.png')}");
}}
QRadioButton::indicator:checked {{
    background: {BG};
    border: 5px solid {PRIMARY};
}}
QCheckBox:disabled, QRadioButton:disabled {{ color: {TEXT_DISABLED}; }}

/* --------------------------------------------------------------- tables */
QHeaderView::section {{
    background: {SURFACE};
    border: none;
    border-bottom: 1px solid {BORDER};
    border-right: 1px solid {BORDER};
    padding: 9px 10px;
    color: {TEXT_MUTED};
    font-weight: 600;
}}
QHeaderView::section:hover {{ background: {SURFACE_HOVER}; color: {TEXT}; }}
QHeaderView::up-arrow {{
    image: url("{_icon('arrow_up.png')}");
    width: 10px;
    height: 6px;
}}
QHeaderView::down-arrow {{
    image: url("{_icon('arrow_down.png')}");
    width: 10px;
    height: 6px;
}}
QTableWidget, QTableView {{
    border: 1px solid {BORDER};
    border-radius: 8px;
    gridline-color: #F0F3F8;
    background: {BG};
    alternate-background-color: #FBFCFE;
    selection-background-color: {PRIMARY_SOFT};
}}
QTableWidget::item, QTableView::item {{ padding: 6px 8px; border-bottom: 1px solid #F4F6FA; }}
QTableWidget::item:selected, QTableView::item:selected {{ background: {PRIMARY_SOFT}; color: {TEXT}; }}
QTableWidget::item:focus, QTableView::item:focus {{ border: none; }}
QTableCornerButton::section {{ background: {SURFACE}; border: none; }}
QListWidget {{
    border: 1px solid {BORDER};
    border-radius: 8px;
    background: {BG};
    padding: 4px;
}}
QListWidget::item {{ padding: 8px 10px; border-radius: 7px; }}
QListWidget::item:hover {{ background: {SURFACE_HOVER}; }}
QListWidget::item:selected {{ background: {PRIMARY_SOFT}; color: {PRIMARY}; }}

/* ------------------------------------------------------------ scrollbars */
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: #D5DCE8; border-radius: 5px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: {BORDER_HOVER}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: transparent; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: #D5DCE8; border-radius: 5px; min-width: 30px; }}
QScrollBar::handle:horizontal:hover {{ background: {BORDER_HOVER}; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{ background: transparent; }}
/* 深色系统主题下，滚动视口会把黑底透出来形成黑带。滚动区自身、视口
   与内容层都显式刷成页面底色：任何一层被裁掉/跳过时都不会露出黑底，
   也避免"滚动时新露出的条带没被画到"的整条黑带。 */
QScrollArea {{ border: none; background: {BG}; }}
QScrollArea > QWidget#qt_scrollarea_viewport {{ background: {BG}; }}
QScrollArea > QWidget > QWidget {{ background: {BG}; }}
QScrollArea > QWidget > QScrollBar {{ background: transparent; }}
QAbstractScrollArea::corner {{ background: transparent; }}

/* -------------------------------------------------------------- splitter */
QSplitter {{ background: transparent; }}
QSplitter::handle {{ background: transparent; border: none; }}
QSplitter::handle:horizontal {{ width: {SPLITTER_HANDLE_WIDTH}px; }}
QSplitter::handle:vertical {{ height: {SPLITTER_HANDLE_WIDTH}px; }}
QSplitter::handle:hover {{ background: {PRIMARY_SOFT}; border-radius: 5px; }}
QSplitter::handle:pressed {{ background: {PRIMARY_BORDER}; border-radius: 5px; }}

/* ------------------------------------------------------------------ tabs */
QTabWidget::pane {{ border: 1px solid {BORDER}; border-radius: 8px; top: -1px; background: {BG}; }}
QTabBar {{ background: transparent; }}
QTabBar::tab {{
    background: transparent;
    padding: 9px 18px;
    color: {TEXT_MUTED};
    border: none;
    border-bottom: 2px solid transparent;
}}
QTabBar::tab:hover {{ color: {TEXT}; }}
QTabBar::tab:selected {{ color: {PRIMARY}; border-bottom: 2px solid {PRIMARY}; font-weight: 600; }}

/* --------------------------------------------------------------- dialogs */
QMessageBox {{ background: {BG}; }}
QMessageBox QLabel {{ color: {TEXT}; }}
QGroupBox {{
    border: 1px solid {BORDER};
    border-radius: 8px;
    margin-top: 12px;
    padding: 12px;
    font-weight: 600;
}}
QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 4px; }}

/* ------------------------------------------------------------- feedback */
QToolTip {{
    border: 1px solid {BORDER};
    background: {BG};
    color: {TEXT};
    padding: 6px 8px;
    border-radius: 6px;
}}
QProgressBar {{
    border: none;
    border-radius: 6px;
    background: {SURFACE_HOVER};
    height: 10px;
    text-align: center;
}}
QProgressBar::chunk {{ background: {PRIMARY}; border-radius: 6px; }}
QStatusBar {{ background: {SURFACE}; border-top: 1px solid {BORDER}; color: {TEXT_MUTED}; }}
QStatusBar::item {{ border: none; }}
"""


def apply_theme(app) -> None:
    import os
    import sys

    from PySide6.QtCore import QEvent, QObject
    from PySide6.QtGui import QColor, QFont, QIcon, QPalette
    from PySide6.QtWidgets import QStyleFactory

    # Windows 深色模式下，windows11 原生风格会用系统主题绘制 QSS 未覆盖的
    # 子控件（滚动视口、滚动条角落、弹出框边缘），于是白界面里冒出黑块。
    # 统一换用 Fusion，配色完全由这份 QSS + 浅色调色板决定。
    if sys.platform == "win32" and not os.environ.get("SQ_KEEP_NATIVE_STYLE"):
        fusion = QStyleFactory.create("Fusion")
        if fusion is not None:
            app.setStyle(fusion)

    _ensure_icons()
    _apply_app_icon(app, QIcon)
    font = QFont()
    font.setFamilies(FONT_FAMILIES)
    font.setPointSize(9)
    app.setFont(font)
    app.setStyleSheet(APP_QSS)
    app.setPalette(_light_palette(QColor, QPalette))

    # Windows 深色模式会给原生窗口画深色标题栏/边框；逐窗口强制浅色，
    # 避免"白界面 + 黑边"的割裂感（失败时静默忽略）。
    class _WindowPolishFilter(QObject):
        def eventFilter(self, obj, event):
            # 应用级过滤器会收到正在销毁的对象/事件（C++ 侧已释放），
            # 任何异常都必须就地吞掉：漏出的异常状态会让后续所有
            # Qt→Python 回调报 SystemError。
            try:
                if event.type() == QEvent.Show and hasattr(obj, "winId"):
                    _set_light_titlebar(obj)
            except Exception:
                pass
            return False

    window_filter = _WindowPolishFilter()
    previous_filter = getattr(app, "_sq_window_polish_filter", None)
    if previous_filter is not None:
        try:
            app.removeEventFilter(previous_filter)
        except Exception:
            pass
    app._sq_window_polish_filter = window_filter
    app.installEventFilter(window_filter)


def _light_palette(qcolor, qpalette):
    """Explicit light palette so unstyled native widgets never render dark."""
    palette = qpalette()
    palette.setColor(qpalette.Window, qcolor(BG))
    palette.setColor(qpalette.WindowText, qcolor(TEXT))
    palette.setColor(qpalette.Base, qcolor(BG))
    palette.setColor(qpalette.AlternateBase, qcolor(SURFACE))
    palette.setColor(qpalette.Text, qcolor(TEXT))
    palette.setColor(qpalette.Button, qcolor(BG))
    palette.setColor(qpalette.ButtonText, qcolor(TEXT))
    palette.setColor(qpalette.Highlight, qcolor(PRIMARY))
    palette.setColor(qpalette.HighlightedText, qcolor("#FFFFFF"))
    palette.setColor(qpalette.ToolTipBase, qcolor(BG))
    palette.setColor(qpalette.ToolTipText, qcolor(TEXT))
    palette.setColor(qpalette.PlaceholderText, qcolor(TEXT_MUTED))
    palette.setColor(qpalette.Disabled, qpalette.Text, qcolor(TEXT_DISABLED))
    palette.setColor(qpalette.Disabled, qpalette.ButtonText, qcolor(TEXT_DISABLED))
    return palette


def _set_light_titlebar(widget) -> None:
    """Ask DWM to draw a light caption/border for a top-level window."""
    import sys

    if sys.platform != "win32":
        return
    try:
        import ctypes
        from ctypes import wintypes

        hwnd = int(widget.winId())
        if not hwnd:
            return
        value = ctypes.c_int(0)  # 0 = 浅色（关闭 immersive dark mode）
        for attribute in (20, 19):  # 新版/旧版 DWMWA_USE_IMMERSIVE_DARK_MODE
            result = ctypes.windll.dwmapi.DwmSetWindowAttribute(
                wintypes.HWND(hwnd),
                ctypes.c_uint(attribute),
                ctypes.byref(value),
                ctypes.sizeof(value),
            )
            if result == 0:
                break
    except Exception:
        return


def _apply_app_icon(app, qicon) -> None:
    """Give every window the SQ mark; a missing asset is not fatal."""
    from .config import asset_path

    for name in ("sq.ico", "sq.png"):
        path = asset_path("icon", name)
        if path.exists():
            icon = qicon(str(path))
            if not icon.isNull():
                app.setWindowIcon(icon)
                return
