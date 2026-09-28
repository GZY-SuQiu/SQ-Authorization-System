PRIMARY = "#2F6BFF"
PRIMARY_HOVER = "#1E5BEF"
PRIMARY_PRESSED = "#1749C7"
BG = "#FFFFFF"
SURFACE = "#F7F9FC"
BORDER = "#E6EAF2"
TEXT = "#1D2330"
TEXT_MUTED = "#8A94A6"
SUCCESS = "#18A957"
WARNING = "#F2A93B"
DANGER = "#F04438"
INFO = "#2F6BFF"

FONT_FAMILY = '"Microsoft YaHei UI", "Segoe UI", "PingFang SC", sans-serif'

APP_QSS = f"""
* {{
    font-family: {FONT_FAMILY};
    font-size: 13px;
    color: {TEXT};
    outline: none;
}}
QMainWindow, QDialog, QWidget#Root {{
    background: {BG};
}}
QFrame#Sidebar {{
    background: {SURFACE};
    border-right: 1px solid {BORDER};
}}
QFrame#Card {{
    background: {BG};
    border: 1px solid {BORDER};
    border-radius: 12px;
}}
QFrame#StatCard {{
    background: {BG};
    border: 1px solid {BORDER};
    border-radius: 12px;
}}
QFrame#Divider {{
    background: {BORDER};
    max-height: 1px;
    border: none;
}}
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
    font-family: "Consolas", "Cascadia Mono", monospace;
    font-size: 14px;
    letter-spacing: 1px;
}}
QPushButton {{
    background: {BG};
    border: 1px solid #D9E0EC;
    border-radius: 9px;
    padding: 8px 16px;
    color: {TEXT};
}}
QPushButton:hover {{ background: #F2F5FB; border-color: #C3CEE3; }}
QPushButton:pressed {{ background: #E8EEFA; }}
QPushButton:disabled {{ color: #B4BCCB; background: #F5F7FB; border-color: {BORDER}; }}
QPushButton[variant="primary"] {{
    background: {PRIMARY};
    border: 1px solid {PRIMARY};
    color: #FFFFFF;
    font-weight: 600;
}}
QPushButton[variant="primary"]:hover {{ background: {PRIMARY_HOVER}; border-color: {PRIMARY_HOVER}; }}
QPushButton[variant="primary"]:pressed {{ background: {PRIMARY_PRESSED}; }}
QPushButton[variant="primary"]:disabled {{ background: #A9C1FF; border-color: #A9C1FF; color: #FFFFFF; }}
QPushButton[variant="danger"] {{ background: {BG}; border: 1px solid #F5C2BE; color: #D92D20; }}
QPushButton[variant="danger"]:hover {{ background: #FEF3F2; }}
QPushButton[variant="ghost"] {{ background: transparent; border: 1px solid transparent; color: #5B6478; }}
QPushButton[variant="ghost"]:hover {{ background: #F2F5FB; }}
QPushButton#NavButton {{
    text-align: left;
    padding: 10px 14px;
    border-radius: 9px;
    border: 1px solid transparent;
    color: #5B6478;
    font-weight: 500;
}}
QPushButton#NavButton:hover {{ background: #EDF1F9; }}
QPushButton#NavButton:checked {{ background: #EAF0FF; color: {PRIMARY}; font-weight: 600; }}
QLineEdit, QComboBox, QSpinBox, QPlainTextEdit, QTextEdit {{
    background: {BG};
    border: 1px solid #D9E0EC;
    border-radius: 9px;
    padding: 8px 12px;
    selection-background-color: {PRIMARY};
    selection-color: #FFFFFF;
}}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QPlainTextEdit:focus, QTextEdit:focus {{
    border: 1px solid {PRIMARY};
}}
QLineEdit:disabled, QSpinBox:disabled, QComboBox:disabled {{ background: #F5F7FB; color: #9AA3B2; }}
QComboBox::drop-down {{ border: none; width: 26px; }}
QComboBox QAbstractItemView {{
    border: 1px solid {BORDER};
    border-radius: 8px;
    background: {BG};
    selection-background-color: #EAF0FF;
    selection-color: {PRIMARY};
    padding: 4px;
}}
QHeaderView::section {{
    background: {SURFACE};
    border: none;
    border-bottom: 1px solid {BORDER};
    padding: 9px 10px;
    color: {TEXT_MUTED};
    font-weight: 600;
}}
QTableWidget {{
    border: 1px solid {BORDER};
    border-radius: 10px;
    gridline-color: #F0F3F8;
    background: {BG};
}}
QTableWidget::item {{ padding: 6px 8px; border-bottom: 1px solid #F4F6FA; }}
QTableWidget::item:selected {{ background: #EAF0FF; color: {TEXT}; }}
QListWidget {{
    border: 1px solid {BORDER};
    border-radius: 10px;
    background: {BG};
    padding: 4px;
}}
QListWidget::item {{ padding: 8px 10px; border-radius: 7px; }}
QListWidget::item:selected {{ background: #EAF0FF; color: {PRIMARY}; }}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: #D5DCE8; border-radius: 5px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: #BFC9DA; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: transparent; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: #D5DCE8; border-radius: 5px; min-width: 30px; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
QTabWidget::pane {{ border: 1px solid {BORDER}; border-radius: 10px; top: -1px; }}
QTabBar::tab {{ background: transparent; padding: 9px 18px; color: {TEXT_MUTED}; border: none; }}
QTabBar::tab:selected {{ color: {PRIMARY}; border-bottom: 2px solid {PRIMARY}; font-weight: 600; }}
QCheckBox {{ spacing: 8px; }}
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
    background: #EDF1F9;
    height: 10px;
    text-align: center;
}}
QProgressBar::chunk {{ background: {PRIMARY}; border-radius: 6px; }}
"""


def apply_theme(app) -> None:
    app.setStyleSheet(APP_QSS)
