# -*- coding: utf-8 -*-
"""二维码：矩阵生成（qrcode 库，缺失时优雅降级）+ 桌面端展示对话框。

设计要点：
- 矩阵生成纯逻辑（可无 Qt 环境测试）；对话框内惰性导入 PySide6。
- qrcode 只负责编码，渲染用 QImage 逐像素绘制——不依赖 pillow。
"""

from __future__ import annotations

__all__ = ["make_qr_matrix", "matrix_ascii", "show_qr_dialog"]


def make_qr_matrix(text: str):
    """生成二维码布尔矩阵（含静区）；空文本或库缺失时返回 None。"""
    value = str(text or "").strip()
    if not value:
        return None
    try:
        import qrcode  # type: ignore
    except Exception:
        return None
    try:
        qr = qrcode.QRCode(
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=1,
            border=2,
        )
        qr.add_data(value)
        qr.make(fit=True)
        return [[bool(cell) for cell in row] for row in qr.get_matrix()]
    except Exception:
        return None


def matrix_ascii(matrix) -> str:
    """ASCII 预览（测试 / CLI 用）。"""
    if not matrix:
        return ""
    return "\n".join("".join("##" if cell else "  " for cell in row) for row in matrix)


def show_qr_dialog(parent, title: str, text: str) -> bool:
    """弹出二维码对话框；qrcode 不可用时回退为提示框。返回是否展示成功。"""
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QImage, QPixmap
    from PySide6.QtWidgets import (
        QDialog,
        QLabel,
        QMessageBox,
        QPushButton,
        QVBoxLayout,
    )

    matrix = make_qr_matrix(text)
    if matrix is None:
        QMessageBox.information(parent, title, "二维码组件不可用（缺少 qrcode 依赖）。")
        return False
    scale = 4
    size = len(matrix)
    image = QImage(size * scale, size * scale, QImage.Format.Format_Mono)
    image.fill(1)  # 1 = 白底
    for y, row in enumerate(matrix):
        for x, cell in enumerate(row):
            if not cell:
                continue
            for dy in range(scale):
                for dx in range(scale):
                    image.setPixel(x * scale + dx, y * scale + dy, 0)

    dialog = QDialog(parent)
    dialog.setWindowTitle(title)
    layout = QVBoxLayout(dialog)
    qr_label = QLabel()
    qr_label.setPixmap(QPixmap.fromImage(image))
    qr_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    layout.addWidget(qr_label)
    tip = QLabel("用手机扫描即可读取内容；数据仅在本机生成，不会上传网络。")
    tip.setObjectName("Muted")
    tip.setWordWrap(True)
    layout.addWidget(tip)
    close_button = QPushButton("关闭")
    close_button.clicked.connect(dialog.accept)
    layout.addWidget(close_button, alignment=Qt.AlignmentFlag.AlignRight)
    dialog.exec()
    return True
