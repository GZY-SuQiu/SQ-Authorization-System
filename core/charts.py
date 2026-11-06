# -*- coding: utf-8 -*-
"""轻量图表组件（自绘，零第三方依赖）——数据看板专用。

只实现柱状图：足够展示"新增 / 激活 / 到期"的按日趋势，不引入 QtCharts
（避免打包体积与平台差异）。颜色从控件调色板取值，深浅主题自适应。
"""

from __future__ import annotations

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QWidget


class BarChart(QWidget):
    """多序列柱状图。

    用法::

        chart.set_data(["01-01", "01-02", ...], [
            ("新增", [3, 5, ...], theme.PRIMARY),
            ("激活", [1, 2, ...], theme.SUCCESS),
        ])
    """

    def __init__(self, parent=None, *, min_height: int = 190, show_legend: bool = True):
        super().__init__(parent)
        self._labels: list[str] = []
        self._series: list[tuple[str, list[int], str]] = []
        self._show_legend = bool(show_legend)
        self.setMinimumHeight(int(min_height))

    def set_data(self, labels, series) -> None:
        self._labels = [str(label) for label in (labels or [])]
        cleaned: list[tuple[str, list[int], str]] = []
        for name, values, color in series or []:
            cleaned.append(
                (
                    str(name),
                    [max(0, int(value or 0)) for value in (values or [])],
                    str(color),
                )
            )
        self._series = cleaned
        self.update()

    # ------------------------------------------------------------------ #
    def paintEvent(self, event) -> None:  # noqa: N802 - Qt override
        painter = QPainter(self)
        try:
            painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
            self._paint(painter)
        finally:
            painter.end()

    def _paint(self, painter: QPainter) -> None:
        rect = self.rect().adjusted(10, 8, -10, -8)
        palette = self.palette()
        muted = palette.color(palette.ColorRole.PlaceholderText)
        text_color = palette.color(palette.ColorRole.WindowText)

        values = [value for _, series_values, _ in self._series for value in series_values]
        if not values or max(values) <= 0:
            painter.setPen(QPen(muted))
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, "暂无数据")
            return

        legend_h = 20 if (self._show_legend and self._series) else 0
        bottom_h = 16
        plot = QRectF(
            rect.left(),
            rect.top() + legend_h,
            rect.width(),
            rect.height() - legend_h - bottom_h,
        )
        max_value = max(values)
        group_count = max(
            len(self._labels),
            max((len(series_values) for _, series_values, _ in self._series), default=0),
        )
        if group_count <= 0:
            return

        font = QFont(self.font())
        font.setPointSize(max(7, font.pointSize() - 2))
        painter.setFont(font)

        # 网格 + Y 轴刻度
        grid_pen = QPen(QColor(128, 128, 128, 60))
        for step in range(4):
            y = plot.top() + plot.height() * step / 3.0
            painter.setPen(grid_pen)
            painter.drawLine(int(plot.left()), int(y), int(plot.right()), int(y))
            painter.setPen(QPen(muted))
            painter.drawText(
                QRectF(plot.left(), y - 14, 44, 14),
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                str(int(max_value * (3 - step) / 3)),
            )

        # 柱体
        series_count = max(1, len(self._series))
        group_w = plot.width() / group_count
        pad = 6.0
        bar_w = max(1.5, (max(2.0, group_w - pad * 2)) / series_count - 1.0)
        label_stride = max(1, group_count // 10)

        for group_index in range(group_count):
            for series_index, (_name, series_values, color) in enumerate(self._series):
                if group_index >= len(series_values):
                    continue
                value = series_values[group_index]
                if value <= 0:
                    continue
                bar_h = plot.height() * (value / max_value)
                x = plot.left() + group_w * group_index + pad + (bar_w + 1.0) * series_index
                painter.fillRect(
                    QRectF(x, plot.bottom() - bar_h, bar_w, bar_h), QColor(color)
                )
            if group_index % label_stride == 0 and group_index < len(self._labels):
                painter.setPen(QPen(muted))
                painter.drawText(
                    QRectF(
                        plot.left() + group_w * group_index,
                        plot.bottom() + 2,
                        group_w * label_stride,
                        bottom_h,
                    ),
                    Qt.AlignmentFlag.AlignCenter,
                    self._labels[group_index],
                )

        # 图例
        if legend_h:
            x = rect.left()
            for name, _series_values, color in self._series:
                painter.fillRect(QRectF(x, rect.top() + 4, 10, 10), QColor(color))
                painter.setPen(QPen(text_color))
                painter.drawText(
                    QRectF(x + 14, rect.top(), 130, 18),
                    Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                    name,
                )
                x += 140
