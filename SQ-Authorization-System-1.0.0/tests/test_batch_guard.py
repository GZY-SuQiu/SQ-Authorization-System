"""合题批次 C 的离屏 Qt 守卫测试。

- P2-18 批量操作重入互斥（``core/pages.py`` 的 ``_run_batch``）；
- P1-12 客户端头像限尺寸解码（``verification/ui.py``）。

（本批次只批了 ``test_batch_guard.py`` / ``test_manifest_repair.py`` 两个新
测试文件，头像用例与批量互斥同属客户端守卫，因此放在本文件内。）
"""

import base64
import os
import struct
import zlib

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6")

from PySide6.QtCore import QBuffer, QIODevice, QSize, Qt  # noqa: E402
from PySide6.QtGui import QImage  # noqa: E402
from PySide6.QtWidgets import QApplication, QLabel  # noqa: E402

from core import pages as pages_module  # noqa: E402
from core.api_client import ApiError  # noqa: E402
from core.pages import LicensesPage  # noqa: E402
from verification import ui as verification_ui  # noqa: E402


@pytest.fixture(scope="module")
def qt_app():
    app = QApplication.instance() or QApplication([])
    yield app


def notify(*_args, **_kwargs) -> None:
    return None


def make_item(index: int, status: str = "unused", batch: str = "B1") -> dict:
    return {
        "key_code": f"LIC-{index:04d}",
        "edition": "standard",
        "status": status,
        "duration_days": 30,
        "duration_unit": "day",
        "max_devices": 2,
        "machine_codes": [],
        "created_at": "2026-10-08 10:00:00",
        "expires_at": None,
        "batch_no": batch,
        "note": f"客户{index}",
    }


class FakeClient:
    """只实现 LicensesPage 批量路径需要的最小客户端接口。"""

    def __init__(self, count: int = 3):
        self.items = [make_item(index) for index in range(count)]
        self.revoked: list[str] = []

    def list_licenses(self, **params):
        limit = int(params.get("limit") or 100)
        offset = int(params.get("offset") or 0)
        keyword = str(params.get("keyword") or "").lower()
        status = str(params.get("status") or "")
        batch_no = str(params.get("batch_no") or "")
        rows = [
            item
            for item in self.items
            if (not keyword or keyword in item["key_code"].lower())
            and (not status or item["status"] == status)
            and (not batch_no or item["batch_no"] == batch_no)
        ]
        return {"items": rows[offset:offset + limit], "total": len(rows)}

    def list_batches(self, **params):
        return {
            "items": [{"batch_no": "B1", "total": len(self.items), "note": ""}],
            "total": 1,
        }

    def revoke_license(self, key_code: str):
        self.revoked.append(key_code)
        return {"ok": True}

    def restore_license(self, key_code: str):
        return {"ok": True}


def _prepare_page(client, monkeypatch):
    page = LicensesPage(client, notify)
    page.refresh()
    page.table.selectAll()
    messages: list[tuple[str, str]] = []
    page.notify = lambda message, kind="info": messages.append((kind, message))
    monkeypatch.setattr(pages_module, "confirm", lambda *args, **kwargs: True)
    monkeypatch.setattr(pages_module, "info", lambda *args, **kwargs: None)
    return page, messages


# --------------------------------------------------------------------------- #
# P2-18 批量互斥
# --------------------------------------------------------------------------- #
def test_batch_reentry_runs_once_and_disables_buttons(qt_app, monkeypatch):
    executed: list[str] = []
    disabled_during: list[bool] = []
    holder: list[LicensesPage] = []

    class ReentrantClient(FakeClient):
        def revoke_license(self, key_code: str):
            page = holder[0]
            executed.append(key_code)
            disabled_during.append(not page.ops_button.isEnabled())
            # 模拟 processEvents() 期间用户再次点击批量入口：必须被互斥挡下。
            page.revoke_selected()
            return {"ok": True}

    client = ReentrantClient(3)
    page, messages = _prepare_page(client, monkeypatch)
    holder.append(page)
    enabled_before = [widget.isEnabled() for widget in page._batch_widgets]

    page.revoke_selected()

    # 表格开启排序，执行顺序不保证；关键是每个密钥只执行一次。
    assert sorted(executed) == sorted(item["key_code"] for item in client.items)
    assert disabled_during == [True, True, True]
    assert any("批量操作进行中" in message for _kind, message in messages), messages
    assert page._batch_running is False
    assert page.ops_button.isEnabled()
    # 结束后按原状态恢复（例如第一页的“下一页”本来就是禁用的）。
    assert [widget.isEnabled() for widget in page._batch_widgets] == enabled_before


def test_batch_flag_resets_after_unexpected_exception(qt_app, monkeypatch):
    client = FakeClient(3)

    def boom(key_code: str):
        raise RuntimeError(f"boom:{key_code}")

    client.revoke_license = boom
    page, _messages = _prepare_page(client, monkeypatch)
    refreshed: list[bool] = []
    original_refresh = page.refresh

    def counting_refresh():
        refreshed.append(True)
        original_refresh()

    page.refresh = counting_refresh

    with pytest.raises(RuntimeError):
        page.revoke_selected()

    assert page._batch_running is False
    assert page._batch_busy_state == []
    assert page.ops_button.isEnabled()
    assert refreshed, "异常路径也必须在 finally 里刷新表格"


def test_batch_apierror_reports_and_resets_flag(qt_app, monkeypatch):
    client = FakeClient(3)

    def flaky(key_code: str):
        if key_code.endswith("0001"):
            raise ApiError("状态不允许")
        return {"ok": True}

    client.revoke_license = flaky
    page, messages = _prepare_page(client, monkeypatch)

    page.revoke_selected()

    assert page._batch_running is False
    assert page.ops_button.isEnabled()
    assert any(kind == "warning" for kind, _message in messages), messages


def test_progress_dialog_is_application_modal(qt_app, monkeypatch):
    created: list = []
    real_progress = pages_module.QProgressDialog

    class RecordingProgressDialog(real_progress):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            created.append(self)

    monkeypatch.setattr(pages_module, "QProgressDialog", RecordingProgressDialog)

    client = FakeClient(2)
    page, _messages = _prepare_page(client, monkeypatch)
    original = client.revoke_license
    seen: list = []

    def recording(key_code: str):
        seen.append(created[0].windowModality())
        return original(key_code)

    client.revoke_license = recording

    page.revoke_selected()

    assert created, "批量执行必须使用进度框"
    assert created[0].windowModality() == Qt.ApplicationModal
    assert seen and all(value == Qt.ApplicationModal for value in seen)
    assert not created[0].isVisible()


# --------------------------------------------------------------------------- #
# P1-12 头像限尺寸解码
# --------------------------------------------------------------------------- #
def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _png_bytes(width: int = 64, height: int = 64) -> bytes:
    image = QImage(width, height, QImage.Format_ARGB32)
    image.fill(Qt.red)
    buffer = QBuffer()
    buffer.open(QIODevice.WriteOnly)
    assert image.save(buffer, "PNG")
    return bytes(buffer.data())


def _png_bomb_bytes(width: int = 65535, height: int = 65535) -> bytes:
    """头部声明超大像素、文件却很小的 PNG（解码炸弹样本）。"""

    def chunk(tag: bytes, payload: bytes) -> bytes:
        crc = zlib.crc32(tag + payload) & 0xFFFFFFFF
        return struct.pack(">I", len(payload)) + tag + payload + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    idat = b"\x78\x9c\x03\x00\x00\x00\x00\x01"  # 空的 zlib 流：读取必然失败
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", idat)
        + chunk(b"IEND", b"")
    )


def _install_recording_reader(monkeypatch) -> list:
    """把 verification.ui 里的 QImageReader 换成记录 setScaledSize 的包装。"""
    recorded: list = []
    real_reader = verification_ui.QImageReader

    class RecordingReader:
        def __init__(self, device):
            self._reader = real_reader(device)
            self.scaled: list[QSize] = []
            recorded.append(self)

        def setAutoTransform(self, enabled):
            self._reader.setAutoTransform(enabled)

        def size(self):
            return self._reader.size()

        def setScaledSize(self, size):
            self.scaled.append(QSize(size))
            self._reader.setScaledSize(size)

        def read(self):
            return self._reader.read()

    monkeypatch.setattr(verification_ui, "QImageReader", RecordingReader)
    return recorded


def test_avatar_huge_header_falls_back_without_crash(qt_app):
    bomb = _png_bomb_bytes()
    assert len(bomb) < 1024

    label = QLabel()
    verification_ui.apply_avatar_to_label(label, {"data_base64": _b64(bomb)}, "张三")

    assert label.text() == "张"
    assert label.pixmap().isNull()


def test_avatar_uses_scaled_reader_and_shows_small_image(qt_app, monkeypatch):
    recorded = _install_recording_reader(monkeypatch)

    payload = _b64(_png_bytes(300, 120))
    pixmap = verification_ui.rounded_avatar_pixmap(payload)

    assert recorded and recorded[0].scaled, "必须先 setScaledSize 再 read()"
    for size in recorded[0].scaled:
        assert 0 < size.width() <= verification_ui.AVATAR_DECODE_LIMIT
        assert 0 < size.height() <= verification_ui.AVATAR_DECODE_LIMIT
    assert pixmap is not None and not pixmap.isNull()
    assert pixmap.size() == QSize(
        verification_ui.AVATAR_SIZE, verification_ui.AVATAR_SIZE
    )

    label = QLabel()
    verification_ui.apply_avatar_to_label(label, {"data_base64": payload}, "李四")
    assert label.text() == ""
    assert not label.pixmap().isNull()


def test_avatar_bomb_payload_is_not_decoded_full_size(qt_app, monkeypatch):
    recorded = _install_recording_reader(monkeypatch)

    assert verification_ui.rounded_avatar_pixmap(_b64(_png_bomb_bytes())) is None
    assert recorded and recorded[0].scaled, "炸弹样本也必须走限尺寸路径"
    for size in recorded[0].scaled:
        assert 0 < size.width() <= verification_ui.AVATAR_DECODE_LIMIT
        assert 0 < size.height() <= verification_ui.AVATAR_DECODE_LIMIT
