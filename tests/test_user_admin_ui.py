"""Regression tests for the portal user-management page (headless Qt).

Also locks in the console split from contract section 5: the admin window
must not expose 管理员管理/系统设置, the master window must, and both carry
their own role badge text and window title.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QPushButton  # noqa: E402

import core.user_admin as user_admin  # noqa: E402
from core.api_client import ApiClient  # noqa: E402
from core.config import Config  # noqa: E402
from core.user_admin import UserAdminPage  # noqa: E402


def make_account(index: int, status: str = "active") -> dict:
    return {
        "id": index,
        "email": f"user{index}@example.com",
        "display_name": f"用户{index}",
        "status": status,
        "email_verified_at": "2026-10-01 09:00:00",
        "created_at": "2026-10-01 09:00:00",
        "last_login_at": "2026-10-07 12:00:00",
        "bound_key": "GSQ-AAAAA-BBBBB-CCCCC-DDDD1",
        "binding_status": "bound",
        "license_status": "active",
        "expires_at": "2026-12-31 23:59:59",
    }


ACCOUNTS = [
    make_account(1, "active"),
    {
        **make_account(2, "disabled"),
        "display_name": "",
        "bound_key": "",
        "binding_status": "unbound",
        "license_status": "unbound",
        "expires_at": None,
        "last_login_at": None,
    },
]


def notify(*_args, **_kwargs) -> None:
    return None


class RecordingNotify:
    def __init__(self):
        self.messages: list[tuple[str, str]] = []

    def __call__(self, message, kind="info", msec=3000):
        self.messages.append((kind, message))

    def kinds(self) -> list[str]:
        return [kind for kind, _ in self.messages]


class FakeAdminClient:
    """Mirrors GET /api/admin/portal_accounts plus the two write endpoints."""

    def __init__(self, accounts=None):
        self.base_url = "http://127.0.0.1:8765"
        self.accounts = [
            dict(item) for item in (ACCOUNTS if accounts is None else accounts)
        ]
        self.calls: list[tuple] = []

    def portal_accounts(self, keyword="", status="", limit=200, offset=0):
        self.calls.append(("portal_accounts", keyword, status, limit, offset))
        rows = self.accounts
        if keyword:
            needle = keyword.lower()
            rows = [
                row
                for row in rows
                if needle
                in f"{row.get('email', '')} {row.get('display_name') or ''}".lower()
            ]
        if status:
            rows = [row for row in rows if row.get("status") == status]
        return {
            "items": [dict(row) for row in rows[offset : offset + limit]],
            "total": len(rows),
        }

    def set_portal_account_status(self, id, status):
        self.calls.append(("set_portal_account_status", id, status))
        for row in self.accounts:
            if row["id"] == id:
                row["status"] = status
        return {"ok": True}

    def admin_unbind_portal_account(self, id):
        self.calls.append(("admin_unbind_portal_account", id))
        for row in self.accounts:
            if row["id"] == id:
                row["bound_key"] = ""
                row["binding_status"] = "unbound"
                row["license_status"] = "unbound"
        return {"ok": True}


def _last_call(client: FakeAdminClient) -> tuple:
    return client.calls[-1]


class UserAdminPageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def _page(self, client=None, notify_fn=notify) -> UserAdminPage:
        page = UserAdminPage(client or FakeAdminClient(), notify_fn)
        self.addCleanup(page.deleteLater)
        return page

    def test_page_construction_exposes_columns_and_buttons(self):
        page = self._page()
        headers = [
            page.table.horizontalHeaderItem(col).text()
            for col in range(page.table.columnCount())
        ]
        self.assertEqual(
            headers,
            ["邮箱", "名称", "状态", "绑定 Key", "许可证状态", "到期", "注册时间", "最后登录"],
        )
        texts = {page.btn_refresh.text(), page.btn_enable.text(), page.btn_disable.text(), page.btn_unbind.text()}
        self.assertEqual(texts, {"刷新", "启用", "禁用", "强制脱绑"})
        status_values = [
            page.status.itemData(index) for index in range(page.status.count())
        ]
        self.assertEqual(status_values, ["", "active", "disabled"])

    def test_refresh_renders_one_row_per_account(self):
        client = FakeAdminClient()
        page = self._page(client)
        page.refresh()

        self.assertEqual(page.table.rowCount(), 2)
        self.assertEqual(page.table.item(0, 0).text(), "user1@example.com")
        self.assertEqual(page.table.item(0, 1).text(), "用户1")
        self.assertIn("正常", page.table.item(0, 2).text())
        self.assertIn("已禁用", page.table.item(1, 2).text())
        self.assertEqual(page.table.item(1, 3).text(), "未绑定")
        self.assertEqual(page.total_label.text(), "共 2 位用户")
        self.assertEqual(_last_call(client), ("portal_accounts", "", "", 200, 0))

    def test_search_and_status_filter_forward_parameters(self):
        client = FakeAdminClient()
        page = self._page(client)
        page.refresh()

        page.keyword.setText("user2")
        page.apply_filters()
        self.assertEqual(_last_call(client), ("portal_accounts", "user2", "", 200, 0))
        self.assertEqual(page.table.rowCount(), 1)
        self.assertEqual(page.table.item(0, 0).text(), "user2@example.com")

        page.keyword.clear()
        page.status.setCurrentIndex(2)  # 已禁用 -> disabled
        self.assertEqual(_last_call(client)[2], "disabled")
        self.assertEqual(page.table.rowCount(), 1)
        self.assertIn("已禁用", page.table.item(0, 2).text())

    def test_disable_and_enable_call_the_status_endpoint(self):
        client = FakeAdminClient()
        page = self._page(client)
        page.refresh()
        page.table.selectRow(0)

        with mock.patch.object(user_admin, "confirm", lambda *a, **k: True):
            page.disable_account()
        self.assertIn(("set_portal_account_status", 1, "disabled"), client.calls)

        page.table.selectRow(1)
        with mock.patch.object(user_admin, "confirm", lambda *a, **k: True):
            page.enable_account()
        self.assertIn(("set_portal_account_status", 2, "active"), client.calls)

    def test_disabled_action_keeps_state_when_cancelled(self):
        client = FakeAdminClient()
        page = self._page(client)
        page.refresh()
        page.table.selectRow(0)

        with mock.patch.object(user_admin, "confirm", lambda *a, **k: False):
            page.disable_account()
        self.assertNotIn("set_portal_account_status", [call[0] for call in client.calls])

    def test_force_unbind_calls_the_unbind_endpoint(self):
        client = FakeAdminClient()
        messages = RecordingNotify()
        page = self._page(client, messages)
        page.refresh()
        page.table.selectRow(0)

        with mock.patch.object(user_admin, "confirm", lambda *a, **k: True):
            page.force_unbind()

        self.assertIn(("admin_unbind_portal_account", 1), client.calls)
        self.assertIn("success", messages.kinds())
        # The follow-up refresh shows the released binding.
        self.assertEqual(page.table.item(0, 3).text(), "未绑定")

    def test_actions_without_selection_only_notify(self):
        client = FakeAdminClient()
        messages = RecordingNotify()
        page = self._page(client, messages)
        page.refresh()
        page.table.clearSelection()
        page.table.setCurrentCell(-1, -1)

        page.disable_account()
        page.force_unbind()

        self.assertNotIn("set_portal_account_status", [call[0] for call in client.calls])
        self.assertNotIn("admin_unbind_portal_account", [call[0] for call in client.calls])
        self.assertEqual(messages.kinds().count("warning"), 2)


class _FakeResponse:
    def __init__(self, payload=None, status_code: int = 200):
        self.status_code = status_code
        body = json.dumps(payload if payload is not None else {"ok": True})
        self.content = body.encode("utf-8")
        self.headers: dict = {}
        self.text = body

    def json(self):
        return json.loads(self.content.decode("utf-8"))


class PortalAccountClientContractTests(unittest.TestCase):
    """Frozen admin-side client methods and their paths."""

    def _call(self, method_name, *args):
        client = ApiClient("http://127.0.0.1:8765")
        client.token = "admin-token"
        calls: list[dict] = []

        def transport(method, url, **kwargs):
            calls.append(
                {
                    "method": method,
                    "url": url,
                    "headers": dict(kwargs.get("headers") or {}),
                    "data": kwargs.get("data"),
                    "params": kwargs.get("params"),
                }
            )
            return _FakeResponse()

        with mock.patch("core.api_client.requests.request", transport):
            getattr(client, method_name)(*args)
        return calls[0]

    def test_account_list_query_parameters(self):
        call = self._call("portal_accounts", "ali", "active", 50, 100)
        self.assertEqual(call["method"], "GET")
        self.assertTrue(call["url"].endswith("/api/admin/portal_accounts"))
        self.assertEqual(
            call["params"],
            {"keyword": "ali", "status": "active", "limit": 50, "offset": 100},
        )
        self.assertEqual(call["headers"]["Authorization"], "Bearer admin-token")

    def test_status_endpoint_path_and_body(self):
        call = self._call("set_portal_account_status", 7, "disabled")
        self.assertEqual(call["method"], "POST")
        self.assertTrue(
            call["url"].endswith("/api/admin/portal_accounts/7/status")
        )
        self.assertEqual(json.loads(call["data"]), {"status": "disabled"})

    def test_unbind_endpoint_path(self):
        call = self._call("admin_unbind_portal_account", 7)
        self.assertEqual(call["method"], "POST")
        self.assertTrue(call["url"].endswith("/api/admin/portal_accounts/7/unbind"))


class ConsoleSplitTests(unittest.TestCase):
    """Section 5: the two consoles stay visibly and structurally distinct."""

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        cls._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.root = Path(cls._tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _windows(self):
        from admin.ui import AdminWindow
        from master.ui import MasterWindow

        client = FakeAdminClient()
        # must_change_password keeps the constructor from firing page
        # refreshes the fake client does not implement.
        user = {"username": "operator", "role": "admin", "must_change_password": True}
        master_user = dict(user, role="master")
        config = Config("master", path=self.root / "master_config.json")
        admin = AdminWindow(client, user)
        master = MasterWindow(client, master_user, config)
        for window in (admin, master):
            self.addCleanup(window.close)
            self.addCleanup(window.deleteLater)
        return admin, master

    def test_admin_navigation_excludes_system_pages(self):
        admin, _master = self._windows()
        labels = [button.text() for button in admin._buttons]
        self.assertIn("用户管理", labels)
        self.assertNotIn("管理员管理", labels)
        self.assertNotIn("系统设置", labels)
        self.assertEqual(
            admin.windowTitle(), "密钥授权系统 · 管理端（密钥运营）"
        )
        self.assertEqual(admin.role_badge.text(), "密钥运营")

    def test_master_navigation_includes_system_pages(self):
        _admin, master = self._windows()
        labels = [button.text() for button in master._buttons]
        self.assertIn("用户管理", labels)
        self.assertIn("管理员管理", labels)
        self.assertIn("系统设置", labels)
        self.assertEqual(
            master.windowTitle(), "密钥授权系统 · 主控端（系统管理）"
        )
        self.assertEqual(master.role_badge.text(), "系统管理")

    def test_user_management_sits_after_key_management(self):
        admin, master = self._windows()
        for window in (admin, master):
            labels = [button.text() for button in window._buttons]
            self.assertEqual(
                labels[labels.index("密钥管理") + 1], "用户管理"
            )
            self.assertIsInstance(window.user_admin, UserAdminPage)

    def test_nav_buttons_are_real_buttons(self):
        admin, _master = self._windows()
        self.assertTrue(all(isinstance(btn, QPushButton) for btn in admin._buttons))


if __name__ == "__main__":
    unittest.main()
