"""Regression tests for the verification client's portal profile UI.

Covers the profile/avatar client contract, the account card shown after an
e-mail login (name / avatar / fallback initial) and the edit dialog.
"""

import base64
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QBuffer, QIODevice, Qt  # noqa: E402
from PySide6.QtGui import QPixmap  # noqa: E402
from PySide6.QtWidgets import QApplication, QDialog, QFileDialog  # noqa: E402

import verification.ui as verify_ui  # noqa: E402
from core.api_client import ApiClient, ApiError  # noqa: E402
from core.config import Config  # noqa: E402
from verification.ui import (  # noqa: E402
    AVATAR_MAX_BYTES,
    ProfileEditDialog,
    VerifyWindow,
)


def png_bytes(size: int = 8) -> bytes:
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.red)
    buffer = QBuffer()
    buffer.open(QIODevice.WriteOnly)
    pixmap.save(buffer, "PNG")
    data = bytes(buffer.data())
    buffer.close()
    return data


def png_base64(size: int = 8) -> str:
    return base64.b64encode(png_bytes(size)).decode("ascii")


class RecordingNotify:
    def __init__(self):
        self.messages: list[tuple[str, str]] = []

    def __call__(self, message, kind="info", msec=3000):
        self.messages.append((kind, message))

    def kinds(self) -> list[str]:
        return [kind for kind, _ in self.messages]


class FakePortalClient:
    """Minimal ApiClient stand-in used to build a real VerifyWindow."""

    def __init__(self, profile=None):
        self.base_url = "http://127.0.0.1:8765"
        self.portal_token = ""
        self.portal_token_expires_at = 0
        self.session_secret = None
        self.calls: list[tuple] = []
        self.login_payload: dict = {}
        self.profile = {
            "ok": True,
            "email": "user@example.com",
            "display_name": "",
            "email_verified": True,
            "avatar": None,
        }
        if profile:
            self.profile.update(profile)

    # --- surface used by VerifyWindow ----------------------------------
    def set_trusted_public_keys(self, *_args):
        return None

    def set_session_secret(self, secret):
        self.session_secret = secret

    def clear_portal_session(self):
        self.portal_token = ""
        self.portal_token_expires_at = 0

    # --- portal profile contract ---------------------------------------
    def portal_login(self, email, password):
        self.calls.append(("portal_login", email, password))
        payload = {
            "ok": True,
            "email": email,
            "token": "portal-token",
            "expires_in": 600,
            "binding": None,
        }
        payload.update(self.login_payload)
        self.portal_token = "portal-token"
        self.portal_token_expires_at = int(time.time()) + 600
        for key in ("email", "display_name", "avatar"):
            if key in payload:
                self.profile[key] = payload[key]
        return payload

    def portal_profile(self):
        self.calls.append(("portal_profile",))
        return dict(self.profile)

    def portal_update_profile(self, display_name):
        self.calls.append(("portal_update_profile", display_name))
        self.profile["display_name"] = display_name
        return {"ok": True}

    def portal_upload_avatar(self, mime, data_base64):
        self.calls.append(("portal_upload_avatar", mime, data_base64))
        self.profile["avatar"] = {"mime": mime, "data_base64": data_base64}
        return {"ok": True}

    def portal_delete_avatar(self):
        self.calls.append(("portal_delete_avatar",))
        self.profile["avatar"] = None
        return {"ok": True}

    def portal_me(self):
        self.calls.append(("portal_me",))
        return dict(self.profile, binding=None)


class _FakeResponse:
    def __init__(self, payload=None, status_code: int = 200):
        self.status_code = status_code
        body = json.dumps(payload if payload is not None else {"ok": True})
        self.content = body.encode("utf-8")
        self.headers: dict = {}
        self.text = body

    def json(self):
        return json.loads(self.content.decode("utf-8"))


class PortalProfileClientContractTests(unittest.TestCase):
    """The four new client methods must keep their frozen paths/bodies."""

    def _call(self, method_name, *args):
        client = ApiClient("http://127.0.0.1:8765")
        client.portal_token = "portal-token"
        calls: list[dict] = []

        def transport(method, url, **kwargs):
            calls.append(
                {
                    "method": method,
                    "url": url,
                    "headers": dict(kwargs.get("headers") or {}),
                    "data": kwargs.get("data"),
                }
            )
            return _FakeResponse()

        with mock.patch("core.api_client.requests.request", transport):
            getattr(client, method_name)(*args)
        return calls[0]

    def test_profile_read_uses_portal_bearer(self):
        call = self._call("portal_profile")
        self.assertEqual(call["method"], "GET")
        self.assertTrue(call["url"].endswith("/api/portal/profile"))
        self.assertEqual(call["headers"]["Authorization"], "Bearer portal-token")

    def test_profile_update_body(self):
        call = self._call("portal_update_profile", "张三")
        self.assertEqual(call["method"], "PUT")
        self.assertTrue(call["url"].endswith("/api/portal/profile"))
        self.assertEqual(json.loads(call["data"]), {"display_name": "张三"})
        self.assertEqual(call["headers"]["Authorization"], "Bearer portal-token")

    def test_avatar_upload_body(self):
        call = self._call("portal_upload_avatar", "image/png", "QUJD")
        self.assertEqual(call["method"], "POST")
        self.assertTrue(call["url"].endswith("/api/portal/avatar"))
        self.assertEqual(
            json.loads(call["data"]), {"mime": "image/png", "data_base64": "QUJD"}
        )

    def test_avatar_delete(self):
        call = self._call("portal_delete_avatar")
        self.assertEqual(call["method"], "DELETE")
        self.assertTrue(call["url"].endswith("/api/portal/avatar"))
        self.assertIsNone(call["data"])


class ProfileVerifyWindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        cls._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.root = Path(cls._tmp.name)
        cls.config = Config("verification", path=cls.root / "verification_config.json")

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _window(self, client) -> VerifyWindow:
        with mock.patch.object(verify_ui, "ApiClient", return_value=client):
            window = VerifyWindow(self.config)
        self.addCleanup(window.close)
        self.addCleanup(window.deleteLater)
        return window

    def _login(self, window, client):
        window.portal_login_email.setText("user@example.com")
        window.portal_login_password.setText("secret")
        window.portal_login()
        self.assertTrue(window.portal_authenticated)
        self.assertEqual(client.calls[0], ("portal_login", "user@example.com", "secret"))

    def test_login_shows_display_name_email_and_avatar(self):
        client = FakePortalClient()
        client.login_payload = {
            "display_name": "张三",
            "avatar": {"mime": "image/png", "data_base64": png_base64()},
        }
        window = self._window(client)
        self._login(window, client)

        self.assertEqual(window.portal_display_name_label.text(), "张三")
        self.assertEqual(window.portal_email_label.text(), "user@example.com")
        pixmap = window.portal_avatar_label.pixmap()
        self.assertIsNotNone(pixmap)
        self.assertFalse(pixmap.isNull())
        self.assertEqual(window.portal_avatar_label.text(), "")

    def test_missing_display_name_shows_email_prefix(self):
        client = FakePortalClient()
        window = self._window(client)
        self._login(window, client)
        self.assertEqual(window.portal_display_name_label.text(), "user")

    def test_empty_avatar_falls_back_to_initial(self):
        client = FakePortalClient()
        client.login_payload = {"display_name": "张三", "avatar": None}
        window = self._window(client)
        self._login(window, client)

        self.assertTrue(window.portal_avatar_label.pixmap().isNull())
        self.assertEqual(window.portal_avatar_label.text(), "张")

    def test_broken_avatar_payload_does_not_crash(self):
        client = FakePortalClient()
        client.login_payload = {
            "display_name": "李四",
            "avatar": {"mime": "image/png", "data_base64": "!!!not-base64!!!"},
        }
        window = self._window(client)
        self._login(window, client)

        self.assertTrue(window.portal_avatar_label.pixmap().isNull())
        self.assertEqual(window.portal_avatar_label.text(), "李")

    def test_window_refreshes_profile_from_server(self):
        client = FakePortalClient()
        window = self._window(client)
        self._login(window, client)

        client.profile["display_name"] = "改名后"
        self.assertTrue(window.portal_refresh_profile())
        self.assertIn(("portal_profile",), client.calls)
        self.assertEqual(window.portal_display_name_label.text(), "改名后")

    def test_edit_dialog_refreshes_card_immediately(self):
        client = FakePortalClient()
        window = self._window(client)
        self._login(window, client)

        class AutoSaveDialog(verify_ui.ProfileEditDialog):
            def exec(self):
                self.name.setText("王五")
                self.save()
                return QDialog.Accepted

        with mock.patch.object(verify_ui, "ProfileEditDialog", AutoSaveDialog):
            window.open_profile_editor()

        self.assertIn(("portal_update_profile", "王五"), client.calls)
        self.assertEqual(window.portal_display_name, "王五")
        self.assertEqual(window.portal_display_name_label.text(), "王五")


class ProfileEditDialogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        cls._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.root = Path(cls._tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _dialog(self, client, **kwargs) -> ProfileEditDialog:
        dialog = ProfileEditDialog(
            client,
            RecordingNotify(),
            fallback_text="user@example.com",
            **kwargs,
        )
        self.addCleanup(dialog.deleteLater)
        return dialog

    def test_save_uploads_name_and_avatar(self):
        client = FakePortalClient()
        avatar_path = self.root / "avatar.png"
        avatar_path.write_bytes(png_bytes())
        dialog = self._dialog(client)
        dialog.name.setText("  李四  ")

        with mock.patch.object(
            QFileDialog,
            "getOpenFileName",
            staticmethod(lambda *a, **k: (str(avatar_path), "")),
        ):
            dialog.choose_avatar()
        self.assertIsNotNone(dialog.pending_avatar)
        self.assertEqual(dialog.pending_avatar["mime"], "image/png")

        dialog.save()
        self.assertTrue(dialog.saved)
        self.assertEqual(dialog.result(), QDialog.Accepted)
        names = [call[0] for call in client.calls]
        self.assertEqual(
            names[:3],
            ["portal_update_profile", "portal_upload_avatar", "portal_profile"],
        )
        self.assertEqual(client.calls[0], ("portal_update_profile", "李四"))
        expected = base64.b64encode(avatar_path.read_bytes()).decode("ascii")
        self.assertEqual(
            client.calls[1], ("portal_upload_avatar", "image/png", expected)
        )
        self.assertIsInstance(dialog.profile, dict)
        self.assertEqual(dialog.profile["display_name"], "李四")
        self.assertEqual(dialog.profile["avatar"]["data_base64"], expected)

    def test_save_removes_existing_avatar(self):
        client = FakePortalClient()
        dialog = self._dialog(
            client,
            avatar={"mime": "image/png", "data_base64": png_base64()},
        )
        dialog.clear_avatar()
        dialog.save()

        self.assertTrue(dialog.saved)
        self.assertEqual(
            [call[0] for call in client.calls],
            ["portal_delete_avatar", "portal_profile"],
        )

    def test_oversized_avatar_is_rejected_before_upload(self):
        client = FakePortalClient()
        big_path = self.root / "big.png"
        big_path.write_bytes(b"\x89PNG" + b"0" * (AVATAR_MAX_BYTES + 1))
        notify = RecordingNotify()
        dialog = ProfileEditDialog(client, notify)
        self.addCleanup(dialog.deleteLater)

        self.assertFalse(dialog.load_avatar_file(str(big_path)))
        self.assertIsNone(dialog.pending_avatar)
        self.assertIn("warning", notify.kinds())

    def test_unsupported_extension_is_rejected(self):
        client = FakePortalClient()
        bad_path = self.root / "avatar.gif"
        bad_path.write_bytes(b"GIF89a")
        notify = RecordingNotify()
        dialog = ProfileEditDialog(client, notify)
        self.addCleanup(dialog.deleteLater)

        self.assertFalse(dialog.load_avatar_file(str(bad_path)))
        self.assertEqual(client.calls, [])
        self.assertIn("warning", notify.kinds())

    def test_dialog_previews_the_current_avatar(self):
        client = FakePortalClient()
        dialog = self._dialog(
            client,
            display_name="张三",
            avatar={"mime": "image/png", "data_base64": png_base64()},
        )
        self.assertFalse(dialog.avatar_preview.pixmap().isNull())

    def test_save_reports_local_result_when_refresh_fails(self):
        client = FakePortalClient()

        def broken_profile():
            client.calls.append(("portal_profile",))
            raise ApiError("网络不可用", offline_ok=True)

        client.portal_profile = broken_profile
        notify = RecordingNotify()
        dialog = ProfileEditDialog(client, notify, fallback_text="user@example.com")
        self.addCleanup(dialog.deleteLater)
        dialog.name.setText("赵六")
        dialog.save()

        self.assertTrue(dialog.saved)
        self.assertEqual(dialog.profile, {"ok": True, "display_name": "赵六"})
        self.assertIn("success", notify.kinds())


if __name__ == "__main__":
    unittest.main()
