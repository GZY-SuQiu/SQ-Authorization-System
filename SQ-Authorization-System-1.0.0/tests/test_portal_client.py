import json
import time
import unittest
from unittest import mock

import requests

from core.api_client import ApiClient, ApiError


class _FakeResponse:
    def __init__(self, status_code: int = 200, payload=None, headers=None):
        if isinstance(payload, (bytes, bytearray)):
            content = bytes(payload)
        elif payload is None:
            content = b""
        else:
            content = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.status_code = status_code
        self.content = content
        self.headers = dict(headers or {})
        self.text = content.decode("utf-8", "replace")

    def json(self):
        return json.loads(self.content or b"{}")


class _Transport:
    def __init__(self, responses=None):
        self.calls: list[dict] = []
        self._responses = list(responses or [])

    def __call__(self, method, url, **kwargs):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": dict(kwargs.get("headers") or {}),
                "data": kwargs.get("data"),
                "params": kwargs.get("params"),
            }
        )
        response = self._responses.pop(0) if self._responses else {"ok": True}
        if isinstance(response, _FakeResponse):
            return response
        if isinstance(response, tuple):
            return _FakeResponse(response[0], response[1])
        return _FakeResponse(200, response)


def _client() -> ApiClient:
    return ApiClient("http://127.0.0.1:8765")


def _body(call: dict) -> dict:
    return json.loads(call["data"].decode("utf-8"))


class PortalHeaderTests(unittest.TestCase):
    def test_portal_me_prefers_portal_token_over_admin_token(self):
        client = _client()
        client.token = "admin-token"
        client.portal_token = "portal-token"
        transport = _Transport([{"ok": True, "email": "user@example.com"}])
        with mock.patch("core.api_client.requests.request", transport):
            data = client.portal_me()
        self.assertTrue(data["ok"])
        call = transport.calls[0]
        self.assertEqual(call["method"], "GET")
        self.assertTrue(call["url"].endswith("/api/portal/me"))
        self.assertEqual(call["headers"]["Authorization"], "Bearer portal-token")

    def test_admin_request_still_uses_admin_token(self):
        client = _client()
        client.token = "admin-token"
        client.portal_token = "portal-token"
        transport = _Transport([{"ok": True}])
        with mock.patch("core.api_client.requests.request", transport):
            client.me()
        call = transport.calls[0]
        self.assertTrue(call["url"].endswith("/api/admin/me"))
        self.assertEqual(call["headers"]["Authorization"], "Bearer admin-token")

    def test_portal_public_call_does_not_leak_admin_token(self):
        client = _client()
        client.token = "admin-token"
        transport = _Transport(
            [{"ok": True, "token": "portal-token", "expires_in": 600}]
        )
        with mock.patch("core.api_client.requests.request", transport):
            client.portal_login("user@example.com", "secret")
        self.assertNotIn("Authorization", transport.calls[0]["headers"])

    def test_portal_401_clears_only_portal_token(self):
        client = _client()
        client.token = "admin-token"
        client.portal_token = "expired-portal-token"
        client.portal_token_expires_at = int(time.time()) + 600
        transport = _Transport([(401, {"detail": "门户会话已过期"})])
        with mock.patch("core.api_client.requests.request", transport):
            with self.assertRaises(ApiError):
                client.portal_me()
        self.assertEqual(client.portal_token, "")
        self.assertEqual(client.portal_token_expires_at, 0)
        self.assertEqual(client.token, "admin-token")

    def test_admin_401_does_not_clear_portal_token(self):
        client = _client()
        client.token = "expired-admin-token"
        client.portal_token = "portal-token"
        transport = _Transport([(401, {"detail": "管理员会话已过期"})])
        with mock.patch("core.api_client.requests.request", transport):
            with self.assertRaises(ApiError):
                client.me()
        self.assertEqual(client.token, None)
        self.assertEqual(client.portal_token, "portal-token")

    def test_invalid_portal_payload_clears_token(self):
        client = _client()
        client.portal_token = "bad-token"
        client.portal_token_expires_at = int(time.time()) + 600
        transport = _Transport([{"ok": False, "code": "invalid_token"}])
        with mock.patch("core.api_client.requests.request", transport):
            data = client.portal_me()
        self.assertFalse(data["ok"])
        self.assertEqual(client.portal_token, "")
        self.assertEqual(client.portal_token_expires_at, 0)


class PortalMethodTests(unittest.TestCase):
    def test_send_code_path_and_body(self):
        client = _client()
        transport = _Transport([{"ok": True}])
        with mock.patch("core.api_client.requests.request", transport):
            client.portal_send_code("user@example.com", "register")
        call = transport.calls[0]
        self.assertEqual(call["method"], "POST")
        self.assertTrue(call["url"].endswith("/api/portal/email/send_code"))
        self.assertEqual(
            _body(call), {"email": "user@example.com", "purpose": "register"}
        )

    def test_login_saves_token_and_expiry(self):
        client = _client()
        client.token = "admin-token"
        transport = _Transport(
            [
                {
                    "ok": True,
                    "token": "portal-token",
                    "expires_in": 43200,
                    "email": "user@example.com",
                    "binding": None,
                }
            ]
        )
        before = int(time.time())
        with mock.patch("core.api_client.requests.request", transport):
            data = client.portal_login("user@example.com", "secret")
        after = int(time.time())
        call = transport.calls[0]
        self.assertTrue(call["url"].endswith("/api/portal/login"))
        self.assertEqual(
            _body(call), {"email": "user@example.com", "password": "secret"}
        )
        self.assertEqual(data["token"], "portal-token")
        self.assertEqual(client.portal_token, "portal-token")
        self.assertGreaterEqual(client.portal_token_expires_at, before + 43200)
        self.assertLessEqual(client.portal_token_expires_at, after + 43200)
        self.assertEqual(client.token, "admin-token")

    def test_register_saves_token_and_expiry(self):
        client = _client()
        transport = _Transport(
            [
                {
                    "ok": True,
                    "token": "register-token",
                    "expires_in": 120,
                    "email": "new@example.com",
                }
            ]
        )
        before = int(time.time())
        with mock.patch("core.api_client.requests.request", transport):
            client.portal_register("new@example.com", "123456", "secret")
        call = transport.calls[0]
        self.assertTrue(call["url"].endswith("/api/portal/register"))
        self.assertEqual(
            _body(call),
            {"email": "new@example.com", "code": "123456", "password": "secret"},
        )
        self.assertEqual(client.portal_token, "register-token")
        self.assertGreaterEqual(client.portal_token_expires_at, before + 120)

    def test_bind_runs_attest_first_and_forwards_header(self):
        client = _client()
        client.portal_token = "portal-token"
        events: list[str] = []
        transport = _Transport([{"ok": True, "binding": {"key_code": "GSQ-1"}}])

        def ensure_attest(*, role: str, machine_code: str) -> str:
            events.append("attest")
            self.assertEqual(role, "verification")
            self.assertEqual(machine_code, "MACHINE-1")
            return "attest-token"

        with mock.patch.object(client, "ensure_attest", side_effect=ensure_attest):
            with mock.patch("core.api_client.requests.request", transport):
                events.append("before")
                data = client.portal_bind("GSQ-KEY", "MACHINE-1", "DESKTOP-1")
                events.append("after")
        call = transport.calls[0]
        self.assertTrue(call["url"].endswith("/api/portal/bind"))
        self.assertEqual(
            _body(call),
            {
                "key_code": "GSQ-KEY",
                "machine_code": "MACHINE-1",
                "device_name": "DESKTOP-1",
            },
        )
        self.assertEqual(call["headers"]["Authorization"], "Bearer portal-token")
        self.assertEqual(call["headers"]["X-Attest-Token"], "attest-token")
        self.assertEqual(events, ["before", "attest", "after"])
        self.assertTrue(data["ok"])

    def test_unbind_path_and_portal_authorization(self):
        client = _client()
        client.token = "admin-token"
        client.portal_token = "portal-token"
        transport = _Transport([{"ok": True}])
        with mock.patch("core.api_client.requests.request", transport):
            client.portal_unbind()
        call = transport.calls[0]
        self.assertEqual(call["method"], "POST")
        self.assertTrue(call["url"].endswith("/api/portal/unbind"))
        self.assertIsNone(call["data"])
        self.assertEqual(call["headers"]["Authorization"], "Bearer portal-token")

    def test_renew_request_body(self):
        client = _client()
        client.portal_token = "portal-token"
        transport = _Transport([{"ok": True, "request_id": 7}])
        with mock.patch("core.api_client.requests.request", transport):
            client.portal_renew_request("请尽快处理")
        call = transport.calls[0]
        self.assertTrue(call["url"].endswith("/api/portal/renew_request"))
        self.assertEqual(_body(call), {"note": "请尽快处理"})
        self.assertEqual(call["headers"]["Authorization"], "Bearer portal-token")

    def test_password_reset_path_and_body(self):
        client = _client()
        transport = _Transport([{"ok": True}])
        with mock.patch("core.api_client.requests.request", transport):
            client.portal_password_reset("user@example.com", "123456", "new-secret")
        call = transport.calls[0]
        self.assertTrue(call["url"].endswith("/api/portal/password/reset"))
        self.assertEqual(
            _body(call),
            {
                "email": "user@example.com",
                "code": "123456",
                "new_password": "new-secret",
            },
        )


class AdminEmailMethodTests(unittest.TestCase):
    def test_admin_methods_use_admin_authorization_and_contract_paths(self):
        client = _client()
        client.token = "admin-token"
        client.portal_token = "portal-token"
        cases = [
            (
                "admin_set_email",
                ("user@example.com",),
                "/api/admin/email/set",
                {"email": "user@example.com"},
            ),
            (
                "admin_verify_email",
                ("123456",),
                "/api/admin/email/verify",
                {"code": "123456"},
            ),
            (
                "admin_password_forgot",
                ("user@example.com",),
                "/api/admin/password/forgot",
                {"email": "user@example.com"},
            ),
            (
                "admin_password_reset",
                ("user@example.com", "123456", "new-secret"),
                "/api/admin/password/reset",
                {
                    "email": "user@example.com",
                    "code": "123456",
                    "new_password": "new-secret",
                },
            ),
        ]
        transport = _Transport([{"ok": True} for _ in cases])
        with mock.patch("core.api_client.requests.request", transport):
            for name, args, _path, _payload in cases:
                getattr(client, name)(*args)
        self.assertEqual(len(transport.calls), len(cases))
        for call, (_name, _args, path, payload) in zip(transport.calls, cases):
            self.assertEqual(call["method"], "POST")
            self.assertTrue(call["url"].endswith(path))
            self.assertEqual(_body(call), payload)
            self.assertEqual(call["headers"]["Authorization"], "Bearer admin-token")


class FailureSemanticsTests(unittest.TestCase):
    def test_login_failure_returns_payload_without_replacing_token(self):
        client = _client()
        client.portal_token = "old-token"
        transport = _Transport(
            [{"ok": False, "code": "invalid_credentials", "message": "邮箱或密码错误"}]
        )
        with mock.patch("core.api_client.requests.request", transport):
            data = client.portal_login("user@example.com", "bad")
        self.assertFalse(data["ok"])
        self.assertEqual(client.portal_token, "old-token")

    def test_transport_error_keeps_api_error_semantics(self):
        client = _client()
        transport = _Transport()
        with mock.patch(
            "core.api_client.requests.request",
            side_effect=requests.ConnectionError("down"),
        ):
            with self.assertRaises(ApiError) as ctx:
                client.portal_login("user@example.com", "secret")
        self.assertTrue(ctx.exception.offline_ok)
        self.assertEqual(transport.calls, [])


if __name__ == "__main__":
    unittest.main()
