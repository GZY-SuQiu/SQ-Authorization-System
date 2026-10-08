import json
import time
import unittest
from unittest import mock

import requests

from core.api_client import ATTEST_REQUIRED_MESSAGE, ApiClient, ApiError


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
    """Records requests and serves queued responses (or raises a fixed error)."""

    def __init__(self, responses=None, error: Exception | None = None):
        self.calls: list[dict] = []
        self._responses = list(responses or [])
        self._error = error

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
        if self._error is not None:
            raise self._error
        if self._responses:
            response = self._responses.pop(0)
        else:
            response = {"ok": True}
        if isinstance(response, _FakeResponse):
            return response
        if isinstance(response, tuple):
            return _FakeResponse(response[0], response[1])
        return _FakeResponse(200, response)


def _client(**kwargs) -> ApiClient:
    return ApiClient("http://127.0.0.1:8765", **kwargs)


def _integrity_result(role: str = "verification") -> dict:
    return {
        "ok": True,
        "skipped": False,
        "role": role,
        "exe_name": "验证端.exe",
        "exe_path": "C:/app/验证端.exe",
        "exe_hash": "a" * 64,
        "exe_size": 123,
        "version": "1.0.0",
        "manifest_verified": True,
        "checked_at": "2026-10-07 12:00:00",
        "issues": [],
    }


def _request_body(call: dict) -> dict:
    return json.loads(call["data"].decode("utf-8"))


class AttestHeaderTests(unittest.TestCase):
    def test_request_attaches_attest_token_header(self):
        client = _client()
        transport = _Transport([{"ok": True}])
        with mock.patch("core.api_client.requests.request", transport):
            data = client._request("GET", "/api/health", attest_token="tok-123")
        self.assertEqual(data, {"ok": True})
        self.assertEqual(transport.calls[0]["headers"]["X-Attest-Token"], "tok-123")

    def test_request_without_token_omits_header(self):
        client = _client()
        transport = _Transport([{"ok": True}])
        with mock.patch("core.api_client.requests.request", transport):
            client.health()
        self.assertNotIn("X-Attest-Token", transport.calls[0]["headers"])


class EnsureAttestTests(unittest.TestCase):
    def test_ensure_attest_fetches_once_and_reuses_cache(self):
        client = _client()
        result = _integrity_result()
        client.set_integrity_result(result)
        transport = _Transport([{"ok": True, "attest_token": "tok-1", "expires_in": 600}])
        with mock.patch("core.api_client.requests.request", transport):
            first = client.ensure_attest(role="verification", machine_code="MC-1")
            second = client.ensure_attest(role="verification", machine_code="MC-1")
        self.assertEqual(first, "tok-1")
        self.assertEqual(second, "tok-1")
        self.assertEqual(len(transport.calls), 1)
        call = transport.calls[0]
        self.assertEqual(call["method"], "POST")
        self.assertTrue(call["url"].endswith("/api/client/attest"))
        self.assertNotIn("X-Attest-Token", call["headers"])
        self.assertEqual(
            _request_body(call),
            {
                "role": "verification",
                "exe_name": "验证端.exe",
                "exe_hash": "a" * 64,
                "version": "1.0.0",
                "release_id": "",
                "manifest_sha256": "",
                "machine_code": "MC-1",
                "local_check": result,
            },
        )

    def test_ensure_attest_refreshes_near_expiry(self):
        client = _client()
        client.set_integrity_result(_integrity_result())
        client.attest_token = "stale-token"
        client.attest_token_expires_at = int(time.time()) + 30
        transport = _Transport([{"ok": True, "attest_token": "tok-2", "expires_in": 600}])
        with mock.patch("core.api_client.requests.request", transport):
            token = client.ensure_attest(role="verification", machine_code="MC-2")
        self.assertEqual(token, "tok-2")
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(_request_body(transport.calls[0])["machine_code"], "MC-2")

    def test_attest_network_failure_is_swallowed(self):
        client = _client()
        client.set_integrity_result(_integrity_result())
        transport = _Transport(error=requests.ConnectionError("server down"))
        with mock.patch("core.api_client.requests.request", transport):
            self.assertIsNone(client.attest(role="verification", machine_code="MC-1"))
            self.assertIsNone(client.ensure_attest(role="verification", machine_code="MC-1"))
        self.assertEqual(client.attest_token, "")
        self.assertEqual(len(transport.calls), 2)

    def test_rejected_attest_does_not_raise(self):
        client = _client()
        client.set_integrity_result(_integrity_result())
        transport = _Transport([(403, {"detail": ATTEST_REQUIRED_MESSAGE})])
        with mock.patch("core.api_client.requests.request", transport):
            self.assertIsNone(client.ensure_attest(role="verification", machine_code="MC-1"))
        self.assertEqual(client.attest_token, "")


class IntegrityReportTests(unittest.TestCase):
    def test_report_integrity_failure_payload(self):
        client = _client()
        client.set_integrity_result(_integrity_result())
        detail = {
            "issues": [{"code": "hash_mismatch", "file": "验证端.exe", "detail": "哈希不一致"}],
            "checked_at": "2026-10-07 12:00:00",
            "manifest_verified": True,
        }
        transport = _Transport([{"ok": True}])
        with mock.patch("core.api_client.requests.request", transport):
            with mock.patch("core.api_client.machine.machine_code", return_value="mc-report"):
                data = client.report_integrity_failure("hash_mismatch", detail)
        self.assertEqual(data, {"ok": True})
        call = transport.calls[0]
        self.assertEqual(call["method"], "POST")
        self.assertTrue(call["url"].endswith("/api/client/integrity_report"))
        self.assertEqual(
            _request_body(call),
            {
                "role": "verification",
                "exe_name": "验证端.exe",
                "exe_hash": "a" * 64,
                "version": "1.0.0",
                "machine_code": "MC-REPORT",
                "reason": "hash_mismatch",
                "detail": detail,
            },
        )


class ClientCallAttestTests(unittest.TestCase):
    def _ready_client(self) -> ApiClient:
        client = ApiClient("http://127.0.0.1:8765", response_public_key="ab" * 32)
        client.set_integrity_result(_integrity_result())
        client.attest_token = "cached-token"
        client.attest_token_expires_at = int(time.time()) + 3600
        return client

    def test_client_calls_forward_cached_attest_token(self):
        client = self._ready_client()
        for name, args in (
            ("activate", ("KEY-1", "MC-1")),
            ("verify", ("KEY-1", "MC-1")),
            ("heartbeat", ("KEY-1", "MC-1")),
        ):
            with self.subTest(name=name):
                with mock.patch.object(client, "_request", return_value={"ok": True}) as request:
                    getattr(client, name)(*args)
                self.assertEqual(request.call_args.kwargs.get("attest_token"), "cached-token")

    def test_attest_required_code_is_rejected(self):
        client = self._ready_client()
        with mock.patch.object(
            client, "_request", return_value={"ok": False, "code": "attest_required"}
        ):
            with self.assertRaises(ApiError) as ctx:
                client.verify("KEY-1", "MC-1")
        self.assertEqual(str(ctx.exception), ATTEST_REQUIRED_MESSAGE)


if __name__ == "__main__":
    unittest.main()
