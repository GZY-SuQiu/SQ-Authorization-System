import hashlib
import json
import unittest
from unittest import mock

from core import security
from core.api_client import ApiClient, ApiError


class _FakeResponse:
    def __init__(self, status_code=200, payload=b"{}", headers=None):
        self.status_code = status_code
        self.content = payload
        self.headers = headers or {}
        self.text = payload.decode("utf-8", "replace")

    def json(self):
        return json.loads(self.content or b"{}")


class PasswordHashTests(unittest.TestCase):
    def test_new_hashes_are_versioned_and_verifiable(self):
        digest, salt = security.hash_password("Abcd1234")
        self.assertTrue(digest.startswith("pbkdf2_sha256$"))
        self.assertTrue(security.verify_password("Abcd1234", digest, salt))
        self.assertFalse(security.verify_password("Abcd12345", digest, salt))

    def test_legacy_hashes_still_verify(self):
        salt = "0123456789abcdef0123456789abcdef"
        legacy = hashlib.pbkdf2_hmac(
            "sha256", b"Abcd1234", salt.encode("utf-8"), 120_000
        ).hex()
        self.assertTrue(security.verify_password("Abcd1234", legacy, salt))

    def test_malformed_hash_inputs_fail_closed(self):
        malformed = (
            "",
            "pbkdf2_sha256$not-a-number$deadbeef",
            "pbkdf2_sha256$999999999$deadbeef",
            "pbkdf2_sha256$600000$",
            None,
            12345,
        )
        for value in malformed:
            self.assertFalse(security.verify_password("Abcd1234", value, "salt"))

    def test_token_with_extra_separator_is_rejected(self):
        token = security.create_token({"uid": 1}, "secret")
        self.assertIsNotNone(security.verify_token(token, "secret"))
        self.assertIsNone(security.verify_token(token + ".extra", "secret"))
        self.assertIsNone(security.verify_token("." + token, "secret"))


class ApiClientSessionTests(unittest.TestCase):
    def _client(self) -> ApiClient:
        return ApiClient("http://127.0.0.1:8765")

    def test_failed_login_clears_previous_token(self):
        client = self._client()
        client.token = "stale-token"
        fake = _FakeResponse(401, b'{"detail":"\xe7\x94\xa8\xe6\x88\xb7\xe5\x90\x8d\xe6\x88\x96\xe5\xaf\x86\xe7\xa0\x81\xe9\x94\x99\xe8\xaf\xaf"}')
        with mock.patch("core.api_client.requests.request", return_value=fake):
            with self.assertRaises(ApiError):
                client.login("admin", "wrong-password")
        self.assertIsNone(client.token)

    def test_rejected_session_clears_token(self):
        client = self._client()
        client.token = "stale-token"
        fake = _FakeResponse(401, b'{"detail":"expired"}')
        with mock.patch("core.api_client.requests.request", return_value=fake):
            with self.assertRaises(ApiError):
                client.me()
        self.assertIsNone(client.token)

    def test_policy_forbidden_keeps_token(self):
        # The forced password change returns 403 while the handover token is
        # still valid. Dropping it here makes the change-password call itself
        # fail later with "未登录或登录状态无效".
        client = self._client()
        client.token = "handover-token"
        fake = _FakeResponse(403, b'{"detail":"please change password"}')
        with mock.patch("core.api_client.requests.request", return_value=fake):
            with self.assertRaises(ApiError):
                client.me()
        self.assertEqual(client.token, "handover-token")

    def test_logout_clears_cached_credentials(self):
        client = self._client()
        client.token = "token"
        client.session_secret = "session"
        client.logout(clear_device_session=True)
        self.assertIsNone(client.token)
        self.assertIsNone(client.session_secret)

    def test_redirect_response_is_rejected(self):
        client = self._client()
        fake = _FakeResponse(302, b"", headers={"Location": "http://evil.example/"})
        with mock.patch("core.api_client.requests.request", return_value=fake):
            with self.assertRaises(ApiError):
                client.health()

    def test_url_with_credentials_is_rejected(self):
        with self.assertRaises(ApiError):
            ApiClient("http://user:secret@127.0.0.1:8765")

    def test_malformed_port_is_rejected(self):
        with self.assertRaises(ApiError):
            ApiClient("http://127.0.0.1:not-a-port")


if __name__ == "__main__":
    unittest.main()
