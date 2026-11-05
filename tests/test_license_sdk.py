"""BUGFIX 批次（问题四）：Python SDK 端到端回归。

复用 ``tests/test_api_hardening.py`` 的 ``LiveServer`` 模式（真实 uvicorn +
FastAPI + SQLite），验证 ``sdk.LicenseClient`` 的 activate/verify/heartbeat/
is_valid、错误密钥、响应公钥验签失败与离线激活码校验。
"""

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from core import offline, security
from core.api_client import ApiClient
from core.config import Config
from core.database import Database
from sdk import (
    LicenseClient,
    LicenseError,
    LicenseSignatureError,
)
from tests.test_api_hardening import LiveServer, login_ready

UNKNOWN_KEY = "GSQ-AAAAA-AAAAA-AAAAA-AAAAA"


class _FakeResponseServer:
    """最小伪服务器：用于返回攻击者签名/无签名的响应。"""

    def __init__(self, body: bytes, private_key: str, key_id: str, sign: bool = True):
        self.body = body
        self.private_key = private_key
        self.key_id = key_id
        self.sign = sign
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                if outer.sign:
                    message = security.canonical_response_message(
                        "POST",
                        self.path,
                        self.headers.get("X-Client-Timestamp", ""),
                        self.headers.get("X-Client-Nonce", ""),
                        200,
                        outer.body,
                        outer.key_id,
                    )
                    self.send_header(
                        "X-Server-Signature",
                        offline.sign_message(outer.private_key, message),
                    )
                    self.send_header("X-Server-Key-Id", outer.key_id)
                self.send_header("Content-Length", str(len(outer.body)))
                self.end_headers()
                self.wfile.write(outer.body)

            def log_message(self, *args):
                return

        self.httpd = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_port}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc_info):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)
        return False


class LicenseSdkTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        self.config = Config("server", self.root / "server_config.json")
        self.db = Database(self.root / "license.db")
        _, self.bootstrap = self.db.ensure_default_admin()
        self.live = LiveServer(self.config, self.db)
        self.live.start()
        self.server_url = f"http://127.0.0.1:{self.live.port}"
        self.response_public_key = self.config.security["response_public_key"]
        self.response_key_id = self.config.security["response_key_id"]
        self.admin = ApiClient(
            self.server_url,
            response_public_key=self.response_public_key,
            response_key_id=self.response_key_id,
        )
        login_ready(self.admin, self.bootstrap)

    def tearDown(self):
        self.live.stop()
        self.db.close()
        self.tmp.cleanup()

    # ---- helpers ------------------------------------------------------ #
    def _new_key(self, **kwargs) -> str:
        params = {"count": 1, "max_devices": 2}
        params.update(kwargs)
        return self.admin.generate_licenses(**params)["keys"][0]

    def _sdk(self, **kwargs) -> LicenseClient:
        return LicenseClient(
            kwargs.pop("server_url", self.server_url),
            kwargs.pop("response_public_key", self.response_public_key),
            kwargs.pop("response_key_id", self.response_key_id),
            **kwargs,
        )

    # ---- 在线流程 ------------------------------------------------------ #
    def test_activate_verify_heartbeat_and_is_valid(self):
        key = self._new_key()
        sdk = self._sdk()
        activated = sdk.activate(key, "MACHINE-SDK-1", "demo-pc")
        self.assertTrue(activated["ok"])
        self.assertEqual(activated["code"], "activated")
        self.assertTrue(sdk.session_secret)
        self.assertEqual(sdk.last_key_code, key)
        self.assertEqual(sdk.last_machine_code, "MACHINE-SDK-1")

        verified = sdk.verify()
        self.assertTrue(verified["ok"])
        self.assertEqual(verified["code"], "valid")
        self.assertEqual(verified["expires_at"], activated["expires_at"])

        beat = sdk.heartbeat()
        self.assertTrue(beat["ok"])
        self.assertEqual(beat["code"], "alive")
        self.assertIsNotNone(beat.get("next_interval"))

        self.assertTrue(sdk.is_valid())
        self.admin.revoke_license(key)
        self.assertFalse(sdk.is_valid())

    def test_unknown_key_returns_not_found_and_no_session(self):
        sdk = self._sdk()
        result = sdk.activate(UNKNOWN_KEY, "MACHINE-SDK-2")
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "not_found")
        self.assertIsNone(sdk.session_secret)
        with self.assertRaises(LicenseError) as ctx:
            sdk.verify(UNKNOWN_KEY, "MACHINE-SDK-2")
        self.assertEqual(ctx.exception.code, "no_session")
        self.assertFalse(sdk.is_valid(UNKNOWN_KEY, "MACHINE-SDK-2"))

    def test_verify_uses_hmac_session_signature(self):
        key = self._new_key()
        sdk = self._sdk()
        self.assertTrue(sdk.activate(key, "MACHINE-SDK-3")["ok"])
        # 伪造会话密钥后，服务端必须拒绝（证明请求确实带 HMAC 签名）。
        sdk.session_secret = "00" * 32
        result = sdk.verify()
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "signature_invalid")

    def test_explicit_machine_code_and_remembered_defaults(self):
        sdk = self._sdk()
        machine = sdk.machine_code()
        self.assertTrue(machine)
        self.assertEqual(machine, machine.upper())

        key = self._new_key()
        self.assertTrue(sdk.activate(key)["ok"])
        self.assertEqual(sdk.last_machine_code, machine)
        self.assertTrue(sdk.verify()["ok"])
        self.assertTrue(sdk.heartbeat(key_code=key, machine_code=machine)["ok"])

    def test_reset_session_clears_credentials(self):
        key = self._new_key()
        sdk = self._sdk()
        self.assertTrue(sdk.activate(key, "MACHINE-SDK-4")["ok"])
        sdk.reset_session()
        self.assertIsNone(sdk.session_secret)
        self.assertEqual(sdk.last_key_code, "")
        with self.assertRaises(LicenseError) as ctx:
            sdk.verify()
        self.assertEqual(ctx.exception.code, "no_session")

    # ---- 响应验签 ------------------------------------------------------ #
    def test_forged_response_signature_is_rejected(self):
        attacker_private, _ = offline.generate_keypair()
        body = json.dumps(
            {
                "ok": True,
                "code": "activated",
                "session_secret": "attacker-secret",
                "expires_at": None,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        with _FakeResponseServer(body, attacker_private, "attacker-key") as fake:
            sdk = self._sdk(
                server_url=fake.url,
                response_key_id="",
            )
            with self.assertRaises(LicenseSignatureError) as ctx:
                sdk.activate(UNKNOWN_KEY, "MACHINE-ATTACK")
        self.assertEqual(ctx.exception.code, "response_signature_invalid")
        self.assertIsNone(sdk.session_secret)

    def test_unsigned_response_is_rejected(self):
        body = json.dumps(
            {"ok": True, "code": "activated", "session_secret": "x"},
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        with _FakeResponseServer(body, "", "", sign=False) as fake:
            sdk = self._sdk(server_url=fake.url)
            with self.assertRaises(LicenseSignatureError) as ctx:
                sdk.activate(UNKNOWN_KEY, "MACHINE-ATTACK")
        self.assertEqual(ctx.exception.code, "signature_missing")

    def test_response_key_id_mismatch_is_rejected(self):
        private_key = self.config.security["response_private_key"]
        body = json.dumps(
            {"ok": True, "code": "activated", "session_secret": "x"},
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        with _FakeResponseServer(body, private_key, "other-key-id") as fake:
            sdk = self._sdk(server_url=fake.url)
            with self.assertRaises(LicenseSignatureError) as ctx:
                sdk.activate(UNKNOWN_KEY, "MACHINE-ATTACK")
        self.assertEqual(ctx.exception.code, "response_key_mismatch")

    def test_constructor_requires_response_public_key(self):
        with self.assertRaises(LicenseError) as ctx:
            LicenseClient(self.server_url, "")
        self.assertEqual(ctx.exception.code, "response_key_missing")

    def test_remote_insecure_http_is_blocked_unless_allowed(self):
        with self.assertRaises(LicenseError) as ctx:
            LicenseClient("http://10.0.0.1:8765", self.response_public_key)
        self.assertEqual(ctx.exception.code, "insecure_http_blocked")
        client = LicenseClient(
            "http://10.0.0.1:8765",
            self.response_public_key,
            allow_insecure_http=True,
        )
        self.assertEqual(client.server_url, "http://10.0.0.1:8765")

    # ---- 离线激活码 ---------------------------------------------------- #
    def test_verify_offline_valid_code_and_failures(self):
        key = self._new_key(duration_days=30)
        code = self.admin.offline_code(key, "MACHINE-OFF-1")["code"]
        sdk = self._sdk()
        sdk.set_offline_public_key(self.config.security["offline_public_key"])

        valid = sdk.verify_offline(code, "MACHINE-OFF-1")
        self.assertTrue(valid["ok"])
        self.assertEqual(valid["code"], "valid")
        self.assertEqual(valid["key_code"], key)
        self.assertEqual(valid["machine_code"], "MACHINE-OFF-1")
        self.assertTrue(valid["expires_at"])

        mismatch = sdk.verify_offline(code, "MACHINE-OFF-2")
        self.assertFalse(mismatch["ok"])
        self.assertEqual(mismatch["code"], "machine_mismatch")

        # 改签名段的第一个字符（6 位全有效），确保解码后的签名真的不同；
        # base64url 末尾字符存在被解码器忽略的低位，改末位可能等价。
        head, _, signature = code.rpartition(".")
        first = "A" if signature[:1] != "A" else "B"
        tampered = f"{head}.{first}{signature[1:]}"
        self.assertNotEqual(tampered, code)
        invalid = sdk.verify_offline(tampered, "MACHINE-OFF-1")
        self.assertFalse(invalid["ok"])
        self.assertEqual(invalid["code"], "invalid_code")

    def test_verify_offline_refreshes_public_key_from_server(self):
        key = self._new_key(duration_days=30)
        code = self.admin.offline_code(key, "MACHINE-OFF-3")["code"]
        sdk = self._sdk()
        self.assertEqual(sdk.offline_public_key, "")
        fetched = sdk.refresh_offline_public_key()
        self.assertEqual(fetched, self.config.security["offline_public_key"])
        self.assertTrue(sdk.verify_offline(code, "MACHINE-OFF-3")["ok"])

    def test_verify_offline_rejects_expired_code(self):
        key = self._new_key(duration_days=30)
        payload = offline.build_activation_payload(
            machine_code="MACHINE-OFF-4",
            key_code=key,
            edition="standard",
            duration_days=30,
            expires_at="2000-01-01 00:00:00",
            max_devices=1,
        )
        expired = offline.make_activation_code(
            payload, self.config.security["offline_private_key"]
        )
        sdk = self._sdk()
        sdk.set_offline_public_key(self.config.security["offline_public_key"])
        result = sdk.verify_offline(expired, "MACHINE-OFF-4")
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "expired")

    def test_verify_offline_without_key_returns_error_dict(self):
        # 端口 1 不会被监听：刷新公钥失败，但 verify_offline 只返回错误字典。
        sdk = LicenseClient("http://127.0.0.1:1", self.response_public_key)
        result = sdk.verify_offline("LICACT1.whatever.signature", "MACHINE-OFF-5")
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "offline_key_missing")


if __name__ == "__main__":
    unittest.main()
