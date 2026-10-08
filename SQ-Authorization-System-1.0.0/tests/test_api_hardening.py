import json
import socket
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import requests
import uvicorn

from core import offline, security
from core.api_client import ApiClient, ApiError
from core.config import Config
from core.database import Database
from server.api import create_app


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class LiveServer:
    def __init__(self, config: Config, db: Database):
        self.config = config
        self.db = db
        self.port = _free_port()
        app = create_app(config, db)
        self.server = uvicorn.Server(
            uvicorn.Config(
                app,
                host="127.0.0.1",
                port=self.port,
                log_level="warning",
                access_log=False,
            )
        )
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def start(self) -> None:
        self.thread.start()
        for _ in range(100):
            if self.server.started:
                return
            time.sleep(0.05)
        raise RuntimeError("测试服务器启动超时")

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=5)


READY_PASSWORD = "ReadyPass#2026"


def login_ready(client: ApiClient, bootstrap: str) -> dict:
    """Log in as the bootstrap master and clear the forced password change.

    A fresh database creates the master account with ``must_change_password``
    set, and the API refuses everything except the change-password endpoint
    until it is cleared. Tests that are not about that gate start here.
    """
    login = client.login("admin", bootstrap)
    if login.get("must_change_password"):
        client.change_password(bootstrap, READY_PASSWORD)
    return login


class ApiHardeningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        self.config = Config("server", self.root / "server_config.json")
        self.db = Database(self.root / "license.db")
        _, self.bootstrap = self.db.ensure_default_admin()
        self.live = LiveServer(self.config, self.db)
        self.live.start()
        self.client = ApiClient(
            f"http://127.0.0.1:{self.live.port}",
            response_public_key=self.config.security["response_public_key"],
            response_key_id=self.config.security["response_key_id"],
        )

    def tearDown(self):
        self.live.stop()
        self.db.close()
        self.tmp.cleanup()

    def test_end_to_end_and_password_invalidation(self):
        login = self.client.login("admin", self.bootstrap)
        self.assertEqual(login["role"], "master")
        # The bootstrap password is one-time: until it is replaced every other
        # endpoint has to stay closed, even for a correctly authenticated
        # caller holding the handover password.
        with self.assertRaises(ApiError) as blocked:
            self.client.generate_licenses(count=1, max_devices=1)
        self.assertIn("修改密码", str(blocked.exception))

        # The password gate is a policy rejection, not an authentication
        # failure: the handover token must survive so the operator can
        # replace the password without being bounced to the login screen.
        self.assertIsNotNone(self.client.token)
        old_token = self.client.token
        changed = self.client.change_password(self.bootstrap, "NewPass1234")
        self.assertTrue(changed["ok"])
        self.assertNotEqual(old_token, self.client.token)
        self.assertEqual(self.client.me()["username"], "admin")

        key = self.client.generate_licenses(count=1, max_devices=1)["keys"][0]
        activated = self.client.activate(key, "MACHINE-1", "pc")
        self.assertTrue(activated["ok"])
        self.assertEqual(self.client.verify(key, "MACHINE-1")["code"], "valid")
        self.assertTrue(self.client.heartbeat(key, "MACHINE-1")["ok"])


    def test_local_client_can_pin_public_keys_then_activate(self):
        client = ApiClient(f"http://127.0.0.1:{self.live.port}")
        keys = client.public_key()
        client.apply_public_key_response(keys)
        self.assertTrue(client.response_public_key)
        self.assertTrue(client.offline_public_key)
        login_ready(self.client, self.bootstrap)
        key = self.client.generate_licenses(count=1)['keys'][0]
        self.assertTrue(client.activate(key, "MACHINE-PIN")["ok"])

    def test_expired_offline_code_is_rejected(self):
        login_ready(self.client, self.bootstrap)
        key = self.client.generate_licenses(count=1, duration_days=1)["keys"][0]
        self.db.update_license_expiry(key, "2000-01-01 00:00:00")
        with self.assertRaises(ApiError):
            self.client.offline_code(key, "MACHINE-2")

    def test_revoke_restore_and_renew(self):
        login_ready(self.client, self.bootstrap)
        key = self.client.generate_licenses(count=1, max_devices=1, duration_days=1)["keys"][0]
        self.client.activate(key, "MACHINE-3")
        self.client.revoke_license(key)
        detail = self.client.license_detail(key)
        self.assertEqual(detail["activations"][0]["status"], "active")
        self.client.restore_license(key)
        self.assertEqual(self.client.verify(key, "MACHINE-3")["code"], "valid")

        self.db.update_license_expiry(key, "2000-01-01 00:00:00")
        renewed = self.client.renew_license(key, 2, "day")
        self.assertTrue(renewed["ok"])
        self.assertEqual(self.client.verify(key, "MACHINE-3")["code"], "valid")

    def test_signed_request_nonce_replay_is_rejected(self):
        login_ready(self.client, self.bootstrap)
        key = self.client.generate_licenses(count=1)['keys'][0]
        self.client.activate(key, "MACHINE-REPLAY")
        path = "/api/client/verify"
        body = json.dumps(
            {"key_code": key, "machine_code": "MACHINE-REPLAY"},
            separators=(",", ":"),
        ).encode("utf-8")
        timestamp = security.now_ts()
        nonce = "nonce-replay-test"
        signature = security.sign_request(
            self.client.session_secret,
			"POST",
			path,
			timestamp,
			nonce,
			body,
		)
        headers = {
            "Content-Type": "application/json",
            "X-Client-Timestamp": str(timestamp),
            "X-Client-Nonce": nonce,
            "X-Client-Signature": signature,
        }
        url = f"http://127.0.0.1:{self.live.port}{path}"
        first = requests.post(url, data=body, headers=headers, timeout=5)
        second = requests.post(url, data=body, headers=headers, timeout=5)
        self.assertEqual(first.json()["code"], "valid")
        self.assertEqual(second.json()["code"], "replay")

    def test_fake_server_cannot_forge_activation_response(self):
        attacker_private, attacker_public = offline.generate_keypair()
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

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                message = security.canonical_response_message(
                    "POST",
                    self.path,
                    self.headers.get("X-Client-Timestamp", ""),
                    self.headers.get("X-Client-Nonce", ""),
                    200,
                    body,
                    "attacker-key",
                )
                signature = offline.sign_message(attacker_private, message)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("X-Server-Signature", signature)
                self.send_header("X-Server-Key-Id", "attacker-key")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                return

        fake = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=fake.serve_forever, daemon=True)
        thread.start()
        try:
            client = ApiClient(
                f"http://127.0.0.1:{fake.server_port}",
                response_public_key=self.config.security["response_public_key"],
                response_key_id=self.config.security["response_key_id"],
            )
            with self.assertRaises(ApiError):
                client.activate("LIC-AAAAA-AAAAA-AAAAA-AAAAA", "MACHINE-X")
        finally:
            fake.shutdown()
            fake.server_close()
            thread.join(timeout=3)

    def test_signed_error_response_is_authenticated(self):
        with self.assertRaises(ApiError) as context:
            self.client.login("admin", "wrong-password")
        self.assertIn("用户名或密码错误", str(context.exception))

    def test_malformed_client_payload_is_rejected_without_500(self):
        body = json.dumps(
            {"key_code": "LIC-TEST", "machine_code": {"nested": True}},
            separators=(",", ":"),
        ).encode("utf-8")
        response = requests.post(
            f"http://127.0.0.1:{self.live.port}/api/client/verify",
            data=body,
            headers={"Content-Type": "application/json"},
            timeout=5,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["code"], "bad_request")

        surrogate = b'{"key_code":"\\ud800","machine_code":"M"}'
        activate = requests.post(
            f"http://127.0.0.1:{self.live.port}/api/client/activate",
            data=surrogate,
            headers={"Content-Type": "application/json"},
            timeout=5,
        )
        self.assertEqual(activate.status_code, 422)

        raw = requests.post(
            f"http://127.0.0.1:{self.live.port}/api/client/verify",
            data=surrogate,
            headers={"Content-Type": "application/json"},
            timeout=5,
        )
        self.assertEqual(raw.status_code, 200)
        self.assertEqual(raw.json()["code"], "bad_request")

    def test_chunked_request_over_limit_is_rejected(self):
        body = (b"x" * 1024 for _ in range(130))
        response = requests.post(
            f"http://127.0.0.1:{self.live.port}/api/admin/login",
            data=body,
            headers={"Content-Type": "application/json"},
            timeout=5,
        )
        self.assertEqual(response.status_code, 413)

    def test_unsigned_error_response_is_rejected_when_key_is_pinned(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'{"detail":"forged"}'
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                return

        fake = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=fake.serve_forever, daemon=True)
        thread.start()
        try:
            client = ApiClient(
                f"http://127.0.0.1:{fake.server_port}",
                response_public_key=self.config.security["response_public_key"],
                response_key_id=self.config.security["response_key_id"],
            )
            with self.assertRaises(ApiError) as context:
                client.health()
            self.assertIn("签名", str(context.exception))
        finally:
            fake.shutdown()
            fake.server_close()
            thread.join(timeout=3)

    def test_missing_pinned_key_blocks_activation(self):
        client = ApiClient(f"http://127.0.0.1:{self.live.port}")
        with self.assertRaises(ApiError):
            client.activate("LIC-AAAAA-AAAAA-AAAAA-AAAAA", "MACHINE-Y")


if __name__ == "__main__":
    unittest.main()
