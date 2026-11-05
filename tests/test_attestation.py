import json
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

import requests
import uvicorn

from core import security
from core.config import Config
from core.database import Database
from server.api import create_app
from core.api_client import ApiClient

HASH_A = "a" * 64
HASH_B = "b" * 64
UNKNOWN_HASH = "c" * 64


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class LiveServer:
    """Same shape as tests/test_api_hardening.py so both suites stay aligned."""

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


class AttestTokenTests(unittest.TestCase):
    def test_round_trip_binds_hash_machine_and_role(self):
        token = security.create_attest_token("secret", HASH_A, "machine-1", "verification", 600)
        ok, payload = security.verify_attest_token("secret", token, "MACHINE-1", "verification")
        self.assertTrue(ok)
        self.assertEqual(payload["typ"], "attest")
        self.assertEqual(payload["hash"], HASH_A)
        self.assertEqual(payload["mc"], "MACHINE-1")
        self.assertEqual(payload["role"], "verification")

    def test_wrong_hash_machine_or_role_is_rejected(self):
        token = security.create_attest_token("secret", HASH_A, "MACHINE-1", "verification", 600)
        self.assertFalse(security.verify_attest_token("secret", token, "MACHINE-1", "admin")[0])
        self.assertFalse(security.verify_attest_token("secret", token, "MACHINE-2", "verification")[0])
        self.assertFalse(security.verify_attest_token("other-secret", token, "MACHINE-1", "verification")[0])

        malformed = security.create_attest_token("secret", "not-a-hash", "MACHINE-1", "verification", 600)
        self.assertEqual(
            security.verify_attest_token("secret", malformed, "MACHINE-1", "verification"),
            (False, None),
        )

    def test_tampered_or_expired_token_is_rejected(self):
        token = security.create_attest_token("secret", HASH_A, "MACHINE-1", "verification", 600)
        body, signature = token.split(".", 1)
        tampered = f"{body}.{'A' if signature[0] != 'A' else 'B'}{signature[1:]}"
        self.assertEqual(
            security.verify_attest_token("secret", tampered, "MACHINE-1", "verification"),
            (False, None),
        )

        original_now = security.now_ts
        try:
            security.now_ts = lambda: 1_000_000
            expired = security.create_attest_token(
                "secret", HASH_A, "MACHINE-1", "verification", 10
            )
            security.now_ts = lambda: 1_000_100
            self.assertEqual(
                security.verify_attest_token("secret", expired, "MACHINE-1", "verification"),
                (False, None),
            )
        finally:
            security.now_ts = original_now


class ReleaseHashDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = Database(Path(self.tmp.name) / "license.db")

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_upsert_list_match_count_and_set_active(self):
        self.db.upsert_release_hash("verification.exe", HASH_A, size=10, version="1.0.0", note="first")
        self.db.upsert_release_hash("verification.exe", HASH_A, size=20, version="1.0.1", note="second")

        items = self.db.list_release_hashes()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["size"], 20)
        self.assertEqual(items[0]["version"], "1.0.1")
        self.assertEqual(items[0]["note"], "second")
        self.assertEqual(self.db.count_active_release_hashes(), 1)

        # Lookups normalise case in both directions.
        self.assertIsNotNone(self.db.match_release_hash(HASH_A.upper()))
        self.assertIsNotNone(self.db.match_release_hash(HASH_A, "verification.exe"))
        self.assertIsNone(self.db.match_release_hash(HASH_A, "other.exe"))
        self.assertIsNone(self.db.match_release_hash(UNKNOWN_HASH))

        self.assertTrue(self.db.set_release_hash_active("verification.exe", HASH_A, False))
        self.assertEqual(self.db.count_active_release_hashes(), 0)
        self.assertIsNone(self.db.match_release_hash(HASH_A))
        self.assertFalse(self.db.set_release_hash_active("missing.exe", HASH_A, True))

    def test_upsert_keeps_one_row_per_file_and_hash(self):
        self.db.upsert_release_hash("server.exe", HASH_A, size=1)
        self.db.upsert_release_hash("server.exe", HASH_B, size=2)
        self.assertEqual(len(self.db.list_release_hashes()), 2)
        self.assertEqual(self.db.count_active_release_hashes(), 2)

    def test_tamper_events_are_written_and_paged(self):
        for index in range(5):
            self.db.add_tamper_event(
                "verification",
                "verification.exe",
                HASH_A,
                "1.0.0",
                f"MACHINE-{index}",
                "127.0.0.1",
                "hash_mismatch",
                detail=f"event-{index}",
            )
        items, total = self.db.list_tamper_events(limit=2, offset=0)
        self.assertEqual(total, 5)
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]["reason"], "hash_mismatch")
        self.assertEqual(items[0]["machine_code"], "MACHINE-4")
        page_two, total_two = self.db.list_tamper_events(limit=2, offset=2)
        self.assertEqual(total_two, 5)
        self.assertEqual(page_two[0]["machine_code"], "MACHINE-2")
        # The limit is clamped into 1..1000, the offset never goes negative.
        clamped, _ = self.db.list_tamper_events(limit=99_999, offset=-5)
        self.assertEqual(len(clamped), 5)


class AttestationApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        self.config = Config("server", self.root / "server_config.json")
        self.config.security["attest_mode"] = "auto"
        self.db = Database(self.root / "license.db")
        _, self.bootstrap = self.db.ensure_default_admin()
        self.db.upsert_release_hash(
            "verification.exe", HASH_A, size=1, version="1.0.0", note="test"
        )
        self.live = LiveServer(self.config, self.db)
        self.live.start()
        self.base = f"http://127.0.0.1:{self.live.port}"

    def tearDown(self):
        self.live.stop()
        self.db.close()
        self.tmp.cleanup()

    def _attest(self, exe_hash: str, machine_code: str = "MACHINE-1") -> requests.Response:
        return requests.post(
            f"{self.base}/api/client/attest",
            json={
                "role": "verification",
                "exe_name": "verification.exe",
                "exe_hash": exe_hash,
                "version": "1.0.0",
                "machine_code": machine_code,
                "local_check": {"ok": True},
            },
            timeout=5,
        )

    def test_attest_known_hash_returns_token(self):
        response = self._attest(HASH_A)
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["attest_token"])
        self.assertEqual(payload["expires_in"], 600)
        ok, token_payload = security.verify_attest_token(
            self.config.security["secret_key"],
            payload["attest_token"],
            "MACHINE-1",
            "verification",
        )
        self.assertTrue(ok)
        self.assertEqual(token_payload["hash"], HASH_A)

    def test_attest_unknown_hash_records_tamper_event(self):
        response = self._attest(UNKNOWN_HASH)
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["code"], "unknown_build")
        self.assertIn("message", payload)

        items, total = self.db.list_tamper_events()
        self.assertEqual(total, 1)
        self.assertEqual(items[0]["reason"], "unknown_build")
        self.assertEqual(items[0]["exe_hash"], UNKNOWN_HASH)

    def test_activate_without_token_is_rejected_with_fixed_detail(self):
        response = requests.post(
            f"{self.base}/api/client/activate",
            json={
                "key_code": "GSQ-AAAAA-AAAAA-AAAAA-AAAAA",
                "machine_code": "MACHINE-1",
                "device_name": "pc",
            },
            timeout=5,
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json()["detail"], "客户端完整性校验未通过，已拒绝访问"
        )

    def test_activate_with_valid_token_passes_the_gate(self):
        token = self._attest(HASH_A).json()["attest_token"]
        response = requests.post(
            f"{self.base}/api/client/activate",
            json={
                "key_code": "GSQ-AAAAA-AAAAA-AAAAA-AAAAA",
                "machine_code": "MACHINE-1",
                "device_name": "pc",
            },
            headers={"X-Attest-Token": token},
            timeout=5,
        )
        self.assertEqual(response.status_code, 200)
        # No such licence exists in this fixture; reaching the licence lookup is
        # what proves the gate opened.
        self.assertFalse(response.json()["ok"])
        self.assertEqual(response.json()["code"], "not_found")

    def test_activate_with_token_for_another_machine_is_rejected(self):
        token = self._attest(HASH_A, machine_code="MACHINE-1").json()["attest_token"]
        response = requests.post(
            f"{self.base}/api/client/activate",
            json={
                "key_code": "GSQ-AAAAA-AAAAA-AAAAA-AAAAA",
                "machine_code": "MACHINE-9",
                "device_name": "pc",
            },
            headers={"X-Attest-Token": token},
            timeout=5,
        )
        self.assertEqual(response.status_code, 403)

    def test_integrity_report_is_recorded(self):
        response = requests.post(
            f"{self.base}/api/client/integrity_report",
            json={
                "role": "verification",
                "exe_name": "verification.exe",
                "exe_hash": HASH_A,
                "version": "1.0.0",
                "machine_code": "MACHINE-1",
                "reason": "hash_mismatch",
                "detail": json.dumps({"issue": "hash_mismatch"}, ensure_ascii=False),
            },
            timeout=5,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"ok": True})
        items, total = self.db.list_tamper_events()
        self.assertEqual(total, 1)
        self.assertEqual(items[0]["reason"], "hash_mismatch")
        self.assertEqual(json.loads(items[0]["detail"])["issue"], "hash_mismatch")

    def test_real_client_attest_handshake_unlocks_the_gate(self):
        client = ApiClient(
            self.base,
            response_public_key=self.config.security["response_public_key"],
            response_key_id=self.config.security["response_key_id"],
        )
        client.set_integrity_result(
            {
                "ok": True,
                "skipped": False,
                "role": "verification",
                "exe_name": "verification.exe",
                "exe_hash": HASH_A,
                "version": "1.0.0",
            }
        )
        token = client.ensure_attest(role="verification", machine_code="MACHINE-1")
        self.assertTrue(token)
        # The real client now reaches the licence lookup instead of the gate.
        data = client.activate("GSQ-AAAAA-AAAAA-AAAAA-AAAAA", "MACHINE-1", "pc")
        self.assertEqual(data["code"], "not_found")

    def test_client_dict_detail_is_stored_as_json(self):
        client = ApiClient(
            self.base,
            response_public_key=self.config.security["response_public_key"],
            response_key_id=self.config.security["response_key_id"],
        )
        client.set_integrity_result(
            {
                "role": "verification",
                "exe_name": "verification.exe",
                "exe_hash": HASH_A,
                "version": "1.0.0",
            }
        )
        data = client.report_integrity_failure(
            "hash_mismatch", {"issues": [{"code": "hash_mismatch"}]}
        )
        self.assertEqual(data, {"ok": True})
        items, _ = self.db.list_tamper_events()
        self.assertEqual(items[0]["reason"], "hash_mismatch")
        self.assertEqual(json.loads(items[0]["detail"])["issues"][0]["code"], "hash_mismatch")

    def test_release_and_tamper_endpoints_require_bearer(self):
        self.assertEqual(requests.get(f"{self.base}/api/release/list", timeout=5).status_code, 401)
        self.assertEqual(
            requests.get(f"{self.base}/api/tamper/events", timeout=5).status_code, 401
        )

    def test_attest_mode_off_skips_the_gate(self):
        # A fresh app instance reads the flag once at creation time.
        self.config.security["attest_mode"] = "off"
        second = LiveServer(self.config, self.db)
        second.start()
        try:
            response = requests.post(
                f"http://127.0.0.1:{second.port}/api/client/activate",
                json={
                    "key_code": "GSQ-AAAAA-AAAAA-AAAAA-AAAAA",
                    "machine_code": "MACHINE-1",
                    "device_name": "pc",
                },
                timeout=5,
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["code"], "not_found")
        finally:
            second.stop()

    def test_master_can_import_a_signed_release_manifest(self):
        from core import integrity, offline

        private_key, public_key = offline.generate_keypair()
        self.config.security["release_public_key"] = public_key
        manifest = {
            "format": integrity.MANIFEST_FORMAT,
            "version": "9.9.9",
            "generated_at": "2026-10-07T12:00:00+08:00",
            "apps": {
                "server": {"path": "server.exe", "sha256": HASH_B, "size": 3},
            },
            "folder": {},
        }
        raw = json.dumps(manifest, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        signature = offline.sign_message(private_key, raw)

        client = ApiClient(
            self.base,
            response_public_key=self.config.security["response_public_key"],
            response_key_id=self.config.security["response_key_id"],
        )
        login = client.login("admin", self.bootstrap)
        if login.get("must_change_password"):
            client.change_password(self.bootstrap, "ReadyPass#2026")
        data = client._request(
            "POST",
            "/api/release/import",
            json_body={"manifest": raw.decode("utf-8"), "signature": signature},
        )
        self.assertEqual(data, {"ok": True, "imported": 1})
        match = self.db.match_release_hash(HASH_B, "server.exe")
        self.assertIsNotNone(match)
        self.assertEqual(match["version"], "9.9.9")

        listing = client._request("GET", "/api/release/list")
        self.assertTrue(
            any(item["sha256"] == HASH_B for item in listing["items"])
        )
        self.assertEqual(listing["total"], len(listing["items"]))

        status = client._request(
            "POST",
            "/api/release/status",
            json_body={"file_name": "server.exe", "sha256": HASH_B, "active": False},
        )
        self.assertEqual(status, {"ok": True})
        self.assertIsNone(self.db.match_release_hash(HASH_B, "server.exe"))


if __name__ == "__main__":
    unittest.main()
