import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core import offline, security
from core.config import Config


class ConfigIsolationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_server_generates_secrets_and_clients_do_not(self):
        server = Config("server", self.root / "server_config.json")
        admin = Config("admin", self.root / "admin_config.json")
        verification = Config("verification", self.root / "verification_config.json")

        self.assertTrue(server.security["secret_key"])
        self.assertTrue(server.security["offline_private_key"])
        self.assertTrue(server.security["response_private_key"])
        self.assertEqual(server.security["response_key_id"], f"ed25519-{server.security['response_public_key'][:16]}")

        for client in (admin, verification):
            self.assertNotIn("security", client.data)
            self.assertNotIn("offline_private_key", json.dumps(client.data))
            self.assertNotIn("response_private_key", json.dumps(client.data))
            self.assertFalse(client.client["response_public_key"])

    def test_server_and_client_keys_are_distinct(self):
        first = Config("server", self.root / "one.json")
        second = Config("server", self.root / "two.json")
        self.assertNotEqual(
            first.security["offline_private_key"], second.security["offline_private_key"]
        )
        self.assertNotEqual(
            first.security["response_private_key"], second.security["response_private_key"]
        )

    def test_client_legacy_migration_keeps_only_public_key(self):
        legacy = self.root / "config.json"
        legacy.write_text(
            json.dumps(
                {
                    "security": {
                        "secret_key": "server-secret",
                        "offline_private_key": "private",
                        "offline_public_key": "public-only",
                    },
                    "client": {"server_url": "http://127.0.0.1:9999"},
                }
            ),
            encoding="utf-8",
        )
        with mock.patch("core.config.APP_DIR", self.root), mock.patch(
            "core.config.LEGACY_CONFIG_PATH", legacy
        ):
            client = Config("admin", self.root / "admin_config.json")
        self.assertEqual(client.client["offline_public_key"], "public-only")
        self.assertNotIn("private", json.dumps(client.data))
        self.assertNotIn("server-secret", json.dumps(client.data))

    def test_legacy_private_key_is_never_loaded_into_client(self):
        legacy = self.root / "config.json"
        legacy.write_text(
            json.dumps(
                {
                    "client": {
                        "offline_private_key": "bad-private",
                        "offline_public_key": "public",
                    }
                }
            ),
            encoding="utf-8",
        )
        with mock.patch("core.config.APP_DIR", self.root), mock.patch(
            "core.config.LEGACY_CONFIG_PATH", legacy
        ):
            client = Config("verification", self.root / "verification_config.json")
        self.assertNotIn("bad-private", json.dumps(client.data))
        self.assertEqual(client.client["offline_public_key"], "public")


class Ed25519CompatibilityTests(unittest.TestCase):
    def test_offsets_round_trip_and_reject_other_key(self):
        private_key, public_key = offline.generate_keypair()
        other_private, other_public = offline.generate_keypair()
        payload = {
            "mc": "MACHINE-001",
            "key": "LIC-AAAAA-AAAAA-AAAAA-AAAAA",
            "exp": None,
        }
        code = offline.make_activation_code(payload, private_key)
        self.assertIsNotNone(offline.parse_activation_code(code, public_key))
        self.assertIsNone(offline.parse_activation_code(code, other_public))

    def test_malformed_external_values_fail_closed(self):
        self.assertIsNone(security.verify_token("abc.é", "secret"))
        self.assertFalse(
            security.verify_request_signature(
                "secret", "POST", "/api/client/verify", 123, "nonce", b"{}", "é"
            )
        )
        self.assertEqual(security.normalize_key(["not", "text"]), "")

        private_key, public_key = offline.generate_keypair()
        bad_payload = offline.make_activation_code(
            {"mc": {"nested": True}, "key": "LIC-TEST"}, private_key
        )
        self.assertIsNone(offline.parse_activation_code(bad_payload, public_key))
        bad_expiry = offline.make_activation_code(
            {"mc": "MACHINE", "key": "LIC-TEST", "exp": "not-a-date"},
            private_key,
        )
        self.assertIsNone(offline.parse_activation_code(bad_expiry, public_key))

    def test_response_signature_binds_request_context(self):
        private_key, public_key = offline.generate_keypair()
        message = security.canonical_response_message(
            "POST",
            "/api/client/activate",
            123,
            "nonce-a",
            200,
            b'{"ok":true}',
            "key-1",
        )
        signature = offline.sign_message(private_key, message)
        self.assertTrue(offline.verify_message(public_key, message, signature))
        changed = security.canonical_response_message(
            "POST",
            "/api/client/activate",
            123,
            "nonce-b",
            200,
            b'{"ok":true}',
            "key-1",
        )
        self.assertFalse(offline.verify_message(public_key, changed, signature))

    def test_malformed_expiry_fails_closed(self):
        self.assertTrue(security.is_expired("not-a-date"))
        self.assertEqual(security.seconds_left("not-a-date"), 0)
        self.assertFalse(security.is_expired(None))


if __name__ == "__main__":
    unittest.main()
