import tempfile
import threading
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from core import security
from core.config import Config
from core.database import Database


class DatabaseHardeningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        Config("server", self.root / "server_config.json")
        self.db = Database(self.root / "license.db")

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_bootstrap_is_random_and_strength_valid(self):
        created, password = self.db.ensure_default_admin()
        self.assertTrue(created)
        self.assertTrue(password)
        self.assertTrue(security.password_strength(password or "")[0])

    def test_device_limit_is_atomic_under_concurrency(self):
        _, keys = self.db.generate_licenses(1, max_devices=1)
        key = keys[0]
        license_row = self.db.get_license(key)
        barrier = threading.Barrier(2)
        results: list[str] = []
        lock = threading.Lock()

        def worker(number: int) -> None:
            barrier.wait()
            result = self.db.activate_atomic(
                license_row["id"],
                key,
                f"MACHINE-{number}",
                f"device-{number}",
                None,
                f"session-{number}",
            )[0]
            with lock:
                results.append(result)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(results), ["activated", "limit"])
        self.assertEqual(self.db.count_active_activations(license_row["id"]), 1)

    def test_revoke_and_restore_preserve_device_binding(self):
        _, keys = self.db.generate_licenses(1, max_devices=1)
        key = keys[0]
        license_row = self.db.get_license(key)
        self.db.activate_atomic(license_row["id"], key, "MACHINE", "pc", None, "session")
        self.db.set_license_status(key, "revoked")
        self.assertEqual(self.db.get_activation(key, "MACHINE")["status"], "active")
        restored = self.db.restore_license(key)
        self.assertEqual(restored, "active")
        self.assertEqual(self.db.get_activation(key, "MACHINE")["status"], "active")

    def test_restore_expired_revoked_requires_renewal(self):
        _, keys = self.db.generate_licenses(1, max_devices=1, duration_days=1)
        key = keys[0]
        license_row = self.db.get_license(key)
        self.db.activate_atomic(license_row["id"], key, "MACHINE", "pc", None, "session")
        self.db.set_license_status(key, "revoked")
        self.db.update_license_expiry(key, "2000-01-01 00:00:00")
        self.assertEqual(self.db.restore_license(key), "__expired__")

    def test_renewal_updates_existing_activation_expiry(self):
        _, keys = self.db.generate_licenses(1, max_devices=1, duration_days=1)
        key = keys[0]
        license_row = self.db.get_license(key)
        self.db.activate_atomic(license_row["id"], key, "MACHINE", "pc", None, "session")
        self.db.update_license_expiry(key, "2000-01-01 00:00:00")
        result = self.db.renew_license(key, 3, "day")
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "active")
        self.assertFalse(security.is_expired(self.db.get_activation(key, "MACHINE")["expires_at"]))

    def test_batch_ids_are_unique(self):
        first, _ = self.db.generate_licenses(1)
        second, _ = self.db.generate_licenses(1)
        self.assertNotEqual(first, second)
        self.assertTrue(first.startswith("B"))
        self.assertTrue(second.startswith("B"))

    def test_batch_revoke_is_scoped_to_one_batch(self):
        first, first_keys = self.db.generate_licenses(1)
        second, second_keys = self.db.generate_licenses(1)
        self.assertNotEqual(first, second)
        self.assertEqual(self.db.revoke_batch(first), 1)
        self.assertEqual(self.db.get_license(first_keys[0])['status'], 'revoked')
        self.assertEqual(self.db.get_license(second_keys[0])['status'], 'unused')

    def test_frozen_license_cannot_activate_at_database_layer(self):
        _, keys = self.db.generate_licenses(1, max_devices=1)
        key = keys[0]
        license_row = self.db.get_license(key)
        self.assertIsNotNone(self.db.freeze_license(key, "2999-01-01 00:00:00"))
        result, activation_id, _ = self.db.activate_atomic(
            license_row["id"], key, "MACHINE-FROZEN", "pc", None, "session"
        )
        self.assertEqual(result, "invalid")
        self.assertIsNone(activation_id)

    def test_expired_license_is_materialized(self):
        _, keys = self.db.generate_licenses(1, duration_days=1)
        key = keys[0]
        self.db.update_license_expiry(key, "2000-01-01 00:00:00")
        self.db.sweep_expired()
        self.assertEqual(self.db.get_license(key)["status"], "expired")
        self.assertEqual(self.db.stats()["expired"], 1)


if __name__ == "__main__":
    unittest.main()
