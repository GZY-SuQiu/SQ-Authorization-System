"""Regression tests for the activation-count card (激活次数卡).

Covers the database counter/auto-revoke transaction, the server API surface,
the offline-code restriction and the generator UI, plus a concurrency check
that the configured limit can never be overspent.
"""

import os
import tempfile
import threading
import unittest
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.api_client import ApiClient, ApiError  # noqa: E402
from core.config import Config  # noqa: E402
from core.database import Database  # noqa: E402
from tests.test_api_hardening import LiveServer, login_ready  # noqa: E402


class ActivationCardDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        Config("server", self.root / "server_config.json")
        self.db = Database(self.root / "license.db")

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def _card(self, limit: int = 3):
        _, keys = self.db.generate_licenses(
            1, card_type="activation", activation_limit=limit
        )
        key = keys[0]
        return key, self.db.get_license(key)

    def test_generate_rejects_non_positive_limit(self):
        with self.assertRaises(ValueError):
            self.db.generate_licenses(1, card_type="activation", activation_limit=0)

    def test_duration_cards_keep_the_old_behaviour(self):
        _, keys = self.db.generate_licenses(1, duration_days=7, max_devices=2)
        lic = self.db.get_license(keys[0])
        self.assertEqual(lic["card_type"], "duration")
        self.assertEqual(lic["activation_limit"], 0)
        self.assertEqual(lic["activation_count"], 0)
        self.assertEqual(lic["auto_revoked"], 0)
        self.assertEqual(lic["duration_days"], 7)
        self.assertEqual(lic["max_devices"], 2)

    def test_activation_card_counts_new_machines_and_auto_revokes(self):
        key, lic = self._card(limit=3)
        self.assertEqual(lic["activation_limit"], 3)
        self.assertEqual(lic["activation_count"], 0)
        # 次数卡不再叠加设备数限制，也没有固定到期时间。
        self.assertEqual(lic["max_devices"], 0)
        self.assertIsNone(lic["expires_at"])

        for index in range(2):
            result, _, _ = self.db.activate_atomic(
                lic["id"], key, f"M-{index}", f"设备{index}", None, f"s-{index}"
            )
            self.assertEqual(result, "activated")
        # 同一机器重复激活只刷新会话，不重复消耗次数。
        self.assertEqual(
            self.db.activate_atomic(lic["id"], key, "M-0", "设备0", None, "s-0")[0],
            "already",
        )
        self.assertEqual(self.db.get_license(key)["activation_count"], 2)

        self.assertEqual(
            self.db.activate_atomic(lic["id"], key, "M-2", "设备2", None, "s-2")[0],
            "activated",
        )
        exhausted = self.db.get_license(key)
        self.assertEqual(exhausted["activation_count"], 3)
        self.assertEqual(exhausted["status"], "revoked")
        self.assertEqual(exhausted["auto_revoked"], 1)

        # 达到上限立即吊销，新机器和原机器都不能再激活。
        self.assertEqual(
            self.db.activate_atomic(lic["id"], key, "M-9", "设备9", None, "s-9")[0],
            "exhausted",
        )
        self.assertEqual(
            self.db.activate_atomic(lic["id"], key, "M-0", "设备0", None, "s-0b")[0],
            "exhausted",
        )
        self.assertEqual(self.db.get_license(key)["activation_count"], 3)

    def test_concurrent_activations_never_overspend_the_limit(self):
        key, lic = self._card(limit=3)
        workers = 8
        barrier = threading.Barrier(workers)
        results: list[str] = []
        lock = threading.Lock()

        def worker(number: int) -> None:
            barrier.wait()
            result = self.db.activate_atomic(
                lic["id"], key, f"CON-{number}", f"并发{number}", None, f"s-{number}"
            )[0]
            with lock:
                results.append(result)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(workers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(sorted(results).count("activated"), 3)
        self.assertEqual(sorted(results).count("exhausted"), workers - 3)
        self.assertEqual(self.db.get_license(key)["activation_count"], 3)
        self.assertEqual(self.db.count_active_activations(lic["id"]), 3)

    def test_exhausted_card_is_terminal_for_admin_actions(self):
        key, lic = self._card(limit=1)
        self.db.activate_atomic(lic["id"], key, "ONLY", "唯一的设备", None, "s")
        self.assertEqual(self.db.restore_license(key), "__exhausted__")
        self.assertIsNone(self.db.renew_license(key, 30, "day"))
        self.assertEqual(self.db.get_license(key)["status"], "revoked")

    def test_exhaustion_is_terminal_across_freeze_operations(self):
        key, lic = self._card(limit=1)
        self.db.activate_atomic(lic["id"], key, "FREEZE-1", "设备", None, "s")
        self.assertIsNone(
            self.db.freeze_license(key, "2999-01-01 00:00:00", "不应覆盖已用尽")
        )

        # Simulate a stale/interleaved freeze row. Terminal state healing must
        # restore revocation instead of reviving the card after the freeze.
        self.db._execute(
            "UPDATE licenses SET status = 'frozen', prev_status = 'unused',"
            " frozen_until = '2000-01-01 00:00:00', auto_revoked = 1"
            " WHERE key_code = ?",
            (key,),
        )
        self.db.release_expired_freeze(key)
        healed = self.db.get_license(key)
        self.assertEqual(healed["status"], "revoked")
        self.assertEqual(healed["auto_revoked"], 1)
        self.assertEqual(self.db.unfreeze_license(key), None)
        self.assertEqual(
            self.db.activate_atomic(lic["id"], key, "FREEZE-1", "设备", None, "s")[0],
            "exhausted",
        )

    def test_batch_restore_skips_exhausted_cards(self):
        batch, keys = self.db.generate_licenses(
            2, card_type="activation", activation_limit=1
        )
        first, second = keys
        lic = self.db.get_license(first)
        self.db.activate_atomic(lic["id"], first, "B-1", "批次设备", None, "s")
        self.db.set_license_status(second, "revoked")

        self.assertEqual(self.db.restore_batch(batch), 1)
        self.assertEqual(self.db.get_license(first)["status"], "revoked")
        self.assertEqual(self.db.get_license(first)["auto_revoked"], 1)
        self.assertEqual(self.db.get_license(second)["status"], "unused")

    def test_stats_and_batch_summary_report_exhausted_cards(self):
        key, lic = self._card(limit=1)
        self.db.activate_atomic(lic["id"], key, "STAT", "统计设备", None, "s")
        self.assertEqual(self.db.stats()["exhausted"], 1)
        # 次数用尽后卡密彻底吊销，绑定设备不再计入有效设备。
        self.assertEqual(self.db.stats()["devices"], 0)
        row = self.db.list_batches()[0]
        self.assertEqual(row["exhausted"], 1)
        self.assertEqual(row["activation_cards"], 1)


class ActivationCardApiTests(unittest.TestCase):
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
        login_ready(self.client, self.bootstrap)

    def tearDown(self):
        self.live.stop()
        self.db.close()
        self.tmp.cleanup()

    def _generate(self, limit: int = 2) -> str:
        return self.client.generate_licenses(
            count=1, card_type="activation", activation_limit=limit
        )["keys"][0]

    def _device(self) -> ApiClient:
        """One client per machine: a session secret belongs to one binding."""
        return ApiClient(
            f"http://127.0.0.1:{self.live.port}",
            response_public_key=self.config.security["response_public_key"],
            response_key_id=self.config.security["response_key_id"],
        )

    def test_generate_requires_a_positive_limit(self):
        with self.assertRaises(ApiError) as ctx:
            self.client.generate_licenses(count=1, card_type="activation")
        self.assertIn("激活次数", str(ctx.exception))

    def test_activate_verify_and_heartbeat_expose_the_counter(self):
        key = self._generate(limit=2)
        first = self.client.activate(key, "MACHINE-A", "电脑A")
        self.assertTrue(first["ok"])
        self.assertEqual(first["card_type"], "activation")
        self.assertEqual(first["activation_limit"], 2)
        self.assertEqual(first["activation_count"], 1)
        self.assertEqual(first["activation_left"], 1)
        self.assertIsNone(first["expires_at"])

        verified = self.client.verify(key, "MACHINE-A")
        self.assertTrue(verified["ok"])
        self.assertEqual(verified["activation_count"], 1)
        self.assertEqual(verified["activation_left"], 1)

        heart = self.client.heartbeat(key, "MACHINE-A")
        self.assertTrue(heart["ok"])
        self.assertEqual(heart["activation_left"], 1)
        self.assertEqual(self.db.get_license(key)["activation_count"], 1)

    def test_exhausted_card_revokes_all_devices(self):
        key = self._generate(limit=2)
        first_device = self._device()
        second_device = self._device()
        self.assertTrue(first_device.activate(key, "MACHINE-1")["ok"])
        second = second_device.activate(key, "MACHINE-2")
        self.assertTrue(second["ok"])
        self.assertEqual(second["activation_left"], 0)
        self.assertIn("用尽", second["message"])

        third = self._device().activate(key, "MACHINE-3")
        self.assertFalse(third["ok"])
        self.assertEqual(third["code"], "exhausted")

        first_verify = first_device.verify(key, "MACHINE-1")
        second_verify = second_device.verify(key, "MACHINE-2")
        second_heartbeat = second_device.heartbeat(key, "MACHINE-2")
        self.assertFalse(first_verify["ok"])
        self.assertEqual(first_verify["code"], "exhausted")
        self.assertFalse(second_verify["ok"])
        self.assertEqual(second_verify["code"], "exhausted")
        self.assertFalse(second_heartbeat["ok"])
        self.assertEqual(second_heartbeat["code"], "exhausted")
        self.assertEqual(self.db.get_license(key)["activation_count"], 2)

    def test_exhausted_card_is_terminal_for_admin_actions(self):
        key = self._generate(limit=1)
        self.assertTrue(self.client.activate(key, "MACHINE-ONLY")["ok"])

        with self.assertRaises(ApiError) as freeze:
            self.client.freeze_license(key, 1, "hour", "不应成功")
        self.assertIn("无法冻结", str(freeze.exception))

        with self.assertRaises(ApiError) as restore:
            self.client.restore_license(key)
        self.assertIn("用尽", str(restore.exception))

        with self.assertRaises(ApiError) as renew:
            self.client.renew_license(key, 30, "day")
        self.assertIn("不支持续期", str(renew.exception))

        with self.assertRaises(ApiError) as offline:
            self.client.offline_code(key, "MACHINE-OFFLINE")
        self.assertIn("离线", str(offline.exception))

        self.assertEqual(self.db.get_license(key)["activation_count"], 1)
        self.assertEqual(self.db.get_license(key)["status"], "revoked")

    def test_detail_exposes_the_counter_for_the_management_ui(self):
        key = self._generate(limit=5)
        self.assertTrue(self.client.activate(key, "MACHINE-DETAIL")["ok"])
        lic = self.client.license_detail(key)["license"]
        self.assertEqual(lic["card_type"], "activation")
        self.assertEqual(lic["activation_count"], 1)
        self.assertEqual(lic["activation_limit"], 5)
        self.assertEqual(lic["auto_revoked"], 0)


@pytest.fixture(scope="module")
def qt_app():
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication

    yield QApplication.instance() or QApplication([])


def test_generate_page_switches_between_card_modes(qt_app):
    from core.pages import GeneratePage

    class GenerateClient:
        def __init__(self):
            self.payload: dict = {}

        def generate_licenses(self, **payload):
            self.payload = payload
            return {
                "batch_no": "B-COUNT",
                "count": 1,
                "keys": ["GSQ-AAAAA-BBBBB-CCCCC-DDDDD"],
            }

    client = GenerateClient()
    page = GeneratePage(client, lambda *args, **kwargs: None)
    assert page.card_mode.currentData() == "duration"
    assert not page.duration.isHidden()
    assert page.activation_limit.isHidden()

    page.card_mode.setCurrentIndex(1)
    assert page.unit.isHidden()
    assert page.duration.isHidden()
    assert page.devices.isHidden()
    assert not page.activation_limit.isHidden()
    assert not page.form.labelForField(page.activation_limit).isHidden()

    page.activation_limit.setValue(25)
    page.generate()
    assert client.payload["card_type"] == "activation"
    assert client.payload["activation_limit"] == 25
    assert client.payload["duration_days"] == 0
    assert client.payload["duration_unit"] == "day"
    assert client.payload["max_devices"] == 0
    assert page.last_meta["usage"] == "25 次"

    page.reset_form()
    assert page.card_mode.currentData() == "duration"
    assert page.activation_limit.isHidden()


def test_card_helpers_describe_activation_cards(qt_app):
    from core.pages import card_mode_text, card_status_text, card_usage_text

    activation = {
        "card_type": "activation",
        "activation_limit": 10,
        "activation_count": 3,
        "status": "active",
        "auto_revoked": 0,
    }
    assert card_mode_text(activation) == "激活次数卡"
    assert card_usage_text(activation) == "3 / 10 次"
    assert card_status_text(activation) is None

    exhausted = dict(activation, status="revoked", auto_revoked=1)
    assert card_status_text(exhausted) == "已用尽"

    duration = {"card_type": "duration", "duration_days": 7, "duration_unit": "day"}
    assert card_mode_text(duration) == "时长卡"
    assert card_usage_text(duration) == "7 天"
    assert card_status_text(duration) is None


if __name__ == "__main__":
    unittest.main()
