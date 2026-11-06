# -*- coding: utf-8 -*-
"""B2 客户端深化加固测试：判定收口单元 + watermark 双点加固。"""
import unittest

from core import offline


class WatermarkTests(unittest.TestCase):
    def test_seal_verify_roundtrip(self):
        sig = offline.seal_watermark("MC-ONE", 1730000000)
        self.assertTrue(offline.verify_watermark("MC-ONE", 1730000000, sig))
        # 机器码/时间戳被换 → 校验失败
        self.assertFalse(offline.verify_watermark("MC-TWO", 1730000000, sig))
        self.assertFalse(offline.verify_watermark("MC-ONE", 1730000001, sig))
        # 空签名 / 空时间戳
        self.assertFalse(offline.verify_watermark("MC-ONE", 1730000000, ""))
        self.assertFalse(offline.verify_watermark("MC-ONE", 0, sig))

    def test_seal_is_case_insensitive_machine(self):
        sig = offline.seal_watermark("mc-one", 1730000000)
        self.assertTrue(offline.verify_watermark("MC-ONE", 1730000000, sig))

    def test_effective_last_seen_takes_max(self):
        ts_a, ts_b = 1730000000, 1730000500
        entries = [
            (ts_a, offline.seal_watermark("M", ts_a)),
            (ts_b, offline.seal_watermark("M", ts_b)),
        ]
        self.assertEqual(offline.effective_last_seen("M", entries), ts_b)

    def test_effective_last_seen_ignores_tampered(self):
        ts_a, ts_b = 1730000000, 1730000500
        # 高位条目签名被编辑 → 被忽略，退回有效条目
        entries = [(ts_b, "deadbeef" * 8), (ts_a, offline.seal_watermark("M", ts_a))]
        self.assertEqual(offline.effective_last_seen("M", entries), ts_a)

    def test_effective_last_seen_empty_and_garbage(self):
        self.assertEqual(offline.effective_last_seen("M", []), 0)
        self.assertEqual(offline.effective_last_seen("M", None), 0)
        self.assertEqual(offline.effective_last_seen("M", [(0, "x"), ("bad", "y")]), 0)

    def test_check_rolled_back(self):
        last = 1730000000
        # 时间前进 → 非回拨
        self.assertFalse(offline.check_rolled_back("M", last, last + 100))
        # 回拨 7 小时 → 判定回拨（超过 6 小时容忍）
        self.assertTrue(offline.check_rolled_back("M", last, last - 7 * 3600))
        # 回拨 1 小时 → 在容忍内（DST/NTP 修正）
        self.assertFalse(offline.check_rolled_back("M", last, last - 3600))
        # 无记录 → 不判定
        self.assertFalse(offline.check_rolled_back("M", 0, 123456.0))


class EvaluatePayloadTests(unittest.TestCase):
    FUTURE = "2027-01-01 00:00:00"
    PAST = "2020-01-01 00:00:00"

    def test_ok(self):
        verdict = offline.evaluate_activation_payload(
            {"mc": "AAA-BBB", "exp": self.FUTURE}, "AAA-BBB"
        )
        self.assertTrue(verdict["ok"])
        self.assertEqual(verdict["code"], "ok")

    def test_machine_mismatch(self):
        verdict = offline.evaluate_activation_payload(
            {"mc": "AAA-BBB", "exp": self.FUTURE}, "CCC-DDD"
        )
        self.assertFalse(verdict["ok"])
        self.assertEqual(verdict["code"], "machine_mismatch")

    def test_machine_case_insensitive(self):
        verdict = offline.evaluate_activation_payload(
            {"mc": "aaa-bbb", "exp": self.FUTURE}, "AAA-BBB"
        )
        self.assertTrue(verdict["ok"])

    def test_expired(self):
        verdict = offline.evaluate_activation_payload(
            {"mc": "AAA-BBB", "exp": self.PAST}, "AAA-BBB"
        )
        self.assertFalse(verdict["ok"])
        self.assertEqual(verdict["code"], "expired")

    def test_permanent_no_expiry(self):
        verdict = offline.evaluate_activation_payload(
            {"mc": "AAA-BBB", "exp": None}, "AAA-BBB"
        )
        self.assertTrue(verdict["ok"])

    def test_clock_rolled_back_blocks_before_anything(self):
        now = 1730000000.0
        verdict = offline.evaluate_activation_payload(
            {"mc": "AAA-BBB", "exp": self.FUTURE},
            "AAA-BBB",
            last_seen=1730000000,
            now=now - 7 * 3600,
        )
        self.assertFalse(verdict["ok"])
        self.assertEqual(verdict["code"], "clock_rolled_back")

    def test_empty_machine_binding_passes(self):
        # 离线码未写机器码时（异常历史数据）不因空值误拦
        verdict = offline.evaluate_activation_payload({"mc": "", "exp": self.FUTURE}, "AAA-BBB")
        self.assertTrue(verdict["ok"])

    def test_invalid_payload(self):
        verdict = offline.evaluate_activation_payload(None, "AAA-BBB")
        self.assertFalse(verdict["ok"])
        self.assertEqual(verdict["code"], "invalid")


if __name__ == "__main__":
    unittest.main()
