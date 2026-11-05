"""Outbox 租约与崩溃恢复测试（P1-5）。"""

import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from core import security
from core.database import Database


class OutboxRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = Database(Path(self.tmp.name) / "license.db", "outbox-secret")

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    @staticmethod
    def _old_timestamp() -> str:
        return (datetime.now() - timedelta(minutes=10)).strftime(security.TIME_FORMAT)

    def test_stale_sending_email_is_reclaimed(self):
        email_id = self.db.enqueue_email(
            "user@example.com", "verify_email", {"code": "123456"}
        )
        self.assertIsNotNone(email_id)
        first = self.db.claim_due_emails()
        self.assertEqual([int(row["id"]) for row in first], [int(email_id)])
        self.assertEqual(first[0]["status"], "sending")
        self.assertTrue(first[0]["claimed_at"])

        # 模拟领取后进程被 kill：把领取时间改到 10 分钟前。
        self.db._execute(
            "UPDATE email_outbox SET claimed_at = ? WHERE id = ?",
            (self._old_timestamp(), email_id),
        )
        recovered = self.db.claim_due_emails()
        self.assertEqual([int(row["id"]) for row in recovered], [int(email_id)])

    def test_fresh_sending_email_is_not_reclaimed(self):
        email_id = self.db.enqueue_email(
            "user@example.com", "verify_email", {"code": "123456"}
        )
        self.db.claim_due_emails()
        self.assertEqual(self.db.claim_due_emails(), [])

    def test_stale_sending_channel_message_is_reclaimed(self):
        channel_id = self.db.create_notification_channel(
            "webhook", "测试渠道", "https://example.com/hook"
        )
        message_id = self.db.enqueue_channel_message(
            channel_id, "subject", "body"
        )
        self.assertIsNotNone(message_id)
        first = self.db.claim_due_channel_messages()
        self.assertEqual([int(row["id"]) for row in first], [int(message_id)])
        self.db._execute(
            "UPDATE channel_outbox SET claimed_at = ? WHERE id = ?",
            (self._old_timestamp(), message_id),
        )
        recovered = self.db.claim_due_channel_messages()
        self.assertEqual([int(row["id"]) for row in recovered], [int(message_id)])


if __name__ == "__main__":
    unittest.main()
