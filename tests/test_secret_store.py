"""本机机密存储（DPAPI/兼容回退）测试。"""

import sys
import unittest

from core import secret_store


class SecretStoreTests(unittest.TestCase):
    def test_roundtrip(self):
        token = secret_store.protect("P@ssw0rd-测试")
        self.assertTrue(token)
        self.assertNotIn("P@ssw0rd", token)
        self.assertEqual(secret_store.unprotect(token), "P@ssw0rd-测试")

    def test_empty_values(self):
        self.assertEqual(secret_store.protect(""), "")
        self.assertEqual(secret_store.unprotect(""), "")
        self.assertEqual(secret_store.unprotect("garbage-token"), "")

    def test_windows_uses_dpapi_prefix(self):
        token = secret_store.protect("secret")
        if sys.platform == "win32":
            self.assertTrue(
                token.startswith("dpapi:") or token.startswith("b64:"),
                token[:16],
            )
            self.assertTrue(secret_store.is_secure_available())
        else:
            self.assertTrue(token.startswith("b64:"))
            self.assertFalse(secret_store.is_secure_available())


if __name__ == "__main__":
    unittest.main()
