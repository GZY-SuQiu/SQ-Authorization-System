"""SDK 嵌入第三方宿主程序时的 attest 豁免测试。

宿主 exe 不可能进入本产品发布白名单，因此 SDK 走共享密钥豁免：
必须显式开启 ``sdk_attest_exempt``、配置 ``sdk_shared_secret``，并携带
``X-SDK-Token = HMAC(shared_secret, machine_code)``；缺少任何一项都不放行。
"""

import tempfile
import unittest
from pathlib import Path

import requests

from core import security
from core.config import Config
from core.database import Database
from tests.test_api_hardening import LiveServer


class SdkAttestExemptTests(unittest.TestCase):
    def _start(self, exempt: bool = True, shared_secret: str = ""):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        root = Path(self.tmp.name)
        self.config = Config("server", root / "server_config.json")
        self.config.data["security"]["attest_mode"] = "auto"
        self.config.data["security"]["sdk_attest_exempt"] = exempt
        self.config.data["security"]["sdk_shared_secret"] = shared_secret
        self.db = Database(root / "license.db", self.config.security["secret_key"])
        self.db.ensure_default_admin()
        # 一条 active 发布哈希即可让 auto 模式进入强制 attest。
        self.db.upsert_release_hash("验证端.exe", "a" * 64, 1, "1.0.0")
        self.live = LiveServer(self.config, self.db)
        self.live.start()
        self.base = f"http://127.0.0.1:{self.live.port}"

    def tearDown(self):
        live = getattr(self, "live", None)
        if live is not None:
            live.stop()
        db = getattr(self, "db", None)
        if db is not None:
            db.close()
        tmp = getattr(self, "tmp", None)
        if tmp is not None:
            tmp.cleanup()

    def _activate(self, headers=None):
        body = {
            "key_code": "GSQ-NO-SUCH-1",
            "machine_code": "SDK-M-1",
            "device_name": "sdk",
        }
        return requests.post(
            f"{self.base}/api/client/activate",
            json=body,
            headers=headers or {},
            timeout=10,
        )

    def test_shared_secret_exemption_requires_matching_token(self):
        self._start(exempt=True, shared_secret="s3cret-value")
        self.assertEqual(self._activate().status_code, 403)
        self.assertEqual(
            self._activate(
                {"X-Client-Kind": "sdk", "X-SDK-Token": "wrong-token"}
            ).status_code,
            403,
        )
        token = security.hash_action_code("s3cret-value", "SDK-M-1")
        allowed = self._activate({"X-Client-Kind": "sdk", "X-SDK-Token": token})
        self.assertNotEqual(allowed.status_code, 403, allowed.text)
        self.assertEqual(allowed.json().get("code"), "not_found", allowed.text)

    def test_exemption_disabled_by_default_even_with_token(self):
        self._start(exempt=False, shared_secret="s3cret-value")
        token = security.hash_action_code("s3cret-value", "SDK-M-1")
        denied = self._activate({"X-Client-Kind": "sdk", "X-SDK-Token": token})
        self.assertEqual(denied.status_code, 403, denied.text)

    def test_header_alone_cannot_bypass(self):
        self._start(exempt=True, shared_secret="")
        denied = self._activate({"X-Client-Kind": "sdk"})
        self.assertEqual(denied.status_code, 403, denied.text)


if __name__ == "__main__":
    unittest.main()
