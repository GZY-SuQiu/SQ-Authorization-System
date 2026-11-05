"""BUGFIX 批次（问题三/四）：release 绑定校验与 verification 独立运行。

覆盖 ``docs/BUGFIX-INTERFACE.md`` 第 3、4 节的客户端部分：

- ``run_self_check`` 结果新增 ``release_id`` / ``manifest_sha256``；
- 内嵌 ``RELEASE_ID`` 与清单 ``release_id`` 不一致记 ``release_mismatch`` 并失败；
- ``verification`` 在清单与签名文件都不存在时进入 standalone（不弹窗、不退出），
  任一文件存在则照旧严格校验，admin/master/server 行为不变。
"""

import hashlib
import io
import json
import os
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

from core import integrity, offline


APP_FILES = {
    "server": "本地服务器.exe",
    "admin": "管理端.exe",
    "master": "主控端.exe",
    "verification": "验证端.exe",
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fake_pyside(calls: list) -> types.ModuleType:
    """最小 PySide6.QtWidgets 替身：standalone 场景不应触发任何弹窗。"""
    stub = types.ModuleType("PySide6.QtWidgets")
    stub.QApplication = type(
        "QApplication", (), {"instance": staticmethod(lambda: object())}
    )
    stub.QMessageBox = type(
        "QMessageBox",
        (),
        {"critical": staticmethod(lambda *args, **kwargs: calls.append(args))},
    )
    return stub


class IntegrityStandaloneTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.app_dir = Path(self._tmp.name).resolve()
        self.private_key, self.public_key = offline.generate_keypair()
        self.app_bytes = b"standalone-verification-exe::v1"
        (self.app_dir / APP_FILES["verification"]).write_bytes(self.app_bytes)

        # 开发树里 core/release_identity.py 可能由 build.py 生成；
        # 默认置空，保证“无内嵌 RELEASE_ID”分支可复现。
        self._real_load_release_id = integrity.load_release_id
        patcher = mock.patch.object(integrity, "load_release_id", return_value="")
        patcher.start()
        self.addCleanup(patcher.stop)

    # ---- helpers ------------------------------------------------------ #
    def _manifest(self, release_id: str = "") -> dict:
        manifest = {
            "format": integrity.MANIFEST_FORMAT,
            "version": "1.0.0",
            "generated_at": "2026-10-08T10:00:00+08:00",
            "apps": {
                "verification": {
                    "path": APP_FILES["verification"],
                    "sha256": _sha256(self.app_bytes),
                    "size": len(self.app_bytes),
                }
            },
            "folder": {
                "guarded_extensions": [".exe", ".dll"],
                "exempt_files": [integrity.MANIFEST_NAME, integrity.SIGNATURE_NAME],
                "required_apps": list(APP_FILES),
            },
        }
        if release_id:
            manifest["release_id"] = release_id
        return manifest

    def _write_manifest(self, manifest: dict, sign_key: str | None = None) -> bytes:
        raw = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
        (self.app_dir / integrity.MANIFEST_NAME).write_bytes(raw)
        signature = offline.sign_message(sign_key or self.private_key, raw)
        (self.app_dir / integrity.SIGNATURE_NAME).write_text(signature, encoding="ascii")
        return raw

    def _run(self, role: str = "verification", **kwargs) -> dict:
        return integrity.run_self_check(
            role,
            app_dir=self.app_dir,
            public_key_hex=self.public_key,
            force=True,
            **kwargs,
        )

    @staticmethod
    def _codes(result: dict) -> list[str]:
        return [issue.get("code") for issue in (result.get("issues") or [])]

    # ---- standalone 模式 ---------------------------------------------- #
    def test_verification_without_files_is_standalone(self):
        result = self._run("verification")
        self.assertTrue(result["ok"])
        self.assertTrue(result["skipped"])
        self.assertEqual(result["role"], "verification")
        self.assertEqual(self._codes(result), ["standalone_mode"])
        self.assertFalse(result["manifest_verified"])
        self.assertEqual(result["exe_name"], APP_FILES["verification"])
        self.assertEqual(result["exe_hash"], _sha256(self.app_bytes))
        # 两个新字段必须始终存在；清单缺失时 manifest_sha256 为空串。
        self.assertIn("release_id", result)
        self.assertIn("manifest_sha256", result)
        self.assertEqual(result["manifest_sha256"], "")
        self.assertEqual(result["release_id"], "")
        self.assertTrue(integrity.get_last_result()["skipped"])

    def test_startup_gate_standalone_does_not_exit_or_popup(self):
        calls: list = []
        env = {
            key: value
            for key, value in os.environ.items()
            if key not in ("SQ_INTEGRITY_NO_POPUP",)
        }
        env["SQ_FORCE_INTEGRITY"] = "1"
        with mock.patch.object(
            integrity, "_default_app_dir", return_value=self.app_dir
        ):
            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch.dict(
                    sys.modules, {"PySide6.QtWidgets": _fake_pyside(calls)}
                ):
                    result = integrity.run_startup_gate("verification")
        self.assertTrue(result["ok"])
        self.assertTrue(result["skipped"])
        self.assertEqual(self._codes(result), ["standalone_mode"])
        self.assertEqual(calls, [])

    def test_verification_with_manifest_but_tampered_exe_fails(self):
        raw = self._write_manifest(self._manifest())
        (self.app_dir / APP_FILES["verification"]).write_bytes(b"tampered")
        result = self._run("verification")
        self.assertFalse(result["ok"])
        self.assertFalse(result["skipped"])
        self.assertIn("hash_mismatch", self._codes(result))
        self.assertEqual(result["manifest_sha256"], _sha256(raw))

    def test_verification_with_only_manifest_fails(self):
        self._write_manifest(self._manifest())
        (self.app_dir / integrity.SIGNATURE_NAME).unlink()
        result = self._run("verification")
        self.assertFalse(result["ok"])
        self.assertFalse(result["skipped"])
        self.assertIn("manifest_missing", self._codes(result))

    def test_verification_with_only_signature_fails(self):
        raw = json.dumps(
            self._manifest(), ensure_ascii=False, indent=2
        ).encode("utf-8")
        signature = offline.sign_message(self.private_key, raw)
        (self.app_dir / integrity.SIGNATURE_NAME).write_text(
            signature, encoding="ascii"
        )
        result = self._run("verification")
        self.assertFalse(result["ok"])
        self.assertFalse(result["skipped"])
        self.assertIn("manifest_missing", self._codes(result))

    def test_admin_without_files_still_fails(self):
        for role in ("admin", "master", "server"):
            with self.subTest(role=role):
                result = self._run(role)
                self.assertFalse(result["ok"])
                self.assertFalse(result["skipped"])
                self.assertIn("manifest_missing", self._codes(result))
                self.assertEqual(result["manifest_sha256"], "")

    # ---- release 绑定校验 --------------------------------------------- #
    def test_release_id_mismatch_fails_with_release_mismatch(self):
        with mock.patch.object(integrity, "load_release_id", return_value="a" * 32):
            self._write_manifest(self._manifest(release_id="b" * 32))
            result = self._run("verification")
        self.assertFalse(result["ok"])
        self.assertEqual(self._codes(result), ["release_mismatch"])
        self.assertEqual(result["issues"][0]["file"], integrity.MANIFEST_NAME)
        self.assertEqual(result["release_id"], "a" * 32)

    def test_release_id_match_passes(self):
        release_id = "c" * 32
        with mock.patch.object(integrity, "load_release_id", return_value=release_id):
            self._write_manifest(self._manifest(release_id=release_id))
            result = self._run("verification")
        self.assertTrue(result["ok"])
        self.assertNotIn("release_mismatch", self._codes(result))
        self.assertEqual(result["release_id"], release_id)

    def test_empty_embedded_release_id_skips_binding_check(self):
        with mock.patch.object(integrity, "load_release_id", return_value=""):
            self._write_manifest(self._manifest(release_id="d" * 32))
            result = self._run("verification")
        self.assertTrue(result["ok"])
        self.assertNotIn("release_mismatch", self._codes(result))
        self.assertEqual(result["release_id"], "d" * 32)

    def test_load_release_id_handles_missing_and_present_module(self):
        # 这里直接调用未被 setUp 打桩的真实实现。
        with mock.patch.dict(sys.modules, {"core.release_identity": None}):
            self.assertEqual(self._real_load_release_id(), "")

        module = types.ModuleType("core.release_identity")
        module.RELEASE_ID = "e" * 32
        with mock.patch.dict(sys.modules, {"core.release_identity": module}):
            self.assertEqual(self._real_load_release_id(), "e" * 32)

        module.RELEASE_ID = ""
        with mock.patch.dict(sys.modules, {"core.release_identity": module}):
            self.assertEqual(self._real_load_release_id(), "")

    # ---- 开发模式 ------------------------------------------------------ #
    def test_dev_mode_still_skips_and_exposes_new_fields(self):
        env = {
            key: value
            for key, value in os.environ.items()
            if key != "SQ_FORCE_INTEGRITY"
        }
        with mock.patch.dict(os.environ, env, clear=True):
            result = integrity.run_self_check(
                "verification", app_dir=self.app_dir, public_key_hex=self.public_key
            )
        self.assertTrue(result["ok"])
        self.assertTrue(result["skipped"])
        self.assertEqual(self._codes(result), ["skip_dev_mode"])
        self.assertIn("release_id", result)
        self.assertIn("manifest_sha256", result)
        self.assertEqual(result["manifest_sha256"], "")

    def test_dev_mode_digest_reports_existing_manifest(self):
        raw = self._write_manifest(self._manifest())
        env = {
            key: value
            for key, value in os.environ.items()
            if key != "SQ_FORCE_INTEGRITY"
        }
        with mock.patch.dict(os.environ, env, clear=True):
            result = integrity.run_self_check(
                "verification", app_dir=self.app_dir, public_key_hex=self.public_key
            )
        self.assertTrue(result["skipped"])
        self.assertEqual(result["manifest_sha256"], _sha256(raw))

    def test_tampered_release_still_exits_via_gate(self):
        """verification 有文件且被篡改时，门禁仍按失败处理（不回退 standalone）。"""
        self._write_manifest(self._manifest())
        (self.app_dir / APP_FILES["verification"]).write_bytes(b"tampered")
        env = {key: value for key, value in os.environ.items()}
        env["SQ_FORCE_INTEGRITY"] = "1"
        env["SQ_INTEGRITY_NO_POPUP"] = "1"
        with mock.patch.object(
            integrity, "_default_app_dir", return_value=self.app_dir
        ):
            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch("core.api_client.ApiClient.report_integrity_failure"):
                    with redirect_stderr(io.StringIO()):
                        with self.assertRaises(SystemExit) as ctx:
                            integrity.run_startup_gate("verification")
        self.assertEqual(ctx.exception.code, 1)
        self.assertFalse(integrity.get_last_result()["ok"])
        self.assertFalse(integrity.get_last_result()["skipped"])


if __name__ == "__main__":
    unittest.main()
