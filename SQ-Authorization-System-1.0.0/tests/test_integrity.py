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
REQUIRED_APPS = ["server", "admin", "master", "verification"]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _failure_result(role: str = "verification") -> dict:
    return {
        "ok": False,
        "skipped": False,
        "role": role,
        "exe_name": APP_FILES.get(role, ""),
        "exe_path": f"C:/app/{APP_FILES.get(role, '')}",
        "exe_hash": "",
        "exe_size": 0,
        "version": "1.0.0",
        "manifest_verified": True,
        "checked_at": "2026-10-07 12:00:00",
        "issues": [
            {"code": "hash_mismatch", "file": APP_FILES.get(role, ""), "detail": "哈希不一致"}
        ],
    }


def _fake_pyside(calls: list) -> types.ModuleType:
    """Minimal PySide6.QtWidgets stand-in so popup tests never touch a real GUI."""
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


class IntegritySelfCheckTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.app_dir = Path(self._tmp.name).resolve()
        self.private_key, self.public_key = offline.generate_keypair()
        self.other_private_key, _ = offline.generate_keypair()
        self.manifest = self._build_release()

    # ---- helpers ----------------------------------------------------- #
    def _write_app(self, role: str, data: bytes | None = None) -> bytes:
        payload = data if data is not None else f"payload::{role}::v1".encode("utf-8")
        (self.app_dir / APP_FILES[role]).write_bytes(payload)
        return payload

    def _build_release(self) -> dict:
        apps = {}
        for role in REQUIRED_APPS:
            payload = self._write_app(role)
            apps[role] = {
                "path": APP_FILES[role],
                "sha256": _sha256(payload),
                "size": len(payload),
            }
        return {
            "format": integrity.MANIFEST_FORMAT,
            "version": "1.0.0",
            "generated_at": "2026-10-07T12:00:00+08:00",
            "apps": apps,
            "folder": {
                "guarded_extensions": [".exe", ".dll"],
                "exempt_files": [integrity.MANIFEST_NAME, integrity.SIGNATURE_NAME],
                "required_apps": list(REQUIRED_APPS),
            },
        }

    def _write_manifest(self, manifest: dict | None = None, sign_key: str | None = None) -> None:
        raw = json.dumps(
            manifest if manifest is not None else self.manifest,
            ensure_ascii=False,
            indent=2,
        ).encode("utf-8")
        (self.app_dir / integrity.MANIFEST_NAME).write_bytes(raw)
        signature = offline.sign_message(sign_key or self.private_key, raw)
        (self.app_dir / integrity.SIGNATURE_NAME).write_text(signature, encoding="ascii")

    def _check(self, role: str = "verification", **kwargs) -> dict:
        """Write the current manifest and run a forced self check."""
        self._write_manifest()
        return integrity.run_self_check(
            role,
            app_dir=self.app_dir,
            public_key_hex=self.public_key,
            force=True,
            **kwargs,
        )

    def _codes(self, result: dict) -> list[str]:
        return [issue.get("code") for issue in (result.get("issues") or [])]

    # ---- happy path -------------------------------------------------- #
    def test_valid_release_passes(self):
        result = self._check("verification")
        self.assertTrue(result["ok"])
        self.assertFalse(result["skipped"])
        self.assertEqual(result["role"], "verification")
        self.assertEqual(result["exe_name"], APP_FILES["verification"])
        self.assertEqual(Path(result["exe_path"]), self.app_dir / APP_FILES["verification"])
        self.assertEqual(result["exe_hash"], self.manifest["apps"]["verification"]["sha256"])
        self.assertEqual(result["exe_size"], self.manifest["apps"]["verification"]["size"])
        self.assertEqual(result["version"], "1.0.0")
        self.assertTrue(result["manifest_verified"])
        self.assertTrue(result["checked_at"])
        self.assertEqual(result["issues"], [])
        self.assertEqual(integrity.get_last_result()["ok"], True)

    def test_server_role_passes_when_everything_matches(self):
        result = self._check("server")
        self.assertTrue(result["ok"])
        self.assertEqual(result["exe_name"], APP_FILES["server"])

    # ---- tampering --------------------------------------------------- #
    def test_modified_byte_is_hash_mismatch(self):
        self.assertTrue(self._check("verification")["ok"])
        victim = self.app_dir / APP_FILES["verification"]
        data = bytearray(victim.read_bytes())
        data[0] ^= 0x01
        victim.write_bytes(bytes(data))
        result = self._check("verification")
        self.assertFalse(result["ok"])
        self.assertIn("hash_mismatch", self._codes(result))
        self.assertTrue(
            any(
                issue["code"] == "hash_mismatch" and issue["file"] == APP_FILES["verification"]
                for issue in result["issues"]
            )
        )

    def test_extra_guarded_file_is_reported(self):
        (self.app_dir / "工具.exe").write_bytes(b"MZ")
        (self.app_dir / "备注.txt").write_bytes(b"plain text is ignored")
        result = self._check("verification")
        self.assertFalse(result["ok"])
        extra = [issue for issue in result["issues"] if issue["code"] == "extra_file"]
        self.assertEqual([issue["file"] for issue in extra], ["工具.exe"])

    def test_missing_own_exe_is_reported(self):
        (self.app_dir / APP_FILES["verification"]).unlink()
        result = self._check("verification")
        self.assertFalse(result["ok"])
        self.assertIn("exe_missing", self._codes(result))

    def test_server_requires_every_required_app(self):
        (self.app_dir / APP_FILES["admin"]).unlink()
        result = self._check("server")
        self.assertFalse(result["ok"])
        missing = [issue for issue in result["issues"] if issue["code"] == "missing_file"]
        self.assertEqual([issue["file"] for issue in missing], [APP_FILES["admin"]])

    def test_client_role_tolerates_missing_other_apps(self):
        (self.app_dir / APP_FILES["admin"]).unlink()
        result = self._check("verification")
        self.assertTrue(result["ok"])
        self.assertEqual(result["issues"], [])

    def test_client_role_rejects_modified_other_app_when_present(self):
        (self.app_dir / APP_FILES["master"]).write_bytes(b"tampered-master")
        result = self._check("verification")
        self.assertFalse(result["ok"])
        self.assertTrue(
            any(
                issue["code"] == "hash_mismatch" and issue["file"] == APP_FILES["master"]
                for issue in result["issues"]
            )
        )

    # ---- manifest / signature ---------------------------------------- #
    def test_signature_signed_by_other_key_is_invalid(self):
        self._write_manifest(sign_key=self.other_private_key)
        result = integrity.run_self_check(
            "verification",
            app_dir=self.app_dir,
            public_key_hex=self.public_key,
            force=True,
        )
        self.assertFalse(result["ok"])
        self.assertFalse(result["manifest_verified"])
        self.assertIn("signature_invalid", self._codes(result))

    def test_missing_manifest_is_reported(self):
        self._write_manifest()
        (self.app_dir / integrity.MANIFEST_NAME).unlink()
        result = integrity.run_self_check(
            "verification", app_dir=self.app_dir, public_key_hex=self.public_key, force=True
        )
        self.assertFalse(result["ok"])
        self.assertIn("manifest_missing", self._codes(result))

    def test_broken_json_manifest_is_invalid(self):
        (self.app_dir / integrity.MANIFEST_NAME).write_bytes(b"{not valid json")
        (self.app_dir / integrity.SIGNATURE_NAME).write_text("AAAA", encoding="ascii")
        result = integrity.run_self_check(
            "verification", app_dir=self.app_dir, public_key_hex=self.public_key, force=True
        )
        self.assertFalse(result["ok"])
        self.assertIn("manifest_invalid", self._codes(result))

    def test_empty_release_key_is_reported(self):
        self._write_manifest()
        with mock.patch.object(integrity, "load_release_public_key", return_value=""):
            result = integrity.run_self_check(
                "verification", app_dir=self.app_dir, public_key_hex="", force=True
            )
        self.assertFalse(result["ok"])
        self.assertIn("release_key_missing", self._codes(result))

    def test_read_and_verify_manifest_returns_manifest(self):
        self._write_manifest()
        manifest, issues = integrity.read_and_verify_manifest(
            self.app_dir, public_key_hex=self.public_key
        )
        self.assertEqual(issues, [])
        self.assertEqual(manifest["format"], integrity.MANIFEST_FORMAT)

    # ---- development mode -------------------------------------------- #
    def test_dev_mode_is_skipped(self):
        env = {key: value for key, value in os.environ.items() if key != "SQ_FORCE_INTEGRITY"}
        with mock.patch.dict(os.environ, env, clear=True):
            result = integrity.run_self_check(
                "verification", app_dir=self.app_dir, public_key_hex=self.public_key
            )
        self.assertTrue(result["ok"])
        self.assertTrue(result["skipped"])
        self.assertEqual(self._codes(result), ["skip_dev_mode"])
        self.assertFalse(result["manifest_verified"])

    def test_force_env_enables_full_check(self):
        self._write_manifest()
        with mock.patch.dict(os.environ, {"SQ_FORCE_INTEGRITY": "1"}):
            result = integrity.run_self_check(
                "verification", app_dir=self.app_dir, public_key_hex=self.public_key
            )
        self.assertFalse(result["skipped"])
        self.assertTrue(result["ok"])

    # ---- startup gate ------------------------------------------------ #
    def test_startup_gate_returns_skipped_in_dev_mode(self):
        env = {key: value for key, value in os.environ.items() if key != "SQ_FORCE_INTEGRITY"}
        with mock.patch.dict(os.environ, env, clear=True):
            result = integrity.run_startup_gate("verification")
        self.assertTrue(result["ok"])
        self.assertTrue(result["skipped"])

    def test_startup_gate_failure_reports_and_exits(self):
        calls: list = []
        env = {key: value for key, value in os.environ.items() if key != "SQ_INTEGRITY_NO_POPUP"}
        with mock.patch.object(integrity, "run_self_check", return_value=_failure_result()):
            with mock.patch("core.api_client.ApiClient.report_integrity_failure") as report:
                with mock.patch.dict(os.environ, env, clear=True):
                    with mock.patch.dict(sys.modules, {"PySide6.QtWidgets": _fake_pyside(calls)}):
                        with redirect_stderr(io.StringIO()):
                            with self.assertRaises(SystemExit) as ctx:
                                integrity.run_startup_gate("verification")
        self.assertEqual(ctx.exception.code, 1)
        self.assertTrue(report.called)
        self.assertEqual(report.call_args[0][0], "hash_mismatch")
        self.assertFalse(integrity.get_last_result()["ok"])
        # gui 默认允许弹窗，且环境变量未禁用时应当尝试弹窗。
        self.assertEqual(len(calls), 1)

    def test_startup_gate_gui_false_skips_popup(self):
        calls: list = []
        env = {key: value for key, value in os.environ.items() if key != "SQ_INTEGRITY_NO_POPUP"}
        with mock.patch.object(integrity, "run_self_check", return_value=_failure_result()):
            with mock.patch("core.api_client.ApiClient.report_integrity_failure"):
                with mock.patch.dict(os.environ, env, clear=True):
                    with mock.patch.dict(sys.modules, {"PySide6.QtWidgets": _fake_pyside(calls)}):
                        with redirect_stderr(io.StringIO()):
                            with self.assertRaises(SystemExit):
                                integrity.run_startup_gate("verification", gui=False)
        self.assertEqual(calls, [])

    def test_startup_gate_no_popup_env_wins_over_gui(self):
        calls: list = []
        failure = _failure_result()
        with mock.patch.dict(os.environ, {"SQ_INTEGRITY_NO_POPUP": "1"}):
            with mock.patch.object(integrity, "run_self_check", return_value=failure):
                with mock.patch("core.api_client.ApiClient.report_integrity_failure"):
                    with mock.patch.dict(sys.modules, {"PySide6.QtWidgets": _fake_pyside(calls)}):
                        with redirect_stderr(io.StringIO()):
                            with self.assertRaises(SystemExit):
                                integrity.run_startup_gate("verification", gui=True)
        self.assertEqual(calls, [])

    def test_startup_gate_server_role_never_reports(self):
        with mock.patch.dict(os.environ, {"SQ_INTEGRITY_NO_POPUP": "1"}):
            with mock.patch.object(
                integrity, "run_self_check", return_value=_failure_result("server")
            ):
                with mock.patch("core.api_client.ApiClient.report_integrity_failure") as report:
                    with redirect_stderr(io.StringIO()):
                        with self.assertRaises(SystemExit):
                            integrity.run_startup_gate("server", gui=False)
        self.assertFalse(report.called)


if __name__ == "__main__":
    unittest.main()
