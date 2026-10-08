import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

from core import offline
from tools import release_manifest


class ReleaseManifestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        self.dist = self.root / "dist"
        self.dist.mkdir()
        self.keys_path = self.root / "release_keys" / "release_key.json"
        self.exe_paths = {}
        for role, name in release_manifest.RELEASE_APPS:
            path = self.dist / name
            path.write_bytes(f"fake-exe-{role}".encode("utf-8"))
            self.exe_paths[role] = path

    def tearDown(self):
        self.tmp.cleanup()

    def _keypair(self) -> dict:
        return release_manifest.ensure_keypair(self.keys_path)

    def _manifest(self, version: str = "1.0.0") -> tuple[dict, bytes]:
        manifest = release_manifest.build_manifest(self.dist, version)
        return manifest, release_manifest.manifest_bytes(manifest)

    def test_ensure_keypair_persists_and_is_idempotent(self):
        first = self._keypair()
        self.assertTrue(self.keys_path.is_file())
        self.assertRegex(first["private_key"], r"^[0-9a-f]{64}$")
        self.assertRegex(first["public_key"], r"^[0-9a-f]{64}$")
        self.assertEqual(offline.public_from_private(first["private_key"]), first["public_key"])
        self.assertTrue(first["created_at"])

        stored = json.loads(self.keys_path.read_text(encoding="utf-8"))
        self.assertEqual(stored["private_key"], first["private_key"])
        self.assertEqual(stored["public_key"], first["public_key"])

        second = release_manifest.ensure_keypair(self.keys_path)
        self.assertEqual(second["private_key"], first["private_key"])
        self.assertEqual(second["public_key"], first["public_key"])

    def test_manifest_schema_sha256_and_size(self):
        expected_paths = {
            "server": "本地服务器.exe",
            "admin": "管理端.exe",
            "master": "主控端.exe",
            "verification": "验证端.exe",
        }
        manifest, raw = self._manifest()

        self.assertEqual(manifest["format"], "sq-release-manifest-v1")
        self.assertEqual(manifest["version"], "1.0.0")
        self.assertIn("T", manifest["generated_at"])
        self.assertEqual(
            manifest["folder"],
            {
                "guarded_extensions": [".exe", ".dll"],
                "exempt_files": ["release_manifest.json", "release_manifest.sig"],
                "required_apps": ["server", "admin", "master", "verification"],
            },
        )
        self.assertEqual(set(manifest["apps"]), set(expected_paths))

        for role, name in expected_paths.items():
            entry = manifest["apps"][role]
            self.assertEqual(set(entry), {"path", "sha256", "size"})
            self.assertEqual(entry["path"], name)
            payload = self.exe_paths[role].read_bytes()
            self.assertEqual(entry["sha256"], hashlib.sha256(payload).hexdigest())
            self.assertRegex(entry["sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(entry["size"], len(payload))

        text = raw.decode("utf-8")
        self.assertFalse(text.startswith("\ufeff"))
        # 2 空格缩进：format 字段位于第二行且内容开关正确。
        self.assertIn('\n  "format": "sq-release-manifest-v1"', text)

    def test_sign_and_verify_roundtrip(self):
        keys = self._keypair()
        _manifest, raw = self._manifest()
        signature = offline.sign_message(keys["private_key"], raw)
        self.assertTrue(offline.verify_message(keys["public_key"], raw, signature))

    def test_tampered_manifest_bytes_fail_verification(self):
        keys = self._keypair()
        _manifest, raw = self._manifest()
        signature = offline.sign_message(keys["private_key"], raw)

        tampered = bytearray(raw)
        idx = tampered.index(b"1.0.0")
        tampered[idx] = ord("2")
        self.assertNotEqual(bytes(tampered), raw)
        self.assertFalse(offline.verify_message(keys["public_key"], bytes(tampered), signature))
        self.assertTrue(offline.verify_message(keys["public_key"], raw, signature))

    def test_tampered_exe_changes_hash_and_breaks_match(self):
        manifest, _raw = self._manifest()
        original_hash = manifest["apps"]["admin"]["sha256"]

        target = self.exe_paths["admin"]
        payload = bytearray(target.read_bytes())
        payload[-1] ^= 0x01
        target.write_bytes(bytes(payload))

        rebuilt = release_manifest.build_manifest(self.dist, "1.0.0")
        self.assertNotEqual(rebuilt["apps"]["admin"]["sha256"], original_hash)
        self.assertEqual(
            rebuilt["apps"]["admin"]["sha256"],
            hashlib.sha256(target.read_bytes()).hexdigest(),
        )
        self.assertNotEqual(rebuilt["apps"]["admin"]["sha256"], manifest["apps"]["admin"]["sha256"])

    def test_write_pubkey_module_is_generated_product(self):
        keys = self._keypair()
        target = self.root / "release_pubkey.py"
        release_manifest.write_pubkey_module(keys["public_key"], path=target)

        content = target.read_text(encoding="utf-8")
        self.assertEqual(content, f'RELEASE_PUBLIC_KEY_HEX = "{keys["public_key"]}"\n')

        sys.modules.pop("release_pubkey_probe", None)
        import importlib.util

        spec = importlib.util.spec_from_file_location("release_pubkey_probe", target)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(module.RELEASE_PUBLIC_KEY_HEX, keys["public_key"])

    def test_write_signed_manifest_writes_both_copies(self):
        keys = self._keypair()
        written = release_manifest.write_signed_manifest(
            self.dist, "1.0.0", keys_path=self.keys_path
        )

        for option in ("manifest", "signature", "releases_manifest", "releases_signature"):
            self.assertTrue(written[option].is_file(), written[option])

        manifest_path = self.dist / "release_manifest.json"
        signature_path = self.dist / "release_manifest.sig"
        releases = self.dist / "releases"

        raw = manifest_path.read_bytes()
        self.assertEqual(raw, (releases / "release_manifest.json").read_bytes())
        self.assertEqual(signature_path.read_bytes(), (releases / "release_manifest.sig").read_bytes())
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))

        signature_text = signature_path.read_text(encoding="utf-8")
        self.assertEqual(signature_text.count("\n"), 0)
        self.assertTrue(offline.verify_message(keys["public_key"], raw, signature_text))

        manifest = json.loads(raw.decode("utf-8"))
        self.assertEqual(manifest["format"], "sq-release-manifest-v1")
        self.assertEqual(manifest["version"], "1.0.0")
        self.assertEqual(written["fingerprint"], offline.public_key_fingerprint(keys["public_key"]))

    def test_build_manifest_reports_missing_app(self):
        (self.dist / "主控端.exe").unlink()
        with self.assertRaises(FileNotFoundError):
            release_manifest.build_manifest(self.dist, "1.0.0")


if __name__ == "__main__":
    unittest.main()
