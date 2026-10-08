"""P1-9 清单修复通道测试：``repair_manifest`` 与 ``--repair-manifest``。

规则：签名不对或 exe 哈希与清单不一致时拒绝修复（fail-closed），只有全部
通过才原子写回 manifest + sig 并写 ``integrity_repair.log``。
"""

import hashlib
import json
from pathlib import Path

import pytest

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


def _make_target(tmp_path: Path) -> Path:
    target = tmp_path / "program"
    target.mkdir()
    for role in REQUIRED_APPS:
        (target / APP_FILES[role]).write_bytes(f"payload::{role}::v1".encode("utf-8"))
    return target


def _make_manifest(target: Path) -> dict:
    entries = {}
    for role in REQUIRED_APPS:
        data = (target / APP_FILES[role]).read_bytes()
        entries[role] = {
            "path": APP_FILES[role],
            "sha256": _sha256(data),
            "size": len(data),
        }
    return {
        "format": integrity.MANIFEST_FORMAT,
        "version": "1.0.0",
        "generated_at": "2026-10-08T12:00:00+08:00",
        "apps": entries,
        "folder": {
            "guarded_extensions": [".exe", ".dll"],
            "exempt_files": [integrity.MANIFEST_NAME, integrity.SIGNATURE_NAME],
            "required_apps": list(REQUIRED_APPS),
        },
    }


def _write_source(source: Path, manifest: dict, private_key: str) -> bytes:
    raw = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
    (source / integrity.MANIFEST_NAME).write_bytes(raw)
    (source / integrity.SIGNATURE_NAME).write_text(
        offline.sign_message(private_key, raw), encoding="ascii"
    )
    return raw


@pytest.fixture()
def release(tmp_path):
    private_key, public_key = offline.generate_keypair()
    target = _make_target(tmp_path)
    manifest = _make_manifest(target)
    source = tmp_path / "release_package"
    source.mkdir()
    _write_source(source, manifest, private_key)
    return {
        "private_key": private_key,
        "public_key": public_key,
        "target": target,
        "source": source,
        "manifest": manifest,
        "tmp_path": tmp_path,
    }


def _repair(release, role: str = "verification", **kwargs) -> dict:
    return integrity.repair_manifest(
        release["source"],
        target_dir=release["target"],
        role=role,
        public_key_hex=release["public_key"],
        **kwargs,
    )


# --------------------------------------------------------------------------- #
# 成功路径
# --------------------------------------------------------------------------- #
def test_repair_restores_manifest_and_signature(release):
    target = release["target"]
    # 目标目录的清单被同步工具改坏，签名文件干脆丢了。
    (target / integrity.MANIFEST_NAME).write_bytes(b"{broken manifest")

    result = _repair(release)

    assert result["ok"] is True
    assert result["code"] == ""
    assert result["role"] == "verification"
    assert result["checked_apps"] == ["verification"]
    assert result["manifest_sha256"] == _sha256(
        (release["source"] / integrity.MANIFEST_NAME).read_bytes()
    )

    manifest, issues = integrity.read_and_verify_manifest(
        target, public_key_hex=release["public_key"]
    )
    assert issues == []
    assert manifest["version"] == "1.0.0"
    assert (target / integrity.MANIFEST_NAME).read_bytes() == (
        release["source"] / integrity.MANIFEST_NAME
    ).read_bytes()
    assert (target / integrity.SIGNATURE_NAME).is_file()
    assert not list(target.glob("*.tmp"))

    # 修复后目标目录必须能通过真正的完整性门禁。
    check = integrity.run_self_check(
        "verification",
        app_dir=target,
        public_key_hex=release["public_key"],
        force=True,
    )
    assert check["ok"] is True, check["issues"]
    assert check["issues"] == []

    lines = (target / integrity.REPAIR_LOG_NAME).read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["checked_apps"] == ["verification"]
    assert record["role"] == "verification"
    assert record["manifest_sha256"] == result["manifest_sha256"]
    assert result["log_written"] is True


def test_server_repair_checks_all_required_apps(release):
    # 缺一个 required_app 时 server 口径应当拒绝。
    (release["target"] / APP_FILES["admin"]).unlink()
    missing = _repair(release, role="server")
    assert missing["ok"] is False
    assert missing["code"] == "exe_missing"
    assert not (release["target"] / integrity.MANIFEST_NAME).exists()

    # 补齐后全部 required_apps 通过，才允许写回。
    (release["target"] / APP_FILES["admin"]).write_bytes(b"payload::admin::v1")
    result = _repair(release, role="server")
    assert result["ok"] is True
    assert sorted(result["checked_apps"]) == sorted(REQUIRED_APPS)


def test_unknown_role_requires_every_required_app(release):
    # 冻结运行也推断不出角色时按 server 口径处理：全部 required_apps 必须匹配。
    (release["target"] / APP_FILES["master"]).write_bytes(b"tampered-master")
    result = _repair(release, role="")
    assert result["ok"] is False
    assert result["code"] == "hash_mismatch"
    assert not (release["target"] / integrity.MANIFEST_NAME).exists()


def test_embedded_release_key_is_used_by_default(release, monkeypatch):
    monkeypatch.setattr(
        integrity, "load_release_public_key", lambda: release["public_key"]
    )
    result = integrity.repair_manifest(
        release["source"], target_dir=release["target"], role="admin"
    )
    assert result["ok"] is True
    assert result["checked_apps"] == ["admin"]


# --------------------------------------------------------------------------- #
# 拒绝路径（fail-closed）
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("mode", ["other_key", "mangled"])
def test_tampered_signature_is_rejected(release, mode):
    source = release["source"]
    raw = (source / integrity.MANIFEST_NAME).read_bytes()
    if mode == "other_key":
        other_private, _other_public = offline.generate_keypair()
        signature = offline.sign_message(other_private, raw)
    else:
        signature = "A" * len((source / integrity.SIGNATURE_NAME).read_text().strip())
    (source / integrity.SIGNATURE_NAME).write_text(signature, encoding="ascii")

    result = _repair(release)

    assert result["ok"] is False
    assert result["code"] == "signature_invalid"
    assert not (release["target"] / integrity.MANIFEST_NAME).exists()
    assert not (release["target"] / integrity.SIGNATURE_NAME).exists()
    assert not (release["target"] / integrity.REPAIR_LOG_NAME).exists()


def test_tampered_exe_is_rejected(release):
    (release["target"] / APP_FILES["verification"]).write_bytes(b"tampered")

    result = _repair(release)

    assert result["ok"] is False
    assert result["code"] == "hash_mismatch"
    assert APP_FILES["verification"] in result["detail"]
    assert not (release["target"] / integrity.MANIFEST_NAME).exists()
    assert not (release["target"] / integrity.REPAIR_LOG_NAME).exists()


def test_missing_exe_is_rejected(release):
    (release["target"] / APP_FILES["verification"]).unlink()

    result = _repair(release)

    assert result["ok"] is False
    assert result["code"] == "exe_missing"
    assert not (release["target"] / integrity.MANIFEST_NAME).exists()


def test_broken_source_manifest_is_rejected(release):
    (release["source"] / integrity.MANIFEST_NAME).write_bytes(b"{not json")

    result = _repair(release)

    assert result["ok"] is False
    assert result["code"] == "manifest_invalid"
    assert not (release["target"] / integrity.MANIFEST_NAME).exists()


def test_manifest_path_outside_target_is_rejected(release):
    manifest = dict(release["manifest"])
    apps = {name: dict(entry) for name, entry in manifest["apps"].items()}
    apps["verification"]["path"] = "../evil.exe"
    manifest["apps"] = apps
    _write_source(release["source"], manifest, release["private_key"])
    (release["tmp_path"] / "evil.exe").write_bytes(b"payload::verification::v1")

    result = _repair(release)

    assert result["ok"] is False
    assert result["code"] == "manifest_invalid"
    assert not (release["target"] / integrity.MANIFEST_NAME).exists()


def test_verification_standalone_behaviour_is_unchanged(release):
    """修复被拒绝后，验证端“无清单无签名即独立运行”的行为不变。"""
    (release["target"] / APP_FILES["verification"]).unlink()
    assert _repair(release)["ok"] is False

    check = integrity.run_self_check(
        "verification",
        app_dir=release["target"],
        public_key_hex=release["public_key"],
        force=True,
    )
    assert check["ok"] is True
    assert check["skipped"] is True
    assert [issue["code"] for issue in check["issues"]] == ["standalone_mode"]


# --------------------------------------------------------------------------- #
# CLI 通道
# --------------------------------------------------------------------------- #
def test_run_repair_cli_without_flag_continues(release):
    assert integrity.run_repair_cli("verification", argv=["--headless"]) is None
    assert not (release["target"] / integrity.MANIFEST_NAME).exists()


def test_run_repair_cli_success_prints_and_exits_zero(
    release, monkeypatch, capsys
):
    monkeypatch.setattr(integrity, "_default_app_dir", lambda: release["target"])
    monkeypatch.setattr(
        integrity, "load_release_public_key", lambda: release["public_key"]
    )

    code = integrity.run_repair_cli(
        "verification", argv=["--repair-manifest", str(release["source"])]
    )

    assert code == 0
    output = capsys.readouterr().out
    assert "清单修复成功" in output
    assert (release["target"] / integrity.MANIFEST_NAME).is_file()
    assert (release["target"] / integrity.REPAIR_LOG_NAME).is_file()


def test_run_repair_cli_failure_prints_reason_and_exits_one(
    release, monkeypatch, capsys
):
    monkeypatch.setattr(integrity, "_default_app_dir", lambda: release["target"])
    monkeypatch.setattr(
        integrity, "load_release_public_key", lambda: release["public_key"]
    )
    (release["target"] / APP_FILES["verification"]).write_bytes(b"tampered")

    code = integrity.run_repair_cli(
        "verification", argv=["--repair-manifest", str(release["source"])]
    )

    assert code == 1
    captured = capsys.readouterr()
    assert "清单修复失败" in captured.err
    assert "hash_mismatch" in captured.err
    assert not (release["target"] / integrity.MANIFEST_NAME).exists()


def test_run_repair_cli_rejects_empty_path(monkeypatch, capsys):
    code = integrity.run_repair_cli("verification", argv=["--repair-manifest", ""])
    assert code == 1
    assert "清单修复失败" in capsys.readouterr().err
