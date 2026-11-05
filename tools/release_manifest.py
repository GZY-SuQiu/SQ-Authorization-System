"""发布清单与 Ed25519 签名工具。

- `release_keys/release_key.json`：发布私钥（32 字节种子，hex）+ 公钥，只保存在构建机。
- `core/release_pubkey.py`：由本工具写入的生成物，打包时被 PyInstaller 固定进 exe。
- `dist/release_manifest.json` / `dist/release_manifest.sig`：清单及其 Ed25519 签名，
  同时在 `dist/releases/` 保留一份同样的副本。

可以直接调用（构建流程使用），也可以单独重新生成：

    python -m tools.release_manifest --dist dist --version 1.0.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.offline import generate_keypair, public_from_private, public_key_fingerprint, sign_message
from core.security import now_str

MANIFEST_NAME = "release_manifest.json"
SIGNATURE_NAME = "release_manifest.sig"
MANIFEST_FORMAT = "sq-release-manifest-v1"
DEFAULT_KEY_PATH = ROOT / "release_keys" / "release_key.json"
PUBKEY_MODULE_PATH = ROOT / "core" / "release_pubkey.py"
IDENTITY_MODULE_PATH = ROOT / "core" / "release_identity.py"

# app 角色 -> 打包产物文件名。顺序即清单中 apps 的书写顺序。
RELEASE_APPS: list[tuple[str, str]] = [
    ("server", "本地服务器.exe"),
    ("admin", "管理端.exe"),
    ("master", "主控端.exe"),
    ("verification", "验证端.exe"),
]

GUARDED_EXTENSIONS = [".exe", ".dll"]
EXEMPT_FILES = [MANIFEST_NAME, SIGNATURE_NAME]
REQUIRED_APPS = ["server", "admin", "master", "verification"]

_HARDENED_PATHS: set[str] = set()


def sha256_file(path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _harden_permissions(path: Path) -> None:
    """尽力把密钥文件/目录收紧到当前用户（参考 core/config.py）。"""
    try:
        path.chmod(0o600)
    except OSError:
        pass
    if os.name != "nt":
        return
    key = str(path).casefold()
    if key in _HARDENED_PATHS:
        return
    user = os.environ.get("USERNAME", "").strip() or os.environ.get("USER", "").strip()
    if not user:
        return
    try:
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
            check=False,
            capture_output=True,
            timeout=10,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return
    _HARDENED_PATHS.add(key)


def _write_bytes_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    try:
        with open(tmp, "wb") as handle:
            handle.write(data)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def ensure_keypair(keys_path=DEFAULT_KEY_PATH) -> dict:
    """确保发布密钥对存在并返回 {"private_key", "public_key", "created_at"}。

    已存在且合法的密钥对原样返回；文件损坏时直接报错，绝不静默轮换密钥——
    否则已经打包出去的 exe 会因为公钥变化而全部校验失败。
    """
    path = Path(keys_path)
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise RuntimeError(f"发布密钥文件损坏，无法读取：{path}（{exc}）") from exc
        if not isinstance(data, dict):
            raise RuntimeError(f"发布密钥文件格式错误：{path}（应为 JSON 对象）")
        private_hex = str(data.get("private_key") or "").strip().lower()
        public_hex = str(data.get("public_key") or "").strip().lower()
        if len(private_hex) != 64 or len(public_hex) != 64:
            raise RuntimeError(
                f"发布密钥文件不完整：{path}（private_key/public_key 必须是 64 位 hex）"
            )
        try:
            derived = public_from_private(private_hex)
        except ValueError as exc:
            raise RuntimeError(f"发布私钥无法解析：{path}（{exc}）") from exc
        if derived != public_hex:
            raise RuntimeError(f"发布密钥文件公私钥不匹配：{path}")
        return {
            "private_key": private_hex,
            "public_key": public_hex,
            "created_at": str(data.get("created_at") or now_str()),
        }

    private_hex, public_hex = generate_keypair()
    data = {
        "private_key": private_hex,
        "public_key": public_hex,
        "created_at": now_str(),
    }
    _write_bytes_atomic(
        path,
        json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8"),
    )
    _harden_permissions(path)
    _harden_permissions(path.parent)
    return data


def write_pubkey_module(public_hex: str, path=PUBKEY_MODULE_PATH) -> Path:
    """把发布公钥写进 core/release_pubkey.py（生成物，不要手工编辑）。"""
    target = Path(path)
    content = f'RELEASE_PUBLIC_KEY_HEX = "{str(public_hex or "").strip().lower()}"\n'
    _write_bytes_atomic(target, content.encode("utf-8"))
    return target


def new_release_id() -> str:
    """Generate a fresh 32-hex release id for one build run."""
    return secrets.token_hex(16)


def read_release_id(path=IDENTITY_MODULE_PATH) -> str:
    """Read the release id embedded in ``core/release_identity.py``."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        return ""
    match = re.search(r'RELEASE_ID\s*=\s*"([0-9a-fA-F]*)"', text)
    return match.group(1).strip().lower() if match else ""


def write_release_identity(release_id: str, path=IDENTITY_MODULE_PATH) -> Path:
    """Write the generated release identity module (never hand-edited)."""
    target = Path(path)
    content = f'RELEASE_ID = "{str(release_id or "").strip().lower()}"\n'
    _write_bytes_atomic(target, content.encode("utf-8"))
    return target


def build_manifest(dist_dir, version: str = "", apps=None, release_id: str = "") -> dict:
    """按冻结契约对 dist 下四个 exe 计算 sha256/size，返回 manifest dict。"""
    dist = Path(dist_dir)
    app_paths = dict(RELEASE_APPS)
    if apps:
        overrides = dict(apps)
        for role in app_paths:
            if role in overrides:
                app_paths[role] = str(overrides[role])

    entries: dict[str, dict] = {}
    missing: list[str] = []
    for role, default_name in RELEASE_APPS:
        rel_path = app_paths.get(role, default_name)
        full_path = dist / rel_path
        if not rel_path or not full_path.is_file():
            missing.append(f"{role} ({rel_path or '未指定路径'})")
            continue
        entries[role] = {
            "path": rel_path,
            "sha256": sha256_file(full_path),
            "size": full_path.stat().st_size,
        }
    if missing:
        raise FileNotFoundError(
            "dist 目录缺少待签名产物：" + "、".join(missing) + f"（dist={dist}）"
        )

    return {
        "format": MANIFEST_FORMAT,
        "version": str(version or "").strip(),
        "release_id": str(release_id or "").strip().lower(),
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "apps": entries,
        "folder": {
            "guarded_extensions": list(GUARDED_EXTENSIONS),
            "exempt_files": list(EXEMPT_FILES),
            "required_apps": list(REQUIRED_APPS),
        },
    }


def manifest_bytes(manifest: dict) -> bytes:
    """清单的规范字节：UTF-8 无 BOM + 2 空格缩进（签名对象就是这些字节）。"""
    return json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")


def write_signed_manifest(
    dist_dir, version: str = "", apps=None, keys_path=None, release_id=None
) -> dict:
    """生成清单与签名，写入 dist 根目录和 dist/releases/，返回写入的路径。"""
    dist = Path(dist_dir)
    keys_path = Path(keys_path) if keys_path else DEFAULT_KEY_PATH
    keys = ensure_keypair(keys_path)
    private_hex = str(keys["private_key"]).strip().lower()
    public_hex = public_from_private(private_hex)
    if public_hex != str(keys["public_key"]).strip().lower():
        raise RuntimeError(f"发布密钥文件公私钥不匹配：{keys_path}")

    if release_id is None:
        release_id = read_release_id()
    manifest = build_manifest(dist, version, apps=apps, release_id=release_id)
    raw = manifest_bytes(manifest)
    signature = sign_message(private_hex, raw)

    releases = dist / "releases"
    written = {
        "manifest": dist / MANIFEST_NAME,
        "signature": dist / SIGNATURE_NAME,
        "releases_manifest": releases / MANIFEST_NAME,
        "releases_signature": releases / SIGNATURE_NAME,
        "public_key": public_hex,
        "fingerprint": public_key_fingerprint(public_hex),
        "release_id": str(release_id or "").strip().lower(),
    }
    for path in (
        written["manifest"],
        written["signature"],
        written["releases_manifest"],
        written["releases_signature"],
    ):
        _write_bytes_atomic(path, raw if path.name == MANIFEST_NAME else signature.encode("ascii"))
    return written


def assemble_release_package(dist_dir, package_name: str = "release_package") -> Path:
    """Build a clean distribution folder with exes + signed manifest only.

    ``dist/`` accumulates runtime files (configs, database, backups) when the
    exes are launched in place. Shipping that folder would leak private keys
    and development data, so the deliverable is this dedicated package.
    """
    dist = Path(dist_dir)
    package = dist / package_name
    if package.exists():
        shutil.rmtree(package)
    (package / "releases").mkdir(parents=True, exist_ok=True)
    for _role, name in RELEASE_APPS:
        source = dist / name
        if not source.is_file():
            raise FileNotFoundError(f"缺少打包产物：{source}")
        shutil.copy2(source, package / name)
    for name in (MANIFEST_NAME, SIGNATURE_NAME):
        shutil.copy2(dist / name, package / name)
        releases_source = dist / "releases" / name
        if releases_source.is_file():
            shutil.copy2(releases_source, package / "releases" / name)
    return package


def verify_release_package(package_dir) -> list[str]:
    """Return hygiene problems (private keys / database / configs) in a package."""
    package = Path(package_dir)
    problems: list[str] = []
    for path in package.rglob("*"):
        if not path.is_file():
            continue
        name = path.name.lower()
        if name.endswith("_config.json") or name == "config.json":
            problems.append(f"包含运行配置：{path}")
            continue
        if name.endswith(".db") or name.endswith(".db-wal") or name.endswith(".db-shm"):
            problems.append(f"包含数据库文件：{path}")
            continue
        if name == "release_key.json" or name.endswith(".key") or name.endswith(".pem"):
            problems.append(f"包含私钥文件：{path}")
            continue
        if path.suffix.lower() in (".json", ".txt", ".py", ".env"):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if any(
                marker in text
                for marker in (
                    '"private_key"',
                    "private_key =",
                    "secret_key",
                    "BEGIN PRIVATE KEY",
                )
            ):
                problems.append(f"包含疑似密钥内容：{path}")
    return problems


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m tools.release_manifest",
        description="生成发布清单 release_manifest.json 与 Ed25519 签名 release_manifest.sig",
    )
    parser.add_argument("--dist", default=str(ROOT / "dist"), help="打包产物目录（默认 dist）")
    parser.add_argument("--version", default="", help="版本号，例如 1.0.0")
    parser.add_argument(
        "--keys",
        default=str(DEFAULT_KEY_PATH),
        help=f"发布密钥文件（默认 {DEFAULT_KEY_PATH}）",
    )
    parser.add_argument(
        "--release-id",
        default="",
        help="发布标识；默认读取 core/release_identity.py（保证与已打包 exe 内嵌值一致）",
    )
    args = parser.parse_args(argv)

    dist = Path(args.dist).resolve()
    if not dist.is_dir():
        print(f"错误：目录不存在 {dist}", file=sys.stderr)
        return 1
    try:
        release_id = str(args.release_id or "").strip().lower() or read_release_id()
        written = write_signed_manifest(
            dist, args.version, keys_path=Path(args.keys), release_id=release_id
        )
    except Exception as exc:
        print(f"错误：生成发布清单失败：{exc}", file=sys.stderr)
        return 1

    print(f"发布清单：{written['manifest']}")
    print(f"清单签名：{written['signature']}")
    print(f"副本目录：{written['manifest'].parent / 'releases'}")
    print(f"公钥指纹：{written['fingerprint']}")
    print(f"发布标识：{written['release_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
