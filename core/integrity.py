"""客户端发布完整性自检（C1 批次 B）。

实现 ``docs/INTEGRITY-INTERFACE.md`` 第 3 节冻结的接口：发布清单/签名读取校验、
按角色的 ``run_self_check``、最近一次结果缓存以及启动门禁 ``run_startup_gate``。

开发模式（未冻结且未设置 ``SQ_FORCE_INTEGRITY=1``）整体跳过，保证源码运行零摩擦；
冻结产物则强制校验，失败时按契约弹窗、尽力上报并 ``SystemExit(1)``。

BUGFIX 批次（问题三/四）在此基础上补充：

- 读取 ``core.release_identity.RELEASE_ID``，与清单 ``release_id`` 比对，
  不一致记 ``release_mismatch`` 并判失败（内嵌值为空时跳过绑定校验）；
- 结果新增 ``release_id``、``manifest_sha256`` 字段；
- ``verification`` 角色在清单与签名文件都不存在时进入 standalone 模式，
  返回 ``skipped=True`` 且不弹窗、不退出（文件存在即按正常流程严格校验）。

合题批次 C 追加 ``repair_manifest`` 与 ``run_repair_cli``：清单被同步工具改坏
或缺失时，可用 ``--repair-manifest <可信副本目录>`` 导入签名清单修复本程序
目录；签名不对或 exe 哈希与清单不一致时拒绝修复（fail-closed）。
"""

import argparse
import copy
import hashlib
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from .config import APP_VERSION, ROLES

MANIFEST_NAME = "release_manifest.json"
SIGNATURE_NAME = "release_manifest.sig"
MANIFEST_FORMAT = "sq-release-manifest-v1"

CLIENT_ROLES = ("admin", "master", "verification")
DEFAULT_EXE_NAMES = {
    "server": "本地服务器.exe",
    "admin": "管理端.exe",
    "master": "主控端.exe",
    "verification": "验证端.exe",
}

_HASH_CHUNK = 1024 * 1024
_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
REPAIR_LOG_NAME = "integrity_repair.log"

_last_result: dict | None = None


# --------------------------------------------------------------------------- #
# 基础工具
# --------------------------------------------------------------------------- #
def _issue(code: str, file: str = "", detail: str = "") -> dict:
    return {"code": str(code or ""), "file": str(file or ""), "detail": str(detail or "")}


def _app_entry(apps, name: str) -> dict | None:
    """按角色名取清单条目（大小写不敏感）。"""
    if not isinstance(apps, dict):
        return None
    entry = apps.get(name)
    if not isinstance(entry, dict):
        entry = apps.get(str(name or "").strip().lower())
    return entry if isinstance(entry, dict) else None


def _app_path(base: Path, entry: dict | None) -> Path:
    raw = ""
    if isinstance(entry, dict):
        raw = str(entry.get("path") or "").strip()
    if not raw:
        return base
    path = Path(raw)
    return path if path.is_absolute() else base / path


def _path_keys(value) -> set[str]:
    """文件路径的忽略大小写比较键（同时保留全路径与文件名）。"""
    text = str(value or "").strip().replace("\\", "/")
    if not text:
        return set()
    try:
        name = Path(text).name
    except (OSError, ValueError):
        name = text
    return {text.casefold(), name.casefold()}


def _normalize_extension(value) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    return text if text.startswith(".") else f".{text}"


def _default_app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def _resolve_exe_path(role: str, app_dir: Path, manifest: dict | None, exe_path=None) -> Path:
    """本程序可执行文件位置：显式参数 > 冻结时的 sys.executable > 清单/角色默认名。"""
    if exe_path:
        path = Path(exe_path)
        return path if path.is_absolute() else app_dir / path
    if getattr(sys, "frozen", False):
        return Path(sys.executable)
    name = DEFAULT_EXE_NAMES.get(role, f"{role}.exe")
    if isinstance(manifest, dict):
        entry = _app_entry(manifest.get("apps"), role)
        if isinstance(entry, dict) and str(entry.get("path") or "").strip():
            name = str(entry.get("path")).strip()
    return _app_path(app_dir, {"path": name})


def _file_fingerprint(path: Path) -> tuple[str, int]:
    try:
        size = int(path.stat().st_size)
        digest = sha256_file(path)
    except OSError:
        return "", 0
    return digest, size


def _entry_mismatch(entry: dict, actual_hash: str, actual_size: int) -> str:
    """返回不一致说明；一致时返回空串。"""
    expected_hash = str(entry.get("sha256") or "").strip().lower()
    try:
        expected_size = int(entry.get("size") or 0)
    except (TypeError, ValueError):
        expected_size = 0
    if expected_size and actual_size != expected_size:
        return f"文件大小不一致：清单 {expected_size}，实际 {actual_size}"
    if expected_hash and actual_hash != expected_hash:
        return f"哈希不一致：清单 {expected_hash}，实际 {actual_hash or '（无法读取）'}"
    return ""


# --------------------------------------------------------------------------- #
# 契约第 3 节导出接口
# --------------------------------------------------------------------------- #
def sha256_file(path) -> str:
    """分块计算文件 sha256（不整文件读入内存）。"""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(_HASH_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_release_public_key() -> str:
    """读取 ``core.release_pubkey.RELEASE_PUBLIC_KEY_HEX``；缺失或为空时返回空串。"""
    module = None
    try:
        from . import release_pubkey as module
    except Exception:
        module = None
    if module is None:
        try:
            import importlib

            module = importlib.import_module("core.release_pubkey")
        except Exception:
            return ""
    try:
        value = str(getattr(module, "RELEASE_PUBLIC_KEY_HEX", "") or "").strip()
    except Exception:
        return ""
    return value


def load_release_id() -> str:
    """读取 ``core.release_identity.RELEASE_ID``；模块缺失或为空时返回空串。

    发布标识由 ``build.py`` 在打包前生成（32 位 hex），源码运行/开发模式下
    通常不存在该模块，此时必须保持空串以跳过 release 绑定校验。
    """
    try:
        import importlib

        module = importlib.import_module(
            ".release_identity", __package__ or "core"
        )
    except Exception:
        return ""
    try:
        value = str(getattr(module, "RELEASE_ID", "") or "").strip()
    except Exception:
        return ""
    return value


def verify_manifest_signature(manifest_bytes: bytes, signature_text: str, public_key_hex: str) -> bool:
    """校验清单原始字节的 Ed25519 签名（base64url 无填充文本）。"""
    if not isinstance(manifest_bytes, (bytes, bytearray)) or not manifest_bytes:
        return False
    key = str(public_key_hex or "").strip()
    signature = "".join(str(signature_text or "").split())
    if not key or not signature:
        return False
    try:
        from . import offline
    except Exception:
        return False
    try:
        return bool(offline.verify_message(key, bytes(manifest_bytes), signature))
    except Exception:
        return False


def read_and_verify_manifest(app_dir, public_key_hex=None) -> tuple[dict | None, list[dict]]:
    """读取并验签发布清单。

    成功返回 ``(manifest, [])``；任何失败返回 ``(None, [issue...])``。
    ``public_key_hex`` 为空时回退到 ``load_release_public_key()``。
    """
    base = Path(app_dir).resolve() if app_dir else _default_app_dir()
    try:
        manifest_bytes = (base / MANIFEST_NAME).read_bytes()
    except OSError:
        return None, [_issue("manifest_missing", MANIFEST_NAME, "未找到发布清单文件")]
    try:
        signature_text = (base / SIGNATURE_NAME).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None, [_issue("manifest_missing", SIGNATURE_NAME, "未找到发布清单签名文件")]
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError):
        return None, [_issue("manifest_invalid", MANIFEST_NAME, "发布清单不是有效的 JSON")]
    if not isinstance(manifest, dict) or manifest.get("format") != MANIFEST_FORMAT:
        return None, [_issue("manifest_invalid", MANIFEST_NAME, "发布清单格式标识不正确")]
    key = str(public_key_hex or "").strip() or load_release_public_key()
    if not key:
        return None, [_issue("release_key_missing", "", "未配置发布公钥，无法校验发布清单")]
    if not verify_manifest_signature(manifest_bytes, signature_text, key):
        return None, [_issue("signature_invalid", SIGNATURE_NAME, "发布清单签名校验失败")]
    return manifest, []


def repair_manifest(
    source_dir,
    *,
    target_dir=None,
    role=None,
    public_key_hex=None,
) -> dict:
    """从 ``source_dir`` 导入已签名的发布清单，修复目标目录（P1-9 修复通道）。

    通道是 fail-closed 的：只有 ``source_dir`` 里的清单用内嵌发布公钥验签通过，
    且清单中“当前程序对应的 app”（``server`` 角色为全部 ``required_apps``）与
    目标目录现有 exe 的 sha256/size 全部一致时，才会把清单与签名原子写回目标
    目录并追加 ``integrity_repair.log``；任何一步失败都不触碰目标目录的清单。

    ``source_dir`` 是可信副本（发布包根目录）；``target_dir`` 默认取当前程序
    所在目录，``role`` 默认按当前可执行文件名推断（推断不出时按 ``server``
    口径要求全部 ``required_apps`` 匹配）。
    """
    base = {
        "ok": False,
        "code": "",
        "detail": "",
        "role": "",
        "source_dir": "",
        "target_dir": "",
        "version": "",
        "release_id": "",
        "manifest_sha256": "",
        "checked_apps": [],
        "written": [],
        "log_path": "",
        "log_written": False,
    }
    if not str(source_dir or "").strip():
        return _repair_failed(base, "manifest_missing", "未提供修复源目录")

    source = Path(str(source_dir)).expanduser()
    target = Path(target_dir).expanduser() if target_dir else _default_app_dir()
    role_value = str(role or "").strip().lower()
    base.update(source_dir=str(source), target_dir=str(target), role=role_value)

    manifest_path = source / MANIFEST_NAME
    signature_path = source / SIGNATURE_NAME
    try:
        manifest_bytes = manifest_path.read_bytes()
    except OSError:
        return _repair_failed(
            base, "manifest_missing", f"未找到发布清单文件：{manifest_path}"
        )
    try:
        signature_bytes = signature_path.read_bytes()
    except OSError:
        return _repair_failed(
            base, "manifest_missing", f"未找到发布清单签名文件：{signature_path}"
        )
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError):
        return _repair_failed(base, "manifest_invalid", "发布清单不是有效的 JSON")
    if not isinstance(manifest, dict) or manifest.get("format") != MANIFEST_FORMAT:
        return _repair_failed(base, "manifest_invalid", "发布清单格式标识不正确")

    key = str(public_key_hex or "").strip() or load_release_public_key()
    if not key:
        return _repair_failed(base, "release_key_missing", "未配置发布公钥，无法校验发布清单")
    signature_text = signature_bytes.decode("utf-8", errors="replace")
    if not verify_manifest_signature(manifest_bytes, signature_text, key):
        return _repair_failed(
            base, "signature_invalid", f"发布清单签名校验失败：{signature_path}"
        )

    apps = manifest.get("apps")
    if not isinstance(apps, dict) or not apps:
        return _repair_failed(base, "manifest_invalid", "发布清单缺少 apps 登记")

    if not role_value:
        role_value = _infer_role_from_executable() or _role_for_current_exe(manifest)
    base["role"] = role_value
    names, problem = _repair_app_names(role_value, manifest)
    if problem is not None:
        return _repair_failed(
            base,
            str(problem.get("code") or "missing_file"),
            str(problem.get("detail") or "发布清单缺少当前程序的登记"),
        )

    checked: list[str] = []
    for name in names:
        entry = _app_entry(apps, name)
        if not isinstance(entry, dict):
            return _repair_failed(
                base, "missing_file", f"发布清单缺少角色 {name} 的登记"
            )
        path = _app_path(target, entry)
        if not _inside_dir(target, path):
            return _repair_failed(
                base,
                "manifest_invalid",
                f"清单登记的文件路径越出程序目录：{entry.get('path')}",
            )
        if not path.is_file():
            return _repair_failed(
                base,
                "exe_missing",
                f"目标目录缺少 {name} 对应的可执行文件：{path.name or path}",
            )
        actual_hash, actual_size = _file_fingerprint(path)
        detail = _entry_mismatch(entry, actual_hash, actual_size)
        if detail:
            return _repair_failed(
                base, "hash_mismatch", f"{path.name} 与清单不一致：{detail}"
            )
        checked.append(name)

    try:
        written = _write_manifest_pair(target, manifest_bytes, signature_bytes)
    except OSError as exc:
        return _repair_failed(base, "target_unwritable", f"写回 {target} 失败：{exc}")

    base.update(
        ok=True,
        code="",
        detail=f"清单修复完成，已校验 {len(checked)} 个可执行文件",
        version=str(manifest.get("version") or ""),
        release_id=_manifest_release_id(manifest),
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        checked_apps=list(checked),
        written=[str(path) for path in written],
    )
    base["log_written"] = _write_repair_log(
        target,
        {
            "repaired_at": datetime.now().strftime(_TIME_FORMAT),
            "role": role_value,
            "source_dir": str(source),
            "version": base["version"],
            "release_id": base["release_id"],
            "manifest_sha256": base["manifest_sha256"],
            "checked_apps": list(checked),
            "written": [str(path) for path in written],
        },
    )
    return base


def run_self_check(
    role: str,
    app_dir=None,
    public_key_hex=None,
    force: bool = False,
    exe_path=None,
) -> dict:
    """按契约执行一次完整性自检并缓存结果。

    开发模式（未冻结且未设置 ``SQ_FORCE_INTEGRITY=1``）整体跳过，
    返回 ``ok=True``、``skipped=True``、``issues=[skip_dev_mode]``。
    ``verification`` 角色在发布清单与签名文件都不存在时进入 standalone：
    ``ok=True``、``skipped=True``、``issues=[standalone_mode]``，允许独立运行；
    只要其中一个文件存在，就必须按正常流程校验，失败仍判失败。
    """
    role_value = str(role or "").strip().lower()
    if role_value not in ROLES:
        raise ValueError(f"未知程序角色：{role}")
    base = Path(app_dir).resolve() if app_dir else _default_app_dir()
    frozen = bool(getattr(sys, "frozen", False))
    forced = bool(force) or os.environ.get("SQ_FORCE_INTEGRITY") == "1"

    if not frozen and not forced:
        target = _resolve_exe_path(role_value, base, None, exe_path)
        result = _make_result(
            role=role_value,
            ok=True,
            skipped=True,
            exe_path=target,
            exe_hash="",
            exe_size=0,
            version=APP_VERSION,
            manifest_verified=False,
            release_id=load_release_id(),
            manifest_sha256=_manifest_digest(base),
            issues=[_issue("skip_dev_mode", "", "开发模式，已跳过完整性自检")],
        )
        set_last_result(result)
        return result

    embedded_release_id = load_release_id()
    manifest_bytes = _read_file_bytes(base / MANIFEST_NAME)
    manifest_sha256 = (
        hashlib.sha256(manifest_bytes).hexdigest() if manifest_bytes is not None else ""
    )

    if role_value == "verification" and _is_standalone_release(base, manifest_bytes):
        target = _resolve_exe_path(role_value, base, None, exe_path)
        exe_hash = ""
        exe_size = 0
        if target.is_file():
            exe_hash, exe_size = _file_fingerprint(target)
        result = _make_result(
            role=role_value,
            ok=True,
            skipped=True,
            exe_path=target,
            exe_hash=exe_hash,
            exe_size=exe_size,
            version=APP_VERSION,
            manifest_verified=False,
            release_id=embedded_release_id,
            manifest_sha256="",
            issues=[
                _issue(
                    "standalone_mode",
                    "",
                    "未找到发布清单与签名文件，按独立运行模式启动",
                )
            ],
        )
        set_last_result(result)
        return result

    manifest, issues = read_and_verify_manifest(base, public_key_hex)
    manifest_verified = isinstance(manifest, dict)
    manifest_release_id = _manifest_release_id(manifest, manifest_bytes)
    release_id = embedded_release_id or manifest_release_id
    # 只有内嵌值与清单值都存在时才做绑定校验：开发模式/无 release_id 直接跳过。
    if (
        embedded_release_id
        and manifest_release_id
        and embedded_release_id.casefold() != manifest_release_id.casefold()
    ):
        issues.append(
            _issue(
                "release_mismatch",
                MANIFEST_NAME,
                f"发布标识不一致：程序内嵌 {embedded_release_id}，清单 {manifest_release_id}",
            )
        )
    target = _resolve_exe_path(role_value, base, manifest, exe_path)
    version = str((manifest or {}).get("version") or APP_VERSION)

    exe_hash = ""
    exe_size = 0
    if target.is_file():
        exe_hash, exe_size = _file_fingerprint(target)

    if manifest_verified:
        _check_manifest_files(role_value, base, target, manifest, exe_hash, exe_size, issues)

    result = _make_result(
        role=role_value,
        ok=not issues,
        skipped=False,
        exe_path=target,
        exe_hash=exe_hash,
        exe_size=exe_size,
        version=version,
        manifest_verified=manifest_verified,
        release_id=release_id,
        manifest_sha256=manifest_sha256,
        issues=issues,
    )
    set_last_result(result)
    return result


def get_last_result() -> dict | None:
    return copy.deepcopy(_last_result) if isinstance(_last_result, dict) else None


def set_last_result(result: dict | None) -> None:
    global _last_result
    _last_result = copy.deepcopy(result) if isinstance(result, dict) else None


def run_startup_gate(role: str, *, gui: bool | None = None) -> dict:
    """启动门禁。

    开发模式直接返回 skipped 结果（不弹窗不退出）；
    冻结且失败时弹窗（``gui=False`` 或 ``SQ_INTEGRITY_NO_POPUP=1`` 时改为只写 stderr）、
    客户端角色尽力上报 ``report_integrity_failure``，最后 ``SystemExit(1)``。
    """
    role_value = str(role or "").strip().lower()
    result = run_self_check(role_value)
    set_last_result(result)
    if result.get("skipped") or result.get("ok"):
        return result
    _notify_failure(role_value, result, gui=gui)
    raise SystemExit(1)


def print_repair_result(result: dict) -> int:
    """打印 ``repair_manifest`` 的结果并返回进程退出码（0 成功 / 1 失败）。"""
    if isinstance(result, dict) and result.get("ok"):
        target = str(result.get("target_dir") or "")
        version = str(result.get("version") or "未标注")
        release_id = str(result.get("release_id") or "未标注")
        count = len(result.get("checked_apps") or [])
        print(
            f"清单修复成功：已写回 {target} 下的 {MANIFEST_NAME} 与 {SIGNATURE_NAME}"
            f"（版本 {version}，release_id {release_id}，校验 {count} 个可执行文件）。"
        )
        print(f"修复日志：{result.get('log_path')}")
        return 0
    code = str((result or {}).get("code") or "unknown")
    detail = str((result or {}).get("detail") or "未提供原因")
    print(f"清单修复失败（{code}）：{detail}", file=sys.stderr)
    return 1


def run_repair_cli(role: str, argv=None) -> int | None:
    """处理 ``--repair-manifest <目录>``：返回退出码，未提供该参数时返回 ``None``。

    各入口必须在 ``run_startup_gate`` **之前** 调用：门禁在清单损坏时会直接
    ``SystemExit(1)``，修复通道就没有机会执行。参数解析刻意忽略未知参数，
    避免影响 Qt 自身的命令行开关。
    """
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "--repair-manifest", dest="repair_manifest", metavar="目录", default=None
    )
    namespace, _unknown = parser.parse_known_args(
        list(argv) if argv is not None else None
    )
    source = namespace.repair_manifest
    if source is None:
        return None
    return print_repair_result(repair_manifest(source, role=role))


# --------------------------------------------------------------------------- #
# 内部实现
# --------------------------------------------------------------------------- #
def _read_file_bytes(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except OSError:
        return None


def _manifest_digest(base: Path) -> str:
    """manifest 文件原始字节的 sha256；文件缺失/不可读时返回空串。"""
    data = _read_file_bytes(base / MANIFEST_NAME)
    return hashlib.sha256(data).hexdigest() if data is not None else ""


def _manifest_release_id(manifest, raw_bytes=None) -> str:
    """清单里的 release_id：优先取已解析清单，否则尽力从原始字节解析。"""
    value = None
    if isinstance(manifest, dict):
        value = manifest.get("release_id")
    elif isinstance(raw_bytes, (bytes, bytearray)):
        try:
            parsed = json.loads(bytes(raw_bytes).decode("utf-8-sig"))
        except (UnicodeDecodeError, ValueError):
            return ""
        if isinstance(parsed, dict):
            value = parsed.get("release_id")
    return str(value or "").strip()


def _is_standalone_release(base: Path, manifest_bytes: bytes | None) -> bool:
    """verification 角色专用：清单与签名文件都不存在才算独立运行。"""
    if manifest_bytes is not None:
        return False
    try:
        return not (base / SIGNATURE_NAME).exists()
    except OSError:
        return False


def _repair_failed(base: dict, code: str, detail: str) -> dict:
    result = dict(base)
    result["ok"] = False
    result["code"] = str(code or "")
    result["detail"] = str(detail or "")
    return result


def _infer_role_from_executable() -> str:
    """按当前可执行文件名推断角色；非冻结运行或名字陌生时返回空串。"""
    if not getattr(sys, "frozen", False):
        return ""
    try:
        name = Path(sys.executable).name.casefold()
    except (OSError, ValueError):
        return ""
    for role_name, exe_name in DEFAULT_EXE_NAMES.items():
        if exe_name.casefold() == name:
            return role_name
    return ""


def _role_for_current_exe(manifest: dict) -> str:
    """清单里哪个 app 的 path 指向当前可执行文件（用于非默认文件名）。"""
    if not getattr(sys, "frozen", False):
        return ""
    try:
        wanted = Path(sys.executable).name.casefold()
    except (OSError, ValueError):
        return ""
    apps = manifest.get("apps") if isinstance(manifest.get("apps"), dict) else {}
    for name, entry in apps.items():
        if not isinstance(entry, dict):
            continue
        raw = str(entry.get("path") or "").strip()
        if not raw:
            continue
        try:
            candidate = Path(raw).name.casefold()
        except (OSError, ValueError):
            continue
        if candidate == wanted:
            return str(name or "").strip().lower()
    return ""


def _repair_app_names(role: str, manifest: dict) -> tuple[list[str], dict | None]:
    """修复时要与目标目录 exe 逐一比对的 app 名单。

    ``server``（以及角色推断失败时）按全部 ``required_apps`` 比对；其它客户端
    角色只强制“当前程序对应的 app”，与 ``run_self_check`` 的门禁口径一致。
    """
    apps = manifest.get("apps") if isinstance(manifest.get("apps"), dict) else {}
    folder = manifest.get("folder") if isinstance(manifest.get("folder"), dict) else {}
    role_value = str(role or "").strip().lower()
    if role_value == "server" or not role_value:
        required = folder.get("required_apps")
        names = [str(item).strip() for item in required] if isinstance(required, list) else []
        names = [name for name in names if name]
        if not names:
            names = [str(name) for name in apps]
        if not names:
            return [], _issue("manifest_invalid", MANIFEST_NAME, "发布清单没有可校验的 app 登记")
        return names, None
    if _app_entry(apps, role_value) is None:
        return [], _issue(
            "missing_file", role_value, f"发布清单缺少角色 {role_value} 的登记"
        )
    return [role_value], None


def _inside_dir(base: Path, candidate: Path) -> bool:
    """清单登记的文件必须落在目标目录内（拒绝 ../ 越权路径）。"""
    try:
        resolved_base = base.resolve()
        resolved = candidate.resolve()
    except OSError:
        return False
    return resolved == resolved_base or resolved_base in resolved.parents


def _tmp_sibling(path: Path) -> Path:
    return path.with_name(f".{path.name}.repair-{os.getpid()}.tmp")


def _write_bytes_sync(path: Path, data: bytes) -> None:
    with path.open("wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _write_manifest_pair(
    target: Path, manifest_bytes: bytes, signature_bytes: bytes
) -> list[Path]:
    """把清单与签名成对原子写回目标目录。

    两份临时文件先落盘并 fsync，再依次 ``os.replace``；第二次替换失败时回滚
    第一次的结果，避免留下“新清单 + 旧签名”的半成品（那会直接判签名失败）。
    """
    manifest_path = target / MANIFEST_NAME
    signature_path = target / SIGNATURE_NAME
    tmp_manifest = _tmp_sibling(manifest_path)
    tmp_signature = _tmp_sibling(signature_path)
    backups: dict[Path, bytes | None] = {}
    try:
        _write_bytes_sync(tmp_manifest, manifest_bytes)
        _write_bytes_sync(tmp_signature, signature_bytes)
        for path in (manifest_path, signature_path):
            backups[path] = _read_file_bytes(path)
        os.replace(tmp_manifest, manifest_path)
        try:
            os.replace(tmp_signature, signature_path)
        except OSError:
            _restore_file(manifest_path, backups.get(manifest_path))
            raise
    finally:
        for tmp in (tmp_manifest, tmp_signature):
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass
    return [manifest_path, signature_path]


def _restore_file(path: Path, data: bytes | None) -> None:
    """尽力恢复替换前的文件；原本不存在时删除新文件。失败时保持现状。"""
    try:
        if data is None:
            path.unlink(missing_ok=True)
            return
        tmp = _tmp_sibling(path)
        try:
            _write_bytes_sync(tmp, data)
            os.replace(tmp, path)
        finally:
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass
    except OSError:
        pass


def _write_repair_log(target: Path, record: dict) -> bool:
    """在目标目录追加一条修复记录；写日志失败不影响修复结论。"""
    try:
        with (target / REPAIR_LOG_NAME).open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
            )
        return True
    except Exception:
        return False


def _make_result(
    *,
    role: str,
    ok: bool,
    skipped: bool,
    exe_path,
    exe_hash: str,
    exe_size: int,
    version: str,
    manifest_verified: bool,
    release_id: str = "",
    manifest_sha256: str = "",
    issues: list[dict],
) -> dict:
    path = Path(exe_path) if exe_path else None
    return {
        "ok": bool(ok),
        "skipped": bool(skipped),
        "role": role,
        "exe_name": path.name if path else "",
        "exe_path": str(path) if path else "",
        "exe_hash": str(exe_hash or ""),
        "exe_size": int(exe_size or 0),
        "version": str(version or ""),
        "release_id": str(release_id or "").strip(),
        "manifest_sha256": str(manifest_sha256 or "").strip().lower(),
        "manifest_verified": bool(manifest_verified),
        "checked_at": datetime.now().strftime(_TIME_FORMAT),
        "issues": [dict(issue) for issue in issues],
    }


def _check_manifest_files(
    role: str,
    base: Path,
    target: Path,
    manifest: dict,
    exe_hash: str,
    exe_size: int,
    issues: list[dict],
) -> None:
    apps = manifest.get("apps") if isinstance(manifest.get("apps"), dict) else {}
    folder = manifest.get("folder") if isinstance(manifest.get("folder"), dict) else {}

    # 本程序：必须存在且哈希/大小一致。
    own = _app_entry(apps, role)
    if not target.is_file():
        issues.append(_issue("exe_missing", target.name, "未找到本程序可执行文件"))
    elif not isinstance(own, dict):
        issues.append(_issue("missing_file", target.name, f"发布清单缺少角色 {role} 的登记"))
    else:
        detail = _entry_mismatch(own, exe_hash, exe_size)
        if detail:
            issues.append(_issue("hash_mismatch", target.name, detail))

    if role == "server":
        # 服务端要求 required_apps 全部存在且一致。
        required = folder.get("required_apps")
        required_names = [str(item) for item in required] if isinstance(required, list) else []
        for name in required_names:
            entry = _app_entry(apps, name)
            if not isinstance(entry, dict):
                issues.append(_issue("missing_file", name, f"发布清单缺少角色 {name} 的登记"))
                continue
            other = _app_path(base, entry)
            if not other.is_file():
                issues.append(_issue("missing_file", other.name, f"发布清单要求 {name} 必须存在"))
                continue
            other_hash, other_size = _file_fingerprint(other)
            detail = _entry_mismatch(entry, other_hash, other_size)
            if detail:
                issues.append(_issue("hash_mismatch", other.name, detail))
    else:
        # 其它角色只强制自己；清单里其它 app 若存在也必须一致。
        for name, entry in apps.items():
            if str(name or "").strip().lower() == role or not isinstance(entry, dict):
                continue
            other = _app_path(base, entry)
            if not other.is_file():
                continue
            other_hash, other_size = _file_fingerprint(other)
            detail = _entry_mismatch(entry, other_hash, other_size)
            if detail:
                issues.append(_issue("hash_mismatch", other.name, detail))

    _check_extra_files(base, apps, folder, issues)


def _check_extra_files(base: Path, apps: dict, folder: dict, issues: list[dict]) -> None:
    """app_dir 顶层（不递归）的受保护扩展名文件必须已在清单登记。"""
    guarded = {
        ext
        for ext in (_normalize_extension(item) for item in (folder.get("guarded_extensions") or []))
        if ext
    }
    if not guarded:
        return
    exempt: set[str] = set()
    for item in folder.get("exempt_files") or []:
        exempt |= _path_keys(item)
    registered: set[str] = set()
    for entry in apps.values():
        if isinstance(entry, dict):
            registered |= _path_keys(entry.get("path"))
    try:
        candidates = sorted(base.iterdir(), key=lambda path: path.name.casefold())
    except OSError:
        return
    for item in candidates:
        try:
            if not item.is_file():
                continue
        except OSError:
            continue
        if item.suffix.lower() not in guarded:
            continue
        key = item.name.casefold()
        if key in registered or key in exempt:
            continue
        issues.append(_issue("extra_file", item.name, "该文件不在发布清单登记范围内"))


def _gate_message(result: dict) -> str:
    lines = ["本程序未通过完整性自检，已停止启动。"]
    issues = result.get("issues") if isinstance(result.get("issues"), list) else []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        code = str(issue.get("code") or "")
        file = str(issue.get("file") or "")
        detail = str(issue.get("detail") or "")
        lines.append(f"- {code} {file} {detail}".rstrip())
    if len(lines) == 1:
        lines.append("- 未提供更多信息")
    lines.append("")
    lines.append(
        "如为文件同步或杀软误改，请从发布包恢复 release_manifest.json 与 "
        "release_manifest.sig 后重试。"
    )
    lines.append("诊断信息：程序目录下 integrity_tamper.log 与 crash_logs/。")
    return "\n".join(lines)


def _notify_failure(role: str, result: dict, *, gui: bool | None = None) -> None:
    message = _gate_message(result)
    try:
        print(message, file=sys.stderr)
    except Exception:
        pass
    _write_local_tamper_log(result)
    if gui is not False and os.environ.get("SQ_INTEGRITY_NO_POPUP") != "1":
        try:
            from PySide6.QtWidgets import QApplication, QMessageBox

            app = QApplication.instance() or QApplication([])
            QMessageBox.critical(None, "完整性校验失败", message)
        except Exception:
            # 弹窗失败绝不能改变门禁结论（仍然退出）。
            pass
    if role in CLIENT_ROLES:
        try:
            _report_integrity_failure(role, result)
        except Exception:
            pass


def _write_local_tamper_log(result: dict) -> None:
    """在程序目录追加一条本地篡改记录。

    窗口版 exe 没有控制台，stderr 看不到；本地日志是弹窗之外唯一的本机留痕。
    目录不可写时静默跳过，绝不能改变门禁结论。
    """
    try:
        exe_path = str(result.get("exe_path") or "").strip()
        base = Path(exe_path).resolve().parent if exe_path else _default_app_dir()
        record = {
            "checked_at": str(result.get("checked_at") or ""),
            "role": str(result.get("role") or ""),
            "exe_name": str(result.get("exe_name") or ""),
            "exe_hash": str(result.get("exe_hash") or ""),
            "issues": result.get("issues") if isinstance(result.get("issues"), list) else [],
        }
        with (base / "integrity_tamper.log").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
    except Exception:
        pass


def _report_integrity_failure(role: str, result: dict) -> None:
    """尽力把失败结果上报给服务器（任何异常都被调用方吞掉）。"""
    from .api_client import ApiClient
    from .config import get_config

    config = get_config(role)
    client_config = config.client if isinstance(config.client, dict) else {}
    client = ApiClient(
        config.server_url(),
        int(client_config.get("timeout", 8) or 8),
        allow_insecure_http=bool(client_config.get("allow_insecure_http", False)),
        response_public_key=str(client_config.get("response_public_key") or ""),
        response_key_id=str(client_config.get("response_key_id") or ""),
    )
    client.set_trusted_public_keys(
        str(client_config.get("offline_public_key") or ""),
        str(client_config.get("response_public_key") or ""),
        str(client_config.get("response_key_id") or ""),
    )
    client.set_integrity_result(result)
    issues = result.get("issues") if isinstance(result.get("issues"), list) else []
    reason = ""
    if issues and isinstance(issues[0], dict):
        reason = str(issues[0].get("code") or "")
    client.report_integrity_failure(
        reason or "integrity_failed",
        {
            "issues": issues,
            "checked_at": str(result.get("checked_at") or ""),
            "manifest_verified": bool(result.get("manifest_verified")),
        },
    )
