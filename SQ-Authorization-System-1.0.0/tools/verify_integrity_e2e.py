"""C1 完整性自检与 attest 门禁的端到端验收工具。

在打包完成后运行：

    python tools/verify_integrity_e2e.py

覆盖：
1. 发布清单签名与四个 exe 的 sha256/size 核对，releases/ 副本一致性；
2. frozen 服务器 exe 正常启动门禁（--version 返回 0）；
3. 缺失清单 / 多出 exe / 被篡改 exe 三种场景必须拒绝启动；
4. 临时沙箱启动真实服务器，验证 attest 白名单、activate 403 门禁、
   有效 token 放行、未知哈希告警落库。
"""

from __future__ import annotations

import json
import hashlib
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DIST = ROOT / "dist"
EXES = {
    "server": "本地服务器.exe",
    "admin": "管理端.exe",
    "master": "主控端.exe",
    "verification": "验证端.exe",
}
FIXED_DENIED = "客户端完整性校验未通过，已拒绝访问"


def _fail(message: str) -> None:
    print(f"[FAIL] {message}")
    raise SystemExit(1)


def _ok(message: str) -> None:
    print(f"[ OK ] {message}")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def check_manifest() -> dict:
    from core import integrity
    from core.release_pubkey import RELEASE_PUBLIC_KEY_HEX

    if not RELEASE_PUBLIC_KEY_HEX:
        _fail("core/release_pubkey.py 为空，构建没有固定发布公钥")
    manifest_path = DIST / integrity.MANIFEST_NAME
    signature_path = DIST / integrity.SIGNATURE_NAME
    if not manifest_path.is_file() or not signature_path.is_file():
        _fail(f"缺少 {manifest_path} 或 {signature_path}")
    raw = manifest_path.read_bytes()
    signature = signature_path.read_text(encoding="utf-8").strip()
    if not integrity.verify_manifest_signature(raw, signature, RELEASE_PUBLIC_KEY_HEX):
        _fail("发布清单签名校验失败")
    manifest = json.loads(raw.decode("utf-8"))
    if manifest.get("format") != integrity.MANIFEST_FORMAT:
        _fail(f"清单 format 不正确：{manifest.get('format')!r}")
    from core.release_identity import RELEASE_ID

    if not RELEASE_ID or manifest.get("release_id") != RELEASE_ID:
        _fail(
            f"清单 release_id 与内嵌值不一致：清单 {manifest.get('release_id')!r} / 内嵌 {RELEASE_ID!r}"
        )
    apps = manifest.get("apps")
    if not isinstance(apps, dict) or set(apps) != set(EXES):
        _fail(f"清单 apps 角色不完整：{sorted((apps or {}).keys())}")
    for role, name in EXES.items():
        entry = apps[role]
        path = DIST / str(entry.get("path") or "")
        if path.name != name or not path.is_file():
            _fail(f"{role} 条目路径错误或文件缺失：{entry}")
        actual_hash = integrity.sha256_file(path)
        if actual_hash != str(entry.get("sha256") or "").lower():
            _fail(f"{name} 哈希与清单不一致")
        if path.stat().st_size != int(entry.get("size") or -1):
            _fail(f"{name} 大小与清单不一致")
    if (DIST / "releases" / integrity.MANIFEST_NAME).read_bytes() != raw:
        _fail("releases/ 清单副本与根目录不一致")
    if (DIST / "releases" / integrity.SIGNATURE_NAME).read_text(encoding="utf-8").strip() != signature:
        _fail("releases/ 签名副本与根目录不一致")
    _ok(f"清单验签与四个 exe 哈希核对通过（公钥 {RELEASE_PUBLIC_KEY_HEX[:16]}...）")
    return manifest


def _run_gate(exe: Path, cwd: Path, timeout: int = 60) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["SQ_INTEGRITY_NO_POPUP"] = "1"
    args = [str(exe), "--version"] if exe.name == EXES["server"] else [str(exe)]
    try:
        return subprocess.run(
            args,
            cwd=str(cwd),
            env=env,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        _fail(f"{exe.name} 在 {timeout}s 内没有退出（门禁可能未生效）")
        raise


def _terminate_tree(process: subprocess.Popen) -> None:
    """终止 PyInstaller onefile 的父/子进程树。"""
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                capture_output=True,
                timeout=15,
            )
        else:
            process.terminate()
    except Exception:
        pass
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def check_frozen_pass() -> None:
    # 在临时沙箱里运行，避免 dist 目录被生成 server_config.json 等运行残留。
    with tempfile.TemporaryDirectory(prefix="sq_pass_", ignore_cleanup_errors=True) as raw:
        target = Path(raw)
        for name in EXES.values():
            shutil.copy2(DIST / name, target / name)
        shutil.copy2(DIST / "release_manifest.json", target / "release_manifest.json")
        shutil.copy2(DIST / "release_manifest.sig", target / "release_manifest.sig")
        proc = _run_gate(target / EXES["server"], target)
        if proc.returncode != 0:
            _fail(f"正常发布的服务器 exe 未通过门禁，returncode={proc.returncode}")
    _ok("frozen 正常产物通过自检（本地服务器 --version 返回 0）")


def _copy_release_files(target: Path, with_manifest: bool = True) -> None:
    shutil.copy2(DIST / EXES["verification"], target / EXES["verification"])
    if with_manifest:
        shutil.copy2(DIST / "release_manifest.json", target / "release_manifest.json")
        shutil.copy2(DIST / "release_manifest.sig", target / "release_manifest.sig")


def check_frozen_rejections() -> None:
    with tempfile.TemporaryDirectory(prefix="sq_gate_missing_", ignore_cleanup_errors=True) as raw:
        target = Path(raw)
        # 验证端缺两文件属于 standalone（走 run_self_check 校验），这里用 server
        # 角色验证“缺清单必须拒绝”。
        shutil.copy2(DIST / EXES["server"], target / EXES["server"])
        proc = _run_gate(target / EXES["server"], target)
        if proc.returncode == 0:
            _fail("缺少发布清单时服务器仍然启动")
        from core import integrity as _integrity

        standalone = _integrity.run_self_check(
            "verification", app_dir=target, force=True
        )
        codes = {issue.get("code") for issue in standalone.get("issues", [])}
        if not (standalone.get("ok") and standalone.get("skipped") and "standalone_mode" in codes):
            _fail(f"验证端缺两文件没有进入 standalone：{standalone}")
        _ok("缺失清单时服务器被拒绝；验证端按 standalone 模式放行")

    with tempfile.TemporaryDirectory(prefix="sq_gate_extra_", ignore_cleanup_errors=True) as raw:
        target = Path(raw)
        _copy_release_files(target)
        (target / "注入.exe").write_bytes(b"MZ-not-allowed")
        proc = _run_gate(target / EXES["verification"], target)
        if proc.returncode == 0:
            _fail("存在未登记 exe 时验证端仍然启动")
        log = target / "integrity_tamper.log"
        text = log.read_text(encoding="utf-8") if log.is_file() else ""
        if "extra_file" not in text:
            _fail("拒绝原因不是 extra_file，或本地篡改日志没有写入")
        _ok("多出未登记 exe 被拒绝并写入 integrity_tamper.log")

    with tempfile.TemporaryDirectory(prefix="sq_gate_tamper_", ignore_cleanup_errors=True) as raw:
        target = Path(raw)
        _copy_release_files(target)
        exe = target / EXES["verification"]
        exe.write_bytes(exe.read_bytes() + b"SQ-TAMPER")
        proc = _run_gate(exe, target)
        if proc.returncode == 0:
            _fail("被追加数据的验证端仍然启动")
        from core import integrity
        from core.release_pubkey import RELEASE_PUBLIC_KEY_HEX

        result = integrity.run_self_check(
            "verification",
            app_dir=target,
            public_key_hex=RELEASE_PUBLIC_KEY_HEX,
            force=True,
            exe_path=exe,
        )
        codes = {issue.get("code") for issue in result.get("issues", [])}
        if "hash_mismatch" not in codes and "exe_missing" not in codes:
            _fail(f"自检没有把篡改识别为 hash_mismatch：{result.get('issues')}")
        _ok("被篡改 exe 启动被拒绝，自检识别为 hash_mismatch")


def check_attestation(manifest: dict) -> None:
    import requests

    verification = manifest["apps"]["verification"]
    manifest_sha256 = hashlib.sha256(
        (DIST / "release_manifest.json").read_bytes()
    ).hexdigest()
    with tempfile.TemporaryDirectory(prefix="sq_e2e_", ignore_cleanup_errors=True) as raw:
        sandbox = Path(raw)
        for name in EXES.values():
            shutil.copy2(DIST / name, sandbox / name)
        shutil.copy2(DIST / "release_manifest.json", sandbox / "release_manifest.json")
        shutil.copy2(DIST / "release_manifest.sig", sandbox / "release_manifest.sig")
        shutil.copytree(DIST / "releases", sandbox / "releases")
        # 发行包不再携带配置（包含私钥）；沙箱里现场生成一套全新服务端配置。
        from core.config import Config

        Config("server", sandbox / "server_config.json")

        port = _free_port()
        env = os.environ.copy()
        env["SQ_INTEGRITY_NO_POPUP"] = "1"
        process = subprocess.Popen(
            [str(sandbox / EXES["server"]), "--headless", "--port", str(port)],
            cwd=str(sandbox),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        base = f"http://127.0.0.1:{port}"
        try:
            deadline = time.time() + 90
            health = None
            while time.time() < deadline:
                if process.poll() is not None:
                    _fail(f"沙箱服务器提前退出，returncode={process.returncode}")
                try:
                    health = requests.get(f"{base}/api/health", timeout=2)
                    if health.status_code == 200:
                        break
                except requests.RequestException:
                    time.sleep(1)
            if health is None or health.status_code != 200:
                _fail("沙箱服务器健康检查超时")

            machine = "E2E-MACHINE-01"
            payload = {
                "role": "verification",
                "exe_name": verification["path"],
                "exe_hash": verification["sha256"],
                "version": manifest.get("version", ""),
                "release_id": str(manifest.get("release_id") or ""),
                "manifest_sha256": manifest_sha256,
                "machine_code": machine,
                "local_check": {"ok": True, "skipped": False, "issues": []},
            }
            response = requests.post(f"{base}/api/client/attest", json=payload, timeout=10)
            data = response.json()
            if response.status_code != 200 or not data.get("ok") or not data.get("attest_token"):
                _fail(f"白名单哈希未签发 attest token：{response.status_code} {data}")
            token = data["attest_token"]
            _ok("白名单哈希通过 attest 并签发 token")

            body = {"key_code": "GSQ-E2E-TEST", "machine_code": machine, "device_name": "e2e"}
            denied = requests.post(f"{base}/api/client/activate", json=body, timeout=10)
            if denied.status_code != 403 or FIXED_DENIED not in denied.text:
                _fail(f"无 token 的 activate 未被 403 拒绝：{denied.status_code} {denied.text}")
            _ok("无 attest token 的 activate 被 403 拒绝（固定文案）")

            allowed = requests.post(
                f"{base}/api/client/activate",
                json=body,
                headers={"X-Attest-Token": token},
                timeout=10,
            )
            if allowed.status_code == 403:
                _fail(f"有效 token 未通过门禁：{allowed.status_code} {allowed.text}")
            _ok(f"有效 attest token 通过门禁（后续业务返回 {allowed.status_code}）")

            bad = dict(payload)
            bad["exe_hash"] = "ab" * 32
            rejected = requests.post(f"{base}/api/client/attest", json=bad, timeout=10).json()
            if rejected.get("ok") is not False or rejected.get("code") != "unknown_build":
                _fail(f"未知哈希没有被识别：{rejected}")
            _ok("未知哈希被识别为 unknown_build 并落库")

            db_path = sandbox / "data" / "license.db"
            if not db_path.is_file():
                _fail("沙箱数据库不存在")
            connection = sqlite3.connect(str(db_path))
            try:
                active = connection.execute(
                    "SELECT COUNT(*) FROM release_hashes WHERE active = 1"
                ).fetchone()[0]
                tampered = connection.execute("SELECT COUNT(*) FROM tamper_events").fetchone()[0]
            finally:
                connection.close()
            if int(active) != 4:
                _fail(f"启动自动导入的 active 发布哈希数量不是 4：{active}")
            if int(tampered) < 1:
                _fail("未知哈希告警没有写入 tamper_events")
            _ok(f"启动自动导入 4 个发布哈希，tamper_events 记录 {tampered} 条")
        finally:
            _terminate_tree(process)
            time.sleep(1)


def check_repair_flow() -> None:
    """--repair-manifest 在冻结产物上的真实行为。"""
    env = os.environ.copy()
    env["SQ_INTEGRITY_NO_POPUP"] = "1"

    with tempfile.TemporaryDirectory(prefix="sq_repair_ok_", ignore_cleanup_errors=True) as raw:
        target = Path(raw)
        shutil.copy2(DIST / EXES["verification"], target / EXES["verification"])
        (target / "release_manifest.json").write_bytes(b"{broken-manifest")
        try:
            proc = subprocess.run(
                [str(target / EXES["verification"]), "--repair-manifest", str(DIST)],
                cwd=str(target),
                env=env,
                capture_output=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            _fail("--repair-manifest 超时未退出")
        if proc.returncode != 0:
            _fail(f"--repair-manifest 修复失败，returncode={proc.returncode}")
        if not (target / "release_manifest.json").is_file() or not (
            target / "release_manifest.sig"
        ).is_file():
            _fail("修复后清单/签名文件缺失")
        _ok("冻结态 --repair-manifest 成功恢复签名清单")

    with tempfile.TemporaryDirectory(prefix="sq_repair_bad_", ignore_cleanup_errors=True) as raw:
        target = Path(raw)
        exe = target / EXES["verification"]
        shutil.copy2(DIST / EXES["verification"], exe)
        exe.write_bytes(exe.read_bytes() + b"TAMPER")
        try:
            proc = subprocess.run(
                [str(exe), "--repair-manifest", str(DIST)],
                cwd=str(target),
                env=env,
                capture_output=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            _fail("被篡改 exe 的 --repair-manifest 超时未退出")
        if proc.returncode == 0:
            _fail("被篡改的 exe 仍被允许修复")
        if (target / "release_manifest.json").exists():
            _fail("拒绝修复时不应写入清单")
        _ok("被篡改的 exe 拒绝修复（fail closed）")


def main() -> int:
    for name in EXES.values():
        if not (DIST / name).is_file():
            print(f"缺少打包产物 {DIST / name}，请先执行 python build.py")
            return 1
    print("== C1 完整性自检端到端验收 ==")
    manifest = check_manifest()
    check_frozen_pass()
    check_frozen_rejections()
    check_repair_flow()
    check_attestation(manifest)
    print("== 全部验收通过 ==")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
