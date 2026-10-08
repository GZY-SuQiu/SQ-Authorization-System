import shutil
import subprocess
import sys
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"
BUILD = ROOT / "build"
ASSETS = ROOT / "assets"
ICON = ASSETS / "icon" / "sq.ico"
RELEASE_KEYS = ROOT / "release_keys" / "release_key.json"

# 构建脚本可能从任意 cwd 被调用，先保证项目根可导入。
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
import tools.release_manifest as release_manifest  # noqa: E402
from core.config import APP_VERSION  # noqa: E402

RELEASE_VERSION = APP_VERSION

CORE_MODULES = [
    "core",
    "core.config",
    "core.security",
    "core.machine",
    "core.database",
    "core.api_client",
    "core.offline",
    "core.theme",
    "core.widgets",
    "core.shell",
    "core.pages",
    "core.integrity",
    "core.release_pubkey",
    "core.secret_store",
]

SERVER_MODULES = [
    "uvicorn",
    "cryptography",
    "cryptography.hazmat.primitives.asymmetric.ed25519",
    "uvicorn.logging",
    "uvicorn.loops",
    "uvicorn.loops.auto",
    "uvicorn.loops.asyncio",
    "uvicorn.protocols",
    "uvicorn.protocols.http",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.websockets",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan",
    "uvicorn.lifespan.on",
    "fastapi",
    "starlette",
    "starlette.middleware.cors",
    "pydantic",
    "anyio",
    "h11",
    "click",
    "server.mailer",
    "server.alerting",
    "server.risk",
    "server.channels",
]

TARGETS = [
    {
        "name": "本地服务器",
        "script": "server/main.py",
        "hidden": CORE_MODULES + SERVER_MODULES + ["server", "server.api", "server.ui"],
        "console": True,
    },
    {
        "name": "管理端",
        "script": "admin/main.py",
        "hidden": CORE_MODULES + ["admin", "admin.ui"],
        "console": False,
    },
    {
        "name": "验证端",
        "script": "verification/main.py",
        "hidden": CORE_MODULES + ["verification", "verification.ui"],
        "console": False,
    },
    {
        "name": "主控端",
        "script": "master/main.py",
        "hidden": CORE_MODULES + ["master", "master.ui"],
        "console": False,
    },
]


def build_target(target: dict) -> None:
    print(f"\n==== 正在打包 {target['name']}.exe ====")
    if not ICON.exists():
        raise SystemExit(
            f"缺少应用图标 {ICON}，请先运行 python tools/make_icon.py"
        )
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--paths",
        str(ROOT),
        "--name",
        target["name"],
        # The SQ mark: --icon stamps the executable itself, --add-data keeps
        # a copy inside the bundle so the running window can set it too.
        "--icon",
        str(ICON),
        "--add-data",
        f"{ASSETS}{os.pathsep}assets",
        "--distpath",
        str(DIST),
        "--workpath",
        str(BUILD),
        "--specpath",
        str(BUILD),
        "--collect-submodules",
        "uvicorn",
        "--collect-submodules",
        "cryptography",
        "--hidden-import",
        "cryptography",
        "--hidden-import",
        "cryptography.hazmat.primitives.asymmetric.ed25519",
    ]
    if target["console"]:
        cmd.append("--console")
    else:
        cmd.append("--windowed")
    for module in target["hidden"]:
        cmd += ["--hidden-import", module]
    cmd.append(str(ROOT / target["script"]))
    result = subprocess.run(cmd, cwd=str(ROOT), env=_build_environment())
    if result.returncode != 0:
        raise SystemExit(f"{target['name']} 打包失败（退出码 {result.returncode}）")
    _assert_no_conflicting_icu(DIST / f"{target['name']}.exe")


def _build_environment() -> dict:
    """Keep Windows system DLLs ahead of IDE/bundled runtimes on PATH."""
    env = os.environ.copy()
    if sys.platform != "win32":
        return env

    system_root = Path(env.get("SystemRoot", r"C:\Windows"))
    python_dir = Path(sys.executable).resolve().parent
    preferred = [
        system_root / "System32",
        system_root,
        system_root / "System32" / "Wbem",
        system_root / "System32" / "WindowsPowerShell" / "v1.0",
        python_dir,
        python_dir / "Scripts",
    ]
    ordered: list[str] = []
    seen: set[str] = set()
    for entry in preferred + env.get("PATH", "").split(os.pathsep):
        value = str(entry).strip()
        if not value:
            continue
        key = value.casefold()
        if key in seen:
            continue
        seen.add(key)
        ordered.append(value)
    env["PATH"] = os.pathsep.join(ordered)
    return env


def _assert_no_conflicting_icu(exe: Path) -> None:
    """Fail the build if a third-party ICU DLL can shadow the Windows runtime."""
    from PyInstaller.archive.readers import CArchiveReader

    blocked = {"icuuc.dll", "icudt78.dll"}
    archive = CArchiveReader(str(exe))
    conflicting = sorted(
        name for name in archive.toc if Path(name).name.casefold() in blocked
    )
    if conflicting:
        raise SystemExit(
            f"{exe.name} 打包产物包含冲突 ICU DLL：{', '.join(conflicting)}"
        )


def main() -> int:
    if shutil.which("pyinstaller") is None and not _has_module("PyInstaller"):
        print("未检测到 PyInstaller，请先执行：pip install pyinstaller")
        return 1

    DIST.mkdir(exist_ok=True)
    BUILD.mkdir(exist_ok=True)

    # 打包前固定发布公钥，让 PyInstaller 把公钥编进四个 exe。
    release_id = ""
    try:
        keys = release_manifest.ensure_keypair(RELEASE_KEYS)
        release_manifest.write_pubkey_module(keys["public_key"])
        release_id = release_manifest.new_release_id()
        release_manifest.write_release_identity(release_id)
    except Exception as exc:
        print(f"错误：生成发布密钥/公钥模块失败：{exc}")
        return 1

    for target in TARGETS:
        build_target(target)

    # 打包完成后对四个 exe 生成清单并做 Ed25519 签名。
    try:
        written = release_manifest.write_signed_manifest(
            DIST, RELEASE_VERSION, keys_path=RELEASE_KEYS, release_id=release_id
        )
    except Exception as exc:
        print(f"错误：生成发布清单/签名失败：{exc}")
        return 1

    # 对外只分发 dist/release_package：dist/ 会积累运行配置、数据库与备份，
    # 里面包含服务器私钥与开发数据，绝不能整目录交付。
    try:
        package = release_manifest.assemble_release_package(DIST)
        problems = release_manifest.verify_release_package(package)
    except Exception as exc:
        print(f"错误：生成干净发布包失败：{exc}")
        return 1
    if problems:
        print("错误：发布包卫生检查未通过：")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    print("\n==== 打包完成，产物位于 dist 目录 ====")
    for target in TARGETS:
        exe = DIST / f"{target['name']}.exe"
        if exe.exists():
            size = exe.stat().st_size / 1024 / 1024
            print(f"· {exe.name}  ({size:.1f} MB)")
    print(f"发布清单：{written['manifest']}")
    print(f"清单签名：{written['signature']}")
    print(f"副本目录：{written['manifest'].parent / 'releases'}")
    print(f"公钥指纹：{written['fingerprint']}")
    print(f"发布标识：{written['release_id']}")
    print(f"对外分发目录：{package}")
    return 0


def _has_module(name: str) -> bool:
    import importlib.util

    return importlib.util.find_spec(name) is not None


if __name__ == "__main__":
    raise SystemExit(main())
