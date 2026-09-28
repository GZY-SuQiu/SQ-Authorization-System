import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"
BUILD = ROOT / "build"

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
]

SERVER_MODULES = [
    "uvicorn",
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
        "--distpath",
        str(DIST),
        "--workpath",
        str(BUILD),
        "--specpath",
        str(BUILD),
        "--collect-submodules",
        "uvicorn",
    ]
    if target["console"]:
        cmd.append("--console")
    else:
        cmd.append("--windowed")
    for module in target["hidden"]:
        cmd += ["--hidden-import", module]
    cmd.append(str(ROOT / target["script"]))
    result = subprocess.run(cmd, cwd=str(ROOT))
    if result.returncode != 0:
        raise SystemExit(f"{target['name']} 打包失败（退出码 {result.returncode}）")


def main() -> int:
    if shutil.which("pyinstaller") is None and not _has_module("PyInstaller"):
        print("未检测到 PyInstaller，请先执行：pip install pyinstaller")
        return 1

    DIST.mkdir(exist_ok=True)
    BUILD.mkdir(exist_ok=True)

    for target in TARGETS:
        build_target(target)

    print("\n==== 打包完成，产物位于 dist 目录 ====")
    for target in TARGETS:
        exe = DIST / f"{target['name']}.exe"
        if exe.exists():
            size = exe.stat().st_size / 1024 / 1024
            print(f"· {exe.name}  ({size:.1f} MB)")
    return 0


def _has_module(name: str) -> bool:
    import importlib.util

    return importlib.util.find_spec(name) is not None


if __name__ == "__main__":
    raise SystemExit(main())
