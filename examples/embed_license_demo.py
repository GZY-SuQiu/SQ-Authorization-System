"""SQ 授权系统 Python SDK 嵌入示例（命令行可运行）。

用法示例::

    # 固定响应公钥（生产环境必须这样用）
    python examples/embed_license_demo.py ^
        --server https://license.example.com ^
        --public-key <64位hex响应公钥> ^
        --key GSQ-XXXXX-XXXXX-XXXXX-XXXXX

    # 本机联调：未提供 --public-key 时临时从服务器 /api/public_key 获取
    python examples/embed_license_demo.py --server http://127.0.0.1:8765 ^
        --key GSQ-XXXXX-XXXXX-XXXXX-XXXXX --device-name 设计工作站

    # 纯离线校验激活码（需先固定离线公钥）
    python examples/embed_license_demo.py --server http://127.0.0.1:8765 ^
        --offline-code "LICACT1.xxx.yyy" --offline-public-key <64位hex离线公钥>

退出码：0 成功；1 业务失败（密钥无效/离线码无效）；2 参数或网络/验签错误。
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# 允许直接 `python examples/embed_license_demo.py` 运行（脚本目录不是仓库根）。
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests

from sdk import LicenseClient, LicenseError, LicenseSignatureError


def fetch_response_key(server_url: str, timeout: int = 8) -> tuple[str, str]:
    """演示用：从 ``/api/public_key`` 获取响应公钥与密钥标识。

    生产环境必须把公钥写死在调用方代码里；这里仅用于本机联调。
    """
    url = server_url.rstrip("/") + "/api/public_key"
    response = requests.get(url, timeout=timeout, allow_redirects=False)
    response.raise_for_status()
    data = response.json()
    return (
        str(data.get("response_public_key") or ""),
        str(data.get("response_key_id") or ""),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python examples/embed_license_demo.py",
        description="SQ 授权系统 Python SDK 嵌入示例",
    )
    parser.add_argument("--server", default="http://127.0.0.1:8765", help="服务器地址")
    parser.add_argument("--key", default="", help="许可证密钥（激活/校验用）")
    parser.add_argument("--public-key", default="", help="服务器响应公钥（64 位 hex）")
    parser.add_argument("--key-id", default="", help="服务器响应密钥标识（可选）")
    parser.add_argument("--machine-code", default="", help="显式机器码（默认取本机）")
    parser.add_argument("--device-name", default="", help="设备名称（激活时可选）")
    parser.add_argument("--timeout", type=int, default=8, help="请求超时秒数")
    parser.add_argument(
        "--allow-insecure-http",
        action="store_true",
        help="允许远程 http（仅内网测试使用）",
    )
    parser.add_argument("--offline-code", default="", help="离线激活码（只做本地校验）")
    parser.add_argument(
        "--offline-public-key", default="", help="离线公钥（64 位 hex，可选）"
    )
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    server_url = str(args.server or "").strip()
    if not server_url:
        print("错误：--server 不能为空", file=sys.stderr)
        return 2

    public_key = str(args.public_key or "").strip()
    key_id = str(args.key_id or "").strip()
    if not public_key:
        print("[警告] 未提供 --public-key，临时从服务器获取；生产环境必须固定公钥。")
        try:
            public_key, fetched_key_id = fetch_response_key(server_url, args.timeout)
            key_id = key_id or fetched_key_id
        except Exception as exc:
            print(f"错误：获取服务器响应公钥失败：{exc}", file=sys.stderr)
            return 2
    if not public_key:
        print("错误：未获取到服务器响应公钥", file=sys.stderr)
        return 2

    try:
        client = LicenseClient(
            server_url,
            public_key,
            key_id,
            timeout=args.timeout,
            allow_insecure_http=bool(args.allow_insecure_http),
        )
        print(f"本机机器码：{client.machine_code()}")

        if args.offline_code:
            if args.offline_public_key:
                client.set_offline_public_key(args.offline_public_key)
            result = client.verify_offline(
                args.offline_code, args.machine_code or None
            )
            print(f"离线码校验：{result.get('code')} - {result.get('message', '')}")
            if result.get("ok"):
                print(f"  密钥：{result.get('key_code')}")
                print(f"  到期：{result.get('expires_at') or '永久'}")
                return 0
            return 1

        if not args.key:
            print("错误：缺少 --key（激活/校验需要）", file=sys.stderr)
            return 2

        activated = client.activate(
            args.key, args.machine_code or None, args.device_name
        )
        print(
            f"激活：{activated.get('code')} - {activated.get('message', '')}"
        )
        if not activated.get("ok"):
            return 1

        verified = client.verify()
        print(f"校验：{verified.get('code')} - {verified.get('message', '')}")
        beat = client.heartbeat()
        print(f"心跳：{beat.get('code')} - {beat.get('message', '')}")
        print(f"is_valid：{client.is_valid()}")
        return 0
    except LicenseSignatureError as exc:
        print(
            f"错误：服务器响应验签失败（{exc.code}），连接可能被篡改：{exc}",
            file=sys.stderr,
        )
        return 2
    except LicenseError as exc:
        print(f"错误：SDK 调用失败（{exc.code}）：{exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
