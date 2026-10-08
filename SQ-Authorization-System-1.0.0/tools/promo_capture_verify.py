"""Capture the 验证端 window for the promo video.

Usage:  python tools/promo_capture_verify.py

Writes 2x PNGs under <workspace>/promo-video/assets/captures/verify/.
Everything runs offline: the offline activation code is signed with a
throwaway RSA key created for the capture, and no port is ever opened.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import promo_capture_common  # noqa: E402,F401  (sets the Qt env first)

from promo_capture_common import CAPTURES, grab, make_app, pump  # noqa: E402

from core import offline  # noqa: E402
from core.config import Config  # noqa: E402
from verification.ui import VerifyWindow  # noqa: E402

WINDOW_SIZE = (1280, 880)
KEY = "GSQ-7K2M-4P9Q-8R3T-6V1W"
MACHINE_CODE = "8F3A21C4D9E07B56"
DEVICE_NAME = "DESIGN-PC-07"


def quiet(*_args, **_kwargs) -> None:
    """Swallow toasts so transient popups never land in a capture."""


def anonymize_device(window) -> None:
    """The promo must not publish this machine's real hardware fingerprint."""
    from PySide6.QtWidgets import QLabel

    window.machine_code = MACHINE_CODE
    window.device_name = DEVICE_NAME
    window.machine_label.setText(MACHINE_CODE)
    for label in window.findChildren(QLabel):
        text = label.text()
        if text.startswith("设备名：") or text.startswith("设备名:"):
            _prefix, _, rest = text.partition("系统：")
            platform = rest.strip() if rest else "Windows 11"
            label.setText(f"设备名：{DEVICE_NAME}    系统：{platform}")


def build_config(tmp: Path) -> tuple[Config, str]:
    """Verification config pinned to a throwaway offline key pair."""
    private_hex, public_hex = offline.generate_keypair()
    config = Config("verification", tmp / "verification_config.json")
    config.client["offline_public_key"] = public_hex
    config.client["response_public_key"] = public_hex
    config.client["response_key_id"] = "promo-offline-2026"
    config.save()
    return config, private_hex


def main() -> int:
    app = make_app()
    with tempfile.TemporaryDirectory(prefix="promo-verify-") as tmpdir:
        tmp = Path(tmpdir)
        config, private_hex = build_config(tmp)

        window = VerifyWindow(config)
        window.resize(*WINDOW_SIZE)
        window.show()
        window.toast.show_message = quiet
        anonymize_device(window)
        pump(500)

        machine_code = window.machine_code
        request_code = offline.make_request_code(machine_code, window.device_name)

        # 01 初始状态 ------------------------------------------------------
        window.request_output.clear()
        window.offline_input.clear()
        window.input_key.clear()
        window._set_result("info", "尚未校验", "点击“校验状态”查看当前授权情况")
        window._set_online("info", "心跳：未开启")
        pump(160)
        grab(window, "verify/01-idle.png")

        # 02 激活成功 ------------------------------------------------------
        window.input_key.setText(KEY)
        window.auto_check.setChecked(True)
        window._set_result(
            "success",
            "激活成功",
            f"密钥：{KEY}    版本：专业版\n"
            "到期时间：2027-10-01 09:41:05    剩余：365 天\n"
            f"本机机器码：{machine_code}    绑定设备：2 / 3 台",
        )
        window._set_online("success", "心跳：已开启 · 30 秒前同步")
        pump(160)
        grab(window, "verify/02-success.png")

        # 03 离线激活 ------------------------------------------------------
        payload = offline.build_activation_payload(
            machine_code=machine_code,
            key_code=KEY,
            edition="professional",
            duration_days=365,
            expires_at="2027-10-01 09:41:05",
            max_devices=3,
            note="华东区客户",
        )
        activation_code = offline.make_activation_code(payload, private_hex)
        config.client["offline_activation"] = activation_code
        config.client["offline_key"] = KEY
        config.save()

        window.request_output.setPlainText(offline.chunk_code(request_code))
        window.offline_input.setPlainText(offline.chunk_code(activation_code))
        window.input_key.setText(KEY)
        window.import_offline()
        pump(200)
        grab(window, "verify/03-offline.png")

        # 04 校验失败 ------------------------------------------------------
        window.offline_input.clear()
        window.input_key.setText("GSQ-1A3C-5E7G-9J1L-3N5P")
        window._set_result(
            "error",
            "授权无效",
            "密钥已吊销：该密钥已被管理员吊销，无法继续使用。\n"
            "到期时间：2126-09-14 09:20:00",
        )
        window._set_online("error", "心跳停止：密钥已吊销")
        pump(160)
        grab(window, "verify/04-revoked.png")

        window.close()

    print(f"captures -> {CAPTURES / 'verify'}")
    return 0


if __name__ == "__main__":
    os.environ.setdefault("PROMO_CAPTURE_SCALE", "2")
    raise SystemExit(main())
