import ctypes
import hashlib
import os
import platform
import uuid


def _registry_machine_guid() -> str:
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        ) as key:
            value, _ = winreg.QueryValueEx(key, "MachineGuid")
            return str(value)
    except Exception:
        return ""


def _volume_serial() -> str:
    try:
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        serial = wintypes.DWORD(0)
        root = os.environ.get("SystemDrive", "C:") + "\\"
        ok = kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(root),
            None,
            0,
            ctypes.byref(serial),
            None,
            None,
            None,
            0,
        )
        if ok:
            return f"{serial.value:08X}"
    except Exception:
        pass
    return ""


def _mac_address() -> str:
    try:
        node = uuid.getnode()
    except Exception:
        return ""
    # getnode() fabricates a random 48-bit value with the multicast bit set
    # when it cannot read a real adapter. Feeding that into the fingerprint
    # would hand the same machine a different code on every run, so it is
    # treated as "unknown" instead.
    if (node >> 40) & 1:
        return ""
    return f"{node:012X}"


def raw_fingerprint() -> str:
    parts = [
        _registry_machine_guid(),
        _mac_address(),
        _volume_serial(),
        platform.processor() or platform.machine(),
    ]
    return "|".join(p.strip() for p in parts)


def machine_code() -> str:
    digest = hashlib.sha256(raw_fingerprint().encode("utf-8")).hexdigest().upper()
    short = digest[:20]
    return "-".join(short[i : i + 5] for i in range(0, 20, 5))


def device_name() -> str:
    return platform.node() or os.environ.get("COMPUTERNAME", "unknown")


def system_info() -> dict:
    return {
        "device_name": device_name(),
        "platform": platform.platform(),
        "processor": platform.processor() or platform.machine(),
        "machine_code": machine_code(),
    }


# --------------------------------------------------------------------------- #
# 分量指纹与"同机硬件变更"容错（B4）
# --------------------------------------------------------------------------- #
_COMPONENT_SALT = "sq-fp-component-v1:"


def fingerprint_components() -> dict:
    """各指纹因子的独立哈希（供服务端容错判定；无法从哈希还原原值）。"""
    factors = {
        "guid": _registry_machine_guid(),
        "vol": _volume_serial(),
        "mac": _mac_address(),
        "cpu": platform.processor() or platform.machine(),
    }
    out: dict = {}
    for name, value in factors.items():
        text = str(value or "").strip()
        out[name] = (
            hashlib.sha256((_COMPONENT_SALT + name + ":" + text).encode("utf-8"))
            .hexdigest()[:16]
            if text
            else ""
        )
    return out


def same_machine_by_components(new_components, old_components) -> bool:
    """容错判定：设备满员时，判断"新硬件码"是否来自同一台机器的硬件变更。

    保守规则（任一侧缺分量指纹即视为新设备，不做置换）：

    - 主板标识（guid）一致，且 磁盘/网卡/CPU 至少一项一致；或
    - 磁盘标识（vol）一致，且 网卡与 CPU 两项都一致。

    该判定仅用于"把旧绑定置换为新机器码"（不新增占用、不触发克隆风控），
    不改变"设备位已满"本身的安全语义。
    """
    if not isinstance(new_components, dict) or not isinstance(old_components, dict):
        return False

    def get(data: dict, key: str) -> str:
        return str(data.get(key) or "").strip()

    def other_hits() -> int:
        return sum(
            1
            for key in ("mac", "cpu")
            if get(new_components, key)
            and get(new_components, key) == get(old_components, key)
        )

    n_guid, o_guid = get(new_components, "guid"), get(old_components, "guid")
    if n_guid and o_guid and n_guid == o_guid and other_hits() >= 1:
        return True
    n_vol, o_vol = get(new_components, "vol"), get(old_components, "vol")
    if n_vol and o_vol and n_vol == o_vol and other_hits() >= 2:
        return True
    return False
