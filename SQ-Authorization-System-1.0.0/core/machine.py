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
