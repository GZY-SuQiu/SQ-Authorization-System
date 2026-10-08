"""P1 风控判定：IP 跳动与硬件码变更（主流程模块）。

策略（第二轮决策）：

- 同一 Key 在窗口内出现超过 2 个不同 IP 网段 -> 告警（不自动封禁）；
- 设备数已满仍出现新硬件码 -> 冻结该 Key + 高等级告警，主控可解冻/换绑；
- 本模块只做判定与落库，邮件通知由 ``server.alerting`` 负责。
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta

from core import security

__all__ = [
    "PERMANENT_FREEZE_UNTIL",
    "client_subnet",
    "record_ip_event",
    "freeze_for_machine_mismatch",
]

# 直接封禁使用远期冻结时间：可逆（主控可解冻），但用户侧等同于封禁。
PERMANENT_FREEZE_UNTIL = "2099-12-31 23:59:59"


def client_subnet(ip: str) -> str:
    """Return a /24 (IPv4) or /48 (IPv6) network string, or '' if invalid."""
    try:
        address = ipaddress.ip_address(str(ip or "").strip())
    except ValueError:
        return ""
    prefix = 24 if address.version == 4 else 48
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def record_ip_event(
    db,
    license: dict | None,
    machine_code: str,
    ip: str,
    *,
    window_minutes: int = 10,
    threshold: int = 2,
) -> dict | None:
    """Record one IP observation; return alert info when subnets exceed threshold."""
    if not license or not ip or str(ip).strip().lower() in ("", "unknown"):
        return None
    subnet = client_subnet(ip)
    if not subnet:
        return None
    try:
        db.add_activation_ip_event(
            int(license.get("id") or 0),
            str(license.get("key_code") or ""),
            str(machine_code or ""),
            str(ip),
            subnet,
        )
    except Exception:
        return None
    since = (datetime.now() - timedelta(minutes=max(1, int(window_minutes)))).strftime(
        security.TIME_FORMAT
    )
    try:
        changes = int(db.count_ip_changes(str(license.get("key_code") or ""), since))
    except Exception:
        return None
    if changes <= max(0, int(threshold)):
        return None
    try:
        db.add_risk_event(
            "ip_jump",
            "warning",
            str(license.get("key_code") or ""),
            str(machine_code or ""),
            str(ip),
            f"{int(window_minutes)} 分钟内出现 {changes} 个不同 IP 网段，已触发告警",
        )
    except Exception:
        pass
    return {
        "changes": changes,
        "window_minutes": int(window_minutes),
        "threshold": int(threshold),
        "subnet": subnet,
    }


def freeze_for_machine_mismatch(
    db,
    key_code: str,
    machine_code: str,
    ip: str,
    *,
    reason: str = "machine_mismatch：检测到未授权的新硬件码，已冻结该密钥",
) -> dict | None:
    """Freeze a licence after a new-device activation attempt and log the risk."""
    try:
        license = db.get_license(str(key_code or ""))
    except Exception:
        return None
    if not license:
        return None
    try:
        db.freeze_license(str(key_code or ""), PERMANENT_FREEZE_UNTIL, reason)
    except Exception:
        return None
    try:
        db.add_risk_event(
            "machine_mismatch",
            "high",
            str(key_code or ""),
            str(machine_code or ""),
            str(ip or ""),
            reason,
        )
    except Exception:
        pass
    return license
