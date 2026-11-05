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


def handle_machine_mismatch(
    db,
    key_code: str,
    machine_code: str,
    ip: str,
    *,
    same_subnet_grace: bool = True,
    reason_frozen: str = "machine_mismatch：检测到未授权的新硬件码，已冻结该密钥",
    reason_warn: str = "machine_mismatch：检测到同网段新硬件码，已记录（未冻结）",
) -> dict | None:
    """设备满员后出现新硬件码时的分级处置。

    合法换机（重装系统、换电脑）常发生在同一网络段内；克隆则多出现在
    异地网络。因此：新硬件码来自该密钥用过的网络段 -> 仅记录告警；
    来自其他网络段 -> 冻结该密钥（可逆，主控可解冻/换绑）。

    返回 ``{"license", "frozen", "same_subnet", "reason"}``；密钥不存在返回 None。
    """
    try:
        license = db.get_license(str(key_code or ""))
    except Exception:
        return None
    if not license:
        return None

    same_subnet = False
    new_subnet = client_subnet(ip)
    if same_subnet_grace and new_subnet:
        try:
            events = db.recent_activation_ip_events(str(key_code), 50)
        except Exception:
            events = []
        old_subnets = set()
        for event in events:
            subnet = str(event.get("subnet") or "") or client_subnet(event.get("ip"))
            if subnet:
                old_subnets.add(subnet)
        same_subnet = new_subnet in old_subnets

    if same_subnet:
        try:
            db.add_risk_event(
                "machine_mismatch_warn",
                "warning",
                str(key_code or ""),
                str(machine_code or ""),
                str(ip or ""),
                reason_warn,
            )
        except Exception:
            pass
        return {
            "license": license,
            "frozen": False,
            "same_subnet": True,
            "reason": reason_warn,
        }

    try:
        db.freeze_license(str(key_code or ""), PERMANENT_FREEZE_UNTIL, reason_frozen)
    except Exception:
        return None
    try:
        db.add_risk_event(
            "machine_mismatch",
            "high",
            str(key_code or ""),
            str(machine_code or ""),
            str(ip or ""),
            reason_frozen,
        )
    except Exception:
        pass
    return {
        "license": license,
        "frozen": True,
        "same_subnet": False,
        "reason": reason_frozen,
    }


def freeze_for_machine_mismatch(
    db,
    key_code: str,
    machine_code: str,
    ip: str,
    *,
    reason: str = "machine_mismatch：检测到未授权的新硬件码，已冻结该密钥",
) -> dict | None:
    """兼容入口：严格模式（无视网段，总是冻结）。

    保留给不支持分级的旧调用方；新代码请用 ``handle_machine_mismatch``。
    """
    outcome = handle_machine_mismatch(
        db,
        key_code,
        machine_code,
        ip,
        same_subnet_grace=False,
        reason_frozen=reason,
    )
    if not outcome:
        return None
    return outcome.get("license")
