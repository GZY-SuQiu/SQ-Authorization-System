"""P1 告警收件人解析与邮件投递（主流程模块）。

收件人规则（第二轮决策）：

- 绑定类告警（新硬件码、IP 跳动、续费请求）优先发给触发 Key 的绑定邮箱；
- 所有告警同时抄送管理员告警收件人（``smtp.alert_admin_emails`` + 已验证的管理员邮箱）；
- 未配置任何收件人时静默跳过；
- 本模块的任何异常都不能影响激活/校验/心跳主流程，调用方负责记录。
"""

from __future__ import annotations

from datetime import datetime

__all__ = [
    "mask_email",
    "mask_key",
    "admin_alert_emails",
    "bound_account_email",
    "alert_recipients",
    "notify",
    "notify_tamper",
    "notify_machine_mismatch",
    "notify_ip_jump",
    "notify_renewal_request",
]


def mask_email(value: str) -> str:
    """Return ``a***@domain`` style text for logs and mail bodies."""
    email = str(value or "").strip()
    if "@" not in email:
        return (email[:1] + "***") if email else ""
    local, _, domain = email.partition("@")
    if len(local) <= 2:
        masked = (local[:1] or "") + "***"
    else:
        masked = local[:1] + "***" + local[-1:]
    return f"{masked}@{domain}"


def mask_key(value: str) -> str:
    """Mask a licence key: keep a short prefix and suffix."""
    key = str(value or "").strip()
    if len(key) <= 8:
        return (key[:2] + "****") if key else ""
    return key[:4] + "****" + key[-4:]


def _clean_email_list(values) -> list[str]:
    if isinstance(values, str):
        values = values.replace(";", ",").split(",")
    result: list[str] = []
    for item in values or []:
        email = str(item or "").strip().lower()
        if email and "@" in email and email not in result:
            result.append(email)
    return result


def admin_alert_emails(db, smtp_config=None) -> list[str]:
    """Configured admin recipients first, then verified admin account emails."""
    configured = _clean_email_list((smtp_config or {}).get("alert_admin_emails"))
    verified: list[str] = []
    getter = getattr(db, "list_verified_admin_emails", None)
    if callable(getter):
        try:
            verified = _clean_email_list(getter())
        except Exception:
            verified = []
    return configured + [email for email in verified if email not in configured]


def bound_account_email(db, license_id) -> str | None:
    """Resolve the portal email currently bound to a licence, if any."""
    if not license_id:
        return None
    try:
        binding = db.get_binding_by_license(int(license_id))
    except Exception:
        return None
    if not binding or str(binding.get("status") or "") != "bound":
        return None
    try:
        account = db.get_portal_account_by_id(int(binding.get("account_id") or 0))
    except Exception:
        return None
    email = str((account or {}).get("email") or "").strip().lower()
    return email or None


def alert_recipients(
    db,
    smtp_config=None,
    license_id=None,
    *,
    include_bound: bool = True,
    include_admins: bool = True,
) -> list[str]:
    recipients: list[str] = []
    if include_bound:
        bound = bound_account_email(db, license_id)
        if bound:
            recipients.append(bound)
    if include_admins:
        for email in admin_alert_emails(db, smtp_config):
            if email not in recipients:
                recipients.append(email)
    return recipients


def notify(
    db,
    mailer,
    template_code: str,
    variables: dict,
    *,
    license_id=None,
    to_email: str | None = None,
    include_bound: bool = True,
    include_admins: bool = True,
    smtp_config=None,
    dedupe_key: str = "",
) -> list[int]:
    """Enqueue one mail per recipient; never raise to the caller."""
    if mailer is None:
        return []
    targets = (
        _clean_email_list([to_email])
        if to_email
        else alert_recipients(
            db,
            smtp_config,
            license_id,
            include_bound=include_bound,
            include_admins=include_admins,
        )
    )
    outbox_ids: list[int] = []
    for email in targets:
        key = f"{dedupe_key}:{email}" if dedupe_key else ""
        try:
            outbox_id = mailer.enqueue(email, template_code, variables, dedupe_key=key)
        except Exception:
            outbox_id = None
        if outbox_id:
            outbox_ids.append(int(outbox_id))
    return outbox_ids


def _bucket(fmt: str = "%Y%m%d%H") -> str:
    return datetime.now().strftime(fmt)


def notify_tamper(
    db,
    mailer,
    *,
    role: str,
    exe_name: str,
    exe_hash: str,
    machine_code: str,
    ip: str,
    reason: str,
    detail: str = "",
    smtp_config=None,
    license_id=None,
) -> list[int]:
    variables = {
        "role": role or "client",
        "exe_name": exe_name or "-",
        "exe_hash": str(exe_hash or "")[:16],
        "machine_code": str(machine_code or "")[:24],
        "ip": ip or "-",
        "reason": reason or "integrity_failed",
        "detail": str(detail or "")[:500],
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    return notify(
        db,
        mailer,
        "tamper_alert",
        variables,
        license_id=license_id,
        smtp_config=smtp_config,
        dedupe_key=f"tamper:{str(exe_hash or '')[:16]}:{_bucket()}",
    )


def notify_machine_mismatch(
    db,
    mailer,
    *,
    license: dict,
    machine_code: str,
    ip: str,
    reason: str = "检测到未授权的新硬件码，已冻结该密钥",
    smtp_config=None,
) -> list[int]:
    variables = {
        "key_code": mask_key(license.get("key_code")),
        "machine_code": str(machine_code or "")[:24],
        "ip": ip or "-",
        "reason": reason,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    return notify(
        db,
        mailer,
        "risk_alert",
        variables,
        license_id=license.get("id"),
        smtp_config=smtp_config,
        dedupe_key=f"machine_mismatch:{license.get('id')}:{_bucket()}",
    )


def notify_ip_jump(
    db,
    mailer,
    *,
    license: dict,
    machine_code: str,
    ip: str,
    changes: int,
    window_minutes: int,
    smtp_config=None,
) -> list[int]:
    variables = {
        "key_code": mask_key(license.get("key_code")),
        "machine_code": str(machine_code or "")[:24],
        "ip": ip or "-",
        "changes": int(changes),
        "window_minutes": int(window_minutes),
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    return notify(
        db,
        mailer,
        "risk_alert",
        variables,
        license_id=license.get("id"),
        smtp_config=smtp_config,
        dedupe_key=f"ip_jump:{license.get('id')}:{_bucket()}",
    )


def notify_renewal_request(
    db,
    mailer,
    *,
    license: dict,
    account_email: str,
    note: str = "",
    smtp_config=None,
) -> list[int]:
    variables = {
        "key_code": mask_key(license.get("key_code")),
        "account_email": mask_email(account_email),
        "note": str(note or "")[:500],
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    outbox_ids = notify(
        db,
        mailer,
        "renewal_request",
        variables,
        to_email=account_email,
        smtp_config=smtp_config,
        dedupe_key=f"renewal_user:{license.get('id')}:{_bucket()}",
    )
    outbox_ids += notify(
        db,
        mailer,
        "renewal_request",
        variables,
        license_id=license.get("id"),
        include_bound=False,
        include_admins=True,
        smtp_config=smtp_config,
        dedupe_key=f"renewal_admin:{license.get('id')}:{_bucket()}",
    )
    return outbox_ids
