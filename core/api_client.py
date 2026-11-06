import json
import time
from urllib.parse import urlencode, urlparse
import ipaddress
import socket

import requests

from . import integrity, machine, offline, security


class ApiError(Exception):
    """An API failure.

    ``offline_ok`` marks the failures that a cached offline licence is allowed
    to cover. Only transport-level failures qualify: an authoritative server
    answer (rejected signature, revoked licence, expired session) must never be
    overridden by the local fallback.
    """

    def __init__(self, message: str = "", *, offline_ok: bool = False):
        super().__init__(message)
        self.offline_ok = offline_ok


def _is_loopback_host(host: str) -> bool:
    """Return True only when a host resolves exclusively to loopback."""
    value = (host or "").strip().strip("[]").lower().rstrip(".")
    if not value:
        return False
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(value, None, type=socket.SOCK_STREAM)
    except (OSError, socket.gaierror):
        return False
    addresses = []
    for info in infos:
        try:
            addresses.append(ipaddress.ip_address(str(info[4][0]).split("%", 1)[0]))
        except (IndexError, TypeError, ValueError):
            return False
    return bool(addresses) and all(address.is_loopback for address in addresses)


# The server rejects a failed attest gate with this exact message; the
# client must surface it verbatim (contract section 4).
ATTEST_REQUIRED_MESSAGE = "客户端完整性校验未通过，已拒绝访问"


def _default_machine_code() -> str:
    try:
        return str(machine.machine_code() or "").strip().upper()
    except Exception:
        return ""


def is_loopback_url(url: str) -> bool:
    try:
        parsed = urlparse((url or "").strip())
    except Exception:
        return False
    return bool(parsed.hostname) and _is_loopback_host(parsed.hostname)


def validate_server_url(url: str, allow_insecure_http: bool = False) -> str:
    value = (url or "").strip().rstrip("/")
    if not value:
        raise ApiError("服务器地址不能为空")
    try:
        parsed = urlparse(value)
        parsed.port
    except ValueError as exc:
        raise ApiError("服务器地址格式无效") from exc
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ApiError("服务器地址必须使用 http:// 或 https://")
    if parsed.username or parsed.password:
        raise ApiError("服务器地址不能包含用户名或密码")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ApiError("服务器地址只能填写协议、主机和端口，不能包含路径或参数")
    if parsed.username or parsed.password:
        raise ApiError("服务器地址不能包含用户名或密码")
    try:
        parsed.port
    except ValueError as exc:
        raise ApiError("服务器端口无效") from exc
    if parsed.scheme == "http" and not is_loopback_url(value) and not allow_insecure_http:
        raise ApiError(
            "出于安全考虑，远程服务器必须使用 HTTPS；"
            "如为本机/内网测试，请在客户端配置中显式允许不安全 HTTP。"
        )
    return value


class ApiClient:
    def __init__(
        self,
        base_url: str,
        timeout: int = 8,
        ai_timeout: int | None = None,
        allow_insecure_http: bool = False,
        response_public_key: str = "",
        response_key_id: str = "",
    ):
        self.timeout = max(1, int(timeout or 8))
        # AI chat executes a multi-round tool loop server side; the ordinary
        # 8 second REST budget would abort every real query.
        fallback_ai = max(self.timeout * 4, 600)
        try:
            self.ai_timeout = max(self.timeout, int(ai_timeout or fallback_ai))
        except (TypeError, ValueError):
            self.ai_timeout = fallback_ai
        # Each poll is a tiny status read; the overall budget lives in
        # ``ai_timeout`` above.
        self.ai_poll_timeout = max(5, min(self.timeout, 30))
        self.allow_insecure_http = bool(allow_insecure_http)
        self.base_url = validate_server_url(base_url, self.allow_insecure_http)
        self.token: str | None = None
        self.session_secret: str | None = None
        self.portal_token: str = ""
        self.portal_token_expires_at: int = 0
        self.response_public_key = (response_public_key or "").strip()
        self.response_key_id = (response_key_id or "").strip()
        self.offline_public_key = ""

        # Attestation handshake state (contract section 4). The integrity
        # result comes from whatever the startup gate last reported.
        self.attest_token: str = ""
        self.attest_token_expires_at: int = 0
        try:
            self.integrity_result: dict | None = integrity.get_last_result()
        except Exception:
            self.integrity_result = None

        self.last_raw: bytes = b""
        self.last_signature: str = ""
        self.last_key_id: str = ""
        self.last_context: dict = {}

    def set_base_url(self, base_url: str) -> None:
        normalized = validate_server_url(base_url, self.allow_insecure_http)
        if normalized != self.base_url:
            self.token = None
            self.session_secret = None
            self.clear_portal_session()
            # 更换服务器后旧公钥不再可信，必须重新固定，否则会一直验签失败。
            self.response_public_key = ""
            self.response_key_id = ""
            self.offline_public_key = ""
        self.base_url = normalized

    def clear_session(self) -> None:
        self.token = None
        self.session_secret = None

    def clear_portal_session(self) -> None:
        self.portal_token = ""
        self.portal_token_expires_at = 0

    def set_trusted_public_keys(
        self,
        offline_public_key: str = "",
        response_public_key: str = "",
        response_key_id: str = "",
    ) -> None:
        self.offline_public_key = (offline_public_key or self.offline_public_key or "").strip()
        self.response_public_key = (
            response_public_key or self.response_public_key or ""
        ).strip()
        self.response_key_id = (response_key_id or self.response_key_id or "").strip()

    def apply_public_key_response(self, data: dict) -> None:
        self.set_trusted_public_keys(
            data.get("offline_public_key") or data.get("public_key") or "",
            data.get("response_public_key") or "",
            data.get("response_key_id") or "",
        )

    def set_session_secret(self, secret: str | None) -> None:
        self.session_secret = secret or None

    def set_integrity_result(self, result: dict | None) -> None:
        self.integrity_result = result if isinstance(result, dict) else None

    def _capture_response(self, response: requests.Response) -> None:
        self.last_raw = response.content
        self.last_signature = response.headers.get("X-Server-Signature", "")
        self.last_key_id = response.headers.get("X-Server-Key-Id", "")

    def verify_server_signature(self) -> bool:
        if not self.response_public_key or not self.last_signature:
            return False
        if self.response_key_id and self.last_key_id and self.response_key_id != self.last_key_id:
            return False
        context = self.last_context or {}
        try:
            message = security.canonical_response_message(
                context.get("method", ""),
                context.get("path", ""),
                context.get("timestamp", ""),
                context.get("nonce", ""),
                int(context.get("status_code", 0)),
                self.last_raw,
                self.last_key_id or self.response_key_id,
                context.get("query", ""),
            )
        except (TypeError, ValueError):
            return False
        return offline.verify_message(self.response_public_key, message, self.last_signature)

    # ------------------------------------------------------------------ #
    # Attestation handshake (contract section 4)
    # ------------------------------------------------------------------ #
    def attest(self, role: str = "verification", machine_code: str = "") -> dict | None:
        """Request an attestation token; network failures return None."""
        role_value = str(role or "verification").strip().lower() or "verification"
        machine = str(machine_code or "").strip().upper() or _default_machine_code()
        local_check = self.integrity_result
        if not isinstance(local_check, dict):
            try:
                local_check = integrity.run_self_check(role_value)
            except Exception:
                local_check = None
            if isinstance(local_check, dict):
                self.integrity_result = local_check
        result = local_check if isinstance(local_check, dict) else {}
        try:
            data = self._request(
                "POST",
                "/api/client/attest",
                json_body={
                    "role": role_value,
                    "exe_name": str(result.get("exe_name") or ""),
                    "exe_hash": str(result.get("exe_hash") or ""),
                    "version": str(result.get("version") or ""),
                    "release_id": str(result.get("release_id") or ""),
                    "manifest_sha256": str(result.get("manifest_sha256") or ""),
                    "machine_code": machine,
                    "local_check": result,
                },
                offline_ok=False,
                require_signature=False,
            )
        except Exception:
            # Never block normal use: the server decides whether a missing
            # token is fatal.
            return None
        if not isinstance(data, dict):
            return None
        token = str(data.get("attest_token") or "").strip()
        if data.get("ok") and token:
            try:
                expires_in = int(data.get("expires_in") or 0)
            except (TypeError, ValueError):
                expires_in = 0
            if expires_in <= 0:
                expires_in = 600
            self.attest_token = token
            self.attest_token_expires_at = int(time.time()) + expires_in
        else:
            self.attest_token = ""
            self.attest_token_expires_at = 0
        return data

    def ensure_attest(self, role: str = "verification", machine_code: str = "") -> str | None:
        """Return a cached token (valid until 60s before expiry) or refresh it."""
        if self.attest_token and self.attest_token_expires_at - 60 > int(time.time()):
            return self.attest_token
        data = self.attest(role=role, machine_code=machine_code)
        if isinstance(data, dict) and data.get("ok") and self.attest_token:
            return self.attest_token
        return None

    def report_integrity_failure(self, reason: str, detail: dict | None = None) -> dict:
        result = self.integrity_result if isinstance(self.integrity_result, dict) else {}
        return self._request(
            "POST",
            "/api/client/integrity_report",
            json_body={
                "role": str(result.get("role") or ""),
                "exe_name": str(result.get("exe_name") or ""),
                "exe_hash": str(result.get("exe_hash") or ""),
                "version": str(result.get("version") or ""),
                "machine_code": _default_machine_code(),
                "reason": str(reason or ""),
                "detail": detail if isinstance(detail, dict) else {},
            },
            offline_ok=False,
            require_signature=False,
        )

    @staticmethod
    def _raise_if_attest_required(data) -> None:
        if isinstance(data, dict) and data.get("code") == "attest_required":
            raise ApiError(ATTEST_REQUIRED_MESSAGE)

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict | None = None,
        params: dict | None = None,
        require_signature: bool = False,
        sign_with_session: bool = False,
        timeout: int | None = None,
        offline_ok: bool = True,
        attest_token: str | None = None,
        portal_auth: bool = False,
    ) -> dict:
        if require_signature and not self.response_public_key:
            raise ApiError("未配置服务器响应公钥，无法验证服务器身份")
        if sign_with_session and not self.session_secret:
            raise ApiError("缺少会话密钥，请先激活本设备")

        body = None
        if json_body is not None:
            body = json.dumps(
                json_body, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        query = urlencode(
            {key: value for key, value in (params or {}).items() if value is not None},
            doseq=True,
        )
        ts = security.now_ts()
        nonce = security.make_nonce()
        headers = {
            "Accept": "application/json",
            "X-Client-Timestamp": str(ts),
            "X-Client-Nonce": nonce,
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        if portal_auth:
            portal_value = str(self.portal_token or "").strip()
            if portal_value:
                headers["Authorization"] = f"Bearer {portal_value}"
        elif self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if attest_token:
            attest_value = str(attest_token).strip()
            if attest_value:
                headers["X-Attest-Token"] = attest_value
        if sign_with_session:
            headers["X-Client-Signature"] = security.sign_request(
                self.session_secret or "",
                method,
                path,
                ts,
                nonce,
                body,
                query,
            )
        url = self.base_url + path
        request_timeout = self.timeout
        if timeout is not None:
            try:
                request_timeout = max(1, int(timeout))
            except (TypeError, ValueError):
                request_timeout = self.timeout
        try:
            response = requests.request(
                method,
                url,
                headers=headers,
                params=params,
                data=body,
                timeout=request_timeout,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            # Unreachable server / timeout: the only case a cached offline
            # licence may stand in for a live answer.
            if offline_ok:
                raise ApiError(
                    f"无法连接服务器（{self.base_url}）：{exc}", offline_ok=True
                ) from exc
            hint = ""
            if isinstance(exc, requests.Timeout):
                hint = (
                    f"AI 请求超过 {request_timeout} 秒仍未返回，可能仍在执行。"
                    f"请稍后在日志中确认结果，或在本地服务器设置中调大 AI 请求超时。"
                )
            raise ApiError(
                f"调用服务器失败（{self.base_url}）：{exc}{hint}", offline_ok=False
            ) from exc

        if 300 <= response.status_code < 400:
            # A redirect would replay signed headers at some other endpoint,
            # and the response signature only covers the original target.
            raise ApiError("服务器返回了意外的重定向，已中止请求")

        self.last_context = {
            "method": method,
            "path": path,
            "query": query,
            "timestamp": ts,
            "nonce": nonce,
            "status_code": response.status_code,
        }
        self._capture_response(response)

        # Authenticate error responses too when a key is pinned; this prevents
        # an active intermediary from forging denial-of-service errors.
        if self.response_public_key:
            if not self.last_signature:
                raise ApiError("服务器未提供可验证的响应签名")
            if not self.verify_server_signature():
                raise ApiError("服务器响应签名校验失败，连接可能被篡改")
        elif require_signature:
            raise ApiError("服务器未提供可验证的响应签名")

        if response.status_code >= 400:
            if response.status_code == 401:
                # Only an authentication failure invalidates the token.
                # A 403 can be a policy gate (for example the forced
                # password change), where the credential is still valid.
                if portal_auth:
                    self.clear_portal_session()
                else:
                    self.token = None
            detail = response.text
            try:
                detail = response.json().get("detail", detail)
            except Exception:
                pass
            raise ApiError(str(detail or f"HTTP {response.status_code}"))

        if not response.content:
            data = {}
        else:
            try:
                data = response.json()
            except Exception as exc:
                raise ApiError("服务器返回数据格式错误") from exc
            if not isinstance(data, dict):
                raise ApiError("服务器返回数据格式错误")
        if data.get("code") == "unauthenticated":
            if not portal_auth:
                self.session_secret = None
            if portal_auth:
                self.clear_portal_session()
            raise ApiError(data.get("message") or "会话已失效，请重新激活")
        if portal_auth and data.get("code") in (
            "invalid_token",
            "token_invalid",
            "portal_unauthenticated",
            "token_expired",
            "expired",
            "invalid_session",
        ):
            self.clear_portal_session()
        return data

    def health(self) -> dict:
        return self._request("GET", "/api/health")

    def login(self, username: str, password: str) -> dict:
        # Never leave a previous session usable when this login fails.
        self.token = None
        data = self._request(
            "POST",
            "/api/admin/login",
            json_body={"username": username, "password": password},
        )
        self.token = data.get("token")
        if not self.token:
            raise ApiError("服务器未返回登录凭证")
        return data

    def logout(self, clear_device_session: bool = False) -> None:
        """Forget cached credentials so an ended session cannot be reused."""
        self.token = None
        if clear_device_session:
            self.session_secret = None
        self.last_context = {}
        self.last_raw = b""
        self.last_signature = ""
        self.last_key_id = ""

    def me(self) -> dict:
        return self._request("GET", "/api/admin/me")

    def _store_portal_token(self, data: dict) -> dict:
        if not isinstance(data, dict) or not data.get("ok"):
            return data
        if data.get("pending_approval"):
            # 审批模式下注册成功但尚无会话（等待审批），不写 token。
            return data
        token = str(data.get("token") or "").strip()
        if not token:
            raise ApiError("服务器未返回登录凭证")
        self.portal_token = token
        try:
            expires_in = int(data.get("expires_in") or 0)
        except (TypeError, ValueError):
            expires_in = 0
        if expires_in <= 0:
            expires_in = 12 * 3600
        self.portal_token_expires_at = int(time.time()) + expires_in
        return data

    def portal_send_code(self, email: str, purpose: str) -> dict:
        return self._request(
            "POST",
            "/api/portal/email/send_code",
            json_body={"email": email, "purpose": purpose},
            portal_auth=True,
        )

    def portal_register(self, email: str, code: str, password: str) -> dict:
        data = self._request(
            "POST",
            "/api/portal/register",
            json_body={"email": email, "code": code, "password": password},
            portal_auth=True,
        )
        return self._store_portal_token(data)

    def portal_login(self, email: str, password: str) -> dict:
        data = self._request(
            "POST",
            "/api/portal/login",
            json_body={"email": email, "password": password},
            portal_auth=True,
        )
        return self._store_portal_token(data)

    def portal_me(self) -> dict:
        data = self._request("GET", "/api/portal/me", portal_auth=True)
        if isinstance(data, dict) and data.get("ok") is False:
            code = str(data.get("code") or "").strip().lower()
            if code in (
                "",
                "unauthenticated",
                "invalid",
                "invalid_token",
                "token_invalid",
                "token_expired",
                "expired",
                "invalid_session",
                "portal_unauthenticated",
            ):
                self.clear_portal_session()
        return data

    def portal_bind(
        self, key_code: str, machine_code: str, device_name: str = ""
    ) -> dict:
        attest_token = self.ensure_attest(
            role="verification", machine_code=machine_code
        )
        data = self._request(
            "POST",
            "/api/portal/bind",
            json_body={
                "key_code": key_code,
                "machine_code": machine_code,
                "device_name": device_name,
            },
            portal_auth=True,
            attest_token=attest_token,
        )
        self._raise_if_attest_required(data)
        return data

    def portal_unbind(self) -> dict:
        return self._request("POST", "/api/portal/unbind", portal_auth=True)

    def portal_renew_request(self, note: str = "") -> dict:
        return self._request(
            "POST",
            "/api/portal/renew_request",
            json_body={"note": note},
            portal_auth=True,
        )

    def portal_password_reset(self, email: str, code: str, new_password: str) -> dict:
        return self._request(
            "POST",
            "/api/portal/password/reset",
            json_body={"email": email, "code": code, "new_password": new_password},
            portal_auth=True,
        )

    # ------------------------------------------------------ portal profile
    def portal_profile(self) -> dict:
        return self._request("GET", "/api/portal/profile", portal_auth=True)

    def portal_update_profile(self, display_name: str) -> dict:
        return self._request(
            "PUT",
            "/api/portal/profile",
            json_body={"display_name": display_name},
            portal_auth=True,
        )

    def portal_upload_avatar(self, mime: str, data_base64: str) -> dict:
        return self._request(
            "POST",
            "/api/portal/avatar",
            json_body={"mime": mime, "data_base64": data_base64},
            portal_auth=True,
        )

    def portal_delete_avatar(self) -> dict:
        return self._request("DELETE", "/api/portal/avatar", portal_auth=True)

    # -------------------------------------------------- portal user admin
    def portal_accounts(
        self, keyword: str = "", status: str = "", limit: int = 200, offset: int = 0
    ) -> dict:
        return self._request(
            "GET",
            "/api/admin/portal_accounts",
            params={
                "keyword": keyword,
                "status": status,
                "limit": limit,
                "offset": offset,
            },
        )

    def set_portal_account_status(self, id: int, status: str) -> dict:
        return self._request(
            "POST",
            f"/api/admin/portal_accounts/{id}/status",
            json_body={"status": status},
        )

    def admin_unbind_portal_account(self, id: int) -> dict:
        return self._request("POST", f"/api/admin/portal_accounts/{id}/unbind")

    def admin_set_email(self, email: str) -> dict:
        return self._request(
            "POST", "/api/admin/email/set", json_body={"email": email}
        )

    def admin_verify_email(self, code: str) -> dict:
        return self._request(
            "POST", "/api/admin/email/verify", json_body={"code": code}
        )

    def admin_password_forgot(self, email: str) -> dict:
        return self._request(
            "POST", "/api/admin/password/forgot", json_body={"email": email}
        )

    def admin_password_reset(self, email: str, code: str, new_password: str) -> dict:
        return self._request(
            "POST",
            "/api/admin/password/reset",
            json_body={"email": email, "code": code, "new_password": new_password},
        )

    def generate_licenses(self, **payload) -> dict:
        return self._request("POST", "/api/license/generate", json_body=payload)

    def list_licenses(self, **params) -> dict:
        return self._request("GET", "/api/license/list", params=params)

    def license_detail(self, key_code: str) -> dict:
        return self._request(
            "GET", "/api/license/detail", params={"key_code": key_code}
        )

    def metrics_trend(self, days: int = 30) -> dict:
        return self._request("GET", "/api/metrics/trend", params={"days": int(days)})

    def public_key(self) -> dict:
        return self._request("GET", "/api/public_key")

    def offline_code(self, key_code: str, machine_code: str = "", device_name: str = "") -> dict:
        return self._request(
            "POST",
            "/api/license/offline_code",
            json_body={
                "key_code": key_code,
                "machine_code": machine_code,
                "device_name": device_name,
            },
        )

    def rebind_license(self, key_code: str) -> dict:
        """一键换绑：解冻（如需）+ 解绑全部设备。"""
        return self._request(
            "POST", "/api/license/rebind", json_body={"key_code": key_code}
        )

    def list_approvals(self, kind: str = "", status: str = "",
                       limit: int = 50, offset: int = 0) -> dict:
        return self._request(
            "GET",
            "/api/approvals",
            params={
                "kind": kind,
                "status": status,
                "limit": int(limit),
                "offset": int(offset),
            },
        )

    def approve_approval(self, approval_id: int, note: str = "") -> dict:
        return self._request(
            "POST",
            f"/api/approvals/{int(approval_id)}/approve",
            json_body={"note": note},
        )

    def reject_approval(self, approval_id: int, note: str = "") -> dict:
        return self._request(
            "POST",
            f"/api/approvals/{int(approval_id)}/reject",
            json_body={"note": note},
        )

    def delete_portal_account(self, account_id: int) -> dict:
        return self._request(
            "POST", f"/api/admin/portal_accounts/{int(account_id)}/delete"
        )

    def delete_admin(self, admin_id: int) -> dict:
        return self._request(
            "POST", "/api/admin/delete", json_body={"admin_id": int(admin_id)}
        )

    def transfer_request(self, key_code: str, target_email: str) -> dict:
        return self._request(
            "POST",
            "/api/portal/transfer_request",
            json_body={"key_code": key_code, "target_email": target_email},
            portal_auth=True,
        )

    def revoke_license(self, key_code: str) -> dict:
        return self._request(
            "POST", "/api/license/revoke", json_body={"key_code": key_code}
        )

    def restore_license(self, key_code: str) -> dict:
        return self._request(
            "POST", "/api/license/restore", json_body={"key_code": key_code}
        )

    def renew_license(
        self, key_code: str, duration_days: int, duration_unit: str = "day"
    ) -> dict:
        return self._request(
            "POST",
            "/api/license/renew",
            json_body={
                "key_code": key_code,
                "duration_days": duration_days,
                "duration_unit": duration_unit,
            },
        )

    def freeze_license(self, key_code: str, amount: int, unit: str = "hour", reason: str = "") -> dict:
        return self._request(
            "POST",
            "/api/license/freeze",
            json_body={
                "key_code": key_code,
                "amount": amount,
                "unit": unit,
                "reason": reason,
            },
        )

    def unfreeze_license(self, key_code: str) -> dict:
        return self._request(
            "POST", "/api/license/unfreeze", json_body={"key_code": key_code}
        )

    def revoke_batch(self, batch_no: str) -> dict:
        return self._request(
            "POST", "/api/license/revoke_batch", json_body={"batch_no": batch_no}
        )

    def restore_batch(self, batch_no: str) -> dict:
        """Undo a batch revoke; keys go back to their pre-revoke status."""
        return self._request(
            "POST", "/api/license/restore_batch", json_body={"batch_no": batch_no}
        )

    def delete_license(self, key_code: str) -> dict:
        return self._request(
            "POST", "/api/license/delete", json_body={"key_code": key_code}
        )

    def unbind(self, key_code: str, machine_code: str) -> dict:
        return self._request(
            "POST",
            "/api/license/unbind",
            json_body={"key_code": key_code, "machine_code": machine_code},
        )

    def stats(self) -> dict:
        return self._request("GET", "/api/license/stats")

    # ----------------------------------------------------------- alerts
    def alert_rules(self) -> dict:
        return self._request("GET", "/api/alerts/rules")

    def create_alert_rule(self, **fields) -> dict:
        return self._request("POST", "/api/alerts/rules", json_body=dict(fields))

    def update_alert_rule(self, rule_id: int, **fields) -> dict:
        return self._request(
            "PUT", f"/api/alerts/rules/{rule_id}", json_body=dict(fields)
        )

    def delete_alert_rule(self, rule_id: int) -> dict:
        return self._request("DELETE", f"/api/alerts/rules/{rule_id}")

    def alert_events(self, status: str = "", limit: int = 200, offset: int = 0) -> dict:
        return self._request(
            "GET",
            "/api/alerts/events",
            params={"status": status, "limit": limit, "offset": offset},
        )

    def ack_alert_event(self, event_id: int) -> dict:
        return self._request("POST", f"/api/alerts/events/{event_id}/ack")

    def resolve_alert_event(self, event_id: int) -> dict:
        return self._request("POST", f"/api/alerts/events/{event_id}/resolve")

    def metrics_overview(self, window_seconds: int = 600) -> dict:
        return self._request(
            "GET",
            "/api/metrics/overview",
            params={"window_seconds": window_seconds},
        )

    # -------------------------------------------------- notification channels
    def list_channels(self) -> dict:
        return self._request("GET", "/api/channels")

    def create_channel(
        self, kind, name, url, secret="", enabled=True
    ) -> dict:
        return self._request(
            "POST",
            "/api/channels",
            json_body={
                "kind": kind,
                "name": name,
                "url": url,
                "secret": secret,
                "enabled": enabled,
            },
        )

    def update_channel(self, channel_id: int, **fields) -> dict:
        return self._request(
            "PUT", f"/api/channels/{channel_id}", json_body=dict(fields)
        )

    def delete_channel(self, channel_id: int) -> dict:
        return self._request("DELETE", f"/api/channels/{channel_id}")

    def test_channel(self, channel_id: int) -> dict:
        # The server sends synchronously and the channel transport allows up
        # to 10s per attempt; the default REST budget would abort first.
        return self._request(
            "POST",
            f"/api/channels/{channel_id}/test",
            timeout=max(self.timeout, 15),
        )

    def channel_deliveries(
        self, status: str = "", limit: int = 200, offset: int = 0
    ) -> dict:
        return self._request(
            "GET",
            "/api/channels/deliveries",
            params={"status": status, "limit": limit, "offset": offset},
        )

    def ai_config(self) -> dict:
        return self._request("GET", "/api/ai/config")

    def ai_status(self) -> dict:
        return self._request("GET", "/api/ai/status")

    def ai_chat(self, messages: list[dict], on_event=None, cancel_event=None) -> dict:
        """Run one AI turn through the server's background job queue.

        The submit call returns a job id immediately; the tool loop keeps
        running server side while we poll a lightweight status endpoint.

        ``cancel_event`` is optional and defaults to ``None`` (the previous
        behaviour). When a ``threading.Event``-like object is supplied the
        polling loop wakes in small steps and aborts shortly after it is set,
        so closing the AI page never leaves a 600 second poll running.
        """
        if self._cancelled(cancel_event):
            raise ApiError("AI 任务已取消")
        submitted = self._request(
            "POST",
            "/api/ai/chat",
            json_body={"messages": messages},
            timeout=self.ai_poll_timeout,
            offline_ok=False,
        )
        job_id = str(submitted.get("job_id") or "").strip()
        if not job_id:
            # Older servers answer synchronously; honour that instead of failing.
            if submitted.get("reply"):
                return submitted
            raise ApiError("AI 服务未返回任务编号")
        try:
            interval = float(submitted.get("poll_interval") or 0.8)
        except (TypeError, ValueError):
            interval = 0.8
        interval = min(max(interval, 0.2), 5.0)

        deadline = time.monotonic() + self.ai_timeout
        cursor = 0

        def notify(event: dict) -> None:
            if on_event is None:
                return
            try:
                on_event(event)
            except Exception:  # pragma: no cover - UI callback must not break polling
                pass

        while True:
            if self._cancelled(cancel_event):
                raise ApiError("AI 任务已取消")
            status = self._request(
                "GET",
                f"/api/ai/chat/{job_id}",
                params={"after": cursor},
                timeout=self.ai_poll_timeout,
                offline_ok=False,
            )
            for event in status.get("events") or []:
                if isinstance(event, dict):
                    notify(event)
            try:
                cursor = max(cursor, int(status.get("event_cursor") or cursor))
            except (TypeError, ValueError):
                pass
            state = str(status.get("status") or "").strip().lower()
            if state == "done":
                result = status.get("result")
                if not isinstance(result, dict):
                    raise ApiError("AI 服务返回的数据格式无效")
                return result
            if state == "failed":
                raise ApiError(str(status.get("error") or "AI 处理失败"))
            if state in ("expired", "missing"):
                raise ApiError(str(status.get("error") or "AI 任务已过期"))
            if time.monotonic() >= deadline:
                raise ApiError(
                    f"AI 任务超过 {self.ai_timeout} 秒仍未完成，请稍后在审计日志中查看结果"
                )
            if self._wait_cancellable(interval, cancel_event):
                raise ApiError("AI 任务已取消")

    @staticmethod
    def _cancelled(cancel_event) -> bool:
        """Report whether the caller's cancellation flag is set."""
        if cancel_event is None:
            return False
        try:
            checker = getattr(cancel_event, "is_set", None)
            if callable(checker):
                return bool(checker())
            return bool(cancel_event)
        except Exception:  # pragma: no cover - defensive
            return False

    @classmethod
    def _wait_cancellable(cls, seconds: float, cancel_event) -> bool:
        """Sleep up to ``seconds`` in small steps; return True when cancelled."""
        try:
            total = max(0.0, float(seconds))
        except (TypeError, ValueError):
            total = 0.0
        if cancel_event is None:
            if total:
                time.sleep(total)
            return False
        waiter = getattr(cancel_event, "wait", None)
        deadline = time.monotonic() + total
        while True:
            if cls._cancelled(cancel_event):
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            step = min(remaining, 0.2)
            if callable(waiter):
                try:
                    # threading.Event.wait wakes as soon as the flag is set.
                    if waiter(step):
                        return True
                    continue
                except Exception:  # pragma: no cover - foreign event objects
                    waiter = None
            time.sleep(step)

    def ai_confirm(self, confirm_token: str) -> dict:
        """Execute a staged AI write action (two-phase confirmation, P1-6)."""
        return self._request(
            "POST",
            "/api/ai/confirm",
            json_body={"confirm_token": str(confirm_token or "")},
            timeout=self.ai_timeout,
            offline_ok=False,
        )

    def ai_cancel(self, confirm_token: str) -> dict:
        """Cancel a staged AI write action; it can never run afterwards."""
        return self._request(
            "POST",
            "/api/ai/cancel",
            json_body={"confirm_token": str(confirm_token or "")},
            timeout=self.ai_poll_timeout,
            offline_ok=False,
        )

    def list_admins(self) -> dict:
        return self._request("GET", "/api/admin/list")

    def create_admin(self, username: str, password: str, role: str = "admin") -> dict:
        return self._request(
            "POST",
            "/api/admin/create",
            json_body={"username": username, "password": password, "role": role},
        )

    def set_admin_status(self, admin_id: int, status: str) -> dict:
        return self._request(
            "POST",
            "/api/admin/status",
            json_body={"admin_id": admin_id, "status": status},
        )

    def reset_admin_password(self, admin_id: int, password: str) -> dict:
        return self._request(
            "POST",
            "/api/admin/password",
            json_body={"admin_id": admin_id, "password": password},
        )

    def change_password(self, old_password: str, new_password: str) -> dict:
        data = self._request(
            "POST",
            "/api/admin/change_password",
            json_body={"old_password": old_password, "new_password": new_password},
        )
        if data.get("token"):
            self.token = data["token"]
        return data

    def list_batches(self, **params) -> dict:
        return self._request("GET", "/api/license/batches", params=params)

    def list_logs(self, limit: int = 200, **params) -> dict:
        query = {"limit": limit, **params}
        return self._request("GET", "/api/logs", params=query)

    def _machine_components(self) -> dict:
        """本机分量指纹（失败时为空 dict，不影响激活本身）。"""
        try:
            return machine.fingerprint_components() or {}
        except Exception:
            return {}

    def activate(self, key_code: str, machine_code: str, device_name: str = "") -> dict:
        # Activation is the point where the client receives its session secret.
        # It must be authenticated by a pinned asymmetric server key rather than
        # by a secret supplied in the same response.
        if not self.response_public_key:
            raise ApiError("未配置服务器响应公钥，无法安全激活，请先导入服务器公钥")
        attest_token = self.ensure_attest(role="verification", machine_code=machine_code)
        data = self._request(
            "POST",
            "/api/client/activate",
            json_body={
                "key_code": key_code,
                "machine_code": machine_code,
                "device_name": device_name,
                "machine_components": self._machine_components(),
                "portal_token": str(getattr(self, "portal_token", "") or ""),
            },
            require_signature=True,
            attest_token=attest_token,
        )
        self._raise_if_attest_required(data)
        secret = data.get("session_secret")
        if data.get("ok") and secret:
            self.session_secret = secret
        return data

    def verify(self, key_code: str, machine_code: str) -> dict:
        attest_token = self.ensure_attest(role="verification", machine_code=machine_code)
        data = self._request(
            "POST",
            "/api/client/verify",
            json_body={"key_code": key_code, "machine_code": machine_code},
            require_signature=True,
            sign_with_session=True,
            attest_token=attest_token,
        )
        self._raise_if_attest_required(data)
        return data

    def heartbeat(self, key_code: str, machine_code: str) -> dict:
        attest_token = self.ensure_attest(role="verification", machine_code=machine_code)
        data = self._request(
            "POST",
            "/api/client/heartbeat",
            json_body={"key_code": key_code, "machine_code": machine_code},
            require_signature=True,
            sign_with_session=True,
            attest_token=attest_token,
        )
        self._raise_if_attest_required(data)
        return data
