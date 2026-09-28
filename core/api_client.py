import json
from typing import Any

import requests

from . import security


class ApiError(Exception):
    pass


class ApiClient:
    def __init__(self, base_url: str, timeout: int = 8):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.token: str | None = None
        self.session_secret: str | None = None
        self.last_raw: bytes = b""
        self.last_signature: str = ""

    def _request(self, method: str, path: str, **kwargs) -> Any:
        url = self.base_url + path
        headers = kwargs.pop("headers", {})
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            resp = requests.request(method, url, headers=headers, timeout=self.timeout, **kwargs)
        except requests.RequestException as exc:
            raise ApiError(f"无法连接服务器（{self.base_url}）：{exc}") from exc
        self.last_raw = resp.content
        self.last_signature = resp.headers.get("X-Server-Signature", "")
        if resp.status_code >= 400:
            detail = resp.text
            try:
                detail = resp.json().get("detail", detail)
            except Exception:
                pass
            raise ApiError(str(detail))
        if not resp.content:
            return {}
        return resp.json()

    def set_session_secret(self, secret: str | None) -> None:
        self.session_secret = secret or None

    def verify_server_signature(self, secret: str | None = None) -> bool:
        secret = secret or self.session_secret
        if not secret or not self.last_signature:
            return False
        return security.verify_response_signature(secret, self.last_raw, self.last_signature)

    def _signed_request(self, path: str, payload: dict) -> dict:
        if not self.session_secret:
            raise ApiError("缺少会话密钥，请先激活本设备")
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ts = security.now_ts()
        nonce = security.make_nonce()
        sig = security.sign_request(self.session_secret, "POST", path, ts, nonce, body)
        headers = {
            "Content-Type": "application/json",
            "X-Client-Timestamp": str(ts),
            "X-Client-Nonce": nonce,
            "X-Client-Signature": sig,
        }
        try:
            resp = requests.request(
                "POST", self.base_url + path, data=body, headers=headers, timeout=self.timeout
            )
        except requests.RequestException as exc:
            raise ApiError(f"无法连接服务器（{self.base_url}）：{exc}") from exc
        self.last_raw = resp.content
        self.last_signature = resp.headers.get("X-Server-Signature", "")
        if resp.status_code >= 400:
            raise ApiError(resp.text or "请求失败")
        try:
            data = resp.json()
        except Exception as exc:
            raise ApiError("服务器返回数据格式错误") from exc
        if data.get("code") == "unauthenticated":
            self.session_secret = None
            raise ApiError(data.get("message") or "会话已失效，请重新激活")
        if not self.verify_server_signature():
            raise ApiError("服务器响应签名校验失败，连接可能被篡改")
        return data

    def health(self) -> dict:
        return self._request("GET", "/api/health")

    def login(self, username: str, password: str) -> dict:
        data = self._request(
            "POST", "/api/admin/login", json={"username": username, "password": password}
        )
        self.token = data.get("token")
        return data

    def set_base_url(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")

    def me(self) -> dict:
        return self._request("GET", "/api/admin/me")

    def generate_licenses(self, **payload) -> dict:
        return self._request("POST", "/api/license/generate", json=payload)

    def list_licenses(self, **params) -> dict:
        return self._request("GET", "/api/license/list", params=params)

    def license_detail(self, key_code: str) -> dict:
        return self._request("GET", "/api/license/detail", params={"key_code": key_code})

    def public_key(self) -> dict:
        return self._request("GET", "/api/public_key")

    def offline_code(self, key_code: str, machine_code: str = "", device_name: str = "") -> dict:
        return self._request(
            "POST",
            "/api/license/offline_code",
            json={
                "key_code": key_code,
                "machine_code": machine_code,
                "device_name": device_name,
            },
        )

    def revoke_license(self, key_code: str) -> dict:
        return self._request("POST", "/api/license/revoke", json={"key_code": key_code})

    def restore_license(self, key_code: str) -> dict:
        return self._request("POST", "/api/license/restore", json={"key_code": key_code})

    def freeze_license(self, key_code: str, amount: int, unit: str = "hour", reason: str = "") -> dict:
        return self._request(
            "POST",
            "/api/license/freeze",
            json={"key_code": key_code, "amount": amount, "unit": unit, "reason": reason},
        )

    def unfreeze_license(self, key_code: str) -> dict:
        return self._request("POST", "/api/license/unfreeze", json={"key_code": key_code})

    def revoke_batch(self, batch_no: str) -> dict:
        return self._request("POST", "/api/license/revoke_batch", json={"batch_no": batch_no})

    def delete_license(self, key_code: str) -> dict:
        return self._request("POST", "/api/license/delete", json={"key_code": key_code})

    def unbind(self, key_code: str, machine_code: str) -> dict:
        return self._request(
            "POST", "/api/license/unbind", json={"key_code": key_code, "machine_code": machine_code}
        )

    def stats(self) -> dict:
        return self._request("GET", "/api/license/stats")

    def list_admins(self) -> dict:
        return self._request("GET", "/api/admin/list")

    def create_admin(self, username: str, password: str, role: str = "admin") -> dict:
        return self._request(
            "POST", "/api/admin/create", json={"username": username, "password": password, "role": role}
        )

    def set_admin_status(self, admin_id: int, status: str) -> dict:
        return self._request(
            "POST", "/api/admin/status", json={"admin_id": admin_id, "status": status}
        )

    def reset_admin_password(self, admin_id: int, password: str) -> dict:
        return self._request(
            "POST", "/api/admin/password", json={"admin_id": admin_id, "password": password}
        )

    def list_logs(self, limit: int = 200) -> dict:
        return self._request("GET", "/api/logs", params={"limit": limit})

    def activate(self, key_code: str, machine_code: str, device_name: str = "") -> dict:
        data = self._request(
            "POST",
            "/api/client/activate",
            json={"key_code": key_code, "machine_code": machine_code, "device_name": device_name},
        )
        secret = data.get("session_secret")
        if data.get("ok") and secret:
            if self.verify_server_signature(secret):
                self.session_secret = secret
            else:
                raise ApiError("服务器响应签名校验失败，连接可能被篡改")
        return data

    def verify(self, key_code: str, machine_code: str) -> dict:
        return self._signed_request(
            "/api/client/verify", {"key_code": key_code, "machine_code": machine_code}
        )

    def heartbeat(self, key_code: str, machine_code: str) -> dict:
        return self._signed_request(
            "/api/client/heartbeat", {"key_code": key_code, "machine_code": machine_code}
        )
