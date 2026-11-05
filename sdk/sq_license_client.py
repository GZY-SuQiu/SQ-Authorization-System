"""SQ 授权系统 Python SDK：可嵌入第三方软件的许可证客户端。

契约：``docs/BUGFIX-INTERFACE.md`` 第 4 节。实现约束：

- 只依赖 ``core.security`` / ``core.offline`` / ``core.machine`` 与 ``requests``；
- 不读取任何配置文件、不依赖发布清单或 ``core.integrity``；
- 强制校验服务器响应的 Ed25519 签名（``response_public_key`` 必须显式传入）；
- 激活成功后保存 ``session_secret``，``verify`` / ``heartbeat`` 使用 HMAC 请求签名；
- ``machine_code`` 可显式传入，缺省取本机机器码（激活后记住该值）。
"""

from __future__ import annotations

import ipaddress
import json
import socket
from urllib.parse import urlparse

import requests

from core import machine, offline, security

__all__ = [
    "LicenseClient",
    "LicenseError",
    "LicenseSignatureError",
    "LicenseTransportError",
]


class LicenseError(Exception):
    """SDK 统一异常基类。

    ``code`` 是稳定的机器可读原因码（例如 ``no_session``、
    ``response_signature_invalid``、``http_error``）；``status_code``
    仅在服务器返回 HTTP 错误时非零。
    """

    def __init__(self, message: str = "", *, code: str = "", status_code: int = 0):
        super().__init__(str(message or ""))
        self.code = str(code or "")
        try:
            self.status_code = int(status_code or 0)
        except (TypeError, ValueError):
            self.status_code = 0


class LicenseSignatureError(LicenseError):
    """服务器响应签名缺失、不匹配或验签失败（连接可能被篡改）。"""


class LicenseTransportError(LicenseError):
    """网络层失败：连接被拒绝、超时、DNS 解析失败等。"""


def _is_loopback_host(host: str) -> bool:
    """仅当主机名只解析到回环地址时返回 True。"""
    value = (host or "").strip().strip("[]").lower().rstrip(".")
    if not value:
        return False
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(value, None, type=socket.SOCK_STREAM)
    except OSError:
        return False
    addresses = []
    for info in infos:
        try:
            addresses.append(ipaddress.ip_address(str(info[4][0]).split("%", 1)[0]))
        except (IndexError, TypeError, ValueError):
            return False
    return bool(addresses) and all(address.is_loopback for address in addresses)


def _normalize_server_url(url: str, allow_insecure_http: bool = False) -> str:
    value = str(url or "").strip().rstrip("/")
    if not value:
        raise LicenseError("服务器地址不能为空", code="bad_server_url")
    try:
        parsed = urlparse(value)
        parsed.port
    except ValueError as exc:
        raise LicenseError("服务器地址格式无效", code="bad_server_url") from exc
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise LicenseError(
            "服务器地址必须使用 http:// 或 https://", code="bad_server_url"
        )
    if parsed.username or parsed.password:
        raise LicenseError(
            "服务器地址不能包含用户名或密码", code="bad_server_url"
        )
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise LicenseError(
            "服务器地址只能填写协议、主机和端口，不能包含路径或参数",
            code="bad_server_url",
        )
    if (
        parsed.scheme == "http"
        and not allow_insecure_http
        and not _is_loopback_host(parsed.hostname)
    ):
        raise LicenseError(
            "出于安全考虑，远程服务器必须使用 HTTPS；如为本机/内网测试，"
            "请显式允许不安全 HTTP（allow_insecure_http=True）。",
            code="insecure_http_blocked",
        )
    return value


class LicenseClient:
    """面向第三方软件嵌入的最小许可证客户端。

    典型用法::

        client = LicenseClient("https://license.example.com", RESPONSE_PUBLIC_KEY)
        client.activate("GSQ-XXXXX-XXXXX-XXXXX-XXXXX")
        if client.is_valid():
            ...
    """

    def __init__(
        self,
        server_url,
        response_public_key,
        response_key_id="",
        timeout=8,
        allow_insecure_http=False,
        sdk_shared_secret="",
    ):
        self.allow_insecure_http = bool(allow_insecure_http)
        self.server_url = _normalize_server_url(server_url, self.allow_insecure_http)
        self.response_public_key = str(response_public_key or "").strip()
        if not self.response_public_key:
            raise LicenseError(
                "必须提供服务器响应公钥（response_public_key），否则无法验证服务器身份",
                code="response_key_missing",
            )
        self.response_key_id = str(response_key_id or "").strip()
        self.sdk_shared_secret = str(sdk_shared_secret or "").strip()
        try:
            self.timeout = max(1, int(timeout or 8))
        except (TypeError, ValueError):
            self.timeout = 8

        # 会话状态：激活成功后由服务器下发，verify/heartbeat 用它做 HMAC 请求签名。
        self.session_secret: str | None = None
        self.attest_token: str = ""
        # 离线激活码默认走缓存公钥；可显式设置或调用 refresh_offline_public_key()。
        self.offline_public_key: str = ""
        # 最近一次成功激活的绑定信息，verify/heartbeat 缺省复用。
        self.last_key_code: str = ""
        self.last_machine_code: str = ""
        # 最近一次激活/校验响应下发的功能位（Feature Flags）。
        self._features: list[str] = []

    # ------------------------------------------------------------------ #
    # 契约第 4 节方法
    # ------------------------------------------------------------------ #
    def machine_code(self) -> str:
        """返回本机机器码（大写）。"""
        try:
            value = str(machine.machine_code() or "").strip().upper()
        except Exception as exc:  # 机器指纹异常时给出统一异常
            raise LicenseError(
                f"无法获取本机机器码：{exc}", code="machine_code_failed"
            ) from exc
        if not value:
            raise LicenseError("无法获取本机机器码", code="machine_code_failed")
        return value

    def activate(self, key_code, machine_code=None, device_name="") -> dict:
        """激活本设备。返回服务器原始响应（``ok``/``code`` 字段保持不变）。"""
        key = security.normalize_key(key_code)
        if not key:
            raise LicenseError("密钥不能为空", code="bad_request")
        target_machine = str(machine_code or "").strip().upper() or self.machine_code()
        data = self._request(
            "POST",
            "/api/client/activate",
            json_body={
                "key_code": key,
                "machine_code": target_machine,
                "device_name": str(device_name or "").strip(),
            },
        )
        secret = data.get("session_secret")
        if data.get("ok") and secret:
            self.session_secret = str(secret)
            self.last_key_code = key
            self.last_machine_code = target_machine
        if isinstance(data, dict) and data.get("ok"):
            self._remember_features(data)
        return data

    def verify(self, key_code=None, machine_code=None) -> dict:
        """校验本机授权；缺省复用最近一次激活的密钥与机器码。"""
        self._require_session()
        data = self._request(
            "POST",
            "/api/client/verify",
            json_body={
                "key_code": self._resolve_key(key_code),
                "machine_code": self._resolve_machine(machine_code),
            },
            sign_with_session=True,
        )
        if isinstance(data, dict) and data.get("ok"):
            self._remember_features(data)
        return data

    def heartbeat(self, key_code=None, machine_code=None) -> dict:
        """发送心跳；缺省复用最近一次激活的密钥与机器码。"""
        self._require_session()
        return self._request(
            "POST",
            "/api/client/heartbeat",
            json_body={
                "key_code": self._resolve_key(key_code),
                "machine_code": self._resolve_machine(machine_code),
            },
            sign_with_session=True,
        )

    # ------------------------------------------------------------------ #
    # Feature flags（功能位授权）
    # ------------------------------------------------------------------ #
    def _remember_features(self, data: dict) -> None:
        features = data.get("features") if isinstance(data, dict) else None
        if isinstance(features, list):
            self._features = [str(item) for item in features if isinstance(item, str)]

    def features(self) -> list[str]:
        """最近一次激活/校验响应下发的功能位列表（无则空列表）。"""
        return list(self._features)

    def has_feature(self, name: str) -> bool:
        """便捷判断：指定功能位是否被授权（大小写不敏感）。"""
        needle = str(name or "").strip().lower()
        return bool(needle) and needle in {item.lower() for item in self._features}

    def is_valid(self, key_code=None, machine_code=None) -> bool:
        """便捷封装：任何失败（网络/签名/授权）一律返回 False。"""
        try:
            data = self.verify(key_code=key_code, machine_code=machine_code)
        except LicenseError:
            return False
        return bool(isinstance(data, dict) and data.get("ok"))

    def verify_offline(self, activation_code, machine_code=None) -> dict:
        """本地校验离线激活码（Ed25519 签名 + 机器码 + 到期时间）。

        离线公钥优先取 ``self.offline_public_key``；为空时尝试联网从
        ``/api/public_key`` 获取并缓存，获取失败则返回 ``offline_key_missing``，
        绝不抛出网络异常。
        """
        code = offline.clean_code(activation_code)
        if not code:
            return {
                "ok": False,
                "code": "bad_request",
                "message": "离线激活码不能为空",
            }
        public_key = self._offline_key()
        if not public_key:
            return {
                "ok": False,
                "code": "offline_key_missing",
                "message": "缺少离线公钥，无法校验离线激活码",
            }
        payload = offline.parse_activation_code(code, public_key)
        if not isinstance(payload, dict):
            return {
                "ok": False,
                "code": "invalid_code",
                "message": "离线激活码无效或签名校验失败",
            }
        expected_machine = (
            str(machine_code or "").strip().upper() or self.last_machine_code
        )
        if not expected_machine:
            try:
                expected_machine = self.machine_code()
            except LicenseError as exc:
                # 取不到本机机器码时按失败处理，绝不跳过机器绑定校验。
                return {
                    "ok": False,
                    "code": "machine_code_failed",
                    "message": str(exc),
                }
        actual_machine = str(payload.get("mc") or "").strip().upper()
        if actual_machine and expected_machine and actual_machine != expected_machine:
            return {
                "ok": False,
                "code": "machine_mismatch",
                "message": (
                    f"离线激活码绑定机器码 {actual_machine}，"
                    f"与本机 {expected_machine} 不一致"
                ),
                "machine_code": actual_machine,
                "expected_machine_code": expected_machine,
            }
        expires_at = payload.get("exp")
        if expires_at and security.is_expired(expires_at):
            return {
                "ok": False,
                "code": "expired",
                "message": f"离线激活码已过期（{expires_at}）",
                "expires_at": expires_at,
            }
        return {
            "ok": True,
            "code": "valid",
            "message": "离线激活码验证通过",
            "key_code": str(payload.get("key") or ""),
            "machine_code": actual_machine,
            "expires_at": expires_at,
            "days_left": security.days_left(expires_at),
            "remaining": security.humanize_remaining(expires_at),
            "payload": payload,
        }

    def reset_session(self) -> None:
        """清空会话密钥与激活记忆（离线公钥保留）。"""
        self.session_secret = None
        self.attest_token = ""
        self.last_key_code = ""
        self.last_machine_code = ""

    # ------------------------------------------------------------------ #
    # 扩展辅助（契约之外，方便嵌入方使用）
    # ------------------------------------------------------------------ #
    def set_offline_public_key(self, public_key_hex: str) -> None:
        """显式固定离线公钥（纯离线环境请使用本方法）。"""
        self.offline_public_key = str(public_key_hex or "").strip()

    def refresh_offline_public_key(self) -> str:
        """联网获取服务器离线公钥并缓存，返回公钥 hex（失败时为空串）。"""
        try:
            data = self._request("GET", "/api/public_key")
        except LicenseError:
            return ""
        key = str(data.get("offline_public_key") or data.get("public_key") or "").strip()
        if key:
            self.offline_public_key = key
        return key

    # ------------------------------------------------------------------ #
    # 内部实现
    # ------------------------------------------------------------------ #
    def _offline_key(self) -> str:
        key = str(self.offline_public_key or "").strip()
        if key:
            return key
        return self.refresh_offline_public_key()

    def _require_session(self) -> None:
        if not self.session_secret:
            raise LicenseError("缺少会话密钥，请先激活本设备", code="no_session")

    def _resolve_key(self, key_code=None) -> str:
        key = security.normalize_key(key_code) or self.last_key_code
        if not key:
            raise LicenseError(
                "缺少密钥，请先激活或显式传入 key_code", code="no_key"
            )
        return key

    def _resolve_machine(self, machine_code=None) -> str:
        value = str(machine_code or "").strip().upper()
        if value:
            return value
        if self.last_machine_code:
            return self.last_machine_code
        return self.machine_code()

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict | None = None,
        sign_with_session: bool = False,
    ) -> dict:
        if sign_with_session and not self.session_secret:
            raise LicenseError("缺少会话密钥，请先激活本设备", code="no_session")
        body = None
        if json_body is not None:
            body = json.dumps(
                json_body, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        timestamp = security.now_ts()
        nonce = security.make_nonce()
        headers = {
            "Accept": "application/json",
            "X-Client-Timestamp": str(timestamp),
            "X-Client-Nonce": nonce,
            "X-Client-Kind": "sdk",
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        if sign_with_session:
            headers["X-Client-Signature"] = security.sign_request(
                self.session_secret or "", method, path, timestamp, nonce, body, ""
            )
        attest = str(self.attest_token or "").strip()
        if attest:
            headers["X-Attest-Token"] = attest
        if self.sdk_shared_secret:
            try:
                headers["X-SDK-Token"] = security.hash_action_code(
                    self.sdk_shared_secret, self.machine_code()
                )
            except Exception:
                pass

        try:
            response = requests.request(
                method,
                self.server_url + path,
                headers=headers,
                data=body,
                timeout=self.timeout,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            raise LicenseTransportError(
                f"无法连接服务器（{self.server_url}）：{exc}",
                code="transport_error",
            ) from exc
        if 300 <= response.status_code < 400:
            # 重定向会把已签名的请求头重放到其他目标，直接拒绝。
            raise LicenseError(
                "服务器返回了意外的重定向，已中止请求", code="redirect"
            )
        self._verify_response(method, path, timestamp, nonce, response)
        return self._decode_response(response)

    def _verify_response(self, method, path, timestamp, nonce, response) -> None:
        """强制 Ed25519 验签：任何响应（含错误响应）都必须通过。"""
        signature = str(response.headers.get("X-Server-Signature") or "").strip()
        key_id = str(response.headers.get("X-Server-Key-Id") or "").strip()
        if not signature:
            raise LicenseSignatureError(
                "服务器未提供可验证的响应签名",
                code="signature_missing",
                status_code=response.status_code,
            )
        if self.response_key_id and key_id and key_id != self.response_key_id:
            raise LicenseSignatureError(
                "服务器响应密钥标识不匹配",
                code="response_key_mismatch",
                status_code=response.status_code,
            )
        message = security.canonical_response_message(
            method,
            path,
            timestamp,
            nonce,
            response.status_code,
            response.content,
            key_id or self.response_key_id,
            "",
        )
        if not offline.verify_message(self.response_public_key, message, signature):
            raise LicenseSignatureError(
                "服务器响应签名校验失败，连接可能被篡改",
                code="response_signature_invalid",
                status_code=response.status_code,
            )

    @staticmethod
    def _decode_response(response) -> dict:
        if not response.content:
            data: dict = {}
        else:
            try:
                data = response.json()
            except Exception as exc:
                raise LicenseError(
                    "服务器返回数据格式错误",
                    code="bad_response",
                    status_code=response.status_code,
                ) from exc
            if not isinstance(data, dict):
                raise LicenseError(
                    "服务器返回数据格式错误",
                    code="bad_response",
                    status_code=response.status_code,
                )
        if response.status_code >= 400:
            code = str(data.get("code") or "http_error")
            message = str(data.get("message") or "").strip()
            detail = data.get("detail")
            if not message:
                if isinstance(detail, str):
                    message = detail
                elif detail is not None:
                    message = json.dumps(detail, ensure_ascii=False)
            raise LicenseError(
                message or f"HTTP {response.status_code}",
                code=code,
                status_code=response.status_code,
            )
        return data
