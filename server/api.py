import json
import threading
import time

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from core import offline, security
from core.config import Config
from core.database import Database

VERSION = "1.0.0"

_login_guard: dict[str, list[float]] = {}
_login_lock = threading.Lock()


def _login_allowed(key: str, max_attempts: int, lock_seconds: int) -> bool:
    now = time.time()
    with _login_lock:
        records = [t for t in _login_guard.get(key, []) if now - t < lock_seconds]
        _login_guard[key] = records
        return len(records) < max_attempts


def _record_login_failure(key: str, lock_seconds: int) -> None:
    now = time.time()
    with _login_lock:
        records = [t for t in _login_guard.get(key, []) if now - t < lock_seconds]
        records.append(now)
        _login_guard[key] = records


def _clear_login_failures(key: str) -> None:
    with _login_lock:
        _login_guard.pop(key, None)


def _signed_response(secret: str, data: dict) -> Response:
    body = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    headers = {"X-Server-Signature": security.sign_response(secret, body)}
    return Response(content=body, media_type="application/json", headers=headers)


def _check_signed_request(
    request: Request, raw_body: bytes, secret: str, window: int
) -> tuple[bool, str]:
    ts = request.headers.get("X-Client-Timestamp", "")
    nonce = request.headers.get("X-Client-Nonce", "")
    sig = request.headers.get("X-Client-Signature", "")
    if not ts or not nonce or not sig:
        return False, "缺少请求签名"
    if not security.within_time_window(ts, window=window):
        return False, "请求时间戳已过期"
    if not security.verify_request_signature(
        secret, request.method, request.url.path, ts, nonce, raw_body, sig
    ):
        return False, "请求签名校验失败"
    return True, ""


def _read_payload(raw: bytes) -> dict:
    try:
        data = json.loads(raw or b"{}")
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


class LoginBody(BaseModel):
    username: str
    password: str


class GenerateBody(BaseModel):
    count: int = Field(default=1, ge=1, le=500)
    edition: str = "standard"
    duration_days: int = Field(default=0, ge=0)
    duration_unit: str = "day"
    max_devices: int = Field(default=1, ge=0)
    note: str = ""
    prefix: str = ""


class KeyBody(BaseModel):
    key_code: str


class UnbindBody(BaseModel):
    key_code: str
    machine_code: str


class BatchBody(BaseModel):
    batch_no: str


class FreezeBody(BaseModel):
    key_code: str
    amount: int = Field(default=1, ge=1, le=100000)
    unit: str = "hour"
    reason: str = ""


class AdminCreateBody(BaseModel):
    username: str
    password: str
    role: str = "admin"


class AdminStatusBody(BaseModel):
    admin_id: int
    status: str


class AdminPasswordBody(BaseModel):
    admin_id: int
    password: str


class ActivateBody(BaseModel):
    key_code: str
    machine_code: str
    device_name: str = ""


class OfflineCodeBody(BaseModel):
    key_code: str
    machine_code: str = ""
    device_name: str = ""


def _client_ip(request: Request) -> str:
    if request.client:
        return request.client.host
    return ""


def _frozen_block(db: Database, lic: dict) -> dict | None:
    if not lic or lic["status"] != "frozen":
        return None
    remaining = security.humanize_remaining(lic.get("frozen_until"))
    reason = lic.get("freeze_reason") or ""
    tip = f"该密钥已被冻结，剩余 {remaining}"
    if reason:
        tip += f"（原因：{reason}）"
    return {"ok": False, "code": "frozen", "message": tip}


def do_activate(
    db: Database, key_code: str, machine_code: str, device_name: str, ip: str, session_secret: str
) -> dict:
    key_code = security.normalize_key(key_code)
    machine_code = (machine_code or "").strip().upper()
    if not key_code or not machine_code:
        return {"ok": False, "code": "bad_request", "message": "密钥和机器码不能为空"}

    db.release_expired_freeze(key_code)
    lic = db.get_license(key_code)
    if not lic:
        db.add_log("激活失败", "client", key_code, "密钥不存在", ip)
        return {"ok": False, "code": "not_found", "message": "密钥不存在，请核对后重试"}
    blocked = _frozen_block(db, lic)
    if blocked:
        db.add_log("激活失败", "client", key_code, "密钥已冻结", ip)
        return blocked
    if lic["status"] == "revoked":
        return {"ok": False, "code": "revoked", "message": "该密钥已被吊销，无法激活"}
    if lic["status"] == "expired" or security.is_expired(lic["expires_at"]):
        db.set_license_status(key_code, "expired")
        return {"ok": False, "code": "expired", "message": "该密钥已过期"}

    existing = db.get_activation(key_code, machine_code)
    if existing and existing["status"] == "active":
        db.update_activation_verified(existing["id"])
        db.set_activation_session(existing["id"], session_secret)
        expiry = existing["expires_at"] or lic["expires_at"]
        return {
            "ok": True,
            "code": "already",
            "message": "该设备已激活",
            "session_secret": session_secret,
            "expires_at": expiry,
            "days_left": security.days_left(expiry),
            "remaining": security.humanize_remaining(expiry),
            "server_ts": security.now_ts(),
        }

    max_devices = lic["max_devices"] or 0
    if max_devices and db.count_active_activations(lic["id"]) >= max_devices:
        db.add_log("激活失败", "client", key_code, "设备数达上限", ip)
        return {
            "ok": False,
            "code": "limit",
            "message": f"该密钥最多绑定 {max_devices} 台设备，已达上限",
        }

    expires_at = lic["expires_at"]
    if not expires_at and lic["duration_days"] and lic["duration_days"] > 0:
        expires_at = security.compute_expiry(
            lic["duration_days"], lic.get("duration_unit") or "day"
        )
        db.update_license_expiry(key_code, expires_at)

    if existing:
        db.reactivate_activation(existing["id"], device_name, expires_at)
        activation_id = existing["id"]
    else:
        activation_id = db.create_activation(
            lic["id"], key_code, machine_code, device_name, expires_at
        )
    db.set_activation_session(activation_id, session_secret)
    db.set_license_activated(key_code)
    db.add_log("激活成功", "client", key_code, f"设备 {device_name or machine_code}", ip)
    return {
        "ok": True,
        "code": "activated",
        "message": "激活成功",
        "session_secret": session_secret,
        "expires_at": expires_at,
        "days_left": security.days_left(expires_at),
        "remaining": security.humanize_remaining(expires_at),
        "server_ts": security.now_ts(),
    }


def do_verify(db: Database, key_code: str, machine_code: str) -> dict:
    key_code = security.normalize_key(key_code)
    machine_code = (machine_code or "").strip().upper()
    if not key_code or not machine_code:
        return {"ok": False, "code": "bad_request", "message": "密钥和机器码不能为空"}

    db.release_expired_freeze(key_code)
    lic = db.get_license(key_code)
    if not lic:
        return {"ok": False, "code": "not_found", "message": "密钥不存在"}
    blocked = _frozen_block(db, lic)
    if blocked:
        return blocked
    if lic["status"] == "revoked":
        return {"ok": False, "code": "revoked", "message": "该密钥已被吊销"}
    if lic["status"] == "expired" or security.is_expired(lic["expires_at"]):
        db.set_license_status(key_code, "expired")
        return {"ok": False, "code": "expired", "message": "该密钥已过期"}

    act = db.get_activation(key_code, machine_code)
    if not act or act["status"] != "active":
        return {"ok": False, "code": "not_activated", "message": "本设备尚未激活"}

    expiry = act["expires_at"] or lic["expires_at"]
    if security.is_expired(expiry):
        return {"ok": False, "code": "expired", "message": "该密钥已过期"}
    db.update_activation_verified(act["id"])
    return {
        "ok": True,
        "code": "valid",
        "message": "验证通过",
        "expires_at": expiry,
        "days_left": security.days_left(expiry),
        "remaining": security.humanize_remaining(expiry),
    }


def create_app(config: Config, db: Database) -> FastAPI:
    secret = config.security["secret_key"]
    ttl = int(config.security.get("token_ttl_hours", 12) * 3600)
    default_prefix = config.security.get("key_prefix", "LIC") or "LIC"
    sign_window = int(config.security.get("signature_window_seconds", 300))
    login_max_attempts = int(config.security.get("login_max_attempts", 5))
    login_lock_seconds = int(config.security.get("login_lock_seconds", 300))
    heartbeat_base = float(config.client.get("heartbeat_interval", 20))
    heartbeat_spread = float(config.client.get("heartbeat_jitter", 0.35))
    offline_private = config.security.get("offline_private_key", "") or ""
    offline_public = config.security.get("offline_public_key", "") or ""

    app = FastAPI(title="密钥授权本地服务器", version=VERSION)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    def current_admin(authorization: str | None = Header(default=None)) -> dict:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="未登录或登录状态无效")
        payload = security.verify_token(authorization.split(" ", 1)[1].strip(), secret)
        if not payload:
            raise HTTPException(status_code=401, detail="登录已过期，请重新登录")
        admin = db.get_admin_by_id(int(payload.get("uid", 0)))
        if not admin:
            raise HTTPException(status_code=401, detail="账号不存在")
        if admin["status"] != "active":
            raise HTTPException(status_code=403, detail="账号已被禁用")
        return admin

    def require_master(admin: dict = Depends(current_admin)) -> dict:
        if admin["role"] != "master":
            raise HTTPException(status_code=403, detail="需要主控权限")
        return admin

    @app.get("/api/health")
    def health():
        return {
            "status": "ok",
            "version": VERSION,
            "time": security.now_str(),
            "ts": security.now_ts(),
            "server": f"{config.server['host']}:{config.server['port']}",
        }

    @app.get("/api/public_key")
    def public_key():
        return {"public_key": offline_public, "algorithm": "ed25519"}

    @app.post("/api/admin/login")
    def login(body: LoginBody, request: Request):
        ip = _client_ip(request)
        guard_key = f"{ip}|{body.username.strip().lower()}"
        if not _login_allowed(guard_key, login_max_attempts, login_lock_seconds):
            db.add_log("登录锁定", body.username, "", "尝试过于频繁", ip)
            raise HTTPException(status_code=429, detail="尝试过于频繁，请稍后再试")
        admin = db.get_admin(body.username)
        if not admin or not security.verify_password(body.password, admin["password_hash"], admin["salt"]):
            _record_login_failure(guard_key, login_lock_seconds)
            db.add_log("登录失败", body.username, "", "用户名或密码错误", ip)
            raise HTTPException(status_code=401, detail="用户名或密码错误")
        if admin["status"] != "active":
            raise HTTPException(status_code=403, detail="账号已被禁用")
        _clear_login_failures(guard_key)
        db.touch_admin_login(admin["id"])
        db.add_log("登录成功", admin["username"], "", f"角色 {admin['role']}", ip)
        token = security.create_token(
            {"uid": admin["id"], "username": admin["username"], "role": admin["role"]},
            secret,
            ttl,
        )
        return {
            "token": token,
            "username": admin["username"],
            "role": admin["role"],
            "expires_in": ttl,
        }

    @app.get("/api/admin/me")
    def me(admin: dict = Depends(current_admin)):
        return {"id": admin["id"], "username": admin["username"], "role": admin["role"]}

    @app.post("/api/license/generate")
    def generate(body: GenerateBody, admin: dict = Depends(current_admin)):
        batch_no, keys = db.generate_licenses(
            count=body.count,
            edition=body.edition or "standard",
            duration_days=body.duration_days,
            max_devices=body.max_devices,
            note=body.note,
            created_by=admin["username"],
            prefix=(body.prefix or default_prefix).upper(),
            duration_unit=body.duration_unit,
        )
        db.add_log("生成密钥", admin["username"], batch_no, f"共 {len(keys)} 个", "")
        return {"batch_no": batch_no, "count": len(keys), "keys": keys}

    @app.get("/api/license/list")
    def list_licenses(
        keyword: str = "",
        status: str = "",
        batch_no: str = "",
        limit: int = 200,
        offset: int = 0,
        admin: dict = Depends(current_admin),
    ):
        items = db.list_licenses(keyword, status, batch_no, limit, offset)
        total = db.count_licenses(keyword, status)
        return {"items": items, "total": total}

    @app.get("/api/license/detail")
    def license_detail(key_code: str, admin: dict = Depends(current_admin)):
        lic = db.get_license(key_code)
        if not lic:
            raise HTTPException(status_code=404, detail="密钥不存在")
        return {"license": lic, "activations": db.list_activations(key_code)}

    @app.post("/api/license/offline_code")
    def offline_code(body: OfflineCodeBody, admin: dict = Depends(current_admin)):
        key_code = security.normalize_key(body.key_code)
        machine_code = (body.machine_code or "").strip().upper()
        if not key_code or not machine_code:
            raise HTTPException(status_code=400, detail="密钥和机器码不能为空")
        db.release_expired_freeze(key_code)
        lic = db.get_license(key_code)
        if not lic:
            raise HTTPException(status_code=404, detail="密钥不存在")
        if lic["status"] == "frozen":
            remaining = security.humanize_remaining(lic.get("frozen_until"))
            raise HTTPException(status_code=400, detail=f"该密钥已被冻结（剩余 {remaining}），无法生成离线激活码")
        if lic["status"] == "revoked":
            raise HTTPException(status_code=400, detail="该密钥已被吊销，无法生成离线激活码")
        if not offline_private:
            raise HTTPException(status_code=500, detail="服务器未配置离线签名私钥")

        existing = db.get_activation(key_code, machine_code)
        max_devices = lic["max_devices"] or 0
        if max_devices and (not existing or existing["status"] != "active"):
            if db.count_active_activations(lic["id"]) >= max_devices:
                raise HTTPException(
                    status_code=400,
                    detail=f"该密钥最多绑定 {max_devices} 台设备，已达上限",
                )

        expiry = lic["expires_at"]
        if not expiry and lic["duration_days"] and lic["duration_days"] > 0:
            expiry = security.compute_expiry(
                lic["duration_days"], lic.get("duration_unit") or "day"
            )
            db.update_license_expiry(key_code, expiry)

        if existing:
            db.reactivate_activation(existing["id"], body.device_name, expiry)
        else:
            db.create_activation(lic["id"], key_code, machine_code, body.device_name, expiry)
        db.set_license_activated(key_code)

        payload = offline.build_activation_payload(
            machine_code=machine_code,
            key_code=key_code,
            edition=lic["edition"],
            duration_days=lic["duration_days"],
            expires_at=expiry,
            max_devices=lic["max_devices"],
            note=lic["note"] or "",
        )
        code = offline.make_activation_code(payload, offline_private)
        db.add_log("生成离线激活码", admin["username"], key_code, f"设备 {machine_code}", "")
        return {
            "ok": True,
            "code": code,
            "key_code": key_code,
            "machine_code": machine_code,
            "expires_at": expiry,
            "remaining": security.humanize_remaining(expiry),
            "duration_text": security.duration_text(
                lic["duration_days"], lic.get("duration_unit") or "day"
            ),
        }

    @app.post("/api/license/revoke")
    def revoke(body: KeyBody, admin: dict = Depends(current_admin)):
        if not db.get_license(body.key_code):
            raise HTTPException(status_code=404, detail="密钥不存在")
        db.set_license_status(body.key_code, "revoked")
        db.add_log("吊销密钥", admin["username"], security.normalize_key(body.key_code), "", "")
        return {"ok": True, "message": "已吊销"}

    @app.post("/api/license/restore")
    def restore(body: KeyBody, admin: dict = Depends(current_admin)):
        lic = db.get_license(body.key_code)
        if not lic:
            raise HTTPException(status_code=404, detail="密钥不存在")
        target = db.restore_license(body.key_code)
        if target is None:
            raise HTTPException(status_code=400, detail="该密钥当前不可恢复（仅吊销/过期的密钥可恢复）")
        db.add_log("恢复密钥", admin["username"], security.normalize_key(body.key_code), f"恢复为 {target}", "")
        return {"ok": True, "status": target, "message": "已恢复"}

    @app.post("/api/license/freeze")
    def freeze(body: FreezeBody, admin: dict = Depends(current_admin)):
        if not db.get_license(body.key_code):
            raise HTTPException(status_code=404, detail="密钥不存在")
        unit = security.normalize_unit(body.unit)
        frozen_until = security.compute_freeze_until(body.amount, unit)
        if not frozen_until:
            raise HTTPException(status_code=400, detail="冻结时长必须大于 0")
        prev = db.freeze_license(body.key_code, frozen_until, body.reason)
        if prev is None:
            raise HTTPException(status_code=400, detail="该密钥已被吊销或过期，无法冻结")
        span = security.duration_text(body.amount, unit)
        db.add_log("冻结密钥", admin["username"], security.normalize_key(body.key_code),
                   f"{span} | {body.reason}", "")
        return {"ok": True, "frozen_until": frozen_until, "message": f"已冻结 {span}"}

    @app.post("/api/license/unfreeze")
    def unfreeze(body: KeyBody, admin: dict = Depends(current_admin)):
        if not db.get_license(body.key_code):
            raise HTTPException(status_code=404, detail="密钥不存在")
        target = db.unfreeze_license(body.key_code)
        if target is None:
            raise HTTPException(status_code=400, detail="该密钥当前不处于冻结状态")
        db.add_log("解冻密钥", admin["username"], security.normalize_key(body.key_code), f"恢复为 {target}", "")
        return {"ok": True, "status": target, "message": "已解冻"}

    @app.post("/api/license/revoke_batch")
    def revoke_batch(body: BatchBody, admin: dict = Depends(current_admin)):
        count = db.revoke_batch(body.batch_no)
        db.add_log("吊销批次", admin["username"], body.batch_no, f"共 {count} 个", "")
        return {"ok": True, "count": count}

    @app.post("/api/license/delete")
    def delete_license(body: KeyBody, admin: dict = Depends(current_admin)):
        if not db.get_license(body.key_code):
            raise HTTPException(status_code=404, detail="密钥不存在")
        db.delete_license(body.key_code)
        db.add_log("删除密钥", admin["username"], security.normalize_key(body.key_code), "", "")
        return {"ok": True}

    @app.post("/api/license/unbind")
    def unbind(body: UnbindBody, admin: dict = Depends(current_admin)):
        db.unbind_activation(body.key_code, body.machine_code)
        db.add_log("解绑设备", admin["username"], security.normalize_key(body.key_code), body.machine_code, "")
        return {"ok": True}

    @app.get("/api/license/stats")
    def stats(admin: dict = Depends(current_admin)):
        return db.stats()

    @app.get("/api/admin/list")
    def admin_list(admin: dict = Depends(require_master)):
        return {"items": db.list_admins()}

    @app.post("/api/admin/create")
    def admin_create(body: AdminCreateBody, admin: dict = Depends(require_master)):
        if db.get_admin(body.username):
            raise HTTPException(status_code=400, detail="用户名已存在")
        ok, msg = security.password_strength(body.password)
        if not ok:
            raise HTTPException(status_code=400, detail=msg)
        if body.role not in ("admin", "master"):
            body.role = "admin"
        admin_id = db.create_admin(body.username, body.password, body.role)
        db.add_log("创建管理员", admin["username"], body.username, f"角色 {body.role}", "")
        return {"ok": True, "id": admin_id}

    @app.post("/api/admin/status")
    def admin_status(body: AdminStatusBody, admin: dict = Depends(require_master)):
        if body.status not in ("active", "disabled"):
            raise HTTPException(status_code=400, detail="状态非法")
        if body.admin_id == admin["id"]:
            raise HTTPException(status_code=400, detail="不能修改自己的状态")
        db.set_admin_status(body.admin_id, body.status)
        db.add_log("修改管理员状态", admin["username"], str(body.admin_id), body.status, "")
        return {"ok": True}

    @app.post("/api/admin/password")
    def admin_password(body: AdminPasswordBody, admin: dict = Depends(require_master)):
        if body.admin_id == admin["id"]:
            raise HTTPException(status_code=400, detail="请在个人设置中修改自己的密码")
        ok, msg = security.password_strength(body.password)
        if not ok:
            raise HTTPException(status_code=400, detail=msg)
        db.set_admin_password(body.admin_id, body.password)
        db.add_log("重置管理员密码", admin["username"], str(body.admin_id), "", "")
        return {"ok": True}

    @app.get("/api/logs")
    def logs(limit: int = 200, admin: dict = Depends(current_admin)):
        return {"items": db.list_logs(limit)}

    @app.post("/api/client/activate")
    def activate(body: ActivateBody, request: Request):
        session_secret = security.generate_session_secret()
        result = do_activate(
            db,
            body.key_code,
            body.machine_code,
            body.device_name,
            _client_ip(request),
            session_secret,
        )
        if result.get("ok"):
            return _signed_response(session_secret, result)
        return result

    @app.post("/api/client/verify")
    async def verify(request: Request):
        raw = await request.body()
        payload = _read_payload(raw)
        key_code = security.normalize_key(payload.get("key_code", ""))
        machine_code = (payload.get("machine_code", "") or "").strip().upper()

        act = db.get_activation(key_code, machine_code)
        if not act or not act.get("session_secret"):
            resp = {
                "ok": False,
                "code": "unauthenticated",
                "message": "本设备尚未激活或会话已失效，请重新激活",
            }
            return _signed_response(security.generate_session_secret(), resp)
        secret_sess = act["session_secret"]

        ok, msg = _check_signed_request(request, raw, secret_sess, sign_window)
        if not ok:
            db.add_log("签名校验失败", "client", key_code, msg, _client_ip(request))
            return _signed_response(
                secret_sess, {"ok": False, "code": "signature_invalid", "message": msg}
            )

        ts = int(request.headers.get("X-Client-Timestamp", "0"))
        nonce = request.headers.get("X-Client-Nonce", "")
        db.prune_nonces(ts - sign_window - 60)
        if db.seen_nonce(nonce, key_code):
            db.add_log("重放拦截", "client", key_code, "nonce 重复", _client_ip(request))
            return _signed_response(
                secret_sess, {"ok": False, "code": "replay", "message": "重复请求已被拦截"}
            )

        result = do_verify(db, key_code, machine_code)
        result["server_ts"] = security.now_ts()
        return _signed_response(secret_sess, result)

    @app.post("/api/client/heartbeat")
    async def heartbeat(request: Request):
        raw = await request.body()
        payload = _read_payload(raw)
        key_code = security.normalize_key(payload.get("key_code", ""))
        machine_code = (payload.get("machine_code", "") or "").strip().upper()

        act = db.get_activation(key_code, machine_code)
        if not act or not act.get("session_secret"):
            resp = {"ok": False, "code": "unauthenticated", "message": "尚未激活"}
            return _signed_response(security.generate_session_secret(), resp)
        secret_sess = act["session_secret"]

        ok, msg = _check_signed_request(request, raw, secret_sess, sign_window)
        if not ok:
            return _signed_response(
                secret_sess, {"ok": False, "code": "signature_invalid", "message": msg}
            )

        ts = int(request.headers.get("X-Client-Timestamp", "0"))
        nonce = request.headers.get("X-Client-Nonce", "")
        db.prune_nonces(ts - sign_window - 60)
        if db.seen_nonce(nonce, key_code):
            return _signed_response(
                secret_sess, {"ok": False, "code": "replay", "message": "重复请求已被拦截"}
            )

        interval = security.heartbeat_jitter(heartbeat_base, heartbeat_spread)
        server_ts = security.now_ts()
        if act["status"] != "active":
            return _signed_response(
                secret_sess,
                {
                    "ok": False,
                    "code": "not_active",
                    "message": "授权未处于激活状态",
                    "next_interval": interval,
                    "server_ts": server_ts,
                },
            )
        db.release_expired_freeze(key_code)
        lic = db.get_license(key_code)
        expiry = act["expires_at"] or (lic["expires_at"] if lic else None)
        if lic and lic["status"] == "frozen":
            remaining = security.humanize_remaining(lic.get("frozen_until"))
            reason = lic.get("freeze_reason") or ""
            message = f"授权已被冻结，剩余 {remaining}"
            if reason:
                message += f"（原因：{reason}）"
            return _signed_response(
                secret_sess,
                {
                    "ok": False,
                    "code": "frozen",
                    "message": message,
                    "frozen_until": lic.get("frozen_until"),
                    "next_interval": interval,
                    "server_ts": server_ts,
                },
            )
        if (lic and lic["status"] == "revoked") or security.is_expired(expiry):
            return _signed_response(
                secret_sess,
                {
                    "ok": False,
                    "code": "expired",
                    "message": "授权已失效",
                    "next_interval": interval,
                    "server_ts": server_ts,
                },
            )
        db.touch_heartbeat(act["id"])
        return _signed_response(
            secret_sess,
            {
                "ok": True,
                "code": "alive",
                "message": "在线",
                "expires_at": expiry,
                "days_left": security.days_left(expiry),
                "remaining": security.humanize_remaining(expiry),
                "next_interval": interval,
                "server_ts": server_ts,
                "heartbeat_count": int(act.get("heartbeat_count") or 0) + 1,
            },
        )

    return app
