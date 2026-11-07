from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable

from core import security, offline
from core.database import Database, is_activation_card


UNITS = tuple(security.UNIT_SECONDS.keys())
UNIT_HELP = "有效期单位：minute/hour/day/week/month/quarter/year"
STATUS_VALUES = ("", "unused", "active", "frozen", "revoked", "expired")

# P1-6: every tool that changes server state must go through the two-phase
# confirmation gate in ``AiGateway._run_tool``. Read tools stay immediate.
# Alert-rule writes are not exposed to the AI registry today; if they are added
# later their tool names must land in this set as well.
WRITE_TOOL_NAMES = frozenset(
    {
        "generate_licenses",
        "set_license_status",
        "rebind_license",
        "renew_licenses",
        "delete_licenses",
        "unbind_device",
        "create_offline_code",
        "create_admin",
        "set_admin_status",
        "reset_admin_password",
    }
)

_ACTION_LABELS = {
    "revoke": "吊销",
    "restore": "恢复",
    "freeze": "冻结",
    "unfreeze": "解冻",
}


class ToolError(Exception):
    """Raised when a tool call cannot be completed or is not permitted."""


# 提示注入特征（用于备注/原因等自由文本字段的审计告警；只告警不拦截）。
_INJECTION_HINTS = (
    "忽略之前的", "忽略以上", "忽略所有", "无视之前", "无视以上",
    "ignore previous", "ignore all", "ignore above", "disregard",
    "system prompt", "系统提示词", "系统指令", "新的指令", "指令如下",
    "you are now", "从现在开始你",
)


def _scan_note_injection(text: str) -> bool:
    """轻量提示注入特征扫描：命中仅记审计告警，不阻断业务。"""
    value = str(text or "").lower()
    return any(hint in value for hint in _INJECTION_HINTS)


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    parameters: dict
    handler: Callable[..., Any]
    admin_only: bool = False
    # ``mutating`` marks a write tool: the gateway stages it for operator
    # confirmation instead of executing it on the model's behalf.
    mutating: bool = False


def _obj(properties: dict, required: list[str] | None = None) -> dict:
    return {
        "type": "object",
        "properties": properties,
        "required": required or [],
        "additionalProperties": False,
    }


def _string(description: str, **extra) -> dict:
    out = {"type": "string", "description": description}
    out.update(extra)
    return out


def _integer(description: str, minimum: int | None = None, maximum: int | None = None) -> dict:
    out: dict = {"type": "integer", "description": description}
    if minimum is not None:
        out["minimum"] = minimum
    if maximum is not None:
        out["maximum"] = maximum
    return out


def _unit_schema(default: str = "day") -> dict:
    return _string(UNIT_HELP, enum=list(UNITS), default=default)


def _key_list_schema() -> dict:
    return {
        "type": "array",
        "items": _string("完整卡密，例如 GSQ-XXXXX-XXXXX-XXXXX-XXXXX"),
        "minItems": 1,
        "maxItems": 500,
        "description": "需要处理的完整卡密列表",
    }


def _as_int(value: Any, name: str, minimum: int = 1, maximum: int = 10_000_000) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ToolError(f"参数 {name} 必须是整数") from None
    if number < minimum or number > maximum:
        raise ToolError(f"参数 {name} 超出允许范围")
    return number


def _as_text(value: Any, name: str, *, required: bool = False, max_length: int = 500) -> str:
    text = "" if value is None else str(value)
    text = text.strip()
    if required and not text:
        raise ToolError(f"参数 {name} 不能为空")
    if len(text) > max_length:
        raise ToolError(f"参数 {name} 过长")
    return text


def _as_unit(value: Any, default: str = "day") -> str:
    unit = _as_text(value, "unit", max_length=16).lower() or default
    if not security.valid_unit(unit):
        raise ToolError("不支持的时间单位：" + unit)
    return unit


def _checked_duration(value: Any, unit: Any) -> tuple[int, str]:
    amount = _as_int(value, "duration_value" if value is not None else "duration_days")
    normalized = _as_unit(unit)
    if amount > security.unit_max_value(normalized):
        raise ToolError("有效期超出该单位的允许范围")
    return amount, normalized


def _duration_from_expiry(expires_at: str | None) -> tuple[int, str]:
    if not expires_at:
        return 0, "day"
    seconds = max(0, int(security.seconds_left(expires_at)))
    for unit in ("year", "quarter", "month", "week", "day", "hour", "minute"):
        span = security.unit_seconds(unit)
        if seconds % span == 0:
            return seconds // span, unit
    return max(1, seconds // 86400), "day"


class ToolRegistry:
    """Registry of every management action the AI is allowed to run."""

    def __init__(self, db: Database, config: dict, prefix: str = "GSQ"):
        self.db = db
        self.config = config or {}
        self.prefix = (prefix or self.config.get("key_prefix") or "GSQ").upper()
        self._tools: dict[str, Tool] = {}
        self._register()

    # ------------------------------------------------------------------
    # Schema helpers
    # ------------------------------------------------------------------
    def schemas(self, role: str) -> list[dict]:
        items = []
        for tool in self._tools.values():
            if tool.admin_only and role != "master":
                continue
            items.append(
                {
                    "type": "function",
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.parameters,
                }
            )
        return items

    def names(self, role: str) -> set[str]:
        return {
            tool.name
            for tool in self._tools.values()
            if not (tool.admin_only and role != "master")
        }

    def write_tool_names(self) -> set[str]:
        """Return every registered tool that mutates server state."""
        return {tool.name for tool in self._tools.values() if tool.mutating}

    def is_write_tool(self, name: str) -> bool:
        tool = self._tools.get(str(name or ""))
        return bool(tool and tool.mutating)

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def check(self, name: str, arguments: dict, operator: dict) -> Tool:
        """Resolve and validate a call without executing the handler.

        Staging a two-phase confirmation needs the same permission and schema
        checks as a direct call, but must not run the handler yet.
        """
        tool = self._tools.get(name)
        if tool is None:
            raise ToolError(f"未知工具：{name}")
        if tool.admin_only and operator.get("role") != "master":
            raise ToolError("该操作仅主控端可用")
        if not isinstance(arguments, dict):
            raise ToolError("工具参数必须是 JSON 对象")
        self._validate(tool.parameters, arguments)
        return tool

    def call(self, name: str, arguments: dict, operator: dict, ip: str = "") -> Any:
        tool = self.check(name, arguments, operator)
        result = tool.handler(arguments, operator, ip)
        return self._jsonable(result)

    # ------------------------------------------------------------------
    # Two-phase confirmation previews
    # ------------------------------------------------------------------
    def preview_action(self, name: str, arguments: dict) -> tuple[str, int]:
        """Return ``(summary, affected_count)`` for a pending write action.

        The summary is shown in the operator's confirmation bar, so it must be
        readable and must never contain secrets such as administrator
        passwords. ``arguments`` stays server side until the token expires.
        Target lookups reuse the same helpers as execution, so an action with
        no resolvable target fails before a token is ever issued.
        """
        args = arguments if isinstance(arguments, dict) else {}
        if name == "generate_licenses":
            count = _as_int(args.get("count", 1), "count", 1, 500)
            card_type = (
                _as_text(args.get("card_type", "duration"), "card_type").lower()
                or "duration"
            )
            if card_type == "activation":
                limit = _as_int(
                    args.get("activation_limit", 0), "activation_limit", 1, 100000
                )
                return f"生成 {count} 张次数卡（每张可激活 {limit} 台设备）", count
            raw_value = args.get("duration_value", args.get("duration_days", 0))
            try:
                value = int(raw_value or 0)
            except (TypeError, ValueError):
                raise ToolError("duration_value 必须是整数") from None
            unit = _as_unit(args.get("duration_unit"), "day")
            return (
                f"生成 {count} 张时长卡（有效期 {security.duration_text(value, unit)}）",
                count,
            )

        if name == "set_license_status":
            action = _as_text(args.get("action"), "action", required=True).lower()
            label = _ACTION_LABELS.get(action, action)
            detail = ""
            if action == "freeze":
                amount = _as_int(args.get("amount", 1), "amount", 1, 100000)
                unit = _as_unit(args.get("unit"), "hour")
                detail = f"，冻结时长 {security.duration_text(amount, unit)}"
            batch_no = _as_text(args.get("batch_no"), "batch_no", max_length=128)
            if batch_no and not args.get("key_codes") and action in ("revoke", "restore"):
                count = self.db.count_licenses("", "", batch_no)
                if count <= 0:
                    raise ToolError(f"批次不存在或没有卡密：{batch_no}")
                return f"{label}批次 {batch_no} 的全部 {count} 张卡密{detail}", count
            targets = self._targets(args)
            return f"{label} {len(targets)} 张卡密{detail}", len(targets)

        if name == "renew_licenses":
            value = _as_int(args.get("duration_value"), "duration_value", 1, 36500)
            unit = _as_unit(args.get("duration_unit"), "day")
            targets = self._targets(args)
            return (
                f"为 {len(targets)} 张时长卡续期 {security.duration_text(value, unit)}",
                len(targets),
            )

        if name == "delete_licenses":
            targets = self._targets(args)
            return f"彻底删除 {len(targets)} 张卡密及其绑定（不可恢复）", len(targets)

        if name == "unbind_device":
            key_code = security.normalize_key(
                _as_text(args.get("key_code"), "key_code", required=True, max_length=128)
            )
            machine_code = _as_text(
                args.get("machine_code"), "machine_code", required=True, max_length=128
            ).upper()
            return f"解绑设备 {machine_code}（卡密 {key_code}）", 1

        if name == "create_offline_code":
            key_code = security.normalize_key(
                _as_text(args.get("key_code"), "key_code", required=True, max_length=128)
            )
            machine_code = _as_text(
                args.get("machine_code"), "machine_code", required=True, max_length=128
            ).upper()
            return f"为卡密 {key_code} 生成离线激活码（设备 {machine_code}）", 1

        if name == "create_admin":
            username = _as_text(
                args.get("username"), "username", required=True, max_length=64
            )
            role = (
                _as_text(args.get("role", "admin"), "role").lower() or "admin"
            )
            role_label = "主控" if role == "master" else "管理端"
            return f"创建{role_label}管理员账号 {username}（密码不在预览中显示）", 1

        if name == "set_admin_status":
            admin_id = _as_int(args.get("admin_id"), "admin_id", 1)
            status = _as_text(args.get("status"), "status", required=True).lower()
            label = "启用" if status == "active" else "禁用"
            return f"{label}管理员账号 #{admin_id}", 1

        if name == "reset_admin_password":
            admin_id = _as_int(args.get("admin_id"), "admin_id", 1)
            return f"重置管理员账号 #{admin_id} 的密码（要求下次登录改密）", 1

        return f"执行写操作 {name}", 1

    # ------------------------------------------------------------------
    # Validation / logging
    # ------------------------------------------------------------------
    @staticmethod
    def _validate(schema: dict, arguments: dict) -> None:
        properties = schema.get("properties") or {}
        for key in schema.get("required") or []:
            if key not in arguments or arguments[key] in (None, ""):
                raise ToolError(f"缺少必填参数：{key}")
        for key, value in arguments.items():
            spec = properties.get(key)
            if spec is None:
                raise ToolError(f"不支持参数：{key}")
            expected = spec.get("type")
            if value is None:
                continue
            if expected == "integer" and (isinstance(value, bool) or not isinstance(value, int)):
                raise ToolError(f"参数 {key} 必须是整数")
            if expected == "string" and not isinstance(value, str):
                raise ToolError(f"参数 {key} 必须是字符串")
            if expected == "boolean" and not isinstance(value, bool):
                raise ToolError(f"参数 {key} 必须是布尔值")
            if expected == "array" and not isinstance(value, list):
                raise ToolError(f"参数 {key} 必须是数组")
            enum_values = spec.get("enum")
            if enum_values and value not in enum_values:
                raise ToolError(f"参数 {key} 取值无效")
            if expected == "integer":
                if value < spec.get("minimum", value):
                    raise ToolError(f"参数 {key} 小于最小值")
                if value > spec.get("maximum", value):
                    raise ToolError(f"参数 {key} 超过最大值")
            if expected == "array":
                items = spec.get("items") or {}
                for item in value:
                    if items.get("type") == "string" and not isinstance(item, str):
                        raise ToolError(f"参数 {key} 包含非字符串内容")

    def _log(self, action: str, operator: dict, target: str, detail: str, ip: str) -> None:
        actor = f"AI:{operator.get('username', 'unknown')}"
        self.db.add_log(action, actor, target, detail, ip or "")

    @staticmethod
    def _jsonable(value: Any) -> Any:
        try:
            json.dumps(value, ensure_ascii=False)
            return value
        except (TypeError, ValueError):
            return json.loads(json.dumps(value, ensure_ascii=False, default=str))

    def _license_or_fail(self, key_code: str) -> dict:
        code = security.normalize_key(key_code)
        lic = self.db.get_license(code)
        if not lic:
            raise ToolError(f"密钥不存在：{code}")
        return lic

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------
    def _add(
        self,
        name: str,
        description: str,
        parameters: dict,
        handler: Callable[..., Any],
        *,
        admin_only: bool = False,
        mutating: bool = False,
    ) -> None:
        self._tools[name] = Tool(
            name, description, parameters, handler, admin_only, mutating
        )

    def _register(self) -> None:
        add = self._add

        add(
            "get_stats",
            "读取授权总览统计：密钥总数、已激活、绑定设备、管理员数量、批次数量、已用尽次数卡等。",
            _obj({}),
            self._stats,
        )
        add(
            "list_licenses",
            "按关键字、状态或批次号查询卡密列表（最多 500 条）。写操作前应先用它确认目标卡密。",
            _obj(
                {
                    "keyword": _string("按卡密、备注或批次号模糊搜索"),
                    "status": _string("状态筛选", enum=list(STATUS_VALUES)),
                    "batch_no": _string("批次号精确筛选"),
                    "limit": _integer("返回条数，默认 50", 1, 500),
                }
            ),
            self._list_licenses,
        )
        add(
            "get_license_detail",
            "读取单个卡密的完整信息及其设备绑定记录。",
            _obj({"key_code": _string("完整卡密", minLength=1)}, ["key_code"]),
            self._license_detail,
        )
        add(
            "list_batches",
            "查询批次列表，包含每批的总数、未使用、已激活、冻结、吊销、过期与次数卡用尽数量。",
            _obj(
                {
                    "keyword": _string("按批次号、备注或创建人模糊搜索"),
                    "limit": _integer("返回条数，默认 50", 1, 500),
                }
            ),
            self._list_batches,
        )
        add(
            "list_logs",
            "读取最近的审计日志，可按操作类型和关键字筛选。",
            _obj(
                {
                    "keyword": _string("按操作、对象、详情、来源模糊搜索"),
                    "action": _string("精确操作类型，例如 生成密钥、吊销密钥、AI操作"),
                    "limit": _integer("返回条数，默认 50", 1, 500),
                }
            ),
            self._list_logs,
        )
        add(
            "list_admins",
            "列出全部管理员账号及其角色、状态和最近登录时间。",
            _obj({}),
            self._list_admins,
            admin_only=True,
        )

        add(
            "generate_licenses",
            "批量生成卡密。duration 模式按时长；activation 模式按可激活台数，用尽自动吊销。",
            _obj(
                {
                    "count": _integer("生成数量，默认 1", 1, 500),
                    "card_type": _string("卡密模式", enum=["duration", "activation"], default="duration"),
                    "duration_value": _integer("有效期数值，与 duration_unit 搭配；永久卡填 0", 0, 36500),
                    "duration_unit": _unit_schema(),
                    "activation_limit": _integer("次数卡的可激活台数（card_type=activation 时必填）", 1, 100000),
                    "max_devices": _integer("每张时长卡可绑定设备数，默认 1（浮动席位模式下忽略）", 1, 10000),
                    "max_concurrent": _integer(
                        "浮动席位：同时在线数上限（0=关闭，按绑定设备数计）", 0, 10000
                    ),
                    "fixed_expires_at": _string(
                        "固定到期时间 YYYY-MM-DD HH:MM:SS（提供后该批卡为固定到期模式）"
                    ),
                    "edition": _string("版本标识，默认 standard"),
                    "features": {
                        "type": "array",
                        "items": {"type": "string", "maxLength": 32},
                        "maxItems": 32,
                        "description": "功能位列表（小写字母/数字/._:-；可传逗号分隔字符串）",
                    },
                    "note": _string("备注", maxLength=500),
                    "prefix": _string("卡密前缀，默认使用系统配置"),
                },
                ["count"],
            ),
            self._generate,
            mutating=True,
        )
        add(
            "set_license_status",
            "批量吊销、恢复或冻结卡密。支持传 key_codes 或 batch_no 整批操作。恢复遇到次数卡用尽会明确失败。",
            _obj(
                {
                    "action": _string("操作类型", enum=["revoke", "restore", "freeze", "unfreeze"]),
                    "key_codes": _key_list_schema(),
                    "batch_no": _string("批次号，提供后对该批全部卡密执行同一操作"),
                    "amount": _integer("冻结时长数值（action=freeze 时使用）", 1, 100000),
                    "unit": _unit_schema("hour"),
                    "reason": _string("冻结原因", maxLength=200),
                },
                ["action"],
            ),
            self._set_status,
            mutating=True,
        )
        add(
            "renew_licenses",
            "为一张或多张时长卡续期，支持 key_codes 或 batch_no。次数卡不支持续期。",
            _obj(
                {
                    "key_codes": _key_list_schema(),
                    "batch_no": _string("批次号，提供后对该批全部卡密续期"),
                    "duration_value": _integer("续期数值", 1, 36500),
                    "duration_unit": _unit_schema(),
                },
                ["duration_value"],
            ),
            self._renew,
            mutating=True,
        )
        add(
            "delete_licenses",
            "彻底删除一张或多张卡密及其设备绑定，不可恢复。支持 key_codes 或 batch_no。",
            _obj(
                {
                    "key_codes": _key_list_schema(),
                    "batch_no": _string("批次号，提供后删除该批全部卡密"),
                }
            ),
            self._delete,
            mutating=True,
        )
        add(
            "unbind_device",
            "解绑卡密与某台设备的绑定关系，机器码不区分大小写。",
            _obj(
                {
                    "key_code": _string("完整卡密", minLength=1),
                    "machine_code": _string("设备机器码", minLength=1),
                },
                ["key_code", "machine_code"],
            ),
            self._unbind,
            mutating=True,
        )
        add(
            "rebind_license",
            "一键换绑：解冻（如需）并解绑该密钥的全部活跃设备，便于用户在新设备重新激活。",
            _obj({"key_code": _string("完整卡密", minLength=1)}, ["key_code"]),
            self._rebind,
            mutating=True,
        )
        add(
            "create_offline_code",
            "为时长卡生成离线激活码。次数卡、冻结、吊销、过期卡不可生成。",
            _obj(
                {
                    "key_code": _string("完整卡密", minLength=1),
                    "machine_code": _string("设备机器码", minLength=1),
                    "device_name": _string("设备名称"),
                },
                ["key_code", "machine_code"],
            ),
            self._offline_code,
            mutating=True,
        )

        add(
            "create_admin",
            "创建管理员账号。role 可选 admin（管理端）或 master（主控端）。仅主控可用。",
            _obj(
                {
                    "username": _string("登录账号", minLength=1, maxLength=64),
                    "password": _string("登录密码", minLength=1, maxLength=128),
                    "role": _string("角色", enum=["admin", "master"], default="admin"),
                },
                ["username", "password"],
            ),
            self._create_admin,
            admin_only=True,
            mutating=True,
        )
        add(
            "set_admin_status",
            "启用或禁用管理员账号。不能修改自己，也不能禁用主控账号。仅主控可用。",
            _obj(
                {
                    "admin_id": _integer("管理员 ID", 1),
                    "status": _string("目标状态", enum=["active", "disabled"]),
                },
                ["admin_id", "status"],
            ),
            self._admin_status,
            admin_only=True,
            mutating=True,
        )
        add(
            "reset_admin_password",
            "重置管理员密码，目标账号下次登录必须改密。不能重置自己或其他主控。仅主控可用。",
            _obj(
                {
                    "admin_id": _integer("管理员 ID", 1),
                    "password": _string("新密码", minLength=1, maxLength=128),
                },
                ["admin_id", "password"],
            ),
            self._reset_password,
            admin_only=True,
            mutating=True,
        )

    # ------------------------------------------------------------------
    # Read tools
    # ------------------------------------------------------------------
    def _stats(self, args: dict, operator: dict, ip: str) -> dict:
        return self.db.stats()

    def _list_licenses(self, args: dict, operator: dict, ip: str) -> dict:
        keyword = _as_text(args.get("keyword"), "keyword", max_length=128)
        status = _as_text(args.get("status"), "status", max_length=32)
        batch_no = _as_text(args.get("batch_no"), "batch_no", max_length=128)
        limit = _as_int(args.get("limit", 50), "limit", 1, 500)
        items = self.db.list_licenses(keyword, status, batch_no, limit, 0)
        return {"items": items, "total": self.db.count_licenses(keyword, status, batch_no)}

    def _license_detail(self, args: dict, operator: dict, ip: str) -> dict:
        key_code = _as_text(args["key_code"], "key_code", required=True, max_length=128)
        lic = self._license_or_fail(key_code)
        return {"license": lic, "activations": self.db.list_activations(lic["key_code"])}

    def _list_batches(self, args: dict, operator: dict, ip: str) -> dict:
        keyword = _as_text(args.get("keyword"), "keyword", max_length=128)
        limit = _as_int(args.get("limit", 50), "limit", 1, 500)
        return {
            "items": self.db.list_batches(keyword, limit, 0),
            "total": self.db.count_batches(keyword),
        }

    def _list_logs(self, args: dict, operator: dict, ip: str) -> dict:
        keyword = _as_text(args.get("keyword"), "keyword", max_length=128)
        action = _as_text(args.get("action"), "action", max_length=64)
        limit = _as_int(args.get("limit", 50), "limit", 1, 500)
        return {
            "items": self.db.list_logs(limit, 0, keyword, action),
        }

    def _list_admins(self, args: dict, operator: dict, ip: str) -> dict:
        return {"items": self.db.list_admins()}

    # ------------------------------------------------------------------
    # License write tools
    # ------------------------------------------------------------------
    def _generate(self, args: dict, operator: dict, ip: str) -> dict:
        count = _as_int(args.get("count", 1), "count", 1, 500)
        card_type = _as_text(args.get("card_type", "duration"), "card_type").lower()
        if card_type not in ("duration", "activation", "trial"):
            raise ToolError("card_type 只能是 duration、activation 或 trial")
        max_concurrent = _as_int(args.get("max_concurrent", 0), "max_concurrent", 0, 10000)
        fixed_expires_at = _as_text(
            args.get("fixed_expires_at"), "fixed_expires_at", max_length=32
        )
        edition = _as_text(args.get("edition", "standard"), "edition", max_length=32) or "standard"
        note = _as_text(args.get("note"), "note", max_length=500)
        if note and _scan_note_injection(note):
            self._log("AI操作告警", operator, "生成密钥", "备注疑似提示注入", ip)
        prefix = _as_text(args.get("prefix"), "prefix", max_length=16) or self.prefix
        if not all(ch.isalnum() or ch in "-_" for ch in prefix):
            raise ToolError("卡密前缀只能包含字母、数字、- 或 _")
        try:
            feature_list = security.normalize_features(args.get("features"))
        except ValueError as exc:
            raise ToolError(str(exc)) from None
        if card_type == "trial":
            trial_value = _as_int(
                args.get("duration_value", args.get("duration_days", 0)),
                "duration_value",
                0,
                36500,
            )
            trial_unit = _as_unit(args.get("duration_unit"), "day")
            if trial_value <= 0 and not fixed_expires_at:
                raise ToolError("试用卡必须设置大于 0 的有效期或固定到期时间")
            trial_devices = _as_int(args.get("max_devices", 1), "max_devices", 1, 10000)
            batch_no, keys = self.db.generate_licenses(
                count=count,
                edition=edition,
                duration_days=trial_value,
                max_devices=trial_devices,
                note=note,
                created_by=operator.get("username", ""),
                prefix=prefix.upper(),
                duration_unit=trial_unit,
                card_type="trial",
                features=feature_list,
                max_concurrent=max_concurrent,
                expiry_mode="fixed" if fixed_expires_at else "relative",
                fixed_expires_at=fixed_expires_at or None,
            )
            self._log(
                "AI生成密钥",
                operator,
                batch_no,
                f"试用卡 {count} 张 · {security.duration_text(trial_value, trial_unit)}",
                ip,
            )
            return {
                "ok": True,
                "batch_no": batch_no,
                "count": len(keys),
                "keys": keys,
                "card_type": "trial",
                "duration": security.duration_text(trial_value, trial_unit),
                "max_devices": trial_devices,
            }
        if card_type == "activation":
            limit = _as_int(args.get("activation_limit", 0), "activation_limit", 1, 100000)
            batch_no, keys = self.db.generate_licenses(
                count=count,
                edition=edition,
                note=note,
                created_by=operator.get("username", ""),
                prefix=prefix.upper(),
                card_type="activation",
                activation_limit=limit,
                features=feature_list,
            )
            self._log("AI生成密钥", operator, batch_no, f"次数卡 {count} 张 · {limit} 次", ip)
            return {
                "ok": True,
                "batch_no": batch_no,
                "count": len(keys),
                "keys": keys,
                "card_type": "activation",
                "activation_limit": limit,
            }
        raw_value = args.get("duration_value", args.get("duration_days", 0))
        try:
            value = int(raw_value or 0)
        except (TypeError, ValueError):
            raise ToolError("duration_value 必须是整数") from None
        unit = _as_unit(args.get("duration_unit"), "day")
        if value < 0 or value > security.unit_max_value(unit):
            raise ToolError("有效期超出该单位的允许范围")
        max_devices = _as_int(args.get("max_devices", 1), "max_devices", 1, 10000)
        batch_no, keys = self.db.generate_licenses(
            count=count,
            edition=edition,
            duration_days=value,
            max_devices=max_devices,
            note=note,
            created_by=operator.get("username", ""),
            prefix=prefix.upper(),
            duration_unit=unit,
            features=feature_list,
            max_concurrent=max_concurrent,
            expiry_mode="fixed" if fixed_expires_at else "relative",
            fixed_expires_at=fixed_expires_at or None,
        )
        self._log(
            "AI生成密钥",
            operator,
            batch_no,
            f"时长卡 {count} 张 · {security.duration_text(value, unit)} · {max_devices} 台",
            ip,
        )
        return {
            "ok": True,
            "batch_no": batch_no,
            "count": len(keys),
            "keys": keys,
            "card_type": "duration",
            "duration": security.duration_text(value, unit),
            "max_devices": max_devices,
        }

    def _rebind(self, args: dict, operator: dict, ip: str) -> dict:
        """一键换绑：解冻（如需）+ 解绑全部活跃设备。"""
        key_code = _as_text(args.get("key_code"), "key_code", required=True, max_length=128)
        lic = self._license_or_fail(key_code)
        unfrozen = False
        if str(lic.get("status") or "") == "frozen":
            target = self.db.unfreeze_license(lic["key_code"])
            if isinstance(target, str) and target.startswith("__"):
                raise ToolError("该密钥无法解冻（已过期或次数用尽）")
            unfrozen = True
        unbound = 0
        for item in self.db.list_activations(lic["key_code"]):
            if str(item.get("status") or "") == "active":
                if self.db.unbind_activation(lic["key_code"], item["machine_code"]):
                    unbound += 1
        self._log(
            "AI换绑准备",
            operator,
            lic["key_code"],
            f"解冻{'是' if unfrozen else '否'} · 解绑 {unbound} 台",
            ip,
        )
        return {
            "ok": True,
            "unfrozen": unfrozen,
            "unbound": unbound,
            "guide": f"密钥 {lic['key_code']} 已完成换绑准备，请用户在新设备重新激活。",
        }

    def _targets(self, args: dict) -> list[str]:
        key_codes = args.get("key_codes") or []
        batch_no = _as_text(args.get("batch_no"), "batch_no", max_length=128)
        if not key_codes and not batch_no:
            raise ToolError("请提供 key_codes 或 batch_no")
        codes: list[str] = [security.normalize_key(str(item)) for item in key_codes]
        if batch_no:
            codes.extend(
                row["key_code"]
                for row in self.db.list_licenses(batch_no=batch_no, limit=500)
            )
        unique: list[str] = []
        for code in codes:
            if code and code not in unique:
                unique.append(code)
        if not unique:
            raise ToolError("没有找到可操作的目标卡密")
        if len(unique) > 500:
            raise ToolError("单次最多操作 500 张卡密，请缩小范围或分批执行")
        return unique

    def _set_status(self, args: dict, operator: dict, ip: str) -> dict:
        action = _as_text(args.get("action"), "action", required=True).lower()
        if action not in ("revoke", "restore", "freeze", "unfreeze"):
            raise ToolError("action 只能是 revoke / restore / freeze / unfreeze")
        batch_no = _as_text(args.get("batch_no"), "batch_no", max_length=128)
        if batch_no and not args.get("key_codes"):
            if action == "revoke":
                count = self.db.revoke_batch(batch_no)
                self._log("AI吊销批次", operator, batch_no, f"共 {count} 张", ip)
                return {"ok": True, "action": action, "batch_no": batch_no, "count": count}
            if action == "restore":
                count = self.db.restore_batch(batch_no)
                self._log("AI恢复批次", operator, batch_no, f"共 {count} 张", ip)
                return {"ok": True, "action": action, "batch_no": batch_no, "count": count}
        targets = self._targets(args)
        frozen_until = ""
        reason = _as_text(args.get("reason"), "reason", max_length=200)
        if reason and _scan_note_injection(reason):
            self._log("AI操作告警", operator, batch_no or "多个密钥", "冻结原因疑似提示注入", ip)
        if action == "freeze":
            amount = _as_int(args.get("amount", 1), "amount", 1, 100000)
            unit = _as_unit(args.get("unit"), "hour")
            frozen_until = security.compute_freeze_until(amount, unit) or ""
            if not frozen_until:
                raise ToolError("冻结时长必须大于 0")
        succeeded: list[str] = []
        failed: list[dict] = []
        for code in targets:
            lic = self.db.get_license(code)
            if not lic:
                failed.append({"key_code": code, "reason": "密钥不存在"})
                continue
            if action == "revoke":
                self.db.set_license_status(code, "revoked")
                self._log("AI吊销密钥", operator, code, "", ip)
                succeeded.append(code)
            elif action == "restore":
                target = self.db.restore_license(code)
                if target == "__exhausted__":
                    failed.append({"key_code": code, "reason": "激活次数已用尽，无法恢复"})
                    continue
                if target == "__expired__":
                    failed.append({"key_code": code, "reason": "已过有效期，请先续期"})
                    continue
                if target is None:
                    failed.append({"key_code": code, "reason": "仅吊销状态可恢复"})
                    continue
                self._log("AI恢复密钥", operator, code, f"恢复为 {target}", ip)
                succeeded.append(code)
            elif action == "freeze":
                if is_activation_card(lic):
                    failed.append({"key_code": code, "reason": "激活次数卡不支持冻结"})
                    continue
                prev = self.db.freeze_license(code, frozen_until, reason)
                if prev is None:
                    failed.append({"key_code": code, "reason": "已过期、吊销或处于不可冻结状态"})
                    continue
                self._log("AI冻结密钥", operator, code, f"至 {frozen_until} | {reason}", ip)
                succeeded.append(code)
            else:
                target = self.db.unfreeze_license(code)
                if target in (None, "__expired__", "__exhausted__"):
                    failed.append({"key_code": code, "reason": "当前不可解冻"})
                    continue
                self._log("AI解冻密钥", operator, code, f"恢复为 {target}", ip)
                succeeded.append(code)
        return {
            "ok": bool(succeeded),
            "action": action,
            "count": len(succeeded),
            "key_codes": succeeded,
            "failed": failed,
            "frozen_until": frozen_until or None,
        }

    def _renew(self, args: dict, operator: dict, ip: str) -> dict:
        value = _as_int(args.get("duration_value"), "duration_value", 1, 36500)
        unit = _as_unit(args.get("duration_unit"), "day")
        if value > security.unit_max_value(unit):
            raise ToolError("续期时长超出该单位的允许范围")
        targets = self._targets(args)
        succeeded: list[dict] = []
        failed: list[dict] = []
        for code in targets:
            lic = self.db.get_license(code)
            if not lic:
                failed.append({"key_code": code, "reason": "密钥不存在"})
                continue
            if is_activation_card(lic):
                failed.append({"key_code": code, "reason": "激活次数卡不支持续期"})
                continue
            result = self.db.renew_license(code, value, unit)
            if result is None:
                failed.append({"key_code": code, "reason": "永久卡、已吊销或续期参数无效"})
                continue
            target, new_expiry = result
            self._log(
                "AI续期密钥",
                operator,
                code,
                f"{security.duration_text(value, unit)} -> {new_expiry}",
                ip,
            )
            succeeded.append({"key_code": code, "status": target, "expires_at": new_expiry})
        return {"ok": bool(succeeded), "count": len(succeeded), "items": succeeded, "failed": failed}

    def _delete(self, args: dict, operator: dict, ip: str) -> dict:
        targets = self._targets(args)
        deleted: list[str] = []
        failed: list[dict] = []
        batch_no = _as_text(args.get("batch_no"), "batch_no", max_length=128)
        for code in targets:
            if not self.db.get_license(code):
                failed.append({"key_code": code, "reason": "密钥不存在"})
                continue
            self.db.delete_license(code)
            self._log("AI删除密钥", operator, code, f"批次 {batch_no}" if batch_no else "", ip)
            deleted.append(code)
        return {"ok": bool(deleted), "count": len(deleted), "key_codes": deleted, "failed": failed}

    def _unbind(self, args: dict, operator: dict, ip: str) -> dict:
        key_code = _as_text(args["key_code"], "key_code", required=True, max_length=128)
        machine_code = _as_text(args["machine_code"], "machine_code", required=True, max_length=128)
        self._license_or_fail(key_code)
        changed = self.db.unbind_activation(key_code, machine_code)
        if not changed:
            raise ToolError("未找到对应的有效设备绑定")
        self._log("AI解绑设备", operator, security.normalize_key(key_code), machine_code.upper(), ip)
        return {"ok": True, "key_code": security.normalize_key(key_code), "machine_code": machine_code.upper()}

    def _offline_code(self, args: dict, operator: dict, ip: str) -> dict:
        key_code = _as_text(args["key_code"], "key_code", required=True, max_length=128)
        machine_code = _as_text(args["machine_code"], "machine_code", required=True, max_length=128).upper()
        device_name = _as_text(args.get("device_name"), "device_name", max_length=128)
        private_key = str(self.config.get("offline_private_key") or "").strip()
        if not private_key:
            raise ToolError("服务器未配置离线签名私钥")
        self.db.release_expired_freeze(key_code)
        self.db.sweep_expired()
        lic = self._license_or_fail(key_code)
        if is_activation_card(lic):
            raise ToolError("激活次数卡不支持离线激活码")
        if lic["status"] == "frozen":
            raise ToolError("该密钥已被冻结，无法生成离线激活码")
        if lic["status"] == "revoked":
            raise ToolError("该密钥已被吊销，无法生成离线激活码")
        if lic["status"] == "expired" or security.is_expired(lic.get("expires_at")):
            raise ToolError("该密钥已过期，无法生成离线激活码")
        # An unused duration card has no ``expires_at`` yet. The HTTP endpoint
        # stamps it from the card duration before signing; without this the
        # offline code would be issued for a permanent licence.
        expiry = lic.get("expires_at")
        if not expiry and lic.get("duration_days") and int(lic["duration_days"]) > 0:
            expiry = security.compute_expiry(
                int(lic["duration_days"]), lic.get("duration_unit") or "day"
            )
            self.db.update_license_expiry(lic["key_code"], expiry)
        result, activation_id, effective_expiry = self.db.activate_atomic(
            lic["id"], lic["key_code"], machine_code, device_name, expiry
        )
        if result == "limit":
            raise ToolError(f"该密钥最多绑定 {lic['max_devices']} 台设备，已达上限")
        if result not in ("activated", "already") or activation_id is None:
            raise ToolError("该密钥当前无法生成离线激活码")
        payload = offline.build_activation_payload(
            machine_code=machine_code,
            key_code=lic["key_code"],
            edition=lic["edition"],
            duration_days=lic["duration_days"],
            expires_at=effective_expiry,
            max_devices=lic["max_devices"],
            note=lic["note"] or "",
        )
        code = offline.make_activation_code(payload, private_key)
        self._log("AI生成离线激活码", operator, lic["key_code"], f"设备 {machine_code}", ip)
        return {
            "ok": True,
            "code": code,
            "key_code": lic["key_code"],
            "machine_code": machine_code,
            "expires_at": effective_expiry,
            "remaining": security.humanize_remaining(effective_expiry),
        }

    # ------------------------------------------------------------------
    # Administrator tools (master only)
    # ------------------------------------------------------------------
    def _create_admin(self, args: dict, operator: dict, ip: str) -> dict:
        username = _as_text(args["username"], "username", required=True, max_length=64)
        password = _as_text(args["password"], "password", required=True, max_length=128)
        role = _as_text(args.get("role", "admin"), "role").lower() or "admin"
        if role not in ("admin", "master"):
            raise ToolError("角色只能是 admin 或 master")
        if self.db.get_admin(username):
            raise ToolError(f"管理员已存在：{username}")
        ok, message = security.password_strength(password)
        if not ok:
            raise ToolError(message)
        # 硬规则：AI 工具属于"主控端通道"——创建的管理员一律为待审批，
        # 由服务器端审批后启用（与服务端界面/CLI 之外的路径保持同一口径）。
        admin_id = self.db.create_admin(username, password, role, approved=False)
        self.db.create_approval(
            "admin_register",
            f"AI:{operator.get('username', '')}",
            username,
            {"admin_id": admin_id, "username": username, "role": role},
        )
        self._log("AI创建管理员", operator, username, f"角色 {role} · 待服务端审批", ip)
        return {
            "ok": True,
            "id": admin_id,
            "username": username,
            "role": role,
            "pending_approval": True,
            "message": "已提交服务器端审批，通过后自动启用（AI 创建同样需要审批）。",
        }

    def _admin_status(self, args: dict, operator: dict, ip: str) -> dict:
        admin_id = _as_int(args["admin_id"], "admin_id", 1)
        status = _as_text(args["status"], "status", required=True).lower()
        if status not in ("active", "disabled"):
            raise ToolError("状态只能是 active 或 disabled")
        target = self.db.get_admin_by_id(admin_id)
        if not target:
            raise ToolError(f"管理员不存在：{admin_id}")
        if target["id"] == operator.get("id"):
            raise ToolError("不能修改自己的状态")
        if target["role"] == "master":
            raise ToolError("不能禁用另一位主控账号")
        if status == "active":
            block = self.db.admin_approval_block(admin_id)
            if block == "pending":
                raise ToolError("该账号的创建申请尚未经服务器端审批，不能启用。")
            if block == "rejected":
                raise ToolError(
                    "该账号的创建申请已被服务端拒绝，不能启用；请删除该账号。"
                )
        self.db.set_admin_status(admin_id, status)
        self._log("AI修改管理员状态", operator, target["username"], status, ip)
        return {"ok": True, "admin_id": admin_id, "status": status}

    def _reset_password(self, args: dict, operator: dict, ip: str) -> dict:
        admin_id = _as_int(args["admin_id"], "admin_id", 1)
        password = _as_text(args["password"], "password", required=True, max_length=128)
        target = self.db.get_admin_by_id(admin_id)
        if not target:
            raise ToolError(f"管理员不存在：{admin_id}")
        if target["id"] == operator.get("id"):
            raise ToolError("请在“修改密码”页面修改自己的密码")
        if target["role"] == "master":
            raise ToolError("不能重置另一位主控账号的密码")
        ok, message = security.password_strength(password)
        if not ok:
            raise ToolError(message)
        self.db.set_admin_password(admin_id, password, must_change_password=True)
        self._log("AI重置管理员密码", operator, target["username"], "", ip)
        return {"ok": True, "admin_id": admin_id, "username": target["username"]}
