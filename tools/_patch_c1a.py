# -*- coding: utf-8 -*-
"""C1 审批体系 · 数据层：approvals 表 + 方法 + 账号状态 + 转赠执行。"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def patch(rel_path: str, edits: list[tuple[str, str]]) -> None:
    path = ROOT / rel_path
    text = path.read_text(encoding="utf-8")
    for index, (old, new) in enumerate(edits, 1):
        count = text.count(old)
        assert count == 1, f"{rel_path} edit#{index}: expected 1, found {count}\n---OLD---\n{old[:260]}"
        text = text.replace(old, new, 1)
    path.write_text(text, encoding="utf-8")
    print(f"[ok] {rel_path}: {len(edits)} edits")


patch("core/database.py", [
    # 1) approvals 表（插在 risk_events 前）
    (
        '''CREATE TABLE IF NOT EXISTS risk_events (''',
        '''CREATE TABLE IF NOT EXISTS approvals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  applicant TEXT NOT NULL DEFAULT '',
  target TEXT NOT NULL DEFAULT '',
  payload TEXT NOT NULL DEFAULT '{}',
  reviewer TEXT NOT NULL DEFAULT '',
  review_note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  reviewed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_approvals_kind_status
    ON approvals(kind, status, id);

CREATE TABLE IF NOT EXISTS risk_events (''',
    ),
    # 2) create_portal_account 支持 pending
    (
        '''    def create_portal_account(self, email, password_hash, salt) -> int:
        return self._execute(
            "INSERT INTO portal_accounts (email, password_hash, salt, status,"
            " auth_version, email_verified_at, created_at, last_login_at)"
            " VALUES (?, ?, ?, 'active', 0, NULL, ?, NULL)",
            (
                self._normalize_email(email),
                str(password_hash or ""),
                str(salt or ""),
                security.now_str(),
            ),
        )''',
        '''    def create_portal_account(self, email, password_hash, salt,
                              status: str = "active") -> int:
        """创建门户账号；status 支持 'active' / 'pending'（注册审批模式）。"""
        normalized = str(status or "active").strip().lower()
        if normalized not in ("active", "pending"):
            normalized = "active"
        return self._execute(
            "INSERT INTO portal_accounts (email, password_hash, salt, status,"
            " auth_version, email_verified_at, created_at, last_login_at)"
            " VALUES (?, ?, ?, ?, 0, NULL, ?, NULL)",
            (
                self._normalize_email(email),
                str(password_hash or ""),
                str(salt or ""),
                normalized,
                security.now_str(),
            ),
        )''',
    ),
    # 3) 转赠执行（插在 unbind_portal_license 之后、add_binding_history 之前）
    (
        '''    def add_binding_history(''',
        '''    def transfer_portal_binding(self, license_id: int, from_account_id: int,
                                to_account_id: int, key_code: str,
                                actor: str = "master") -> bool:
        """转赠：卡密绑定从 A 账号转移到 B 账号（同一事务；设备绑定清空）。"""
        now = security.now_str()
        license_id = int(license_id or 0)
        from_id = int(from_account_id or 0)
        to_id = int(to_account_id or 0)
        if not license_id or not from_id or not to_id or from_id == to_id:
            return False
        code = security.normalize_key(key_code)
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT id FROM portal_account_licenses WHERE license_id = ?"
                    " AND account_id = ? AND status = 'bound'",
                    (license_id, from_id),
                ).fetchone()
                if not row:
                    self._conn.commit()
                    return False
                occupied = self._conn.execute(
                    "SELECT id FROM portal_account_licenses WHERE account_id = ?",
                    (to_id,),
                ).fetchone()
                if occupied:
                    self._conn.commit()
                    return False
                self._conn.execute(
                    "UPDATE portal_account_licenses SET account_id = ?, bound_at = ?"
                    " WHERE id = ?",
                    (to_id, now, row["id"]),
                )
                # 转赠后设备绑定清空：新账号需在新设备重新激活。
                self._conn.execute(
                    "UPDATE activations SET status = 'unbound', session_secret = NULL"
                    " WHERE license_id = ? AND status = 'active'",
                    (license_id,),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
        try:
            self.add_binding_history(from_id, license_id, code, "transfer_out",
                                     f"-> account {to_id}", actor)
            self.add_binding_history(to_id, license_id, code, "transfer_in",
                                     f"<- account {from_id}", actor)
        except Exception:
            pass
        return True

    def add_binding_history(''',
    ),
    # 4) 审批方法组（插在 set_portal_account_status 之后）
    (
        '''    def set_portal_account_status(self, account_id, status) -> bool:''',
        '''    # ------------------------------------------------------------------ #
    # 审批中心（仅主控端消费）
    # ------------------------------------------------------------------ #
    def create_approval(self, kind, applicant, target="", payload=None) -> int:
        """创建审批记录（payload 为 dict，JSON 序列化存储）。"""
        body = ""
        if isinstance(payload, dict) and payload:
            try:
                body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
            except Exception:
                body = ""
        return self._execute(
            "INSERT INTO approvals (kind, status, applicant, target, payload,"
            " created_at) VALUES (?, 'pending', ?, ?, ?, ?)",
            (
                str(kind or "")[:64],
                str(applicant or "")[:254],
                str(target or "")[:254],
                body[:8192],
                security.now_str(),
            ),
        )

    def get_approval(self, approval_id: int) -> dict | None:
        return _row_to_dict(
            self._fetchone(
                "SELECT * FROM approvals WHERE id = ?", (int(approval_id or 0),)
            )
        )

    def list_approvals(self, kind="", status="", limit=50, offset=0):
        """返回 (items, total)；kind/status 为空表示不过滤。"""
        sql = " FROM approvals WHERE 1=1"
        params: list = []
        if kind:
            sql += " AND kind = ?"
            params.append(str(kind))
        if status:
            sql += " AND status = ?"
            params.append(str(status))
        total_row = self._fetchone("SELECT COUNT(*) AS n" + sql, tuple(params))
        rows = self._fetchall(
            "SELECT *" + sql + " ORDER BY id DESC LIMIT ? OFFSET ?",
            tuple(params)
            + (max(1, min(int(limit or 50), 200)), max(0, int(offset or 0))),
        )
        return [dict(row) for row in rows], int(total_row["n"]) if total_row else 0

    def count_pending_approvals(self, kind="") -> int:
        if kind:
            row = self._fetchone(
                "SELECT COUNT(*) AS n FROM approvals WHERE status = 'pending'"
                " AND kind = ?",
                (str(kind),),
            )
        else:
            row = self._fetchone(
                "SELECT COUNT(*) AS n FROM approvals WHERE status = 'pending'"
            )
        return int(row["n"]) if row else 0

    def has_pending_transfer(self, license_id: int) -> bool:
        """该卡密是否已有待处理的转赠申请（防重复提交）。"""
        row = self._fetchone(
            "SELECT COUNT(*) AS n FROM approvals WHERE kind = 'license_transfer'"
            " AND status = 'pending' AND payload LIKE ?",
            (f'%"license_id":{int(license_id or 0)}%',),
        )
        return bool(row and int(row["n"]) > 0)

    def review_approval(self, approval_id: int, status: str, reviewer: str = "",
                        note: str = "", *, only_pending: bool = True) -> bool:
        """更新审批状态；only_pending=True 时仅允许 pending 被处理（防双开）。"""
        normalized = str(status or "").strip().lower()
        if normalized not in ("pending", "approved", "rejected"):
            return False
        now = security.now_str()
        with self._lock:
            if only_pending:
                cur = self._conn.execute(
                    "UPDATE approvals SET status = ?, reviewer = ?, review_note = ?,"
                    " reviewed_at = ? WHERE id = ? AND status = 'pending'",
                    (
                        normalized,
                        str(reviewer or "")[:64],
                        str(note or "")[:500],
                        now,
                        int(approval_id or 0),
                    ),
                )
            else:
                cur = self._conn.execute(
                    "UPDATE approvals SET status = ?, reviewer = ?, review_note = ?,"
                    " reviewed_at = ? WHERE id = ?",
                    (
                        normalized,
                        str(reviewer or "")[:64],
                        str(note or "")[:500],
                        now,
                        int(approval_id or 0),
                    ),
                )
            return cur.rowcount == 1

    def set_portal_account_status(self, account_id, status) -> bool:''',
    ),
])

print("C1a 完成（database）")
