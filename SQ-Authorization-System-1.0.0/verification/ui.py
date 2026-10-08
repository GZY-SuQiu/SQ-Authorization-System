import base64
import os
import time

from PySide6.QtCore import QBuffer, QIODevice, QSize, Qt, QTimer
from PySide6.QtGui import QImage, QImageReader, QPainter, QPainterPath, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPlainTextEdit,
    QSizePolicy,
    QScrollArea,
    QStackedWidget,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core import machine, offline, secret_store, security, theme
from core.api_client import ApiClient, ApiError, is_loopback_url
from core.config import APP_AUTHOR, APP_NAME, APP_VERSION, Config
from core.widgets import Card, StatusBadge, Toast, make_button


RESULT_STYLE = {
    "success": (theme.SUCCESS, "#E7F7EE"),
    "warning": (theme.WARNING, "#FEF6E7"),
    "error": (theme.DANGER, "#FDECEA"),
    "info": (theme.TEXT_MUTED, "#F2F4F7"),
}

RESULT_BADGE = {
    "success": "正常",
    "warning": "注意",
    "error": "异常",
    "info": "离线",
}

# Offline validation has to trust the local clock, so winding that clock
# back would otherwise resurrect an expired license. The newest check
# timestamp is therefore remembered and a large step backwards is
# treated as tampering. The tolerance absorbs DST and NTP corrections.
CLOCK_SKEW_TOLERANCE_SECONDS = 6 * 3600
LAST_SEEN_FIELD = "offline_last_seen_ts"

# Portal profile avatars: the server only accepts these image types and caps
# the decoded payload, so the file picker mirrors both rules up front.
AVATAR_SIZE = 64
AVATAR_MAX_BYTES = 256 * 1024
AVATAR_FILE_FILTER = "图片 (*.png *.jpg *.jpeg *.webp);;所有文件 (*)"
AVATAR_MIME_BY_SUFFIX = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
}
# The avatar label is at most 64px, so decoding is capped well below that:
# a tiny file can declare huge pixel dimensions (decode bomb), and the
# scaled size makes QImageReader produce a bounded image instead.
AVATAR_DECODE_LIMIT = 128


def avatar_initial(text: str) -> str:
    """First visible character used when no avatar image is available."""
    value = str(text or "").strip()
    while value and value[0] in "@. ":
        value = value[1:]
    if not value:
        return "?"
    return value[0].upper()


def decode_avatar_bytes(data_base64: str) -> bytes | None:
    """Decode ``data_base64`` defensively; a bad payload is simply "no image"."""
    value = str(data_base64 or "").strip()
    if not value:
        return None
    if value.lower().startswith("data:") and "," in value:
        value = value.split(",", 1)[1]
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception:
        return None
    if not raw or len(raw) > AVATAR_MAX_BYTES:
        return None
    return raw


def decode_avatar_image(raw: bytes, size: int = AVATAR_SIZE) -> QImage | None:
    """Decode one payload at a bounded size, or None when it cannot be read.

    ``QImageReader.setScaledSize`` is called before ``read()`` so a small file
    that declares huge pixel dimensions never gets decoded at full size.
    """
    if not raw:
        return None
    try:
        buffer = QBuffer()
        buffer.setData(raw)
        if not buffer.open(QIODevice.ReadOnly):
            return None
        reader = QImageReader(buffer)
        reader.setAutoTransform(True)
        limit = max(1, min(int(size or AVATAR_SIZE), AVATAR_DECODE_LIMIT))
        declared = reader.size()
        if declared.isValid() and declared.width() > 0 and declared.height() > 0:
            target = declared.scaled(limit, limit, Qt.KeepAspectRatio)
        else:
            # 头部尺寸不可读时也强制目标尺寸，绝不让解码器按原始像素分配。
            target = QSize(limit, limit)
        reader.setScaledSize(target)
        image = reader.read()
        if image is None or image.isNull():
            return None
        return image
    except Exception:
        return None


def rounded_avatar_pixmap(
    data_base64: str, size: int = AVATAR_SIZE
) -> QPixmap | None:
    """Decode one avatar payload into a circular pixmap, or None on failure."""
    raw = decode_avatar_bytes(data_base64)
    if not raw:
        return None
    try:
        image = decode_avatar_image(raw, size)
        if image is None or image.isNull():
            return None
        source = QPixmap.fromImage(image)
        if source.isNull():
            return None
        scaled = source.scaled(
            size, size, Qt.KeepAspectRatioByExpanding, Qt.SmoothTransformation
        )
        rounded = QPixmap(size, size)
        rounded.fill(Qt.transparent)
        painter = QPainter(rounded)
        painter.setRenderHint(QPainter.Antialiasing, True)
        path = QPainterPath()
        path.addEllipse(0.0, 0.0, float(size), float(size))
        painter.setClipPath(path)
        painter.drawPixmap(
            (size - scaled.width()) // 2, (size - scaled.height()) // 2, scaled
        )
        painter.end()
        return rounded
    except Exception:
        return None


def apply_avatar_to_label(label: QLabel, avatar, fallback_text: str = "") -> None:
    """Paint an avatar dict into a round label; fall back to the first letter."""
    payload = avatar.get("data_base64") if isinstance(avatar, dict) else None
    pixmap = rounded_avatar_pixmap(payload or "")
    if pixmap is not None:
        label.setText("")
        label.setStyleSheet("")
        label.setPixmap(pixmap)
        return
    label.setPixmap(QPixmap())
    label.setText(avatar_initial(fallback_text))
    radius = max(1, label.width() // 2)
    label.setStyleSheet(
        f"background: {theme.PRIMARY_SOFT}; color: {theme.PRIMARY};"
        f" border: 1px solid {theme.PRIMARY_BORDER};"
        f" border-radius: {radius}px;"
        " font-size: 22px; font-weight: 700;"
    )


class ProfileEditDialog(QDialog):
    """Edit the signed-in portal account's display name and avatar.

    The dialog only talks to the profile endpoints; every image is read from
    disk, size-checked and base64-encoded locally before it is sent.
    """

    def __init__(
        self,
        client: ApiClient,
        notify,
        display_name: str = "",
        avatar: dict | None = None,
        fallback_text: str = "",
        parent=None,
    ):
        super().__init__(parent)
        self.client = client
        self.notify = notify
        self.initial_display_name = str(display_name or "").strip()
        self.initial_avatar = avatar if isinstance(avatar, dict) else None
        self.fallback_text = str(fallback_text or "").strip()
        self.pending_avatar: dict | None = None
        self.remove_avatar = False
        self.profile: dict | None = None
        self.saved = False

        self.setWindowTitle("编辑资料")
        self.setFixedWidth(420)
        self.setModal(True)

        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(14)

        heading = QLabel("编辑资料")
        heading.setObjectName("Title")
        hint = QLabel("显示名称与头像会展示在验证端资料区")
        hint.setObjectName("Subtitle")
        root.addWidget(heading)
        root.addWidget(hint)

        avatar_row = QHBoxLayout()
        avatar_row.setSpacing(14)
        self.avatar_preview = QLabel("")
        self.avatar_preview.setObjectName("ProfileAvatar")
        self.avatar_preview.setFixedSize(AVATAR_SIZE, AVATAR_SIZE)
        self.avatar_preview.setAlignment(Qt.AlignCenter)
        apply_avatar_to_label(
            self.avatar_preview, self.initial_avatar, self._avatar_fallback()
        )
        avatar_row.addWidget(self.avatar_preview, 0, Qt.AlignTop)
        avatar_actions = QVBoxLayout()
        avatar_actions.setSpacing(8)
        avatar_actions.addWidget(
            make_button("选择头像", "default", self.choose_avatar)
        )
        avatar_actions.addWidget(make_button("移除头像", "ghost", self.clear_avatar))
        avatar_actions.addStretch(1)
        avatar_row.addLayout(avatar_actions, 1)
        root.addLayout(avatar_row)

        self.name = QLineEdit(self.initial_display_name)
        self.name.setPlaceholderText("显示名称（1-32 个字符）")
        self.name.setMaxLength(32)
        self.name.returnPressed.connect(self.save)
        root.addWidget(self._labeled("名称", self.name))

        self.status = QLabel("")
        self.status.setWordWrap(True)
        self.status.setMinimumHeight(20)
        root.addWidget(self.status)

        row = QHBoxLayout()
        row.addStretch(1)
        row.addWidget(make_button("取消", "ghost", self.reject))
        self.btn_save = make_button("保存", "primary", self.save)
        row.addWidget(self.btn_save)
        root.addLayout(row)
        self.name.setFocus()

    def _avatar_fallback(self) -> str:
        return self.initial_display_name or self.fallback_text

    @staticmethod
    def _labeled(label: str, widget: QWidget) -> QWidget:
        box = QWidget()
        layout = QVBoxLayout(box)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        text = QLabel(label)
        text.setObjectName("Muted")
        layout.addWidget(text)
        layout.addWidget(widget)
        return box

    def _show_avatar(self) -> None:
        avatar = self.pending_avatar if self.pending_avatar is not None else None
        if avatar is None and not self.remove_avatar:
            avatar = self.initial_avatar
        apply_avatar_to_label(self.avatar_preview, avatar, self._avatar_fallback())

    def choose_avatar(self) -> None:
        path, _selected = QFileDialog.getOpenFileName(
            self, "选择头像", "", AVATAR_FILE_FILTER
        )
        if not path:
            return
        self.load_avatar_file(path)

    def load_avatar_file(self, path: str) -> bool:
        """Read one image file, enforcing the server's type/size contract."""
        suffix = os.path.splitext(str(path or ""))[1].lower()
        mime = AVATAR_MIME_BY_SUFFIX.get(suffix)
        if not mime:
            self.notify("仅支持 png / jpg / jpeg / webp 格式的图片", "warning")
            return False
        try:
            with open(path, "rb") as handle:
                raw = handle.read(AVATAR_MAX_BYTES + 1)
        except OSError as exc:
            self.notify(f"读取头像失败：{exc}", "error")
            return False
        if not raw:
            self.notify("头像文件为空，请重新选择", "warning")
            return False
        if len(raw) > AVATAR_MAX_BYTES:
            self.notify("头像不能超过 256KB，请压缩后再试", "warning")
            return False
        self.pending_avatar = {
            "mime": mime,
            "data_base64": base64.b64encode(raw).decode("ascii"),
        }
        self.remove_avatar = False
        self._show_avatar()
        self.status.setText("已选择新头像，保存后生效")
        self.status.setStyleSheet(f"color: {theme.TEXT_MUTED};")
        return True

    def clear_avatar(self) -> None:
        self.pending_avatar = None
        self.remove_avatar = True
        self._show_avatar()
        self.status.setText("保存后将移除头像")
        self.status.setStyleSheet(f"color: {theme.TEXT_MUTED};")

    def _set_busy(self, busy: bool) -> None:
        self.name.setEnabled(not busy)
        self.btn_save.setEnabled(not busy)
        self.btn_save.setText("保存中…" if busy else "保存")

    def _fail(self, message: str) -> None:
        self._set_busy(False)
        self.status.setText(message)
        self.status.setStyleSheet(f"color: {theme.DANGER};")
        self.notify(message, "error")

    def save(self) -> None:
        if not self.btn_save.isEnabled():
            return
        name = self.name.text().strip()
        if len(name) > 32:
            self._fail("显示名称不能超过 32 个字符")
            return
        if not name and self.initial_display_name:
            self._fail("显示名称不能为空")
            self.name.setFocus()
            return

        rename = bool(name) and name != self.initial_display_name
        upload = self.pending_avatar is not None
        remove = bool(self.remove_avatar) and bool(self.initial_avatar) and not upload
        if not (rename or upload or remove):
            self.status.setText("资料没有变化")
            self.status.setStyleSheet(f"color: {theme.TEXT_MUTED};")
            self.accept()
            return

        self._set_busy(True)
        self.status.setText("正在保存…")
        self.status.setStyleSheet(f"color: {theme.TEXT_MUTED};")
        try:
            if rename:
                self.client.portal_update_profile(name)
            if upload and self.pending_avatar is not None:
                self.client.portal_upload_avatar(
                    str(self.pending_avatar.get("mime") or ""),
                    str(self.pending_avatar.get("data_base64") or ""),
                )
            elif remove:
                self.client.portal_delete_avatar()
        except ApiError as exc:
            self._fail(str(exc))
            return

        getter = getattr(self.client, "portal_profile", None)
        if callable(getter):
            try:
                data = getter()
                if isinstance(data, dict):
                    self.profile = data
            except ApiError:
                # The edit itself succeeded; the refresh is best effort.
                self.profile = None
        if self.profile is None:
            # Without a follow-up read, still hand the caller the local result
            # so the account card repaints with what was just saved.
            local: dict = {"ok": True}
            if rename:
                local["display_name"] = name
            if upload:
                local["avatar"] = dict(self.pending_avatar or {})
            elif remove:
                local["avatar"] = None
            self.profile = local
        self.saved = True
        self.notify("资料已保存", "success")
        self.accept()


class VerifyWindow(QMainWindow):
    def __init__(self, config: Config):
        super().__init__()
        self.config = config
        self.client = ApiClient(
            config.client.get("server_url", "http://127.0.0.1:8765"),
            int(config.client.get("timeout", 8)),
            allow_insecure_http=bool(config.client.get("allow_insecure_http", False)),
            response_public_key=config.client.get("response_public_key", ""),
            response_key_id=config.client.get("response_key_id", ""),
        )
        self.client.set_trusted_public_keys(
            config.client.get("offline_public_key", ""),
            config.client.get("response_public_key", ""),
            config.client.get("response_key_id", ""),
        )
        self.client.set_session_secret(config.client.get("session_secret"))
        self.machine_code = machine.machine_code()
        self.device_name = machine.device_name()
        self.verify_max_failures = int(config.client.get("verify_max_failures", 5))
        self.verify_lock_seconds = int(config.client.get("verify_lock_seconds", 120))
        self.heartbeat_enabled = bool(config.client.get("heartbeat_enabled", True))
        self.heartbeat_interval = float(config.client.get("heartbeat_interval", 20))
        self.failure_count = 0
        self.locked_until = 0.0
        self.heartbeat_count = 0
        self.time_offset = 0.0
        self.portal_authenticated = False
        self.portal_email = ""
        self.portal_display_name = ""
        self.portal_avatar: dict | None = None
        self.portal_binding: dict | None = None
        self.portal_current_key = ""
        saved_portal_token = str(config.client.get("portal_token") or "").strip()
        if saved_portal_token:
            self.client.portal_token = saved_portal_token
            try:
                self.client.portal_token_expires_at = int(
                    config.client.get("portal_token_expires_at") or 0
                )
            except (TypeError, ValueError):
                self.client.portal_token_expires_at = 0

        self.heartbeat_timer = QTimer(self)
        self.heartbeat_timer.setSingleShot(True)
        self.heartbeat_timer.timeout.connect(self._safe_heartbeat)

        self.setWindowTitle("密钥授权系统 · 验证端")

        content = QWidget()
        content.setObjectName("Root")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        layout.addWidget(self._build_header())

        self.mode_tabs = QTabWidget()
        self.mode_tabs.setObjectName("VerifyModeTabs")
        self.portal_page = self._build_portal_page()
        self.activation_page = self._build_activation_page()
        self.mode_tabs.addTab(self.portal_page, "邮箱登录")
        self.mode_tabs.addTab(self.activation_page, "激活码")
        self.mode_tabs.currentChanged.connect(self._on_mode_changed)
        layout.addWidget(self.mode_tabs, 1)

        default_mode = str(
            config.client.get("default_login_mode")
            or config.client.get("login_mode")
            or config.client.get("verification_mode")
            or config.client.get("portal_default_mode")
            or config.client.get("default_mode")
            or "email"
        ).strip().lower()
        if default_mode in ("activation", "activate", "code", "key", "激活码"):
            self.mode_tabs.setCurrentIndex(1)
        else:
            self.mode_tabs.setCurrentIndex(0)

        self.scroll = QScrollArea()
        self.scroll.setWidget(content)
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.NoFrame)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        # 滚动区与内容层必须是不透明页面底色：透明会让深色系统主题下
        # 滚动时新露出的条带变成整条黑带（见 core/theme.py 同名规则）。
        self.scroll.setStyleSheet(
            f"QScrollArea {{ background: {theme.BG}; border: none; }}"
            f"QScrollArea > QWidget#qt_scrollarea_viewport {{ background: {theme.BG}; }}"
            f"QScrollArea > QWidget > QWidget {{ background: {theme.BG}; }}"
        )
        self.setCentralWidget(self.scroll)

        self._fit_to_screen()
        self.toast = Toast(self)

        self.input_key.setText(str(config.client.get("last_key", "")))
        if config.client.get("auto_verify") and self.input_key.text().strip():
            QTimer.singleShot(400, self._auto_verify_if_activation)
        if self.client.portal_token and self.portal_token_is_usable():
            QTimer.singleShot(250, self.portal_refresh)

    def _build_header(self) -> QWidget:
        box = QWidget()
        row = QHBoxLayout(box)
        row.setContentsMargins(0, 0, 0, 0)
        titles = QVBoxLayout()
        titles.setSpacing(2)
        brand = QLabel("密钥授权 · 验证端")
        brand.setObjectName("Title")
        sub = QLabel("在本设备上输入密钥完成激活与校验")
        sub.setObjectName("Subtitle")
        titles.addWidget(brand)
        titles.addWidget(sub)
        row.addLayout(titles)
        row.addStretch(1)
        credit = QLabel(f"作者：{APP_AUTHOR}    {APP_NAME} v{APP_VERSION}")
        credit.setObjectName("Muted")
        recent = QVBoxLayout()
        recent.setSpacing(2)
        recent.addStretch(1)
        recent.addWidget(credit)
        row.addLayout(recent)
        return box

    def _build_portal_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName("PortalPage")
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 12, 0, 0)
        outer.setSpacing(14)

        self.portal_body_layout = QGridLayout()
        self.portal_body_layout.setContentsMargins(0, 0, 0, 0)
        self.portal_body_layout.setHorizontalSpacing(14)
        self.portal_body_layout.setVerticalSpacing(14)

        self.portal_account_panel = QWidget()
        account = QVBoxLayout(self.portal_account_panel)
        account.setContentsMargins(0, 0, 0, 0)
        account.setSpacing(14)
        account.addWidget(self._build_portal_account_card())
        account.addStretch(1)

        self.portal_binding_panel = QWidget()
        binding = QVBoxLayout(self.portal_binding_panel)
        binding.setContentsMargins(0, 0, 0, 0)
        binding.setSpacing(14)
        binding.addWidget(self._build_portal_binding_card())
        binding.addStretch(1)

        self._portal_compact_layout: bool | None = None
        self._arrange_portal_body(False)
        outer.addLayout(self.portal_body_layout, 1)
        self._refresh_portal_view()
        return page

    def _build_activation_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName("ActivationPage")
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 12, 0, 0)
        outer.setSpacing(14)

        body = QGridLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setHorizontalSpacing(14)
        body.setVerticalSpacing(14)

        self.left_panel = QWidget()
        left = QVBoxLayout(self.left_panel)
        left.setContentsMargins(0, 0, 0, 0)
        left.setSpacing(14)
        left.addWidget(self._build_activate_card())
        left.addWidget(self._build_offline_card())
        left.addStretch(1)

        self.right_panel = QWidget()
        right = QVBoxLayout(self.right_panel)
        right.setContentsMargins(0, 0, 0, 0)
        right.setSpacing(14)
        right.addWidget(self._build_device_card())
        right.addWidget(self._build_result_card(), 1)

        self.body_layout = body
        self._compact_layout: bool | None = None
        self._arrange_body(False)
        outer.addLayout(body, 1)
        return page

    def _build_portal_account_card(self) -> QWidget:
        card = Card(padding=18)
        card.body.addWidget(QLabel("邮箱账号"))

        self.portal_account_stack = QStackedWidget()
        self.portal_account_stack.addWidget(self._build_portal_logged_out())
        self.portal_account_stack.addWidget(self._build_portal_logged_in())
        self.portal_account_stack.setCurrentIndex(0)
        card.body.addWidget(self.portal_account_stack)
        return card

    def _build_portal_logged_out(self) -> QWidget:
        box = QWidget()
        layout = QVBoxLayout(box)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        hint = QLabel("登录后可在这台设备上绑定授权并接收续费提醒。")
        hint.setObjectName("Muted")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        self.portal_auth_tabs = QTabWidget()
        self.portal_auth_tabs.setObjectName("PortalAuthTabs")
        self.portal_auth_tabs.addTab(self._build_portal_login_form(), "登录")
        self.portal_auth_tabs.addTab(self._build_portal_register_form(), "注册")
        self.portal_auth_tabs.addTab(self._build_portal_forgot_form(), "忘记密码")
        layout.addWidget(self.portal_auth_tabs)
        return box

    def _build_portal_login_form(self) -> QWidget:
        box = QWidget()
        layout = QVBoxLayout(box)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(10)

        self.portal_login_email = QLineEdit()
        self.portal_login_email.setPlaceholderText("name@example.com")
        self.portal_login_email.returnPressed.connect(self.portal_login)
        layout.addWidget(self._labeled("邮箱", self.portal_login_email))

        self.portal_login_password = QLineEdit()
        self.portal_login_password.setEchoMode(QLineEdit.Password)
        self.portal_login_password.setPlaceholderText("请输入密码")
        self.portal_login_password.returnPressed.connect(self.portal_login)
        layout.addWidget(self._labeled("密码", self.portal_login_password))

        self.portal_remember_username_check = QCheckBox("记住账号")
        layout.addWidget(self.portal_remember_username_check)

        self.portal_remember_password_check = QCheckBox("记住密码（本机加密保存）")
        self.portal_remember_password_check.toggled.connect(
            self._on_portal_remember_password_toggled
        )
        layout.addWidget(self.portal_remember_password_check)
        if not secret_store.is_secure_available():
            self.portal_remember_password_check.setEnabled(False)
            self.portal_remember_password_check.setToolTip("当前系统不支持安全保存")
            unsupported_hint = QLabel("当前系统不支持安全保存，只能记住账号。")
            unsupported_hint.setObjectName("Muted")
            unsupported_hint.setWordWrap(True)
            layout.addWidget(unsupported_hint)

        self.portal_login_button = make_button("登录", "primary", self.portal_login)
        layout.addWidget(self.portal_login_button)
        layout.addStretch(1)

        self._restore_remembered_login()
        return box

    def _on_portal_remember_password_toggled(self, checked: bool) -> None:
        """“记住密码”必须在“记住账号”之上，勾选时自动锁定。"""

        if checked:
            self.portal_remember_username_check.setChecked(True)
            self.portal_remember_username_check.setEnabled(False)
        else:
            self.portal_remember_username_check.setEnabled(True)

    def _restore_remembered_login(self) -> None:
        """把上次记住的邮箱/密码预填回登录表单（DPAPI 解不开就不预填）。"""

        client = self.config.client
        saved_email = str(client.get("saved_email") or "").strip()
        if client.get("remember_username") and saved_email:
            self.portal_remember_username_check.setChecked(True)
            self.portal_login_email.setText(saved_email)

        saved_password = str(client.get("saved_password") or "")
        if (
            not client.get("remember_password")
            or not saved_password
            or not secret_store.is_secure_available()
        ):
            return
        plain = secret_store.unprotect(saved_password)
        if not plain:
            # 旧 token 换机器/换用户后解不开：清掉内存值，下次保存时落盘。
            client["saved_password"] = ""
            self.portal_remember_password_check.setChecked(False)
            return
        self.portal_login_password.setText(plain)
        self.portal_remember_password_check.setChecked(True)

    def _build_portal_register_form(self) -> QWidget:
        box = QWidget()
        layout = QVBoxLayout(box)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(10)

        self.portal_register_email = QLineEdit()
        self.portal_register_email.setPlaceholderText("name@example.com")
        layout.addWidget(self._labeled("邮箱", self.portal_register_email))

        code_row = QHBoxLayout()
        self.portal_register_code = QLineEdit()
        self.portal_register_code.setPlaceholderText("6 位验证码")
        self.portal_register_send_button = make_button(
            "发送验证码", "default", self.portal_send_register_code
        )
        self.portal_register_send_button.setMinimumWidth(112)
        code_row.addWidget(self.portal_register_code, 1)
        code_row.addWidget(self.portal_register_send_button)
        layout.addWidget(self._labeled("验证码", self._layout_widget(code_row)))

        self.portal_register_password = QLineEdit()
        self.portal_register_password.setEchoMode(QLineEdit.Password)
        self.portal_register_password.setPlaceholderText("至少 8 位")
        layout.addWidget(self._labeled("密码", self.portal_register_password))

        self.portal_register_button = make_button(
            "注册并登录", "primary", self.portal_register
        )
        layout.addWidget(self.portal_register_button)
        layout.addStretch(1)
        return box

    def _build_portal_forgot_form(self) -> QWidget:
        box = QWidget()
        layout = QVBoxLayout(box)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(10)

        self.portal_reset_email = QLineEdit()
        self.portal_reset_email.setPlaceholderText("name@example.com")
        layout.addWidget(self._labeled("邮箱", self.portal_reset_email))

        code_row = QHBoxLayout()
        self.portal_reset_code = QLineEdit()
        self.portal_reset_code.setPlaceholderText("6 位验证码")
        self.portal_reset_send_button = make_button(
            "发送验证码", "default", self.portal_send_reset_code
        )
        self.portal_reset_send_button.setMinimumWidth(112)
        code_row.addWidget(self.portal_reset_code, 1)
        code_row.addWidget(self.portal_reset_send_button)
        layout.addWidget(self._labeled("验证码", self._layout_widget(code_row)))

        self.portal_reset_password = QLineEdit()
        self.portal_reset_password.setEchoMode(QLineEdit.Password)
        self.portal_reset_password.setPlaceholderText("至少 8 位")
        layout.addWidget(self._labeled("新密码", self.portal_reset_password))

        self.portal_reset_button = make_button(
            "重置密码", "primary", self.portal_reset
        )
        layout.addWidget(self.portal_reset_button)
        layout.addStretch(1)
        return box

    def _build_portal_logged_in(self) -> QWidget:
        box = QWidget()
        layout = QVBoxLayout(box)
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(8)

        # The row is pinned to the avatar height so a tall card cannot push
        # the name/address away from the picture.
        profile = QWidget()
        profile.setFixedHeight(AVATAR_SIZE)
        profile_row = QHBoxLayout(profile)
        profile_row.setContentsMargins(0, 0, 0, 0)
        profile_row.setSpacing(14)
        self.portal_avatar_label = QLabel("")
        self.portal_avatar_label.setObjectName("PortalAvatar")
        self.portal_avatar_label.setFixedSize(AVATAR_SIZE, AVATAR_SIZE)
        self.portal_avatar_label.setAlignment(Qt.AlignCenter)
        self.portal_avatar_label.setTextInteractionFlags(Qt.NoTextInteraction)
        profile_row.addWidget(self.portal_avatar_label, 0, Qt.AlignVCenter)

        identity = QVBoxLayout()
        identity.setSpacing(2)
        identity.addStretch(1)
        self.portal_display_name_label = QLabel("")
        self.portal_display_name_label.setObjectName("SectionTitle")
        self.portal_display_name_label.setWordWrap(True)
        self.portal_display_name_label.setSizePolicy(
            QSizePolicy.Ignored, QSizePolicy.Preferred
        )
        identity.addWidget(self.portal_display_name_label)

        self.portal_email_label = QLabel("")
        self.portal_email_label.setObjectName("Muted")
        self.portal_email_label.setWordWrap(True)
        self.portal_email_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.portal_email_label.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        identity.addWidget(self.portal_email_label)
        identity.addStretch(1)
        profile_row.addLayout(identity, 1)
        layout.addWidget(profile)

        info = QGridLayout()
        info.setHorizontalSpacing(12)
        info.setVerticalSpacing(4)
        info.addWidget(QLabel("绑定 Key"), 0, 0)
        info.addWidget(QLabel("状态"), 0, 1)
        info.addWidget(QLabel("到期时间"), 0, 2)
        self.portal_bound_key_label = QLabel("未绑定")
        self.portal_bound_status_label = QLabel("未绑定")
        self.portal_bound_expiry_label = QLabel("未设置")
        for label in (
            self.portal_bound_key_label,
            self.portal_bound_status_label,
            self.portal_bound_expiry_label,
        ):
            label.setObjectName("Muted")
            label.setWordWrap(True)
        info.addWidget(self.portal_bound_key_label, 1, 0)
        info.addWidget(self.portal_bound_status_label, 1, 1)
        info.addWidget(self.portal_bound_expiry_label, 1, 2)
        info.setColumnStretch(0, 2)
        info.setColumnStretch(1, 1)
        info.setColumnStretch(2, 2)
        layout.addLayout(info)

        actions = QHBoxLayout()
        self.portal_edit_button = make_button(
            "编辑资料", "default", self.open_profile_editor
        )
        self.portal_logout_button = make_button("退出登录", "ghost", self.portal_logout)
        actions.addWidget(self.portal_edit_button)
        actions.addWidget(self.portal_logout_button)
        actions.addStretch(1)
        layout.addLayout(actions)
        layout.addStretch(1)
        return box

    def _build_portal_binding_card(self) -> QWidget:
        card = Card(padding=18)
        card.body.addWidget(QLabel("授权绑定"))

        self.portal_binding_stack = QStackedWidget()
        self.portal_binding_stack.addWidget(self._build_portal_binding_hint())
        self.portal_binding_stack.addWidget(self._build_portal_binding_form())
        self.portal_binding_stack.addWidget(self._build_portal_bound_actions())
        self.portal_binding_stack.setCurrentIndex(0)
        card.body.addWidget(self.portal_binding_stack)

        self.portal_result_card = QFrame()
        self.portal_result_card.setObjectName("StatCard")
        result = QVBoxLayout(self.portal_result_card)
        result.setContentsMargins(18, 16, 18, 16)
        result.setSpacing(6)
        result_header = QHBoxLayout()
        self.portal_result_badge = StatusBadge("未登录", "neutral")
        result_header.addWidget(QLabel("账号状态"))
        result_header.addStretch(1)
        result_header.addWidget(self.portal_result_badge)
        result.addLayout(result_header)
        self.portal_result_title = QLabel("未登录")
        self.portal_result_title.setObjectName("Title")
        self.portal_result_detail = QLabel("登录邮箱账号后即可绑定和校验授权。")
        self.portal_result_detail.setObjectName("Muted")
        self.portal_result_detail.setWordWrap(True)
        self.portal_online_label = QLabel("心跳：未开启")
        self.portal_online_label.setObjectName("Muted")
        self.portal_online_label.setWordWrap(True)
        result.addWidget(self.portal_result_title)
        result.addWidget(self.portal_result_detail)
        result.addWidget(self.portal_online_label)
        card.body.addWidget(self.portal_result_card)
        return card

    def _build_portal_binding_hint(self) -> QWidget:
        box = QWidget()
        layout = QVBoxLayout(box)
        layout.setContentsMargins(0, 4, 0, 0)
        label = QLabel("登录后可以绑定一个授权 Key。")
        label.setObjectName("Muted")
        label.setWordWrap(True)
        layout.addWidget(label)
        layout.addStretch(1)
        return box

    def _build_portal_binding_form(self) -> QWidget:
        box = QWidget()
        layout = QVBoxLayout(box)
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(10)

        self.portal_key_input = QLineEdit()
        self.portal_key_input.setPlaceholderText(
            "请输入授权 Key，如 GSQ-XXXXX-XXXXX-XXXXX-XXXXX"
        )
        self.portal_key_input.returnPressed.connect(self.portal_bind)
        layout.addWidget(self._labeled("授权 Key", self.portal_key_input))

        machine_hint = QLabel(f"本机机器码：{self.machine_code}")
        machine_hint.setObjectName("Muted")
        machine_hint.setWordWrap(True)
        layout.addWidget(machine_hint)

        self.portal_bind_button = make_button(
            "绑定并激活", "primary", self.portal_bind
        )
        layout.addWidget(self.portal_bind_button)
        layout.addStretch(1)
        return box

    def _build_portal_bound_actions(self) -> QWidget:
        box = QWidget()
        layout = QVBoxLayout(box)
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(10)

        hint = QLabel("授权已绑定。自助脱绑仅在授权已过期、吊销或次数用尽时可用。")
        hint.setObjectName("Muted")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        actions = QHBoxLayout()
        self.portal_verify_button = make_button("校验状态", "default", self.portal_verify)
        self.portal_renew_button = make_button("请求续费", "default", self.portal_renew)
        self.portal_unbind_button = make_button("脱绑", "danger", self.portal_unbind)
        actions.addWidget(self.portal_verify_button)
        actions.addWidget(self.portal_renew_button)
        actions.addWidget(self.portal_unbind_button)
        actions.addStretch(1)
        layout.addLayout(actions)
        layout.addStretch(1)
        return box

    @staticmethod
    def _layout_widget(layout) -> QWidget:
        box = QWidget()
        box.setLayout(layout)
        layout.setContentsMargins(0, 0, 0, 0)
        return box

    def _build_device_card(self) -> QWidget:
        card = Card(padding=18)
        card.body.addWidget(QLabel("本机信息"))
        info = machine.system_info()

        code_row = QHBoxLayout()
        self.machine_label = QLabel(self.machine_code)
        self.machine_label.setObjectName("KeyText")
        self.machine_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        code_row.addWidget(self.machine_label, 1)
        code_row.addWidget(make_button("复制机器码", "ghost", self.copy_machine))
        card.body.addLayout(code_row)

        meta = QLabel(f"设备名：{info['device_name']}    系统：{info['platform']}")
        meta.setObjectName("Muted")
        meta.setWordWrap(True)
        card.body.addWidget(meta)
        return card

    def _build_activate_card(self) -> QWidget:
        card = Card(padding=18)
        card.body.addWidget(QLabel("激活 / 校验"))

        self.input_server = QLineEdit(self.client.base_url)
        self.input_server.setPlaceholderText("http://127.0.0.1:8765")
        self.input_key = QLineEdit()
        self.input_key.setPlaceholderText("请输入密钥，如 GSQ-XXXXX-XXXXX-XXXXX-XXXXX")
        self.input_key.returnPressed.connect(self.activate)

        card.body.addWidget(self._labeled("服务器地址", self.input_server))
        card.body.addWidget(self._labeled("授权密钥", self.input_key))

        self.auto_check = QCheckBox("记住密钥并在下次启动时自动校验")
        self.auto_check.setChecked(bool(self.config.client.get("auto_verify", True)))
        card.body.addWidget(self.auto_check)

        row = QHBoxLayout()
        row.addWidget(make_button("立即激活", "primary", self.activate))
        row.addWidget(make_button("校验状态", "default", self.verify))
        row.addWidget(make_button("连接测试", "ghost", self.test_connection))
        row.addStretch(1)
        card.body.addLayout(row)
        return card

    def _build_offline_card(self) -> QWidget:
        card = Card(padding=18)
        card.body.addWidget(QLabel("离线激活（无网络环境）"))
        hint = QLabel(
            "步骤：① 生成请求码交给管理员 → ② 管理员返回离线激活码 → "
            "③ 粘贴并导入，之后无需联网即可完成离线校验。"
        )
        hint.setObjectName("Muted")
        hint.setWordWrap(True)
        card.body.addWidget(hint)

        self.request_output = QPlainTextEdit()
        self.request_output.setReadOnly(True)
        self.request_output.setFixedHeight(88)
        self.request_output.setPlaceholderText("点击“生成请求码”后显示，复制发给管理员")
        card.body.addWidget(self._labeled("本机请求码", self.request_output))
        req_row = QHBoxLayout()
        req_row.addWidget(make_button("生成请求码", "default", self.make_request))
        req_row.addWidget(make_button("复制请求码", "ghost", self.copy_request))
        req_row.addWidget(make_button("保存请求码", "ghost", self.save_request))
        req_row.addStretch(1)
        card.body.addLayout(req_row)

        self.offline_input = QPlainTextEdit()
        self.offline_input.setFixedHeight(88)
        self.offline_input.setPlaceholderText("粘贴管理员返回的离线激活码（LICACT1. 开头）")
        card.body.addWidget(self._labeled("离线激活码", self.offline_input))
        imp_row = QHBoxLayout()
        imp_row.addWidget(make_button("导入离线激活码", "primary", self.import_offline))
        imp_row.addWidget(make_button("离线校验", "default", self.offline_verify))
        imp_row.addStretch(1)
        card.body.addLayout(imp_row)
        return card

    def _build_result_card(self) -> QWidget:
        card = Card(padding=18)
        card.setMinimumWidth(300)
        header = QHBoxLayout()
        header.addWidget(QLabel("授权状态"))
        header.addStretch(1)
        self.result_badge = StatusBadge("未校验", "neutral")
        header.addWidget(self.result_badge)
        card.body.addLayout(header)
        self.status_card = QFrame()
        self.status_card.setObjectName("StatCard")
        status_layout = QVBoxLayout(self.status_card)
        status_layout.setContentsMargins(20, 18, 20, 18)
        status_layout.setSpacing(6)
        self.status_title = QLabel("尚未校验")
        self.status_title.setObjectName("Title")
        self.status_detail = QLabel("点击“校验状态”查看当前授权情况")
        self.status_detail.setObjectName("Muted")
        self.status_detail.setWordWrap(True)
        self.online_label = QLabel("心跳：未开启")
        self.online_label.setObjectName("Muted")
        self.online_label.setWordWrap(True)
        self.online_label.setStyleSheet(f"color: {theme.TEXT_MUTED};")
        status_layout.addWidget(self.status_title)
        status_layout.addWidget(self.status_detail)
        status_layout.addWidget(self.online_label)
        card.body.addWidget(self.status_card)
        card.body.addStretch(1)
        return card

    @staticmethod
    def _labeled(label: str, widget: QWidget) -> QWidget:
        box = QWidget()
        layout = QVBoxLayout(box)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        text = QLabel(label)
        text.setObjectName("Muted")
        layout.addWidget(text)
        layout.addWidget(widget)
        return box

    def _on_mode_changed(self, index: int) -> None:
        if index == 1 and getattr(self, "_pending_activation_auto_verify", False):
            self._pending_activation_auto_verify = False
            QTimer.singleShot(0, self.verify)

    def _auto_verify_if_activation(self) -> None:
        if not self.input_key.text().strip():
            return
        if self.mode_tabs.currentIndex() == 1:
            self.verify()
        else:
            self._pending_activation_auto_verify = True

    def portal_token_is_usable(self) -> bool:
        if not getattr(self.client, "portal_token", ""):
            return False
        try:
            expires_at = int(getattr(self.client, "portal_token_expires_at", 0) or 0)
        except (TypeError, ValueError):
            expires_at = 0
        return expires_at <= 0 or expires_at > int(time.time())

    @staticmethod
    def _clean_email(value: str) -> str:
        return str(value or "").strip().lower()

    @staticmethod
    def _portal_failure_message(data: dict, fallback: str) -> str:
        code = str(data.get("code") or "").strip().lower()
        messages = {
            "invalid_credentials": "邮箱或密码错误",
            "already_registered": "该邮箱已注册",
            "invalid_code": "验证码错误或已过期",
            "code_invalid": "验证码错误或已过期",
            "invalid_license": "授权 Key 无效或不可用",
            "rate_limited": "操作过于频繁，请稍后再试",
            "smtp_disabled": "邮件服务未配置",
        }
        return str(data.get("message") or messages.get(code) or fallback)

    def portal_send_register_code(self) -> None:
        email = self._clean_email(self.portal_register_email.text())
        if not email:
            self.toast.show_message("请输入邮箱", "warning")
            return
        try:
            data = self.client.portal_send_code(email, "register")
        except ApiError as exc:
            self.toast.show_message(str(exc), "error")
            return
        if data.get("ok") is False and data.get("code") == "already_registered":
            self.toast.show_message("该邮箱已注册，请直接登录", "warning")
            self.portal_auth_tabs.setCurrentIndex(0)
            self.portal_login_email.setText(email)
            return
        if data.get("ok") is False:
            self.toast.show_message(
                self._portal_failure_message(data, "验证码发送失败"), "error"
            )
            return
        self.toast.show_message("验证码已发送，请查看邮箱", "success")

    def portal_send_reset_code(self) -> None:
        email = self._clean_email(self.portal_reset_email.text())
        if not email:
            self.toast.show_message("请输入邮箱", "warning")
            return
        try:
            data = self.client.portal_send_code(email, "reset")
        except ApiError as exc:
            self.toast.show_message(str(exc), "error")
            return
        if data.get("ok") is False:
            self.toast.show_message(
                self._portal_failure_message(data, "验证码发送失败"), "error"
            )
            return
        self.toast.show_message("如邮箱已注册，验证码已发送", "success")

    def portal_login(self) -> None:
        email = self._clean_email(self.portal_login_email.text())
        password = self.portal_login_password.text()
        if not email or not password:
            self.toast.show_message("请输入邮箱和密码", "warning")
            return
        try:
            data = self.client.portal_login(email, password)
        except ApiError as exc:
            self._set_portal_result("error", "登录失败", str(exc))
            self.toast.show_message(str(exc), "error")
            return
        if not data.get("ok"):
            message = self._portal_failure_message(data, "登录失败")
            self._set_portal_result("error", "登录失败", message)
            self.toast.show_message(message, "error")
            return
        self._persist_remembered_credentials(email, password)
        self._after_portal_authenticated(
            str(data.get("email") or email),
            data.get("binding") if isinstance(data.get("binding"), dict) else None,
            "登录成功",
            profile=data,
        )

    def _persist_remembered_credentials(self, email: str, password: str) -> None:
        """把登录表单的“记住账号/记住密码”写回配置。

        密码只以 secret_store 生成的加密 token 落盘；这里任何异常都只提示，
        不影响已经成功的登录流程。
        """

        try:
            remember_username = self.portal_remember_username_check.isChecked()
            remember_password = (
                self.portal_remember_password_check.isChecked()
                and self.portal_remember_password_check.isEnabled()
            )
            if remember_password and not remember_username:
                # 正常 UI 流程不会走到这里（勾选密码会锁定账号）；兜底提示。
                self.portal_remember_username_check.setChecked(True)
                remember_username = True
                self.toast.show_message("请先勾选「记住账号」，才能记住密码", "warning")

            client = self.config.client
            if remember_username:
                client["remember_username"] = True
                client["saved_email"] = str(email or "")
            else:
                client["remember_username"] = False
                client["saved_email"] = ""
            if remember_password:
                client["saved_password"] = secret_store.protect(password)
                client["remember_password"] = True
            else:
                client["saved_password"] = ""
                client["remember_password"] = False
            self.config.save()
        except Exception as exc:  # 存储失败不能影响登录成功流程
            self.toast.show_message(f"记住登录信息保存失败：{exc}", "warning")

    def portal_register(self) -> None:
        email = self._clean_email(self.portal_register_email.text())
        code = self.portal_register_code.text().strip()
        password = self.portal_register_password.text()
        if not email or not code or not password:
            self.toast.show_message("请填写邮箱、验证码和密码", "warning")
            return
        try:
            data = self.client.portal_register(email, code, password)
        except ApiError as exc:
            self._set_portal_result("error", "注册失败", str(exc))
            self.toast.show_message(str(exc), "error")
            return
        if not data.get("ok"):
            message = self._portal_failure_message(data, "注册失败")
            self._set_portal_result("error", "注册失败", message)
            self.toast.show_message(message, "error")
            return
        self._persist_remembered_credentials(email, password)
        self._after_portal_authenticated(
            str(data.get("email") or email),
            data.get("binding") if isinstance(data.get("binding"), dict) else None,
            "注册成功",
            profile=data,
        )

    def portal_reset(self) -> None:
        email = self._clean_email(self.portal_reset_email.text())
        code = self.portal_reset_code.text().strip()
        new_password = self.portal_reset_password.text()
        if not email or not code or not new_password:
            self.toast.show_message("请填写邮箱、验证码和新密码", "warning")
            return
        try:
            data = self.client.portal_password_reset(email, code, new_password)
        except ApiError as exc:
            self.toast.show_message(str(exc), "error")
            return
        if not data.get("ok"):
            self.toast.show_message(
                self._portal_failure_message(data, "密码重置失败"), "error"
            )
            return
        self._clear_portal_ui()
        self.portal_auth_tabs.setCurrentIndex(0)
        self.portal_login_email.setText(email)
        self.portal_reset_code.clear()
        self.portal_reset_password.clear()
        self._set_portal_result("success", "密码已重置", "请使用新密码登录。")
        self.toast.show_message("密码已重置，请重新登录", "success")

    def _after_portal_authenticated(
        self,
        email: str,
        binding: dict | None,
        title: str,
        profile: dict | None = None,
    ) -> None:
        self.portal_authenticated = True
        self.portal_email = email
        self.portal_binding = binding if isinstance(binding, dict) else None
        self.portal_current_key = self._binding_key(self.portal_binding)
        if isinstance(profile, dict):
            self._apply_portal_profile(profile)
        self._refresh_portal_view()
        if self.portal_binding:
            self._set_portal_result(
                "success", title, self._binding_detail(self.portal_binding)
            )
            if getattr(self.client, "session_secret", None):
                self._set_portal_online("info", "心跳：启动中…")
                self._start_heartbeat(immediate=True)
        else:
            self._set_portal_result("info", title, "尚未绑定授权 Key，请完成绑定。")
        self.toast.show_message(title, "success")

    def _capture_portal_activation(self, data: dict) -> None:
        activation = data.get("activation") if isinstance(data.get("activation"), dict) else {}
        self._merge_portal_license_fields(activation)
        secret = activation.get("session_secret") or data.get("session_secret")
        if not secret and isinstance(activation.get("data"), dict):
            secret = activation["data"].get("session_secret")
        if secret:
            secret_value = str(secret)
            setter = getattr(self.client, "set_session_secret", None)
            if callable(setter):
                setter(secret_value)
            else:
                self.client.session_secret = secret_value
            self.config.client["session_secret"] = secret_value
            self.config.save()

    def _merge_portal_license_fields(self, data: dict) -> None:
        if not isinstance(data, dict) or not isinstance(self.portal_binding, dict):
            return
        for name in (
            "expires_at",
            "days_left",
            "remaining",
            "card_type",
            "activation_limit",
            "activation_count",
            "activation_left",
        ):
            if name in data:
                self.portal_binding[name] = data.get(name)
        code = str(data.get("code") or "").strip().lower()
        if code in ("revoked", "expired", "exhausted", "not_active"):
            self.portal_binding["license_status"] = code
        elif code == "alive" or data.get("ok") is True:
            self.portal_binding["license_status"] = "active"
        self._refresh_portal_view()

    def portal_refresh(self) -> None:
        if not self.portal_token_is_usable():
            self._clear_portal_ui()
            return
        try:
            data = self.client.portal_me()
        except ApiError as exc:
            if not getattr(self.client, "portal_token", ""):
                self._clear_portal_ui()
                self.toast.show_message("登录已失效，请重新登录", "warning")
            else:
                self.toast.show_message(str(exc), "error")
            return
        if not data.get("ok"):
            self._clear_portal_ui()
            self.toast.show_message(
                self._portal_failure_message(data, "登录已失效"), "warning"
            )
            return
        self.portal_authenticated = True
        self.portal_email = str(data.get("email") or self.portal_email)
        self._apply_portal_profile(data)
        self.portal_binding = data.get("binding") if isinstance(data.get("binding"), dict) else None
        self.portal_current_key = self._binding_key(self.portal_binding)
        self._refresh_portal_view()
        if self.portal_binding and getattr(self.client, "session_secret", None):
            self._start_heartbeat(immediate=True)

    # --------------------------------------------------- portal profile
    def _portal_identity(self) -> tuple[str, str]:
        email = str(self.portal_email or "").strip()
        name = str(self.portal_display_name or "").strip()
        if not name and email:
            name = email.split("@", 1)[0]
        return name, email

    def _apply_portal_profile(self, data: dict) -> None:
        """Store display_name/avatar when the server sent them."""
        if not isinstance(data, dict):
            return
        email = str(data.get("email") or "").strip()
        if email:
            self.portal_email = email
        if "display_name" in data:
            self.portal_display_name = str(data.get("display_name") or "").strip()
        if "avatar" in data:
            avatar = data.get("avatar")
            self.portal_avatar = avatar if isinstance(avatar, dict) else None

    def _refresh_portal_identity(self) -> None:
        name, email = self._portal_identity()
        display = getattr(self, "portal_display_name_label", None)
        if display is not None:
            display.setText(name or "未设置")
        label = getattr(self, "portal_email_label", None)
        if label is not None:
            label.setText(email or "未提供邮箱")
        avatar_label = getattr(self, "portal_avatar_label", None)
        if avatar_label is not None:
            apply_avatar_to_label(
                avatar_label, self.portal_avatar, name or email or "?"
            )

    def portal_refresh_profile(self, silent: bool = False) -> bool:
        """Reload the profile (name/avatar) and repaint the account card."""
        getter = getattr(self.client, "portal_profile", None)
        if not callable(getter):
            return False
        try:
            data = getter()
        except ApiError as exc:
            if not silent:
                self.toast.show_message(f"资料刷新失败：{exc}", "error")
            return False
        if not isinstance(data, dict) or data.get("ok") is False:
            return False
        self._apply_portal_profile(data)
        self._refresh_portal_view()
        return True

    def open_profile_editor(self) -> None:
        if not self.portal_authenticated:
            self.toast.show_message("请先登录邮箱账号", "warning")
            return
        dialog = ProfileEditDialog(
            self.client,
            self.toast.show_message,
            display_name=self.portal_display_name,
            avatar=self.portal_avatar,
            fallback_text=self.portal_email,
            parent=self,
        )
        dialog.exec()
        if not dialog.saved:
            return
        if isinstance(dialog.profile, dict) and dialog.profile:
            self._apply_portal_profile(dialog.profile)
            self._refresh_portal_view()
        else:
            # The save succeeded but the follow-up read did not; retry quietly
            # so the account card still reflects the edit right away.
            self.portal_refresh_profile(silent=True)

    def portal_bind(self) -> None:
        key = security.normalize_key(self.portal_key_input.text())
        if not key:
            self.toast.show_message("请输入授权 Key", "warning")
            return
        try:
            data = self.client.portal_bind(key, self.machine_code, self.device_name)
        except ApiError as exc:
            self._set_portal_result("error", "绑定失败", str(exc))
            self.toast.show_message(str(exc), "error")
            return
        if not data.get("ok"):
            message = self._portal_failure_message(data, "绑定失败")
            self._set_portal_result("error", "绑定失败", message)
            self.toast.show_message(message, "error")
            return
        binding = data.get("binding") if isinstance(data.get("binding"), dict) else None
        self.portal_binding = binding
        self.portal_current_key = self._binding_key(binding) or key
        self._capture_portal_activation(data)
        self._refresh_portal_view()
        detail = self._binding_detail(binding) or f"授权 Key：{self._mask_key(key)}"
        self._set_portal_result("success", "绑定并激活成功", detail)
        self.toast.show_message("绑定并激活成功", "success")
        self._set_portal_online("info", "心跳：启动中…")
        self._start_heartbeat(immediate=True)

    def _portal_action_key(self) -> str:
        return self.portal_current_key or self._binding_key(self.portal_binding)

    def portal_verify(self) -> None:
        key = self._portal_action_key()
        if not key:
            self.toast.show_message("当前账号尚未绑定 Key", "warning")
            return
        if not getattr(self.client, "session_secret", None):
            self._set_portal_result(
                "warning", "需要重新激活",
                "当前设备缺少会话密钥，请重新绑定或使用激活码校验。",
            )
            self.toast.show_message("当前设备缺少会话密钥，请重新激活", "warning")
            return
        try:
            data = self.client.verify(key, self.machine_code)
        except ApiError as exc:
            self._set_portal_result("error", "校验失败", str(exc))
            self.toast.show_message(str(exc), "error")
            return
        self._merge_portal_license_fields(data)
        if data.get("ok"):
            self._set_portal_result("success", "授权有效", self._detail(data))
            self._set_portal_online("info", "心跳：启动中…")
            self._start_heartbeat()
        else:
            message = str(data.get("message") or "授权无效")
            self._set_portal_result("error", message, self._detail(data))
            self.toast.show_message(message, "error")

    def portal_renew(self) -> None:
        if not self.portal_binding:
            self.toast.show_message("当前账号尚未绑定 Key", "warning")
            return
        try:
            data = self.client.portal_renew_request("")
        except ApiError as exc:
            self._set_portal_result("error", "续费请求失败", str(exc))
            self.toast.show_message(str(exc), "error")
            return
        if not data.get("ok"):
            message = self._portal_failure_message(data, "续费请求失败")
            self._set_portal_result("error", "续费请求失败", message)
            self.toast.show_message(message, "error")
            return
        self._set_portal_result("success", "续费请求已提交", "管理员处理后会通知您。")
        self.toast.show_message("续费请求已提交", "success")

    def portal_unbind(self) -> None:
        if not self.portal_binding:
            self.toast.show_message("当前账号尚未绑定 Key", "warning")
            return
        if not self._binding_can_unbind(self.portal_binding):
            self._set_portal_result(
                "warning", "不能自助脱绑",
                "授权仍有效，请联系管理员处理。",
            )
            self.toast.show_message("授权仍有效，不能自助脱绑，请联系管理员", "warning")
            return
        try:
            data = self.client.portal_unbind()
        except ApiError as exc:
            self._set_portal_result("error", "脱绑失败", str(exc))
            self.toast.show_message(str(exc), "error")
            return
        if not data.get("ok"):
            message = self._portal_failure_message(data, "脱绑失败")
            self._set_portal_result("error", "脱绑失败", message)
            self.toast.show_message(message, "error")
            return
        self.portal_binding = None
        self.portal_current_key = ""
        setter = getattr(self.client, "set_session_secret", None)
        if callable(setter):
            setter(None)
        else:
            self.client.session_secret = None
        self._persist_session()
        self.heartbeat_timer.stop()
        self._refresh_portal_view()
        self._set_portal_result("info", "已脱绑", "授权设备绑定已释放。")
        self._set_portal_online("info", "心跳：未开启")
        self.toast.show_message("已脱绑", "success")

    def portal_logout(self) -> None:
        self.heartbeat_timer.stop()
        self._clear_portal_ui()
        self.toast.show_message("已退出邮箱登录", "success")

    def _clear_portal_ui(self) -> None:
        clearer = getattr(self.client, "clear_portal_session", None)
        if callable(clearer):
            clearer()
        else:
            self.client.portal_token = ""
            self.client.portal_token_expires_at = 0
        self.portal_authenticated = False
        self.portal_email = ""
        self.portal_display_name = ""
        self.portal_avatar = None
        self.portal_binding = None
        self.portal_current_key = ""
        self._refresh_portal_view()
        self._set_portal_result("info", "未登录", "登录邮箱账号后即可绑定和校验授权。")
        self._set_portal_online("info", "心跳：未开启")

    @staticmethod
    def _binding_key(binding: dict | None) -> str:
        if not isinstance(binding, dict):
            return ""
        value = binding.get("key_code") or binding.get("key")
        if value:
            return str(value)
        nested = binding.get("license")
        if isinstance(nested, dict):
            return str(nested.get("key_code") or nested.get("key") or "")
        return ""

    @staticmethod
    def _binding_status(binding: dict | None) -> str:
        if not isinstance(binding, dict):
            return ""
        for name in ("license_status", "license_state", "status", "binding_status"):
            value = binding.get(name)
            if value:
                return str(value).strip().lower()
        return ""

    @staticmethod
    def _binding_expiry(binding: dict | None) -> str:
        if not isinstance(binding, dict):
            return ""
        for name in (
            "expires_at",
            "license_expires_at",
            "expiry",
            "expire_at",
        ):
            value = binding.get(name)
            if value:
                return str(value)
        nested = binding.get("license")
        if isinstance(nested, dict):
            return str(nested.get("expires_at") or nested.get("expiry") or "")
        return ""

    @classmethod
    def _binding_expiry_display(cls, binding: dict | None) -> str:
        expiry = cls._binding_expiry(binding)
        if expiry:
            return expiry
        if isinstance(binding, dict) and any(
            name in binding
            for name in ("expires_at", "license_expires_at", "expiry", "expire_at")
        ):
            return "永久"
        return "未同步"

    @classmethod
    def _binding_active(cls, binding: dict | None) -> bool:
        if not isinstance(binding, dict):
            return False
        status = cls._binding_status(binding)
        return status not in ("unbound", "released", "none", "inactive")

    @classmethod
    def _binding_display_status(cls, binding: dict | None) -> str:
        if not cls._binding_active(binding):
            return "未绑定"
        status = cls._binding_status(binding)
        if status in ("revoked", "disabled"):
            return "已吊销"
        if status in ("exhausted", "used_up", "exhausted_activations"):
            return "次数用尽"
        if status in ("expired", "timeout"):
            return "已过期"
        if status == "not_active":
            return "未激活"
        expiry = cls._binding_expiry(binding)
        if expiry and security.is_expired(expiry):
            return "已过期"
        return "已绑定"

    @classmethod
    def _binding_can_unbind(cls, binding: dict | None) -> bool:
        if not cls._binding_active(binding):
            return False
        status = cls._binding_status(binding)
        if status in (
            "revoked",
            "expired",
            "exhausted",
            "used_up",
            "exhausted_activations",
            "disabled",
        ):
            return True
        try:
            activation_left = binding.get("activation_left")
            if activation_left not in (None, "") and int(activation_left) == 0:
                return True
        except (TypeError, ValueError):
            pass
        expiry = cls._binding_expiry(binding)
        return bool(expiry and security.is_expired(expiry))

    @classmethod
    def _binding_detail(cls, binding: dict | None) -> str:
        if not isinstance(binding, dict):
            return ""
        key = cls._binding_key(binding)
        expiry = cls._binding_expiry_display(binding)
        return (
            f"Key：{cls._mask_key(key)}\n"
            f"状态：{cls._binding_display_status(binding)}    到期时间：{expiry}"
        )

    @staticmethod
    def _mask_key(key: str) -> str:
        value = str(key or "").strip()
        if not value:
            return "未绑定"
        parts = value.split("-")
        if len(parts) >= 3:
            return f"{parts[0]}-****-****-****-{parts[-1][-4:]}"
        if len(value) > 8:
            return f"{value[:4]}****{value[-4:]}"
        return "****"

    def _set_portal_result(self, kind: str, title: str, detail: str) -> None:
        color, bg = RESULT_STYLE.get(kind, RESULT_STYLE["info"])
        self.portal_result_card.setStyleSheet(
            f"#StatCard {{ background: {bg}; border: 1px solid {color}33; border-radius: 8px; }}"
        )
        self.portal_result_badge.set_state(RESULT_BADGE.get(kind, "状态"), kind)
        self.portal_result_title.setText(title)
        self.portal_result_title.setStyleSheet(f"color: {color};")
        self.portal_result_detail.setText(detail)

    def _set_portal_online(self, kind: str, text: str) -> None:
        color, _ = RESULT_STYLE.get(kind, RESULT_STYLE["info"])
        self.portal_online_label.setText(text)
        self.portal_online_label.setStyleSheet(f"color: {color};")

    def _refresh_portal_view(self) -> None:
        logged_in = bool(self.portal_authenticated)
        self.portal_account_stack.setCurrentIndex(1 if logged_in else 0)
        if not logged_in:
            avatar_label = getattr(self, "portal_avatar_label", None)
            if avatar_label is not None:
                apply_avatar_to_label(avatar_label, None, "")
            self.portal_bound_key_label.setText("未绑定")
            self.portal_bound_status_label.setText("未绑定")
            self.portal_bound_expiry_label.setText("未设置")
            self.portal_binding_stack.setCurrentIndex(0)
            self.portal_bind_button.setEnabled(False)
            self.portal_verify_button.setEnabled(False)
            self.portal_renew_button.setEnabled(False)
            self.portal_unbind_button.setEnabled(False)
            return

        self._refresh_portal_identity()
        binding = self.portal_binding if isinstance(self.portal_binding, dict) else None
        if not self._binding_active(binding):
            self.portal_bound_key_label.setText("未绑定")
            self.portal_bound_status_label.setText("未绑定")
            self.portal_bound_expiry_label.setText("未设置")
            self.portal_binding_stack.setCurrentIndex(1)
            self.portal_bind_button.setEnabled(True)
            self.portal_verify_button.setEnabled(False)
            self.portal_renew_button.setEnabled(False)
            self.portal_unbind_button.setEnabled(False)
            return

        key = self._binding_key(binding)
        expiry = self._binding_expiry_display(binding)
        self.portal_bound_key_label.setText(self._mask_key(key))
        self.portal_bound_status_label.setText(self._binding_display_status(binding))
        self.portal_bound_expiry_label.setText(expiry)
        self.portal_binding_stack.setCurrentIndex(2)
        self.portal_verify_button.setEnabled(True)
        self.portal_renew_button.setEnabled(True)
        can_unbind = self._binding_can_unbind(binding)
        self.portal_unbind_button.setEnabled(can_unbind)
        self.portal_unbind_button.setToolTip(
            "" if can_unbind else "授权仍有效，不能自助脱绑，请联系管理员"
        )

    def _arrange_portal_body(self, compact: bool) -> None:
        if self._portal_compact_layout == compact:
            return
        self.portal_body_layout.removeWidget(self.portal_account_panel)
        self.portal_body_layout.removeWidget(self.portal_binding_panel)
        if compact:
            self.portal_body_layout.addWidget(self.portal_account_panel, 0, 0)
            self.portal_body_layout.addWidget(self.portal_binding_panel, 1, 0)
            self.portal_body_layout.setColumnStretch(0, 1)
            self.portal_body_layout.setColumnStretch(1, 0)
            self.portal_body_layout.setRowStretch(0, 0)
            self.portal_body_layout.setRowStretch(1, 1)
        else:
            self.portal_body_layout.addWidget(self.portal_account_panel, 0, 0)
            self.portal_body_layout.addWidget(self.portal_binding_panel, 0, 1)
            self.portal_body_layout.setColumnStretch(0, 3)
            self.portal_body_layout.setColumnStretch(1, 2)
            self.portal_body_layout.setRowStretch(0, 1)
            self.portal_body_layout.setRowStretch(1, 0)
        self._portal_compact_layout = compact

    def _apply_server(self) -> bool:
        url = self.input_server.text().strip() or "http://127.0.0.1:8765"
        try:
            self.client.set_base_url(url)
        except ApiError as exc:
            self._set_result("error", "服务器地址无效", str(exc))
            self.toast.show_message(f"服务器地址无效：{exc}", "error")
            return False
        self.config.client["server_url"] = self.client.base_url
        self.config.save()
        return True

    def copy_machine(self) -> None:
        QApplication.clipboard().setText(self.machine_code)
        self.toast.show_message("机器码已复制", "success")

    def _can_pin_local_keys(self) -> bool:
        return is_loopback_url(self.client.base_url)

    def _ensure_server_keys(self) -> bool:
        if self.client.offline_public_key and self.client.response_public_key:
            return True
        if not self._can_pin_local_keys():
            self._set_result(
                "error",
                "缺少服务器公钥",
                "远程部署时不能静默信任首次连接，请导入服务器公钥后再激活。",
            )
            return False
        try:
            data = self.client.public_key()
        except ApiError as exc:
            self.toast.show_message(f"获取服务器公钥失败：{exc}", "error")
            return False
        self.client.apply_public_key_response(data)
        if not self.client.offline_public_key or not self.client.response_public_key:
            self.toast.show_message("服务器未返回完整公钥", "error")
            return False
        self.config.client["offline_public_key"] = self.client.offline_public_key
        self.config.client["response_public_key"] = self.client.response_public_key
        self.config.client["response_key_id"] = self.client.response_key_id
        self.config.save()
        return True

    def _offline_public(self) -> str:
        if not self._ensure_server_keys():
            return ""
        return self.client.offline_public_key

    def make_request(self) -> None:
        code = offline.make_request_code(self.machine_code, self.device_name)
        self.request_output.setPlainText(offline.chunk_code(code))
        self.toast.show_message("已生成本机请求码", "success")

    def copy_request(self) -> None:
        code = offline.clean_code(self.request_output.toPlainText())
        if not code:
            self.toast.show_message("请先生成请求码", "warning")
            return
        QApplication.clipboard().setText(code)
        self.toast.show_message("请求码已复制", "success")

    def save_request(self) -> None:
        code = offline.clean_code(self.request_output.toPlainText())
        if not code:
            self.toast.show_message("请先生成请求码", "warning")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "保存请求码", f"request_{self.machine_code}.txt",
            "文本文件 (*.txt);;所有文件 (*)"
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8-sig") as fh:
                fh.write(code + "\n")
        except OSError as exc:
            self.toast.show_message(f"保存失败：{exc}", "error")
            return
        self.toast.show_message("请求码已保存", "success")

    def _offline_payload(self) -> dict | None:
        code = self.config.client.get("offline_activation", "")
        if not code:
            return None
        pub = self._offline_public()
        if not pub:
            return None
        payload = offline.parse_activation_code(code, pub)
        if not payload:
            return None
        mc = (payload.get("mc") or "").upper()
        if mc and mc != self.machine_code.upper():
            return None
        entered_key = security.normalize_key(self.input_key.text())
        if entered_key and payload.get("key") != entered_key:
            return None
        return payload

    def _offline_left(self, payload: dict) -> int | None:
        exp = payload.get("exp")
        return security.seconds_left(exp) if exp else None

    def _clock_rolled_back(self) -> bool:
        remembered = int(self.config.client.get(LAST_SEEN_FIELD) or 0)
        if not remembered:
            return False
        return time.time() < remembered - CLOCK_SKEW_TOLERANCE_SECONDS

    def _touch_last_seen(self) -> None:
        now = int(time.time())
        remembered = int(self.config.client.get(LAST_SEEN_FIELD) or 0)
        if now > remembered:
            self.config.client[LAST_SEEN_FIELD] = now
            self.config.save()

    def import_offline(self) -> None:
        code = offline.clean_code(self.offline_input.toPlainText())
        if not code:
            self.toast.show_message("请粘贴离线激活码", "warning")
            return
        pub = self._offline_public()
        if not pub:
            self._set_result("error", "无法导入", "缺少公钥，请先联网连接服务器获取公钥后再导入。")
            self.toast.show_message("缺少公钥，请先连接服务器", "error")
            return
        # A rolled-back clock must not be allowed to make an already-expired
        # activation code look importable.
        if self._clock_rolled_back():
            self._set_result(
                "error", "系统时间异常",
                "检测到本机时间被回拨，已拒绝导入。请校正系统时间后重试。",
            )
            self.toast.show_message("系统时间异常，已拒绝导入", "error")
            return
        payload = offline.parse_activation_code(code, pub)
        if not payload:
            self._set_result("error", "激活码无效", "签名校验失败，激活码可能被篡改或不属于本系统。")
            self.toast.show_message("激活码无效", "error")
            return
        mc = (payload.get("mc") or "").upper()
        if mc and mc != self.machine_code.upper():
            self._set_result(
                "error", "设备不匹配",
                f"该激活码绑定机器码 {mc}，与本机 {self.machine_code} 不一致。",
            )
            self.toast.show_message("该激活码不属于本机", "error")
            return
        if payload.get("exp") and security.is_expired(payload.get("exp")):
            self._set_result(
                "error", "离线激活码已过期",
                f"到期时间：{payload.get('exp')}",
            )
            self.toast.show_message("离线激活码已过期", "error")
            return
        self.config.client["offline_activation"] = code
        self.config.client["offline_key"] = payload.get("key", "")
        self.config.save()
        exp = payload.get("exp")
        remain = security.humanize_remaining(exp) if exp else "永久"
        self.input_key.setText(payload.get("key", ""))
        self._set_result(
            "success", "离线激活成功",
            f"密钥：{payload.get('key', '')}\n"
            f"到期时间：{exp or '永久'}    剩余：{remain}\n"
            f"已保存到本机，可在无网络环境离线运行。",
        )
        self._set_online("info", "离线模式：本地授权校验")
        self._touch_last_seen()
        self.toast.show_message("离线激活成功", "success")

    def offline_verify(self) -> None:
        payload = self._offline_payload()
        if not payload:
            self._set_result("warning", "无离线授权", "尚未导入有效的离线激活码，或公钥缺失。")
            self.toast.show_message("暂无离线授权", "warning")
            return
        if self._clock_rolled_back():
            self._set_result(
                "error", "系统时间异常",
                "检测到本机时间被回拨，离线校验已拒绝。请校正系统时间后重试。",
            )
            self.toast.show_message("系统时间异常，已拒绝离线校验", "error")
            return
        left = self._offline_left(payload)
        exp = payload.get("exp")
        if left is not None and left <= 0:
            self._set_result("error", "离线授权已过期", f"到期时间：{exp}")
            self.toast.show_message("离线授权已过期", "error")
            return
        remain = security.humanize_remaining(exp) if exp else "永久"
        self._set_result(
            "success", "离线授权有效",
            f"密钥：{payload.get('key', '')}\n到期时间：{exp or '永久'}    剩余：{remain}",
        )
        self._set_online("info", "离线模式：本地授权校验")
        self._touch_last_seen()

    def _offline_fallback(self, reason: str) -> bool:
        payload = self._offline_payload()
        if not payload:
            return False
        if self._clock_rolled_back():
            self._set_result(
                "error", "系统时间异常",
                "检测到本机时间被回拨，离线校验已拒绝。请校正系统时间后重试。",
            )
            self.toast.show_message("系统时间异常，已拒绝离线校验", "error")
            return True
        left = self._offline_left(payload)
        exp = payload.get("exp")
        if left is not None and left <= 0:
            self._set_result("error", "授权已过期", f"离线授权已验证且已过期。到期时间：{exp}")
            self.toast.show_message("离线授权已过期", "error")
            return True
        remain = security.humanize_remaining(exp) if exp else "永久"
        self._set_result(
            "success", "离线授权有效",
            f"网络不可用，已回退本地离线校验。\n"
            f"密钥：{payload.get('key', '')}    到期时间：{exp or '永久'}    剩余：{remain}",
        )
        self._set_online("warning", f"离线模式（{reason}）")
        self._touch_last_seen()
        self.toast.show_message("已离线校验", "success")
        return True

    def test_connection(self) -> None:
        if not self._apply_server():
            return
        try:
            data = self.client.health()
        except ApiError as exc:
            self.toast.show_message(str(exc), "error")
            return
        self.toast.show_message(f"连接正常 · v{data.get('version')}", "success")

    def _set_result(self, kind: str, title: str, detail: str) -> None:
        color, bg = RESULT_STYLE.get(kind, RESULT_STYLE["info"])
        self.status_card.setStyleSheet(
            f"#StatCard {{ background: {bg}; border: 1px solid {color}33; border-radius: 8px; }}"
        )
        self.result_badge.set_state(RESULT_BADGE.get(kind, "状态"), kind)
        self.status_title.setText(title)
        self.status_title.setStyleSheet(f"color: {color};")
        self.status_detail.setText(detail)

    def _remember(self) -> None:
        self.config.client["auto_verify"] = self.auto_check.isChecked()
        self.config.client["last_key"] = (
            self.input_key.text().strip() if self.auto_check.isChecked() else ""
        )
        self._persist_session()

    def _persist_session(self) -> None:
        secret = self.client.session_secret or ""
        if (self.config.client.get("session_secret") or "") != secret:
            self.config.client["session_secret"] = secret
            self.config.save()

    def _register_failure(self) -> None:
        self.failure_count += 1
        if self.failure_count >= self.verify_max_failures:
            self.failure_count = 0
            self.locked_until = time.time() + self.verify_lock_seconds

    def _locked(self) -> bool:
        return time.time() < self.locked_until

    def _set_online(self, kind: str, text: str) -> None:
        color, _ = RESULT_STYLE.get(kind, RESULT_STYLE["info"])
        self.online_label.setText(text)
        self.online_label.setStyleSheet(f"color: {color};")
        if hasattr(self, "portal_online_label"):
            self.portal_online_label.setText(text)
            self.portal_online_label.setStyleSheet(f"color: {color};")

    def _heartbeat_key(self) -> str:
        if self.portal_authenticated:
            return self.portal_current_key or self._binding_key(self.portal_binding)
        return self.input_key.text().strip()

    def _start_heartbeat(self, immediate: bool = False) -> None:
        if self.heartbeat_enabled:
            if immediate:
                QTimer.singleShot(0, self._safe_heartbeat)
            else:
                self.heartbeat_timer.start(int(self.heartbeat_interval * 1000))

    def _safe_heartbeat(self) -> None:
        """定时器护栏：心跳中的意外异常只记日志，不让应用崩溃。"""
        try:
            self.heartbeat()
        except Exception as exc:
            try:
                from core import crashlog

                crashlog.log_exception("verification-heartbeat", exc)
            except Exception:
                pass
            try:
                self.heartbeat_timer.start(int(self.heartbeat_interval * 1000))
            except Exception:
                pass

    def heartbeat(self) -> None:
        key = self._heartbeat_key()
        if not key or not self.client.session_secret:
            return
        try:
            data = self.client.heartbeat(key, self.machine_code)
        except ApiError as exc:
            if not self.client.session_secret:
                self.heartbeat_timer.stop()
                self._persist_session()
                self._set_online("error", "心跳中断：会话已失效，请重新激活")
                return
            self._set_online("warning", f"心跳异常：{exc}")
            self.heartbeat_timer.start(int(self.heartbeat_interval * 1000))
            return
        if data.get("ok"):
            self._merge_portal_license_fields(data)
            self.heartbeat_count = int(
                data.get("heartbeat_count") or (self.heartbeat_count + 1)
            )
            server_ts = data.get("server_ts")
            if server_ts:
                self.time_offset = time.time() - float(server_ts)
            interval = float(data.get("next_interval") or self.heartbeat_interval)
            hint = ""
            if abs(self.time_offset) > 60:
                hint = f" · 时钟偏差 {self.time_offset:+.0f}s"
            self._set_online(
                "success",
                f"心跳在线 · 第 {self.heartbeat_count} 次 · 下次 {interval:.0f}s{hint}",
            )
            self.heartbeat_timer.start(max(5, int(interval * 1000)))
        else:
            self._merge_portal_license_fields(data)
            self.heartbeat_timer.stop()
            message = data.get("message", "授权已失效")
            self._set_online("error", f"心跳停止：{message}")
            self._set_result("error", "授权失效", message)

    def activate(self) -> None:
        if not self._apply_server():
            return
        key = self.input_key.text().strip()
        if not key:
            self.toast.show_message("请输入密钥", "warning")
            return
        if not self._ensure_server_keys():
            return
        try:
            data = self.client.activate(key, self.machine_code, self.device_name)
        except ApiError as exc:
            self._set_result("error", "激活失败", str(exc))
            self.toast.show_message(str(exc), "error")
            return
        if data.get("ok"):
            self._remember()
            self.failure_count = 0
            self.locked_until = 0.0
            kind = "success"
            title = "激活成功" if data.get("code") != "already" else "此设备已激活"
            detail = self._detail(data)
            self._set_result(kind, title, detail)
            self._set_online("info", "心跳：启动中…")
            self._start_heartbeat()
            self.toast.show_message(title, "success")
        else:
            self._persist_session()
            self._register_failure()
            self._set_result("error", data.get("message", "激活失败"), self._detail(data))
            self.toast.show_message(data.get("message", "激活失败"), "error")

    def verify(self) -> None:
        if self._locked():
            remain = max(1, int(self.locked_until - time.time()))
            self._set_result(
                "warning", "已临时锁定", f"连续失败过多，请在 {remain} 秒后重试"
            )
            self.toast.show_message(f"尝试过于频繁，请 {remain} 秒后重试", "warning")
            return
        if not self._apply_server():
            return
        key = self.input_key.text().strip()
        if not key:
            self.toast.show_message("请先输入密钥", "warning")
            return
        if not self._ensure_server_keys() and self._offline_fallback("缺少服务器公钥"):
            return
        try:
            data = self.client.verify(key, self.machine_code)
        except ApiError as exc:
            # Only a transport failure may be covered by the cached offline
            # licence. If the server answered authoritatively (revoked key,
            # expired session, rejected signature) that answer stands.
            if getattr(exc, "offline_ok", False) and self._offline_fallback(str(exc)):
                return
            self._persist_session()
            self._register_failure()
            self._set_result("error", "校验失败", str(exc))
            self.toast.show_message(str(exc), "error")
            return
        if data.get("ok"):
            self._remember()
            self.failure_count = 0
            self.locked_until = 0.0
            self._set_result("success", "授权有效", self._detail(data))
            self._set_online("info", "心跳：启动中…")
            self._start_heartbeat()
        else:
            self._persist_session()
            self._register_failure()
            self._set_result("error", data.get("message", "授权无效"), self._detail(data))

    @staticmethod
    def _detail(data: dict) -> str:
        if data.get("card_type") == "activation":
            limit = int(data.get("activation_limit") or 0)
            used = int(data.get("activation_count") or 0)
            left = int(data.get("activation_left") or 0)
            return (
                "卡密模式：激活次数卡    "
                f"已激活 {used} / {limit} 次    剩余 {left} 次"
            )
        expiry = data.get("expires_at") or "永久"
        remaining = data.get("remaining")
        if remaining:
            return f"到期时间：{expiry}    剩余：{remaining}"
        days = data.get("days_left")
        if days is None:
            return f"到期时间：{expiry}"
        return f"到期时间：{expiry}    剩余：{days} 天"

    def _arrange_body(self, compact: bool) -> None:
        if self._compact_layout == compact:
            return
        self.body_layout.removeWidget(self.left_panel)
        self.body_layout.removeWidget(self.right_panel)
        if compact:
            self.body_layout.addWidget(self.left_panel, 0, 0)
            self.body_layout.addWidget(self.right_panel, 1, 0)
            self.body_layout.setColumnStretch(0, 1)
            self.body_layout.setColumnStretch(1, 0)
            self.body_layout.setRowStretch(0, 0)
            self.body_layout.setRowStretch(1, 1)
        else:
            self.body_layout.addWidget(self.left_panel, 0, 0)
            self.body_layout.addWidget(self.right_panel, 0, 1)
            self.body_layout.setColumnStretch(0, 3)
            self.body_layout.setColumnStretch(1, 2)
            self.body_layout.setRowStretch(0, 1)
            self.body_layout.setRowStretch(1, 0)
        self._compact_layout = compact

    def _fit_to_screen(self) -> None:
        screen = QApplication.primaryScreen()
        if screen is None:
            self.resize(1080, 640)
            return
        avail = screen.availableGeometry()
        width = min(1120, max(760, avail.width() - 60))
        height = min(720, max(480, avail.height() - 80))
        self.setMinimumSize(720, 460)
        self.resize(width, height)
        self.move(
            avail.x() + max(0, (avail.width() - width) // 2),
            avail.y() + max(0, (avail.height() - height) // 2),
        )

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._arrange_body(self.width() < 980)
        self._arrange_portal_body(self.width() < 980)
        if hasattr(self, "toast") and self.toast.isVisible():
            self.toast.move(max(12, (self.width() - self.toast.width()) // 2), 20)
