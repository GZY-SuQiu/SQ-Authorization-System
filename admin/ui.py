from core import theme
from core.api_client import ApiClient
from core.ai_page import AIAssistantPage
from core.alert_center import AlertCenterPage
from core.pages import (
    AboutPage,
    BatchesPage,
    ChangePasswordPage,
    DashboardPage,
    GeneratePage,
    LicensesPage,
    LogsPage,
    OfflinePage,
    OverviewPage,
)
from core.shell import AppShell
from core.user_admin import UserAdminPage
from core.widgets import Toast


class AdminWindow(AppShell):
    def __init__(self, client: ApiClient, user: dict):
        title = "密钥授权系统 · 管理端（密钥运营）"
        super().__init__(title, user, client.base_url)
        self.client = client

        self.toast = Toast(self)
        self.notify = self.toast.show_message

        self.overview = OverviewPage(client, self.notify)
        self.dashboard = DashboardPage(client, self.notify)
        self.change_password = ChangePasswordPage(client, self.notify)
        self.ai = AIAssistantPage(client, self.notify)
        self.alerts = AlertCenterPage(client, self.notify)
        self.generate = GeneratePage(client, self.notify)
        self.licenses = LicensesPage(client, self.notify)
        self.user_admin = UserAdminPage(client, self.notify)
        self.batches = BatchesPage(client, self.notify)
        self.offline = OfflinePage(client, self.notify)
        self.logs = LogsPage(client, self.notify)
        self.about = AboutPage(client, self.notify)

        self.add_page("系统概览", self.overview)
        self.add_page("数据看板", self.dashboard)
        self.add_page("AI 助手", self.ai)
        self.add_page("告警中心", self.alerts)
        self.add_page("生成密钥", self.generate)
        self.add_page("密钥管理", self.licenses)
        self.add_page("用户管理", self.user_admin)
        self.add_page("批次管理", self.batches)
        self.add_page("离线激活", self.offline)
        self.add_page("审计日志", self.logs)
        self.add_page("修改密码", self.change_password, password_gate=True)
        self.add_page("关于", self.about)

        if not user.get("must_change_password"):
            self.overview.refresh()
            self.licenses.refresh()

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if self.toast.isVisible():
            self.toast.move(
                max(12, (self.width() - self.toast.width()) // 2),
                20,
            )
