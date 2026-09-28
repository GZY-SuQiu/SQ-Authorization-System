from core import theme
from core.api_client import ApiClient
from core.pages import AboutPage, GeneratePage, LicensesPage, LogsPage, OfflinePage, OverviewPage
from core.shell import AppShell
from core.widgets import Toast


class AdminWindow(AppShell):
    def __init__(self, client: ApiClient, user: dict):
        title = "密钥授权系统 · 管理端"
        super().__init__(title, user, client.base_url)
        self.client = client

        self.toast = Toast(self)
        self.notify = self.toast.show_message

        self.overview = OverviewPage(client, self.notify)
        self.generate = GeneratePage(client, self.notify)
        self.licenses = LicensesPage(client, self.notify)
        self.offline = OfflinePage(client, self.notify)
        self.logs = LogsPage(client, self.notify)
        self.about = AboutPage(client, self.notify)

        self.add_page("系统概览", self.overview)
        self.add_page("生成密钥", self.generate)
        self.add_page("密钥管理", self.licenses)
        self.add_page("离线激活", self.offline)
        self.add_page("审计日志", self.logs)
        self.add_page("关于", self.about)

        self.overview.refresh()
        self.licenses.refresh()

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if self.toast.isVisible():
            self.toast.move(
                max(12, (self.width() - self.toast.width()) // 2),
                20,
            )
