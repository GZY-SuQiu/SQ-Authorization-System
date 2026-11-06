# -*- coding: utf-8 -*-
"""测试公共装置：进程级限流桶的隔离重置。

server/api.py 的限流（激活 / 登录 / attest）保存在模块级字典中，按调用方 IP
计数——全量测试时所有 LiveServer 都来自 127.0.0.1，累计请求会触发 429，
使后续用例（或限流本身无关的用例）被误伤。这里在每个测试前清空桶，
保证用例之间互不影响；单个用例内部的限流行为不受影响。
"""
import pytest


@pytest.fixture(autouse=True)
def _reset_server_rate_limiters():
    try:
        from server import api as server_api

        server_api._rate_guard.clear()
        server_api._login_guard.clear()
    except Exception:
        # 收集阶段（如无 fastapi 环境）不阻断测试。
        pass
    yield

# 测试进程级的功能默认放宽：老功能测试按"无新门禁"语义运行
# （审批体系与卡密-账号强挂钩由 tests/test_c1.py 显式开启后专项覆盖；
#   产品默认值不受影响。）
try:
    from core import config as _core_config

    _core_config.SERVER_DEFAULT_CONFIG["security"]["binding_required"] = False
    _core_config.SERVER_DEFAULT_CONFIG["security"]["approval_enabled"] = False
except Exception:
    pass
