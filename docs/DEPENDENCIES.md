# 依赖策略（锁定与升级）

## 现状

`requirements.txt` 已对全部运行依赖 **精确 pin**（含 qrcode）；`requirements-dev.txt`
仅含测试工具。两份文件按"本地验证过的版本"更新。

## 升级流程（每季度或按安全公告触发）

1. 在干净虚拟环境安装目标版本：`pip install -r requirements.txt`；
2. 跑全量测试：`python -m pytest tests/ -q`（预期全绿）；
3. 冒烟：`python tools/backup_drill.py` + 服务器启动 + 一次激活/校验；
4. 更新 pin 版本号并注明日期与原因（本文件追加一行记录预算）；
5. 若有安全相关升级（cryptography / fastapi 等），优先发补丁版本。

## 记录

| 日期 | 变更 | 说明 |
|---|---|---|
| 2026-10-08 | 基线 pin | 本地验证版本 |
| 2026-11-06 | + qrcode==8.2 | B5 二维码（纯 Python，无 pillow 依赖） |
