# 版本发布检查单（10 项）

> 每次对外发布前逐项打勾；任何一项未过不发布。

1. **测试全绿**：`python -m pytest tests/ -q` → `N passed`（无 failed；
   沙箱外环境无收集错误）。
2. **代码冻结与版本号**：`core/config.py` 的 `APP_VERSION` 与发布说明一致。
3. **分发卫生**：`python tools/check_shareable.py <发布目录> --fail-on high`
   通过（禁止任何 config / db / 私钥 / 构建状态混入）。
4. **密钥状态确认**：发布密钥未经非受控流转（如已轮换，确认新密钥对唯一）；
   `release_keys/release_key.json` 已离线备份且**不在发布目录**。
5. **构建**：`python build.py`（或加固链 `python tools/build_nuitka.py all`）
   成功；确认 `dist/release_package/` 干净（仅 4 个 exe + 清单 + releases/）。
6. **清单签名**：发布包内含 `release_manifest.json/.sig`，`.sig` 可被内嵌公钥
   验证（构建输出会打印指纹，人工核对一次）。
7. **完整性冒烟**：`python tools/verify_integrity_e2e.py` 通过（验签/篡改拒绝）。
8. **端到端回归**：测试环境跑激活 → 校验 → 心跳 → 离线码 →（如启用）attest 白名单。
9. **备份与回滚预案**：当前生产 `server_config.json + license.db` 已备份；
   回滚目标版本（上一版发布包）可用。
10. **发布说明**：CHANGELOG 记录本版变更；附加注意项（密钥轮换/白名单退役等）
    已写入说明。

## 升级服务器时的附加项

- 导入新发布清单后确认旧版自动退役（`release_auto_retire_old=true`）。
- 若本版含数据库迁移：升级前跑一次 `tools/backup_drill.py`，升级后抽查
  `license.db` 行数一致。
