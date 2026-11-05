# SQ 授权系统文档总索引

> 基线：2026-10-08（合题批次 A/B/C/D 落地时点）；测试基线 432 passed + 12 subtests。
> 状态词含义：**已完成** = 本轮工作产物、结论有效；**历史契约** = 该批次实施期冻结的
> 接口契约，字段仍是现行实现依据，但批次已结束、不再作为待办；**参考** = 常读的
> 操作或接入说明，无完成态概念。
> 维护约定：`docs/` 新增任何 `.md` 必须在本文登记，否则视为未归档。

## 总览

- [`IMPROVEMENT-ANALYSIS.md`](./IMPROVEMENT-ANALYSIS.md) — 全项目需求提取、现状差距与改造建议（5 个只读子分析），是后续各批次的需求来源；状态：参考（历史分析，需求去向见下方各批次契约）。
- [`DIALECTIC-REVIEW.md`](./DIALECTIC-REVIEW.md) — 本期正题/反题/合题审阅，给出四路并行（A/B/C/D）修复范围与明确不做的理由；状态：已完成（2026-10-08 决策依据）。

## 安全

- [`INTEGRITY-INTERFACE.md`](./INTEGRITY-INTERFACE.md) — C1 发布清单格式与完整性自校验的冻结接口契约（`release_manifest.json` 字段、校验时机、失败语义）；状态：历史契约（字段仍为现行实现依据）。
- [`RELEASE-SIGNING.md`](./RELEASE-SIGNING.md) — 发布签名密钥保管与构建/发货流程（Ed25519 私钥归属、manifest 与 `releases/` 副本、卫生门禁）；状态：参考（发布操作手册）。
- [`SELF-AUDIT.md`](./SELF-AUDIT.md) — 对抗性自查记录与修复证据（P0/P1 问题清单、修复方式、延期项计划）；状态：已完成（2026-10-08）。

## 接口契约

- [`P1-INTERFACE.md`](./P1-INTERFACE.md) — P1 冻结接口契约：SMTP 配置、邮箱账号与登录、告警基础及文件归属划分；状态：历史契约（已实现）。
- [`A5-INTERFACE.md`](./A5-INTERFACE.md) — A5 冻结接口契约：可配置告警规则引擎的指标口径、规则表与接口字段；状态：历史契约（已实现）。
- [`A7-INTERFACE.md`](./A7-INTERFACE.md) — A7 冻结接口契约：Webhook/钉钉/企微/飞书通知渠道的表结构、投递与重试语义；状态：历史契约（已实现）。
- [`BUGFIX-INTERFACE.md`](./BUGFIX-INTERFACE.md) — 缺陷修复冻结接口：验证端用户资料、用户管理、release_id 与 Python SDK（第 4 节）的接口约定；状态：历史契约（最新一期，SDK 仍以其第 4 节为准）。

## 实施记录

- [`SDK-PYTHON.md`](./SDK-PYTHON.md) — Python SDK 接入指南：第三方宿主程序的嵌入方式、配置面与验签约束；状态：参考（对外接入文档，随 `BUGFIX-INTERFACE.md` 第 4 节冻结）。

本轮工程侧改动（依赖锁版本、CI 跑 pytest + `pip check`）记录在
`.github/workflows/python-package-conda.yml` 与 `requirements-dev.txt`，不另立文档。
