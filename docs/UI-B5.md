# 界面增强：数据看板 / 二维码 / 深色主题（B5）

## 一、数据看板

- **位置**：管理端 / 主控端导航 →「数据看板」（系统概览之后）。
- **内容**：近 7/14/30/60 天切换；「新增 vs 激活」双序列柱状图、「到期分布」柱状图、
  汇总行（新增 / 激活 / 到期合计）。
- **数据源**：`GET /api/metrics/trend?days=N`（按日聚合 `licenses.created_at`、
  `activations.activated_at`、`licenses.expires_at`）。
- **实现**：`core/charts.py` 自绘柱状图（零第三方依赖，配色随主题调色板）。

## 二、二维码

- **位置**：密钥详情对话框「二维码」按钮（卡密）；离线激活页「二维码」按钮（离线码）。
- **实现**：`core/qr.py`（`qrcode` 库生成矩阵 → QImage 逐像素渲染，不依赖 pillow）。
- **依赖**：`requirements.txt` 已 pin `qrcode==8.2`；缺失时按钮会提示"组件不可用"
  （其余功能不受影响）。
- 用法：手机扫码即可读取；数据仅本机生成，不上传网络。

## 三、深色主题

- **切换方式**：配置文件 `*_config.json` 的 `client.theme_mode` 设为 `"dark"`（或
  `"light"`），**下次启动生效**；临时覆盖可用环境变量 `SQ_THEME=dark`。
- **覆盖范围**：四端全部界面（QSS 全套色板映射 + 深色调色板 + Windows 深色标题栏）。
- **实现机制**：`core/theme.py`
  - `build_dark_qss()`：由浅色 QSS 经颜色映射生成深色版本（长键优先 + 十六进制
    边界保护 + "白字保护"——`color:` 后的 `#FFFFFF` 保留，其余白面映射为深色面）；
  - `_dark_palette()`：原生控件深色调色板（滚动条、菜单、工具提示等）；
  - `_set_titlebar(widget, dark=...)`：DWM 标题栏跟随主题。
- **回归注意**（Windows 构建机上运行）：
  1. 浅色模式跑 `python tools/dark_mode_sweep.py`（不得出现黑带）；
  2. `SQ_THEME=dark` 启动四端，抽查滚动页/设置页/弹窗（本次沙箱无法运行 GUI，
     深色为静态验证 + 色板单测覆盖）。
