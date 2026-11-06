# 部署手册（三场景）

> 适用对象：本地服务器（`本地服务器.exe` / `python server/main.py`）。
> 客户端（验证端 / 管理端 / 主控端 / SDK）通过 `server_url` 连接服务器。

## 场景 A · 内网直连（默认）

适用：局域网内部使用、单机自用。

1. 启动 `本地服务器.exe`（默认 `127.0.0.1:8765`；内网供他人访问改为
   `--host 0.0.0.0`，例如 `本地服务器.exe --host 0.0.0.0`）。
2. 客户端首次连接：登录后自动固定服务端响应公钥（也可用
   `本地服务器.exe --print-public-key` 导出后手动核对）。
3. 内网明文 HTTP 需要在客户端显式允许（`allow_insecure_http`）；
   验证端界面提供"允许内网测试"开关。

**注意**：内网部署同样要保管好 `server_config.json`（含全部服务端私钥）。
默认监听在本机，改 `--host 0.0.0.0` 前确认防火墙策略。

## 场景 B · 公网 VPS（原生 + Caddy 反代）

适用：给外部用户提供授权服务。

1. 服务器准备：Ubuntu 22.04+，域名 A 记录指向本机，开放 80/443。
2. 上传项目并安装依赖：
   ```bash
   apt install -y python3-venv
   python3 -m venv venv && . venv/bin/activate
   pip install cryptography fastapi uvicorn requests pydantic
   ```
3. 只监听本机：
   ```bash
   python server/main.py --headless --host 127.0.0.1 --port 8765
   ```
   推荐做成 systemd 服务（`Restart=always`）。
4. Caddy 反代（自动 HTTPS）：
   ```
   license.example.com {
       reverse_proxy 127.0.0.1:8765
   }
   ```
5. **客户端必须用 https:// 连接**（客户端硬性要求；证书可信）。
   用 `--print-public-key` 导出响应公钥分发/核对，客户端登录后自动固定。
6. 若使用发布白名单：把 `release_manifest.json / .sig / releases/` 放好后
   重启服务器（自动导入）。

**防火墙**：云厂商安全组 + 本机 ufw/iptables 都要放行 443（80 用于
证书签发与跳转）。

## 场景 C · 容器（推荐公网标准姿势）

适用：希望"一条命令部署 + 自动 HTTPS + 数据卷持久化"。

1. 目录准备：仓库根包含 `deploy/`（Dockerfile / entrypoint.sh /
   vps/docker-compose.yml / vps/Caddyfile）。
2. 修改 `deploy/vps/Caddyfile` 的域名，然后：
   ```bash
   cd deploy/vps
   docker compose up -d --build
   ```
3. 数据持久化：`sq-data` 卷挂载 `/data/persist`——`server_config.json`
   与 `license.db` 都在卷内；**容器重建（升级镜像）不会改变密钥与授权数据**。
4. 客户端连接 `https://<域名>`；首启 admin 初始密码从容器日志获取：
   ```bash
   docker compose logs sq-server | grep 初始密码
   ```
5. 备份：自动备份落 `data/backups/auto/`（卷内）；也可从宿主机：
   ```bash
   docker compose exec sq-server python tools/backup_drill.py
   ```

## 通用检查单

- [ ] `server_config.json` 与 `license.db` **成对备份**（丢配置 = 会话密钥废）
- [ ] 客户端固定公钥与服务器 `--print-public-key` 输出一致
- [ ] 外网只用 HTTPS；明文仅限内网显式开启
- [ ] 发布白名单启用后，用 `tools/verify_integrity_e2e.py` 复核
- [ ] 定期跑 `tools/backup_drill.py`（备份恢复演练）
