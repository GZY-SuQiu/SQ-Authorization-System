#!/bin/sh
# SQ 授权系统 · 容器启动脚本
# 把运行时产物（server_config.json 与 data/）持久化到挂载卷，
# 保证容器重建后 secret_key / 响应密钥 / 授权库保持不变。
set -e
cd /app

PERSIST="${SQ_PERSIST_DIR:-/data/persist}"
mkdir -p "$PERSIST/cfg" "$PERSIST/data"

# 配置文件 → 持久卷（首次启动自动初始化）
if [ ! -e /app/server_config.json ] && [ ! -L /app/server_config.json ]; then
    ln -s "$PERSIST/cfg/server_config.json" /app/server_config.json
fi
touch "$PERSIST/cfg/server_config.json"

# 授权数据库目录 → 持久卷
if [ ! -e /app/data ] && [ ! -L /app/data ]; then
    ln -s "$PERSIST/data" /app/data
fi

# 权限收紧（配置含全部服务端私钥）
chmod 600 "$PERSIST/cfg/server_config.json" 2>/dev/null || true

exec python server/main.py "$@"
