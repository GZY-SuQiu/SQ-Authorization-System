# SQ 授权系统 · 本地服务器容器镜像
# 构建上下文：仓库根（SQ-Authorization-System-1.0.0/）
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SQ_PERSIST_DIR=/data/persist

WORKDIR /app

# 服务端运行依赖子集（无 PySide6 / PyInstaller，headless 零 Qt 依赖）
RUN pip install --no-cache-dir \
    cryptography fastapi uvicorn requests pydantic

COPY core ./core
COPY server ./server
COPY deploy ./deploy
# 可选：签名发布清单（存在则服务器启动时自动导入发布白名单）
COPY releases ./releases

VOLUME ["/data"]
EXPOSE 8765

ENTRYPOINT ["/bin/sh", "/app/deploy/entrypoint.sh"]
CMD ["--headless", "--host", "0.0.0.0", "--port", "8765"]
