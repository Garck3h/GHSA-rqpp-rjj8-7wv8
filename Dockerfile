FROM node:22-slim

LABEL maintainer="security-lab"
LABEL description="OpenClaw v2026.3.11 - Vulnerable Version for GHSA-rqpp-rjj8-7wv8 PoC"

# 安装系统依赖 (git 为 npm 安装所需)
RUN apt-get update && apt-get install -y git curl && rm -rf /var/lib/apt/lists/*

# 安装漏洞版本 OpenClaw
RUN npm install -g openclaw@2026.3.11

# 创建 OpenClaw 配置目录
RUN mkdir -p /root/.openclaw

# 使用 openclaw config set 写入正确格式的配置
RUN openclaw config set gateway.mode local && \
    openclaw config set gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback true

# 网关默认端口
EXPOSE 18789

# 启动网关 - 使用密码认证模式
ENTRYPOINT ["openclaw"]
CMD ["gateway", "run", "--port", "18789", "--bind", "lan", "--auth", "password", "--password", "test_vuln_2024", "--verbose"]
