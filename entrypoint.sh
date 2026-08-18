#!/bin/bash
# 容器 entrypoint：启动 Agent 解题
#
# 通用框架：本地/自托管直接启动本地模式；若检测到评测平台注入的
# BENCHMARK_TOKEN（如某些托管评测环境），则进入平台对接模式。
# 平台变量均为可选——没有它们就按本地模式跑。

set -e

echo "================================================"
echo "  CTF Agent entrypoint"
echo "  Time: $(date)"
echo "================================================"

# 大模型 Key 必须存在（本地模式也要用）
if [ -z "$LLM_API_KEY" ]; then
    echo "⚠️ LLM_API_KEY 未注入，LLM 调用会失败"
    echo "   请在 .env 或环境变量中配置后再启动"
    # 不 exit，让主程序报错更清楚
fi

# 平台模式（可选）：BENCHMARK_TOKEN 注入时说明在托管评测环境
if [ -n "$BENCHMARK_TOKEN" ]; then
    echo "  平台模式已检测到 BENCHMARK_TOKEN"
    echo "  BASE_URL: ${BENCHMARK_BASE_URL:-未设置}"
    echo "  TOKEN: ${BENCHMARK_TOKEN:0:8}..."
else
    echo "  本地模式（未检测到平台 token）"
fi

echo "  LLM_API_KEY: ${LLM_API_KEY:0:8}..."
echo "  GATEWAY_MODE: ${GATEWAY_MODE:-off}"

# 启动 Agent 解题循环：
# - 平台模式（有 BENCHMARK_TOKEN）→ main.py auto（对接平台 API）
# - 本地模式 → main.py（本地命令行入口）
echo ""
echo "🚀 启动 Agent..."
if [ -n "$BENCHMARK_TOKEN" ]; then
    exec /app/.venv/bin/python /app/main.py auto
else
    exec /app/.venv/bin/python /app/main.py "$@"
fi
