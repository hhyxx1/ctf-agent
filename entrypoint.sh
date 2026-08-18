#!/bin/bash
# TSecBench 托管模式 entrypoint
# 平台拉起容器后，这个脚本会被执行，启动 Agent 自解题

set -e

echo "================================================"
echo "  TSecBench CTF Agent entrypoint"
echo "  Time: $(date)"
echo "================================================"

# 校验必填环境变量
if [ -z "$BENCHMARK_TOKEN" ]; then
    echo "❌ BENCHMARK_TOKEN 未注入，无法启动托管模式"
    exit 1
fi
if [ -z "$BENCHMARK_BASE_URL" ]; then
    echo "❌ BENCHMARK_BASE_URL 未注入"
    exit 1
fi
if [ -z "$DEEPSEEK_API_KEY" ]; then
    echo "⚠️ DEEPSEEK_API_KEY 未注入，LLM 调用会失败"
    # 不 exit，让主程序报错更清楚
fi

echo "  BASE_URL: $BENCHMARK_BASE_URL"
echo "  TOKEN: ${BENCHMARK_TOKEN:0:8}..."
echo "  DEEPSEEK_API_KEY: ${DEEPSEEK_API_KEY:0:8}..."
echo "  GATEWAY_MODE: ${GATEWAY_MODE:-auto}"

# 启动 Agent 自解题循环
echo ""
echo "🚀 启动 Agent..."
exec /app/.venv/bin/python /app/main.py auto
