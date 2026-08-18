#!/usr/bin/env bash
# XBEN 全量预构建脚本
# 用法: bash prebuild_xben.sh [start_index] [end_index]
# 例: bash prebuild_xben.sh          # 构建全部
#     bash prebuild_xben.sh 0 20     # 只构建前 20 个
#     bash prebuild_xben.sh 20 40    # 构建 20-40
# 作用: 逐个 docker compose build，把镜像全部预构建好，之后黑盒跑不再等构建
set -u

XBEN_ROOT="/home/kali/Projects/validation-benchmarks/benchmarks"
LOG="output/xben_prebuild.log"
mkdir -p output
: > "$LOG"

START=${1:-0}
END=${2:-9999}

cd /home/kali/Projects/ctf/ctf_agent

echo "开始预构建 XBEN 靶场 (index ${START}-${END})，日志: $LOG"
echo "=========================================="

COUNT=0
OK=0
FAIL=0
for dir in "$XBEN_ROOT"/XBEN-*-24; do
    bench=$(basename "$dir")
    # 跳过 XBEN-005 等已能跑的（可选，这里全构建）
    COUNT=$((COUNT+1))
    if [ $COUNT -lt $((START+1)) ] || [ $COUNT -gt $((END+1)) ]; then
        continue
    fi
    echo "[$COUNT] 构建 $bench ..."
    # 用 venv python 修补 Dockerfile（EOL Debian 源）后 compose build
    # timeout 用 --foreground + 超时后强杀进程组，防止 docker buildkit 孙进程成孤儿卡住 daemon
    timeout --foreground -k 30 540 .venv/bin/python - "$bench" <<'PYEOF' >> "$LOG" 2>&1
import sys, os
sys.path.insert(0, '.')
import xben_runner as xr
bench = sys.argv[1]
baks = xr._patch_dockerfiles(bench)
d = os.path.join(xr.XBEN_ROOT, bench)
r = xr._run(f"cd '{d}' && {xr.DOCKER} compose build --build-arg FLAG=FLAG{{prebuild}} 2>&1", timeout=580)
ok = "error" not in r.lower() or "failed" not in r.lower()
print(f"[{bench}] {'OK' if ok else 'FAIL'} | {r[-200:]}")
xr._restore_dockerfiles(baks)
sys.exit(0 if ok else 1)
PYEOF
    if [ $? -eq 0 ]; then
        OK=$((OK+1))
        echo "  ✅ $bench"
    else
        FAIL=$((FAIL+1))
        echo "  ❌ $bench"
    fi
done

echo "=========================================="
echo "预构建完成: 成功 $OK, 失败 $FAIL, 日志: $LOG"
