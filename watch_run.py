"""本地运行状态查看（参考 pi-recon watch_run_logs）：实时 tail 运行日志 + 提取当前状态。

用法（运行 main.py 时把输出重定向到文件，然后另开终端看状态）：
    .venv/bin/python main.py slab > run.log 2>&1
    .venv/bin/python watch_run.py run.log          # 实时查看（Ctrl+C 退出）
    .venv/bin/python watch_run.py run.log --once   # 只看当前快照
"""
import sys
import os
import time
import re
import argparse


def snapshot(path: str) -> str:
    """提取日志当前状态（最近题目/轮次/成功/并行）"""
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            data = f.read()
    except FileNotFoundError:
        return f"[日志文件不存在: {path}]"
    lines = data.splitlines()
    if not lines:
        return "[日志为空]"
    tail = "\n".join(lines[-12:])  # 只看末尾（最新状态）
    # 提取关键标记
    cur_ch = re.findall(r"🎯 解题: (\S+)", data)
    solves = len(re.findall(r"✅ 正确!|完成: solved", data))
    fails = len(re.findall(r"未能解题|完成: failed", data))
    par = len(re.findall(r"🔀", data))
    rounds = re.findall(r"轮次 (\d+)/(\d+)", tail)
    parts = [
        f"当前/最近题目: {cur_ch[-1] if cur_ch else '?'}",
        f"累计: solved {solves} / failed {fails} / 并行触发 {par}",
    ]
    if rounds:
        parts.append(f"最近轮次: {rounds[-1][0]}/{rounds[-1][1]}")
    # 最近几行（最新动作）
    recent = [l for l in tail.splitlines() if l.strip()][-6:]
    return "\n".join(parts + ["--- 最近动作 ---"] + recent)


def main():
    ap = argparse.ArgumentParser(description="本地运行状态查看（tail 日志 + 状态提取）")
    ap.add_argument("log", help="运行日志文件路径")
    ap.add_argument("--once", action="store_true", help="只看一次快照后退出")
    args = ap.parse_args()

    if args.once:
        print(snapshot(args.log))
        return
    try:
        while True:
            os.system("clear")
            print(snapshot(args.log))
            time.sleep(3)
    except KeyboardInterrupt:
        print("\n已退出")


if __name__ == "__main__":
    main()
