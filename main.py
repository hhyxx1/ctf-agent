"""主入口

两种运行模式:
1. 本地模式: python main.py <命令>    (开发调试)
2. 托管模式: 镜像启动后自动执行       (TSecBench 平台)

托管模式自启逻辑:
- AUTO_START=true 且带命令参数时，直接进入 tsecbench 自解题循环
- 平台拉起容器后，entrypoint.sh 调 python main.py auto
- 完成/超时后进程退出，平台回收沙箱
"""
import os
import sys
import time
import logging
from agent import Agent
from batch_solver import batch_from_file, batch_from_api
from tsecbench_solver import run_tsecbench, list_challenges as tb_list, show_status

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logging.getLogger("tools").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)


def cmd_test():
    """跑内置测试"""
    from tests.test_runner import run_all_tests
    tests = [
        ("Base64 解码", "解码 base64 并提交 flag: ZmxhZ3t0ZXN0X2ZsYWd9"),
        ("RSA (小 n)", "RSA题: n=3233, e=65537, c=2557。请解密找到 flag 并提交。"),
        ("Python 计算", "用 Python 计算 2 的 50 次方并告诉我结果"),
        ("Shell 执行", "用 shell 命令列出当前工作目录下的文件"),
        ("文件读取", "读取 output/hint.txt 文件内容并根据提示操作"),
    ]
    results = []
    for name, task in tests:
        print(f"\n{'='*60}\n  测试: {name}\n{'='*60}")
        agent = Agent()
        r = agent.run(task)
        r["test"] = name
        results.append(r)
    print(f"\n{'='*60}\n  测试汇总\n{'='*60}")
    for r in results:
        s = "✅" if r["success"] else ("⚠️" if r["flag_found"] else "❌")
        print(f"  {s} {r['test']}: {r['iterations']} 轮")


def cmd_solve(task: str):
    agent = Agent()
    return agent.run(task)


def cmd_auto():
    """托管模式自启入口

    逻辑:
    1. 检测环境: BENCHMARK_TOKEN 是否注入
    2. 启动 TSecBench 解题循环
    3. 跑完所有题或超时后退出
    """
    from config import config

    print("="*60)
    print("🚀 TSecBench 托管模式自启")
    print("="*60)

    if not config.COMPETITION_TOKEN:
        print("❌ BENCHMARK_TOKEN 未注入，无法启动答题")
        print("   托管模式由平台自动注入；本地调试请手动 export BENCHMARK_TOKEN")
        sys.exit(1)

    if not config.COMPETITION_BASE_URL:
        print("❌ BENCHMARK_BASE_URL 未注入")
        sys.exit(1)

    print(f"  BASE_URL: {config.COMPETITION_BASE_URL}")
    print(f"  LLM 网关: {config.LLM_BASE_URL}")
    print(f"  总时限: {config.TOTAL_TIMEOUT_SEC}s ({config.TOTAL_TIMEOUT_SEC/60:.0f}min)")
    print(f"  单题轮上限: {config.MAX_ITERATIONS}")
    print(f"  并发上限: {config.MAX_CONCURRENT}")

    # 超时守护: 主进程设总时限，到点强行退出，避免平台沙箱超时被杀
    start_time = time.time()

    try:
        run_tsecbench(timeout_sec=config.TOTAL_TIMEOUT_SEC, start_time=start_time)
    except KeyboardInterrupt:
        print("\n⚠️ 手动中断")
    except Exception as e:
        logging.exception(f"自解题失败: {e}")

    elapsed = time.time() - start_time
    print(f"\n✅ 完成，总耗时 {elapsed/60:.1f} 分钟")


def main():
    # 托管模式自启: 平台拉起容器后 entrypoint.sh 莗 python main.py auto
    if len(sys.argv) >= 2 and sys.argv[1] == "auto":
        cmd_auto()
        return

    # 显式启自解题:  AUTO_START=true 且无命令参数时也走 auto
    from config import config
    if config.AUTO_START and len(sys.argv) < 2:
        cmd_auto()
        return

    # 本地命令行模式
    if len(sys.argv) < 2:
        print("""
用法:
  python main.py auto                        托管模式自启（平台/entrypoint 调）
  python main.py test                        跑内置测试
  python main.py solve "题目描述"            解单道题
  python main.py batch tasks.json           从 JSON 文件批量解题
  python main.py batch-api                  旧版比赛 API 批量解题

TSecBench (腾讯安全基准平台):
  python main.py tsecbench                  运行 TSecBench 完整解题循环
  python main.py tsecbench-list             仅列出题目
  python main.py tsecbench-status           查看解题进度

AI Agent 平台 (slab-match / pro.dasctf.com):
  python main.py slab                       运行 AI Agent 平台完整解题循环
  python main.py slab-list                  仅列出题目

配置 (编辑 .env 或由平台注入环境变量):
  BENCHMARK_BASE_URL=https://tsecbench.zc.tencent.com
  BENCHMARK_TOKEN=你的BENCHMARK_TOKEN
  SLAB_HOST=https://pro.dasctf.com
  SLAB_ACCESS_KEY=你的X-Agent-AccessKey
  LLM_API_KEY=sk-xxx
  GATEWAY_MODE=open        启用 .tsecbench.gw 大模型网关（托管必启）
""")
        return

    cmd = sys.argv[1]
    if cmd == "test":
        cmd_test()
    elif cmd == "solve":
        if len(sys.argv) < 3:
            print("错误: 请提供题目描述")
            return
        cmd_solve(sys.argv[2])
    elif cmd == "batch":
        if len(sys.argv) < 3:
            print("错误: 请提供 JSON 文件路径")
            return
        batch_from_file(sys.argv[2])
    elif cmd == "batch-api":
        batch_from_api()
    elif cmd == "tsecbench":
        run_tsecbench()
    elif cmd == "tsecbench-list":
        tb_list()
    elif cmd == "tsecbench-status":
        show_status()
    elif cmd == "slab":
        from slab_match_solver import run_slab
        run_slab()
    elif cmd == "slab-one":
        if len(sys.argv) < 3:
            print("错误: 请提供题目 ID，如: python main.py slab-one 10792")
            return
        from slab_match_solver import run_slab
        run_slab(only_id=int(sys.argv[2]))
    elif cmd == "slab-list":
        from slab_match_solver import list_challenges
        from utils.slab_match_api import SlabMatchAPI
        api = SlabMatchAPI()
        for ch in list_challenges(api):
            mark = "✅" if ch.get("has_solved") else "⬜"
            print(f"  {mark} id={ch['exercise_id']} [{ch.get('category','')}] {ch.get('name','')}")
    else:
        print(f"未知命令: {cmd}")


if __name__ == "__main__":
    main()
