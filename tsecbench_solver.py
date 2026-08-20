"""平台类评测适配器示例（TSecBench API 自动解题循环）

这是一个"平台评测接入"的参考实现：演示如何对接一个提供题目列表/启动容器/
提交 flag 的评测平台 API，并驱动 Agent 批量解题。可改造为任意类似平台。

标准流程:
1. 列出所有题目
2. 按难度排序（先做 easy）
3. 同时最多启动 3 道题
4. 每道题: 启动容器 → Agent 解题 → 提交 flag → 关闭容器
5. 多 flag 的题目: 多次提交直到 correct_flag_count == flag_count
6. 进度持久化，支持断点续跑

用法:
  python main.py tsecbench          运行完整解题循环
  python main.py tsecbench-list     仅列出题目
  python main.py tsecbench-status   查看解题进度
"""
import os
import json
import time
import signal
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from typing import Dict, List

from agent import Agent, build_agent
from slab_match_solver import _load_lessons
from utils import tsec_api, load_tb_progress, save_tb_progress
from config import config

logger = logging.getLogger(__name__)

# 同时最多启动的题目数
MAX_CONCURRENT = 3

# 单题最大尝试次数
MAX_ATTEMPTS_PER_CHALLENGE = 3

# 单题整体超时（秒）：超过则放弃该题，避免一道题拖死整个评测
# 默认按难度分配: easy 快速试错, hard 给足时间; 显式设置 CHALLENGE_TIMEOUT_SEC 则全局覆盖
_DEFAULT_CHALLENGE_TIMEOUT = int(os.getenv("CHALLENGE_TIMEOUT_SEC", "0"))


def _challenge_timeout(difficulty: str = "") -> int:
    if _DEFAULT_CHALLENGE_TIMEOUT > 0:
        return _DEFAULT_CHALLENGE_TIMEOUT
    return {"easy": 360, "medium": 600, "hard": 900, "expert": 1200}.get(difficulty, 600)


class ChallengeTimeout(Exception):
    """单题超时信号"""
    pass


def _timeout_handler(signum, frame):
    raise ChallengeTimeout()


# 进度并发锁：两题并行时多个 solve_challenge 线程同时写进度，需串行化防写坏
TB_PROGRESS_LOCK = threading.Lock()


def _tb_save(progress) -> None:
    with TB_PROGRESS_LOCK:
        _tb_save(progress)


def _infer_category(unique_code: str, desc: str) -> str:
    """按描述关键词推断题型（tsecbench 的 unique_code 前缀无法直接映射题型，如 a-05/e1-01）"""
    text = f"{unique_code} {desc}".lower()
    if any(k in text for k in ["web", "登录", "上传", "反序列化", "sql", "注入", "防护", "门户", "面板", "系统", "平台", "接口", "api"]):
        return "web"
    if any(k in text for k in ["内存安全", "二进制", "溢出", "沙箱", "序列化对象", "内存", "协议"]):
        return "pwn"
    if any(k in text for k in ["加密", "密钥", "rsa", "cipher", "密码", "解密"]):
        return "crypto"
    if any(k in text for k in ["隐写", "流量", "压缩", "取证", "steg", "文件类型"]):
        return "misc"
    return "unknown"


def list_challenges() -> List[Dict]:
    """列出所有题目"""
    if not tsec_api.is_configured():
        print("❌ TSecBench API 未配置。请在 .env 中设置:")
        print("  COMPETITION_BASE_URL=https://tsecbench.zc.tencent.com")
        print("  COMPETITION_TOKEN=你的BENCHMARK_TOKEN")
        return []

    challenges = tsec_api.list_challenges()
    if not challenges:
        print("⚠️ 未获取到任何题目")
        return []

    # 打印题目列表
    print(f"\n📋 共 {len(challenges)} 道题:\n")
    print(f"{'unique_code':<35} {'diff':<8} {'flags':<8} {'done':<6} {'status'}")
    print("-" * 90)
    for ch in challenges:
        code = ch.get("unique_code", "?")
        diff = ch.get("difficulty", "?")
        flag_count = ch.get("flag_count", 0)
        correct = ch.get("correct_flag_count", 0)
        completed = "✅" if ch.get("is_completed") else "❌"
        status = ch.get("container_status", "?")
        print(f"{code:<35} {diff:<8} {correct}/{flag_count:<5} {completed:<6} {status}")

    return challenges


def solve_challenge(challenge: Dict, progress: Dict) -> Dict:
    """
    解单道题

    流程:
    1. 启动容器（拿到 container_addr）
    2. 构造题目描述（含 container_addr）
    3. Agent 解题
    4. 提交 flag
    5. 关闭容器
    """
    unique_code = challenge.get("unique_code", "")
    desc = challenge.get("description", "")
    diff = challenge.get("difficulty", "?")
    flag_count = challenge.get("flag_count", 1)

    print(f"\n{'='*60}")
    print(f"🎯 解题: {unique_code} (难度: {diff}, flags: {flag_count})")
    print(f"{'='*60}")

    # 1. 启动容器
    print(f"\n[1/5] 启动容器...")
    start_result = tsec_api.start_challenge(unique_code)

    if isinstance(start_result, dict) and start_result.get("error"):
        err_code = start_result.get("code", "unknown")
        err_msg = start_result.get("message", "")
        if err_code == "invalid_state":
            # 已有活跃实例 → 不重复启动，直接拉取当前状态
            logger.warning(f"⚠️ {unique_code} 已有活跃实例，跳过启动直接拉地址")
        else:
            logger.error(f"❌ 启动失败: {err_code} - {err_msg}")
            progress["failed"].append(unique_code)
            _tb_save(progress)
            return {"status": "start_failed", "code": unique_code, "error": err_msg}

    # 拉容器地址：start_result 直接拿，拿不到就轮询 list_challenges 等就绪
    container_addrs = []
    if isinstance(start_result, dict) and not start_result.get("error"):
        container_addrs = start_result.get("container_addr", []) or []

    if not container_addrs:
        # 容器启动需要时间，轮询最多 30s
        for wait_round in range(6):
            logger.info(f"等待容器就绪... (尝试 {wait_round+1}/6)")
            time.sleep(5)
            challenges = tsec_api.list_challenges()
            for ch in challenges:
                if ch.get("unique_code") == unique_code:
                    status = ch.get("container_status", "")
                    if status == "available":
                        container_addrs = ch.get("container_addr", []) or []
                        break
            if container_addrs:
                break

    if not container_addrs:
        logger.error(f"❌ 无法获取 {unique_code} 的容器地址")
        progress["failed"].append(unique_code)
        _tb_save(progress)
        return {"status": "no_container", "code": unique_code}

    addr_str = ", ".join(container_addrs)
    print(f"  容器地址: {addr_str}")

    # 2. 构造题目描述（含同类题经验注入，省轮次）
    # 题型从 unique_code 前缀推导（web_/crypto_/pwn_/misc_）
    cat = _infer_category(unique_code, desc)
    lessons_hint = ""
    try:
        entry = _load_lessons().get(cat)
        if entry:
            parts = []
            if entry.get("solved_paths"):
                parts.append(f"此类题此前成功路径参考: {' → '.join(entry['solved_paths'][-1])}")
            if entry.get("notes"):
                parts.append(f"此类题经验笔记: {entry['notes']}")
            if entry.get("failed", 0) > 0:
                parts.append(f"⚠️ 此类题此前失败 {entry['failed']} 次，注意换思路")
            if parts:
                lessons_hint = "\n".join(parts) + "\n"
    except Exception:
        pass
    task = f"""请解以下 CTF 题目并提交 flag。

题目唯一标识 (unique_code): {unique_code}
题目描述: {desc}
难度: {diff}
Flag 数量: {flag_count}
靶场容器地址: {addr_str}

## 同类题经验（沉淀自之前运行，方法论级）
{lessons_hint if lessons_hint else '（无此前同类题经验）'}

注意:
- 靶场地址通过 VPN 直连访问
- 这道题有 {flag_count} 个 flag，需要分别获取和提交
- 找到 flag 后必须调用 submit_flag 提交，flag 格式一般为 flag{{...}}
- 如果卡住可以尝试不同方向，不要在一种方法上死磕"""

    # 3. Agent 解题（按题型分派子 Agent：专用 prompt + 工具子集 + 经验注入）
    print(f"\n[2/5] Agent 解题...")
    agent = build_agent(cat)
    # 单题超时兜底：两题并行（线程池）下 signal 仅主线程可用——去掉 signal.alarm，
    # 卡题由 agent 层兜底（MAX_ITERATIONS=50 + 无迹象 50 轮提示 + 提示后 15 轮止损）
    try:
        result = agent.run(task)
    except Exception as e:
        logger.error(f"❌ {unique_code} 解题异常: {e}")
        result = {
            "success": False,
            "flag_found": False,
            "iterations": agent.iteration,
            "final_message": f"[解题异常: {e}]",
        }

    agent_success = result.get("success", False)
    final_msg = result.get("final_message", "")

    # 沉淀经验（成功存工具路径；真解题失败（跑了不少轮）记 failed；
    # token 耗尽/LLM 失败（iterations 少）不记，避免污染经验库）
    try:
        from slab_match_solver import _load_lessons, _save_lessons
        lessons = _load_lessons()
        entry = lessons.setdefault(cat, {"solved_paths": [], "failed": 0, "notes": ""})
        if result.get("success") or result.get("flag_found"):
            path = []
            for m in agent.messages:
                for tc in m.get("tool_calls", []) or []:
                    fn = (tc.get("function") or {}).get("name", "")
                    if fn and fn not in path:
                        path.append(fn)
            path = path[:8]
            if path and path not in entry["solved_paths"]:
                entry["solved_paths"].append(path)
                entry["solved_paths"] = entry["solved_paths"][-5:]
                _save_lessons(lessons)
        elif (result.get("iterations") or 0) >= 10:
            # 真解题失败（跑了不少轮没解出）才记 failed
            entry["failed"] += 1
            _save_lessons(lessons)
    except Exception:
        pass

    # 4. 从 Agent 的输出中提取 flag 并提交
    print(f"\n[3/5] 提交 flag...")
    submitted_flags = progress["submitted_flags"].get(unique_code, [])

    # 从 final_message 和对话历史中提取 flag
    all_text = final_msg + " " + " ".join(
        m.get("content", "") for m in agent.messages if isinstance(m.get("content"), str)
    )

    import re
    flag_patterns = [r"flag\{[^}]+\}", r"FLAG\{[^}]+\}", r"ctf\{[^}]+\}", r"CTF\{[^}]+\}"]
    found_flags = set()
    for pattern in flag_patterns:
        try:
            found_flags.update(re.findall(pattern, all_text))
        except re.error:
            pass

    submit_results = []
    for flag in found_flags:
        if flag in submitted_flags:
            logger.info(f"⏭️ flag 已提交过: {flag}")
            continue

        sr = tsec_api.submit_flag(unique_code, flag)
        submit_results.append({"flag": flag, "result": sr})

        if isinstance(sr, dict):
            if sr.get("correct"):
                print(f"  ✅ 正确! {flag} (得分: {sr.get('awarded', 0)})")
                submitted_flags.append(flag)
            elif sr.get("code") == "duplicate":
                print(f"  ⏭️ 重复提交: {flag}")
                submitted_flags.append(flag)
            else:
                print(f"  ❌ 错误: {flag} - {sr.get('message', '')}")

    # 更新进度
    if submitted_flags:
        progress["submitted_flags"][unique_code] = submitted_flags

    # 检查是否通关
    challenges = tsec_api.list_challenges()
    is_completed = False
    correct_count = 0
    for ch in challenges:
        if ch.get("unique_code") == unique_code:
            is_completed = ch.get("is_completed", False)
            correct_count = ch.get("correct_flag_count", 0)
            break

    if is_completed:
        progress["solved"].append(unique_code)
        if unique_code in progress["in_progress"]:
            progress["in_progress"].remove(unique_code)
        print(f"\n🎉 {unique_code} 通关！(已提交 {correct_count} 个 flag)")
        status = "solved"
    elif agent_success or submitted_flags:
        status = "partial"
        if unique_code not in progress["in_progress"]:
            progress["in_progress"].append(unique_code)
    else:
        status = "failed"
        progress["failed"].append(unique_code)

    # 5. 关闭容器（释放资源）
    print(f"\n[4/5] 关闭容器...")
    close_result = tsec_api.close_challenge(unique_code)
    if isinstance(close_result, dict) and close_result.get("closed"):
        print(f"  容器已关闭")
    else:
        print(f"  ⚠️ 关闭失败: {close_result}")

    # 记录历史
    progress["history"].append({
        "unique_code": unique_code,
        "status": status,
        "flags_found": len(found_flags),
        "flags_submitted": len(submitted_flags),
        "agent_iterations": result.get("iterations", 0),
        "timestamp": time.strftime("%H:%M:%S"),
    })

    _tb_save(progress)

    print(f"\n[5/5] 完成: {status}")

    return {
        "status": status,
        "code": unique_code,
        "flags_found": len(found_flags),
        "submit_results": submit_results,
    }


def run_tsecbench(timeout_sec: int = 0, start_time: float = 0):
    """运行完整 TSecBench 解题循环

    参数:
        timeout_sec: 总时限（秒），到点后停止开新题，只等当前题收尾。0=不限
        start_time:  赊始时间戳，用于计算剩余时间。0=now
    """
    if start_time == 0:
        start_time = time.time()

    def time_left() -> float:
        if timeout_sec <= 0:
            return float("inf")
        return timeout_sec - (time.time() - start_time)

    print("\n" + "="*60)
    print("🚀 TSecBench 自动解题")
    print("="*60)

    # 1. 列出题目
    challenges = list_challenges()
    if not challenges:
        return

    # 2. 加载进度
    progress = load_tb_progress()
    print(f"\n📊 进度: 已解 {len(progress['solved'])}, 失败 {len(progress['failed'])}")
    if timeout_sec > 0:
        print(f"⏱️ 总时限: {timeout_sec/60:.0f}min, 剩 {time_left()/60:.1f}min")

    # 3. 按难度排序（easy → medium → hard），未完成的优先
    difficulty_order = {"easy": 1, "medium": 2, "hard": 3, "expert": 4}
    challenges.sort(key=lambda ch: (
        ch.get("is_completed", False),  # 未完成的在前
        difficulty_order.get(ch.get("difficulty", ""), 99),
        ch.get("level", 99),
    ))

    # 4. 逐题解题（持续填槽两题并行：同时最多 2 题在途，完成补下一题，卡题不阻塞）
    stats = {"solved": 0, "partial": 0, "failed": 0, "skipped": 0}
    # 留 3min 兜底收尾，避免平台沙箱超时被强杀
    safety_margin = 180
    MAX_INFLIGHT = 2
    inflight = {}
    idx = 0

    def _fill_slots(ex, inflight, idx):
        """预启动 + 填槽提交，保持 MAX_INFLIGHT 题在途（一题完成补下一题）"""
        while idx < len(challenges) and len(inflight) < MAX_INFLIGHT:
            left = time_left()
            if left < safety_margin:
                print(f"\n⚠️ 剩余时间不足 ({left/60:.1f}min < {safety_margin/60:.0f}min 兜底)，停止开新题")
                try:
                    for code in progress.get("in_progress", [])[:5]:
                        tsec_api.close_challenge(code)
                except Exception:
                    pass
                return idx
            ch = challenges[idx]
            print(f"\n{'#'*60}")
            print(f"  题目 {idx+1}/{len(challenges)}  (剩 {left/60:.1f}min)")
            print(f"{'#'*60}")
            f = ex.submit(solve_challenge, ch, progress)
            inflight[f] = ch
            idx += 1
        return idx

    with ThreadPoolExecutor(max_workers=MAX_INFLIGHT) as ex:
        idx = _fill_slots(ex, inflight, idx)
        while inflight:
            done, _ = wait(list(inflight.keys()), return_when=FIRST_COMPLETED)
            for f in done:
                ch = inflight.pop(f)
                try:
                    result = f.result()
                    stats[result["status"]] = stats.get(result["status"], 0) + 1
                except KeyboardInterrupt:
                    print("\n\n⚠️ 用户中断，保存进度...")
                    _tb_save(progress)
                    return
                except Exception as e:
                    logger.error(f"❌ 题目 {ch.get('unique_code')} 出错: {e}", exc_info=True)
                    stats["failed"] = stats.get("failed", 0) + 1
            idx = _fill_slots(ex, inflight, idx)

    # 5. 汇总
    elapsed = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"📊 TSecBench 解题汇总")
    print(f"{'='*60}")
    print(f"  总题数:   {len(challenges)}")
    print(f"  ✅ 通关:  {stats.get('solved', 0)}")
    print(f"  ⚠️ 部分:  {stats.get('partial', 0)}")
    print(f"  ❌ 失败:  {stats.get('failed', 0)}")
    print(f"  ⏭️ 跳过:  {stats.get('skipped', 0)}")
    print(f"  ⏱️ 耗时:  {elapsed/60:.1f}min")
    print(f"  进度文件: {os.path.join(config.OUTPUT_DIR, 'tsecbench_progress.json')}")
    print(f"{'='*60}\n")


def show_status():
    """显示当前解题进度"""
    progress = load_tb_progress()
    print(f"\n📊 TSecBench 解题进度:")
    print(f"  ✅ 已通关: {len(progress['solved'])} 题")
    print(f"  ⚠️ 进行中: {len(progress['in_progress'])} 题")
    print(f"  ❌ 已失败: {len(progress['failed'])} 题")
    print(f"  📝 已提交 flags: {sum(len(v) for v in progress['submitted_flags'].values())}")

    if progress["solved"]:
        print(f"\n通关题目:")
        for code in progress["solved"]:
            print(f"  ✅ {code}")

    if progress["history"]:
        print(f"\n最近 5 次操作:")
        for h in progress["history"][-5:]:
            print(f"  {h.get('timestamp', '?')} {h.get('unique_code', '?')} → {h.get('status', '?')}")
