"""平台类评测适配器示例（TSecBench API 自动解题循环）

这是一个"平台评测接入"的参考实现：演示如何对接一个提供题目列表/启动容器/
提交 flag 的评测平台 API，并驱动 Agent 批量解题。可改造为任意类似平台。

标准流程:
1. 列出所有题目
2. 按难度排序（先做 easy）
3. 同时最多 2 道题在途（完成一道补下一道，不阻塞）
4. 每道题: 启动容器 → Agent 解题 → 提交 flag → 关闭容器
5. 多 flag 的题目: 多次提交直到 correct_flag_count == flag_count
6. 两轮制重试：第一轮全量跑完后，第二轮优先重试未解出的题
7. 进度仅在内存中维护（不落盘，每次运行从空开始）；每题运行细节导出到 output/logs_<run>/

用法:
  python main.py tsecbench          运行完整解题循环
  python main.py tsecbench-list     仅列出题目
  python main.py tsecbench-status   查看解题进度（仅本次进程内，历史不落盘）
"""
import os
import json
import re
import time
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from typing import Dict, List

from agent import build_agent
from llm import LLMQuotaExhausted
from slab_match_solver import _load_lessons, _save_lessons
from tools.flag_tool import filter_flags
from utils import tsec_api
from config import config

logger = logging.getLogger(__name__)

# 进度并发锁：多题并行时多个 solve_challenge 线程同时写内存 progress，需串行化防列表写坏
TB_PROGRESS_LOCK = threading.Lock()


def _update_progress(progress, mutate):
    """在进度锁内执行一次 progress 变更，避免并发线程写坏列表/字典。

    用法: _update_progress(progress, lambda p: p["solved"].append(code))
    """
    with TB_PROGRESS_LOCK:
        mutate(progress)


# 在途容器登记（unique_code → True）：双击 Ctrl+C 打断收尾时仍能清理，防容器泄漏
_ACTIVE_CONTAINERS: Dict[str, bool] = {}


def _safe_close(unique_code: str) -> bool:
    """关闭容器释放资源（失败不抛异常，避免干扰主流程）。"""
    _ACTIVE_CONTAINERS.pop(unique_code, None)
    try:
        res = tsec_api.close_challenge(unique_code)
        if isinstance(res, dict) and res.get("closed"):
            print(f"  容器已关闭")
            return True
        print(f"  ⚠️ 关闭失败: {res}")
    except Exception as e:
        logger.warning(f"关闭容器异常 {unique_code}: {e}")
    return False


def _close_all_active() -> int:
    """中断收尾兜底：关闭所有仍在登记中的容器，返回尝试关闭的数量。"""
    codes = list(_ACTIVE_CONTAINERS.keys())
    for code in codes:
        print(f"  🧹 清理残留容器: {code}")
        _safe_close(code)
    return len(codes)


# ── 运行日志导出 ──────────────────────────────────────────────────────────
# 每次跑完导出到 output/logs_<run>/，单题一份 JSON + 一份总览 RUN_SUMMARY.json

# 运行日志目录：统一用 config.RUN_LOG_DIR（进程启动时生成，审计日志/单题日志/总览同目录）
TB_RUN_ID = config.RUN_ID
TB_LOG_DIR = config.RUN_LOG_DIR
TB_LOG_MANIFEST = os.path.join(TB_LOG_DIR, "manifest.json")


def _safe_name(unique_code: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", unique_code)


def _dump_json(obj, path: str) -> None:
    """原子写 JSON：先序列化到临时文件再 rename。

    - 直接 open+json.dump 是流式写入，中途抛异常会留下半个文件（之前 a-05.json
      因 run_log 里有 set 触发 'Object of type set is not JSON serializable'
      中断在半路 → JSONDecodeError）
    - default 兜底把 set/frozenset 转有序列表，其他未知类型转字符串
    """
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2,
                  default=lambda o: sorted(o) if isinstance(o, (set, frozenset)) else str(o))
    os.replace(tmp, path)


def _export_challenge_log(unique_code: str, diff: str, flag_count: int,
                          result: Dict, agent, task: str, status: str,
                          found_flags: List[str], submit_results: List[Dict],
                          container_addrs: List[str], start_ts: float) -> str:
    """把单题 agent 全过程（输入/输出/工具调用/token/耗时）导出为一份 JSON。"""
    os.makedirs(TB_LOG_DIR, exist_ok=True)

    run_log = result.get("run_log", []) or []
    total_prompt = sum(r.get("usage", {}).get("prompt_tokens") or 0 for r in run_log)
    total_completion = sum(r.get("usage", {}).get("completion_tokens") or 0 for r in run_log)
    llm_calls = len(run_log)
    tool_calls_total = sum(len(r.get("tool_calls", [])) for r in run_log)
    llm_time = round(sum(r.get("llm_elapsed_sec") or 0 for r in run_log), 2)
    tool_time = round(sum(tc.get("elapsed_sec") or 0 for r in run_log
                          for tc in r.get("tool_calls", [])), 2)

    # 工具调用分布统计
    tool_counter = {}
    for r in run_log:
        for tc in r.get("tool_calls", []):
            tool_counter[tc["name"]] = tool_counter.get(tc["name"], 0) + 1

    # 完整消息历史（超长内容截断首尾保留），便于人工核对 agent 看到的上下文
    truncated_messages = []
    for m in (agent.messages or []):
        content = m.get("content")
        if isinstance(content, str) and len(content) > 4000:
            content = content[:3000] + "\n...[截断]...\n" + content[-500:]
        truncated_messages.append({
            "role": m.get("role"),
            "content": content,
            "tool_calls": m.get("tool_calls"),
            "tool_call_id": m.get("tool_call_id"),
            "name": m.get("name"),
        })

    log = {
        "unique_code": unique_code,
        "status": status,
        "difficulty": diff,
        "flag_count": flag_count,
        "container_addrs": container_addrs,
        "task_given": task,
        "found_flags": found_flags,
        "submit_results": submit_results,
        "summary": {
            "elapsed_sec": round(time.time() - start_ts, 1),
            "llm_calls": llm_calls,
            "agent_iterations": result.get("iterations", 0),
            "tool_calls_total": tool_calls_total,
            "prompt_tokens": total_prompt,
            "completion_tokens": total_completion,
            "total_tokens": total_prompt + total_completion,
            "llm_time_sec": llm_time,
            "tool_time_sec": tool_time,
            "tool_breakdown": tool_counter,
        },
        "rounds": run_log,
        "messages": truncated_messages,
    }

    path = os.path.join(TB_LOG_DIR, f"{_safe_name(unique_code)}.json")
    try:
        _dump_json(log, path)
    except Exception as e:
        print(f"  ⚠️ 日志导出失败: {e}")
        return ""

    # 追加到清单（多题并发 → 加锁，失败不影响主流程）
    entry = {
        "unique_code": unique_code,
        "status": status,
        "difficulty": diff,
        "agent_iterations": result.get("iterations", 0),
        "tool_calls_total": tool_calls_total,
        "elapsed_sec": log["summary"]["elapsed_sec"],
        "total_tokens": log["summary"]["total_tokens"],
        "log_file": os.path.basename(path),
    }
    try:
        with TB_PROGRESS_LOCK:
            manifest = []
            if os.path.exists(TB_LOG_MANIFEST):
                with open(TB_LOG_MANIFEST, "r", encoding="utf-8") as f:
                    manifest = json.load(f)
                if not isinstance(manifest, list):
                    manifest = []
            # 按题去重：重试/重跑同题时覆盖旧条目，只保留最终结果
            manifest = [m for m in manifest if m.get("unique_code") != unique_code]
            manifest.append(entry)
            _dump_json(manifest, TB_LOG_MANIFEST)
    except Exception:
        pass  # 清单写入失败不影响主流程

    print(f"  📄 日志已导出: {path}")
    return path


def export_run_summary(progress: Dict, start_time: float) -> str:
    """整个 run 结束时生成总览文件（每题耗时/token/轮次/结论汇总）。"""
    elapsed_total = round(time.time() - start_time, 1)
    history = progress.get("history", [])
    solved = [h["unique_code"] for h in history if h.get("status") == "solved"]
    failed = [h["unique_code"] for h in history if h.get("status") == "failed"]

    # 从单题日志回读 token/耗时统计
    rows = []
    for h in history:
        code = h.get("unique_code", "")
        row = {
            "unique_code": code,
            "status": h.get("status"),
            "difficulty": h.get("difficulty", "?"),
            "agent_iterations": h.get("agent_iterations", 0),
            "flags_found": h.get("flags_found", 0),
            "flags_submitted": h.get("flags_submitted", 0),
            "timestamp": h.get("timestamp", ""),
        }
        log_path = os.path.join(TB_LOG_DIR, f"{_safe_name(code)}.json")
        if os.path.exists(log_path):
            try:
                with open(log_path, "r", encoding="utf-8") as f:
                    s = json.load(f).get("summary", {})
                row.update({
                    "elapsed_sec": s.get("elapsed_sec"),
                    "llm_calls": s.get("llm_calls"),
                    "tool_calls_total": s.get("tool_calls_total"),
                    "prompt_tokens": s.get("prompt_tokens"),
                    "completion_tokens": s.get("completion_tokens"),
                    "total_tokens": s.get("total_tokens"),
                    "llm_time_sec": s.get("llm_time_sec"),
                    "tool_time_sec": s.get("tool_time_sec"),
                    "tool_breakdown": s.get("tool_breakdown"),
                    "log_file": os.path.basename(log_path),
                })
            except Exception:
                pass
        rows.append(row)

    total_tokens = sum(r.get("total_tokens") or 0 for r in rows)

    summary = {
        "run_id": TB_RUN_ID,
        "total_elapsed_sec": elapsed_total,
        "challenges_attempted": len(rows),
        "solved_count": len(solved),
        "failed_count": len(failed),
        "solve_rate": f"{len(solved)/len(rows)*100:.1f}%" if rows else "0.0%",
        "solved_codes": solved,
        "failed_codes": failed,
        "total_tokens_all_challenges": total_tokens,
        "lessons_count": len(progress.get("lessons", [])),
        "submitted_flags": progress.get("submitted_flags", {}),
        "challenges": rows,
    }

    os.makedirs(TB_LOG_DIR, exist_ok=True)
    out_path = os.path.join(TB_LOG_DIR, "RUN_SUMMARY.json")
    try:
        _dump_json(summary, out_path)
    except Exception as e:
        print(f"  ⚠️ 总览导出失败: {e}")
        return ""

    print(f"\n📊 运行总览已导出: {out_path}")
    return out_path


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


def _quick_prerecon(addr_str: str) -> str:
    """T1-③ 轻量预侦察：连通性 + HTTP 头 + 首页摘要 + whatweb 指纹。

    agent.run 之前跑确定性脚本，结果拼进 task——agent 第一轮就站在侦察结果上，
    省掉 5-10 轮手工探测。失败只降级（返回空/部分信息），绝不影响解题流程。
    """
    from tools.base import run_cmd
    parts = []
    for addr in [a.strip() for a in addr_str.split(",") if a.strip()][:2]:
        url = addr if addr.startswith("http") else f"http://{addr}"
        sec = [f"### 目标 {url}"]
        # 连通性 + HTTP 响应头
        head = run_cmd(f"curl -sS -m 8 -i '{url}'", timeout=15)
        if not head or "执行错误" in head or "Connection refused" in head or "Could not resolve" in head:
            sec.append("[连通性异常] curl 连不上——若非 HTTP 服务可能是 pwn/crypto 题，忽略此报告；"
                       "若确为 web 题请检查 VPN/网络后再试")
        else:
            sec.append("[HTTP 响应头+状态]\n" + head[:600])
            # whatweb 指纹（识别框架/语言/CMS）
            what = run_cmd(f"whatweb -a 1 --no-errors '{url}'", timeout=45)
            if what and "执行错误" not in what:
                sec.append("[技术栈指纹]\n" + what[:500])
            # 首页正文摘要（找登录框/注释/线索）
            body = run_cmd(f"curl -sS -m 8 '{url}' | head -c 2500", timeout=15)
            if body:
                sec.append("[首页正文前 2500 字符]\n" + body[:2500])
        parts.append("\n".join(sec))
    report = "\n\n".join(parts)
    return report[:3000]


# ── T1-② 死路地图：记录每题首轮尝试情况，重试轮注入，避免二刷重走死路 ──
_ATTEMPT_HISTORY: Dict[str, Dict] = {}
_ATTEMPT_LOCK = threading.Lock()


def _record_attempt(unique_code: str, agent, submit_results: list, final_msg: str, rounds: int):
    """记录一次尝试的工具使用统计/错误 flag/最终结论（内存中，仅本次运行）"""
    from collections import Counter
    try:
        counter = Counter()
        for m in agent.messages:
            for tc in m.get("tool_calls", []) or []:
                fn = (tc.get("function") or {}).get("name", "")
                if fn:
                    counter[fn] += 1
        wrong_flags = []
        for sr in submit_results:
            r = sr.get("result")
            if not (isinstance(r, dict) and r.get("correct")):
                wrong_flags.append(sr.get("flag", ""))
        with _ATTEMPT_LOCK:
            _ATTEMPT_HISTORY[unique_code] = {
                "rounds": rounds,
                "tools": counter.most_common(8),
                "wrong_flags": [f for f in wrong_flags if f][:10],
                "last_direction": re.sub(
                    r'(?:flag|FLAG|ctf|CTF)\{[^}]{0,200}\}', '[FLAG]', (final_msg or "").strip())[:150],
            }
    except Exception:
        pass


def _build_deadend_hint(code: str) -> str:
    """重试轮的死路地图提示（无记录返回空串）"""
    with _ATTEMPT_LOCK:
        h = dict(_ATTEMPT_HISTORY.get(code) or {})
    if not h:
        return ""
    lines = [f"上一轮已尝试 {h.get('rounds', '?')} 轮未解出。必须换攻击面，不要重复上次的做法："]
    if h.get("tools"):
        lines.append("已用工具（频次）: " + ", ".join(f"{n}×{c}" for n, c in h["tools"]))
    if h.get("wrong_flags"):
        lines.append("已提交且被平台判错（勿再提交）: " + ", ".join(h["wrong_flags"]))
    if h.get("last_direction"):
        lines.append(f"上一轮最终结论: {h['last_direction']}")
    return "\n".join(lines)


def solve_challenge(challenge: Dict, progress: Dict, retry_hint: str = "", retry_round: bool = False) -> Dict:
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
    _challenge_start = time.time()

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
            _update_progress(progress, lambda p: p["failed"].append(unique_code))
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
        _update_progress(progress, lambda p: p["failed"].append(unique_code))
        return {"status": "no_container", "code": unique_code}

    addr_str = ", ".join(container_addrs)
    print(f"  容器地址: {addr_str}")
    _ACTIVE_CONTAINERS[unique_code] = True  # 登记，供中断兜底清理

    # T1-③ 预侦察（确定性脚本，失败不影响解题流程）
    prerecon_report = ""
    try:
        print(f"  🔍 预侦察中...")
        prerecon_report = _quick_prerecon(addr_str)
    except Exception as e:
        logger.warning(f"预侦察异常（忽略）: {e}")

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

## 预侦察报告（脚本自动探测，仅作起点，结论需自行验证）
{prerecon_report if prerecon_report else '（预侦察无有效信息，可能非 HTTP 服务，自行探测）'}

## 同类题经验（沉淀自之前运行，方法论级）
{lessons_hint if lessons_hint else '（无此前同类题经验）'}
"""
    # T1-② 重试轮注入死路地图：让二刷带着首轮的失败地图跑（必须换思路）
    if retry_hint:
        task += f"""
## 上次尝试死路地图（重试轮，务必换攻击面，不要重复上次的做法）
{retry_hint}
"""
    task += f"""
注意:
- 靶场地址通过 VPN 直连访问
- 这道题有 {flag_count} 个 flag，需要分别获取和提交
- 找到 flag 后必须调用 submit_flag 提交，flag 格式一般为 flag{{...}}
## 标准解题流程
1. **fingerprint**（第一步）: 先识别目标组件/框架（curl -I / http_request / web_fingerprint）
2. **first-try**（第二步）: 按组件调对应工具链（Web→登录/LFI/SQL注入；Pwn→逆向/exploit；Crypto→编码/算法）
3. **source**（第三步）: 用 LFI/文件读取等手段获取源码，分析业务逻辑找入口
4. **exploit**（第四步）: 针对发现的漏洞构造利用，找到可疑点后至少复现 2 次确认
5. **submit**（第五步）: 提交前验证 flag 格式（flag{{...}}），调用 submit_flag 提交
6. **注意**: 如果卡住可以尝试不同方向，不要在一种方法上死磕"""

    # 3. Agent 解题（按题型分派子 Agent：专用 prompt + 工具子集 + 经验注入）
    print(f"\n[2/5] Agent 解题...")
    # T2-⑧ 动态预算：easy 紧止损（快速放弃换题），hard 松止损（多给机会）
    _d = (diff or "").lower()
    if "easy" in _d:
        budget = {"no_progress_hint": 30, "no_progress_giveup": 8}
    elif "medium" in _d or "med" in _d:
        budget = {"no_progress_hint": 45, "no_progress_giveup": 12}
    else:
        budget = {"no_progress_hint": 55, "no_progress_giveup": 18}
    # T1-② 重试轮温度提升：强制方向多样性，避免和首轮一模一样的二刷
    temp = min(1.0, config.LLM_TEMPERATURE + 0.25) if retry_round else None
    agent = build_agent(cat, challenge_id=unique_code, temperature=temp, budget=budget)
    # 单题超时兜底：两题并行（线程池）下 signal 仅主线程可用——去掉 signal.alarm，
    # 卡题由 agent 层兜底（MAX_ITERATIONS=50 + 无迹象 50 轮提示 + 提示后 15 轮止损）
    try:
        # 轮次上限统一用 MAX_ITERATIONS（500）：不按难度截断（easy 快题靠迹象提前停，难题跑满）
        _iter_limit = config.MAX_ITERATIONS
        result = agent.run(task, max_iterations=_iter_limit)
    except LLMQuotaExhausted as e:
        # 配额/5小时计费窗口耗尽：重试无意义，整轮应终止。关闭容器、导出日志后上抛，
        # 由 run_tsecbench 捕获并优雅收尾（而不是把每道题都跑成"失败"继续烧容器）。
        logger.error(f"❌ LLM 配额已耗尽，终止本轮: {e}")
        _safe_close(unique_code)
        _update_progress(progress, lambda p: p["failed"].append(unique_code))
        _export_challenge_log(unique_code, diff, flag_count, {
            "success": False, "flag_found": False, "iterations": agent.iteration,
            "final_message": f"[LLM 配额耗尽: {e}]", "run_log": agent._run_log,
        }, agent, task, "quota_exhausted", [], [], container_addrs, _challenge_start)
        raise
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
                # 保留更多成功路径（5→20）：之前 [-5:] 截断导致 42 通关只沉淀 2 条（新顶旧丢弃）
                entry["solved_paths"] = entry["solved_paths"][-20:]
                _save_lessons(lessons)
            # C3 方向级沉淀：agent 最终消息摘要存 notes（方法论级，去 flag 值，防重复）
            if final_msg and len(final_msg.strip()) > 10:
                _dir_note = re.sub(r'(?:flag|FLAG|ctf|CTF)\{[^}]{0,200}\}', '[FLAG]', final_msg.strip())[:150]
                _dir_tag = f"【解题方向】{_dir_note}"
                if _dir_tag not in entry.get("notes", ""):
                    entry["notes"] = (entry.get("notes", "") + "\n" + _dir_tag).strip()[:5000]
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

    flag_patterns = [r"flag\{[^}]+\}", r"FLAG\{[^}]+\}", r"ctf\{[^}]+\}", r"CTF\{[^}]+\}"]
    found_flags = set()
    for pattern in flag_patterns:
        try:
            found_flags.update(re.findall(pattern, all_text))
        except re.error:
            pass
    # 丢弃 flag{...}/flag{xxx} 占位符（之前把文档示例 "flag{...}" 提交给平台吃了 ❌）
    found_flags = set(filter_flags(found_flags))

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

    # 更新进度（锁内写入，避免并发线程写坏）
    if submitted_flags:
        _update_progress(progress, lambda p: p["submitted_flags"].__setitem__(unique_code, list(submitted_flags)))

    # T1-② 记录本轮尝试情况（重试轮的死路地图素材）
    _record_attempt(unique_code, agent, submit_results, final_msg, result.get("iterations", 0))

    # 检查是否通关（API 查询在锁外做，避免持锁期间阻塞）
    challenges = tsec_api.list_challenges()
    is_completed = False
    correct_count = 0
    for ch in challenges:
        if ch.get("unique_code") == unique_code:
            is_completed = ch.get("is_completed", False)
            correct_count = ch.get("correct_flag_count", 0)
            break

    # 按通关状态一次性写回进度（缩短持锁时间）
    if is_completed:
        status = "solved"
        _update_progress(progress, lambda p: (p["solved"].append(unique_code),
                                              p["in_progress"].remove(unique_code) if unique_code in p["in_progress"] else None))
        print(f"\n🎉 {unique_code} 通关！(已提交 {correct_count} 个 flag)")
    elif agent_success or submitted_flags:
        status = "partial"
        _update_progress(progress, lambda p: p["in_progress"].append(unique_code) if unique_code not in p["in_progress"] else None)
    else:
        status = "failed"
        _update_progress(progress, lambda p: p["failed"].append(unique_code))

    # P2-⑤ 进度回收（MoMo-agent 借鉴）：agent 失败/超时时把 partial 发现存进经验库（不白跑）
    if final_msg and len(final_msg.strip()) > 10 and status in ("failed", "partial"):
        try:
            _partial = re.sub(r'(?:flag|FLAG|ctf|CTF)\{[^}]{0,200}\}', '[FLAG]', final_msg.strip())[:150]
            _partial_tag = f"【partial 发现 {unique_code}】{_partial}"
            lessons = _load_lessons()
            entry = lessons.setdefault(cat, {"solved_paths": [], "failed": 0, "notes": ""})
            if _partial_tag not in entry.get("notes", ""):
                entry["notes"] = (entry.get("notes", "") + "\n" + _partial_tag).strip()[:5000]
                _save_lessons(lessons)
        except Exception:
            pass

    # 5. 关闭容器（释放资源）
    print(f"\n[4/5] 关闭容器...")
    close_result = tsec_api.close_challenge(unique_code)
    if isinstance(close_result, dict) and close_result.get("closed"):
        print(f"  容器已关闭")
    else:
        print(f"  ⚠️ 关闭失败: {close_result}")

    # 记录历史（锁内写入，与并发线程的进度写互斥）
    _update_progress(progress, lambda p: p["history"].append({
        "unique_code": unique_code,
        "status": status,
        "difficulty": diff,
        "flags_found": len(found_flags),
        "flags_submitted": len(submitted_flags),
        "agent_iterations": result.get("iterations", 0),
        "timestamp": time.strftime("%H:%M:%S"),
    }))

    # ── 导出单题运行日志 ──
    _export_challenge_log(unique_code, diff, flag_count, result, agent, task, status,
                          found_flags, submit_results, container_addrs, _challenge_start)

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
    # 不加载历史进度（用户要求：每次运行从空开始）
    progress = {"solved": [], "failed": [], "in_progress": [], "submitted_flags": {}, "history": []}
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
    quota_exhausted = False  # LLM 配额耗尽 → 不再开新题/重试，等在途题收尾后直接汇总

    def _collect(f, ch):
        """收取一个完成 future 的结果；LLM 配额耗尽返回 True（终止整轮信号）"""
        try:
            result = f.result()
            stats[result["status"]] = stats.get(result["status"], 0) + 1
        except LLMQuotaExhausted:
            print(f"\n❌ LLM 配额已耗尽，终止本轮（{ch.get('unique_code')} 收尾完成）")
            stats["failed"] = stats.get("failed", 0) + 1
            return True
        except KeyboardInterrupt:
            raise
        except Exception as e:
            logger.error(f"❌ 题目 {ch.get('unique_code')} 出错: {e}", exc_info=True)
            stats["failed"] = stats.get("failed", 0) + 1
        return False

    def _fill_slots(ex, inflight, idx):
        """预启动 + 填槽提交，保持 MAX_INFLIGHT 题在途（一题完成补下一题）"""
        while idx < len(challenges) and len(inflight) < MAX_INFLIGHT:
            left = time_left()
            if left < safety_margin:
                print(f"\n⚠️ 剩余时间不足 ({left/60:.1f}min < {safety_margin/60:.0f}min 兜底)，停止开新题")
                return idx
            ch = challenges[idx]
            print(f"\n{'#'*60}")
            print(f"  题目 {idx+1}/{len(challenges)}  (剩 {left/60:.1f}min)")
            print(f"{'#'*60}")
            f = ex.submit(solve_challenge, ch, progress)
            inflight[f] = ch
            idx += 1
        return idx

    try:
        with ThreadPoolExecutor(max_workers=MAX_INFLIGHT) as ex:
            idx = _fill_slots(ex, inflight, idx)
            while inflight and not quota_exhausted:
                done, _ = wait(list(inflight.keys()), return_when=FIRST_COMPLETED)
                for f in done:
                    ch = inflight.pop(f)
                    if _collect(f, ch):
                        quota_exhausted = True
                if not quota_exhausted:
                    idx = _fill_slots(ex, inflight, idx)
                # 配额耗尽时不再补槽：剩余在途题的 agent 会在下次 LLM 调用时同样抛出
                # LLMQuotaExhausted 并自行关闭容器/导出日志，循环继续排空即可

            # P2-④ 两轮制重试（MoMo-agent 借鉴）：跑完一轮后，第二轮优先重试 failed 题
            # 注意：必须在同一个 with 块内提交，否则 executor 已 shutdown，submit 直接报错
            if not quota_exhausted:
                retry_list = [code for code in progress.get("failed", [])
                              if not progress.get("submitted_flags", {}).get(code)]
                if retry_list:
                    print(f"\n🔄 第二轮重试: {len(retry_list)} 道未解出题 ({', '.join(retry_list[:5])}...)")
                    stats["retry_round"] = True
                    retry_inflight = {}
                    retry_idx = 0
                    retry_failed = list(retry_list)

                    def _retry_fill():
                        nonlocal retry_idx
                        while retry_idx < len(retry_failed) and len(retry_inflight) < MAX_INFLIGHT:
                            left = time_left()
                            if left < safety_margin:
                                print(f"\n⚠️ 剩余时间不足 ({left/60:.1f}min)，重试轮停止开新题")
                                break
                            code = retry_failed[retry_idx]
                            challenge = next((c for c in challenges if c.get("unique_code") == code), None)
                            retry_idx += 1
                            if not challenge:
                                continue
                            print(f"\n  🔄 重试 {code} ({retry_idx}/{len(retry_failed)})")
                            f = ex.submit(solve_challenge, challenge, progress,
                                          retry_hint=_build_deadend_hint(code), retry_round=True)
                            retry_inflight[f] = challenge
                        return retry_idx

                    retry_idx = _retry_fill()
                    while retry_inflight and not quota_exhausted:
                        done, _ = wait(list(retry_inflight.keys()), return_when=FIRST_COMPLETED)
                        for f in done:
                            ch = retry_inflight.pop(f)
                            if _collect(f, ch):
                                quota_exhausted = True
                        if not quota_exhausted:
                            retry_idx = _retry_fill()
                else:
                    print("\n✅ 所有题目已解决，无需重试。")
    except KeyboardInterrupt:
        # with 块退出时 shutdown(wait=True) 会等在途题自行收尾（关容器/导出日志），随后继续汇总
        print("\n\n⚠️ 用户中断，等待在途题收尾...")
    finally:
        # 兜底：无论正常结束还是中断（含第二次 Ctrl+C 打断等待），都清掉登记中未关的容器
        _close_all_active()

    # 5. 汇总
    elapsed = time.time() - start_time

    # 导出运行总览（每题耗时/token/轮次/结论）
    summary_path = export_run_summary(progress, start_time)

    print(f"\n{'='*60}")
    print(f"📊 TSecBench 解题汇总")
    print(f"{'='*60}")
    print(f"  总题数:   {len(challenges)}")
    print(f"  ✅ 通关:  {stats.get('solved', 0)}")
    print(f"  ⚠️ 部分:  {stats.get('partial', 0)}")
    print(f"  ❌ 失败:  {stats.get('failed', 0)}")
    print(f"  ⏭️ 跳过:  {stats.get('skipped', 0)}")
    print(f"  ⏱️ 耗时:  {elapsed/60:.1f}min")
    if summary_path:
        print(f"  📊 运行总览: {summary_path}")
    print(f"  📁 单题日志: {TB_LOG_DIR}/")
    print(f"{'='*60}\n")


def show_status():
    """显示当前解题进度

    进度仅在运行进程内存中维护（不落盘），进程退出即清零。
    历史结果请查看 output/logs_<run>/RUN_SUMMARY.json。
    """
    print("\n📊 TSecBench 解题进度: 进度不落盘，仅运行进程内有效（进程退出即清零）。")
    print("   历史运行结果请查看 output/logs_<run>/RUN_SUMMARY.json 与 manifest.json。")
