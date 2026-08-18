"""批量解题模块 - 从 JSON/比赛API 拉题，逐题自动解题，进度持久化

用法:
  python main.py batch-local tasks.json       从本地 JSON 批量解题
  python main.py batch-api                     从比赛平台 API 拉题批量解题
"""
import os
import json
import time
import logging
from agent import Agent
from utils import api, load_progress, save_progress
from config import config

logger = logging.getLogger(__name__)


def _record_attempt(progress, task_id, task_desc, status, flag=None, rounds=0):
    """记录单题解题结果到进度文件"""
    entry = {
        "task_id": task_id,
        "desc": task_desc[:200],
        "status": status,       # solved / failed / error
        "flag": flag,
        "rounds": rounds,
        "time": time.strftime("%H:%M:%S"),
    }
    progress["history"].append(entry)
    if status == "solved":
        progress["solved"].append(task_id)
    elif status == "failed":
        progress["failed"].append(task_id)
    save_progress(progress)


def solve_task_with_progress(task_id: str, task_desc: str, progress: dict):
    """解单题，结果写入进度文件"""
    print(f"\n{'#'*60}")
    print(f"  题目 {task_id}")
    print(f"{'#'*60}")

    if task_id in progress["solved"]:
        print(f"  ⏭️ 已解过，跳过")
        return "skipped"

    agent = Agent()
    try:
        result = agent.run(task_desc)
        if result["success"]:
            _record_attempt(progress, task_id, task_desc, "solved",
                            flag=result.get("final_message", ""), rounds=result["iterations"])
            return "solved"
        elif result["flag_found"]:
            _record_attempt(progress, task_id, task_desc, "solved",
                            flag="found_but_unsubmitted", rounds=result["iterations"])
            return "solved"
        else:
            _record_attempt(progress, task_id, task_desc, "failed",
                            rounds=result["iterations"])
            return "failed"
    except Exception as e:
        logger.error(f"题目 {task_id} 解题出错: {e}")
        _record_attempt(progress, task_id, task_desc, "error", rounds=0)
        return "error"


def batch_from_file(filepath: str):
    """从本地 JSON 文件批量解题
    JSON 格式:
        ["题目1描述", "题目2描述"]
    或:
        [{"id":"1","desc":"题目描述"}, ...]
    """
    with open(filepath) as f:
        tasks = json.load(f)

    progress = load_progress()
    stats = {"solved": 0, "failed": 0, "error": 0, "skipped": 0}

    for i, task in enumerate(tasks):
        if isinstance(task, dict):
            task_id = task.get("id", f"task_{i}")
            task_desc = task.get("desc") or task.get("description") or ""
            if task.get("attachment_url"):
                api.download_attachment(task["attachment_url"], task.get("attachment_name", ""))
                task_desc += f"\n附件已下载到 attachments/ 目录。"
        else:
            task_id = f"task_{i}"
            task_desc = str(task)

        if not task_desc:
            continue

        status = solve_task_with_progress(task_id, task_desc, progress)
        stats[status] = stats.get(status, 0) + 1

    _print_summary(stats, len(tasks))
    return stats


def batch_from_api():
    """从比赛平台 API 拉取题目列表，逐题解题"""
    if not api.is_configured():
        print("❌ 比赛 API 未配置。请在 .env 中设置 COMPETITION_API_BASE_URL 和 COMPETITION_TOKEN")
        return

    challenges = api.list_challenges()
    if not challenges:
        print("⚠️ 未获取到任何题目")
        return

    print(f"📋 从比赛平台拉取到 {len(challenges)} 道题")

    progress = load_progress()
    stats = {"solved": 0, "failed": 0, "error": 0, "skipped": 0}

    for ch in challenges:
        cid = str(ch.get("id") or ch.get("challenge_id") or "")
        desc = ch.get("description") or ch.get("desc") or ""
        title = ch.get("title") or ch.get("name") or ""
        category = ch.get("category") or ch.get("tags") or ""

        full_desc = f"题目类型: {category}\n标题: {title}\n描述: {desc}"
        if ch.get("attachment_url"):
            api.download_attachment(ch["attachment_url"], ch.get("attachment_name", ""))
            full_desc += f"\n附件已下载到 attachments/ 目录。"

        status = solve_task_with_progress(cid or "unknown", full_desc, progress)
        stats[status] = stats.get(status, 0) + 1

    _print_summary(stats, len(challenges))
    return stats


def _print_summary(stats, total):
    """打印批量解题汇总"""
    print(f"\n{'='*60}")
    print(f"  批量解题汇总")
    print(f"{'='*60}")
    print(f"  总题数:   {total}")
    print(f"  ✅ 已解:  {stats.get('solved', 0)}")
    print(f"  ⏭️ 跳过:  {stats.get('skipped', 0)}")
    print(f"  ❌ 未解:  {stats.get('failed', 0)}")
    print(f"  💥 出错:  {stats.get('error', 0)}")
    print(f"  进度文件: {os.path.join(config.OUTPUT_DIR, 'progress.json')}")
    print(f"{'='*60}\n")
