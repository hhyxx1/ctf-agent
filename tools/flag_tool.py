"""Flag 提取与提交工具"""
import re
import json
import logging
from tools.base import register_tool

logger = logging.getLogger(__name__)

FLAG_PATTERNS = [
    r"flag\{[^}]+\}",
    r"FLAG\{[^}]+\}",
    r"ctf\{[^}]+\}",
    r"CTF\{[^}]+\}",
    r"FLAG\[[^\]]+\]",
    r"HTB\{[^}]+\}",
    r"SEKAI\{[^}]+\}",
    r"hkcert\d*\{[^}]+\}",
    r"HCKERT\d*\{[^}]+\}",
    r"intigriti\{[^}]+\}",
    r"[A-Za-z0-9_]+\{[^}]{6,}\}",  # 兜底：任意 前缀{内容} 且内容>=6 字符
]


@register_tool(
    name="extract_flag",
    description="从一段文本中提取 flag。当你在命令输出、文件内容、解密结果中发现可能的 flag 时，用这个工具确认。",
    parameters={
        "type": "object",
        "properties": {
            "text": {
                "type": "string",
                "description": "可能包含 flag 的文本内容",
            },
        },
        "required": ["text"],
    },
)
def extract_flag(text: str) -> str:
    """从文本中提取 flag"""
    found = []
    for pattern in FLAG_PATTERNS:
        matches = re.findall(pattern, text)
        found.extend(matches)

    if not found:
        return "[未找到 flag] 文本中没有匹配 flag{...} 格式的内容"

    unique = list(dict.fromkeys(found))
    result = f"[找到 {len(unique)} 个 flag]\n"
    for i, flag in enumerate(unique, 1):
        result += f"  {i}. {flag}\n"
    return result.strip()


@register_tool(
    name="submit_flag",
    description="提交 flag 完成题目。在确认找到正确的 flag 后调用此工具。",
    parameters={
        "type": "object",
        "properties": {
            "flag": {
                "type": "string",
                "description": "要提交的 flag 值，例如 'flag{example_flag}'",
            },
            "challenge_id": {
                "type": "string",
                "description": "题目 ID（可选，如果已知）",
            },
        },
        "required": ["flag"],
    },
)
def submit_flag(flag: str, challenge_id: str = "") -> str:
    """提交 flag"""
    logger.info(f"提交 flag: {flag}, challenge_id: {challenge_id}")

    # 通过统一的比赛 API 接口提交
    from utils.competition_api import api
    result = api.submit_flag(flag, challenge_id)

    # 本地模式优先判断：competition_api 未配置时返回 {"status":"local"}，
    # 不能误判为提交成功（否则 Agent 会以为已提交而停止）
    if isinstance(result, dict) and (
        result.get("status") == "local" or "本地模式" in str(result)
    ):
        return f"[本地模式] flag 已记录: {flag}"
    if isinstance(result, dict) and "error" not in result:
        return f"[提交成功] {json.dumps(result, ensure_ascii=False)}"
    else:
        return f"[提交失败] {result}"
