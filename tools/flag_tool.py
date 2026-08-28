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
    # 兜底：任意 前缀{内容} 且内容 6-120 字符。排除分号/引号/花括号/空格——
    # 否则 CSS 片段（body{color:#000;...}、h1{border-right:1px solid ...}）
    # 和 JS 代码（try{let a=...}）会被当 flag 提交；真 flag 极少含空格
    r"[A-Za-z0-9_]{2,}\{[^{};\"'` ]{6,120}\}",
]

# 占位符/文档示例 flag（flag{...}、flag{xxx}、FLAG{____} 等），提取后应丢弃
_PLACEHOLDER_RE = re.compile(r"[.\s_xX*<>?]{1,}")


def filter_flags(candidates):
    """过滤占位符 flag（内容只有 .../xxx/___ 之类的），返回去重后的真实候选列表。"""
    out = []
    for f in dict.fromkeys(candidates):
        m = re.match(r"^[^{}]+\{(.+)\}$", f or "")
        if not m or _PLACEHOLDER_RE.fullmatch(m.group(1)):
            continue
        out.append(f)
    return out


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
    result = f"[找到 {len(unique)} 个 flag]（来源文本: {text[:80]}{'...' if len(text)>80 else ''}）\n"
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

    # P1-① 证据驱动防误报：submit_flag 前校验 flag 格式
    # 接受常见 CTF flag 前缀（flag/ctf/HTB 等迁移题）+ {} 包裹 + 内容长度合理，
    # 防 LLM 幻觉编造垃圾 flag（无 {} 包裹/乱码/超长的拒绝）
    _f = flag.strip()
    if not re.match(r'^[A-Za-z0-9_]{2,12}\{[^\}]{4,}\}$', _f):
        return f"[拒绝提交] flag 格式异常: {_f[:60]}...（疑似 LLM 幻觉编造，请通过漏洞利用复现确认真实 flag）"
    _inner = _f[_f.index('{') + 1:-1]
    if any(ord(c) < 32 or ord(c) > 126 for c in _inner):
        return f"[拒绝提交] flag 内含非 ASCII 字符，疑似乱码：{_f[:60]}..."

    # 分派：tsecbench 平台（BENCHMARK_TOKEN 已配置）→ tsec_api 正式提交
    # （POST /openapi/v1/challenges/submit + unique_code——否则 agent 内提交 404，
    #   导致"找到 flag 还继续解题"浪费轮次）；
    # 否则 → 统一的比赛 API（slab / 本地模式）
    try:
        from utils.tsecbench_api import tsec_api
        if tsec_api.is_configured():
            result = tsec_api.submit_flag(challenge_id, flag)
        else:
            from utils.competition_api import api
            result = api.submit_flag(flag, challenge_id)
    except Exception as e:
        logger.error(f"submit_flag 异常: {e}")
        return f"[提交失败] {e}"

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
