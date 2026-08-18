"""工具基类和注册器"""
import subprocess
import os
import re
import time
import signal
import logging
from config import config

logger = logging.getLogger(__name__)

TOOL_REGISTRY = {}

# ── 反作弊配置（通用框架：从 config 读取，用户按自己环境配置）──
# 禁止 Agent 访问的路径（跑分集源码/答案，读了就等于开卷作弊）
# 默认仅含通用答案目录；具体跑分集路径由 config.FORBIDDEN_PATHS 提供
_DEFAULT_FORBIDDEN = [
    "metadata/solution",                        # 常见 CTF 标准答案目录
    "solution/flag.txt",
]
FORBIDDEN_PATHS = list(getattr(config, "FORBIDDEN_PATHS", None) or _DEFAULT_FORBIDDEN)
# 禁止读取的结果/答案文件（output 下的 json 含正确答案与审计结论）
FORBIDDEN_FILES = [
    "xben_results.json",
    "cybench_results.json",
    "src_audit_xben.json",
    "src_audit_cybench.json",
    "tsecbench_progress.json",
]
# 合法工作目录（runner 复制题目的临时目录），允许访问
ALLOWED_WORKDIRS = list(getattr(config, "ALLOWED_WORKDIRS", None) or ["/tmp/"])
AUDIT_LOG = os.path.join(config.OUTPUT_DIR, "anti_cheat.log")


def _audit_write(line: str):
    """写审计日志"""
    try:
        os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
        with open(AUDIT_LOG, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


def _anti_cheat_check(name: str, arguments: dict) -> str | None:
    """反作弊检查：返回拦截消息则拒绝执行，返回 None 放行。

    检查所有工具参数里是否引用跑分集源码/答案路径。命中即拦截并记审计。
    """
    arg_text = " ".join(str(v) for v in arguments.values())
    arg_lower = arg_text.lower()
    hits = []

    # 1. 禁止路径
    for p in FORBIDDEN_PATHS:
        if p.lower() in arg_lower:
            hits.append(p)
    # 2. 禁止结果文件（出现在命令/路径中的文件名）
    for f in FORBIDDEN_FILES:
        if f in arg_lower:
            hits.append(f)
    # 3. 结果目录 output 下的 json（通用兜底）
    for m in re.findall(r"output/[a-z_]+\.json", arg_lower):
        hits.append(m)

    if hits:
        msg = (
            f"[反作弊拦截] 工具 '{name}' 的参数引用了受保护路径: {list(set(hits))}。"
            f"这些是跑分集源码/答案/结果文件，读取即作弊，已拒绝执行。请只针对题目本身解题。"
        )
        _audit_write(f"{time.strftime('%H:%M:%S')} [CHEAT-BLOCK] {name} args={arg_text[:300]}")
        logger.warning(msg)
        return msg
    return None


def run_cmd(cmd, timeout=120):
    """执行命令（可传字符串或列表）。超时用进程组强杀，防止 msfconsole/nc 等子进程挂死主循环。"""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            shell=isinstance(cmd, str),
            start_new_session=True,  # 独立进程组，超时可整组强杀
        )
        out = (r.stdout or "") + (r.stderr or "")
        if len(out) > 8000:
            out = out[:4000] + "\n...[截断]...\n" + out[-3500:]
        return out.strip() or "[无输出]"
    except subprocess.TimeoutExpired as e:
        # 杀掉整个进程组（含 shell 派生的 msfconsole/nc 等子进程）
        try:
            os.killpg(os.getpgid(e.pid), signal.SIGKILL)
        except Exception:
            pass
        return f"[命令超时，{timeout}s 限制]"
    except FileNotFoundError as e:
        return f"[工具未安装] {e}"
    except Exception as e:
        return f"[执行错误] {e}"


def register_tool(name, description, parameters):
    """装饰器：注册一个工具"""
    def decorator(func):
        TOOL_REGISTRY[name] = {
            "name": name,
            "description": description,
            "parameters": parameters,
            "function": func,
        }
        return func
    return decorator


# ── 结果缓存去重：防止 Agent 重复探测同一目标浪费轮次（日志实测同一命令反复执行 10+ 次）──
_EXEC_CACHE = {}
_EXEC_CACHE_MAX = 300


def check_exec_cache(key: str):
    """查询执行缓存，命中返回缓存结果（已附加重复提示），未命中返回 None"""
    if key in _EXEC_CACHE:
        return f"[缓存命中] 此操作此前已执行过，结果与之前相同：\n{_EXEC_CACHE[key]}\n建议不要重复探测，换个方向。"
    return None


def store_exec_cache(key: str, result: str):
    """存入执行缓存（超出上限时淘汰最旧）"""
    if len(_EXEC_CACHE) >= _EXEC_CACHE_MAX:
        _EXEC_CACHE.pop(next(iter(_EXEC_CACHE)))
    _EXEC_CACHE[key] = result


# 题型工具映射（子 Agent 按题型优先生成；分类错时靠通用兜底解，不会无解）
CATEGORY_TOOLS = {
    "web": ["http_request", "dir_scan", "web_fingerprint", "sqli_scan", "vuln_scan",
            "proxy_scan", "nmap_scan", "hydra_brute", "ssrf_metadata", "run_shell"],
    "pwn": ["binary_analyze", "exploit_template", "rop_gadget_search", "vuln_pattern_scan",
            "ghidra_decompile", "shellcode_encode", "msfvenom_payload", "run_python", "run_shell"],
    "crypto": ["rsa_decrypt", "auto_decode", "encode_data", "run_python", "run_shell"],
    "misc": ["steg_check", "analyze_file", "run_shell", "auto_decode", "encode_data"],
}
# 通用兜底工具：所有子 Agent 都有（run_shell 万能可解一切，分类错不无解）
COMMON_TOOLS = ["run_shell", "read_file", "write_file", "http_request", "run_python",
                "list_dir", "analyze_file", "extract_flag", "submit_flag"]


def get_tools_schema(category: str = ""):
    """返回 OpenAI function calling 格式的工具列表

    - category 为空: 全量工具（兼容原有调用/父 Agent）
    - category 有: 题型优先生成 + 通用兜底（分类错也能解——run_shell 万能兜底）
    """
    cat = (category or "").lower()
    if cat in CATEGORY_TOOLS:
        names = set(CATEGORY_TOOLS[cat]) | set(COMMON_TOOLS)
    else:
        names = None  # 全量
    return [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["parameters"],
            }
        }
        for t in TOOL_REGISTRY.values()
        if names is None or t["name"] in names
    ]


def execute_tool(name, arguments):
    """执行工具调用（含反作弊检查 + 全量审计）"""
    if name not in TOOL_REGISTRY:
        return f"错误：未知工具 '{name}'"

    # 全量审计：记录每次工具调用
    arg_text = " ".join(str(v) for v in arguments.values())
    _audit_write(f"{time.strftime('%H:%M:%S')} [CALL] {name} args={arg_text[:300]}")

    # 反作弊拦截
    block = _anti_cheat_check(name, arguments)
    if block:
        return block

    try:
        logger.info(f"调用工具 {name}，参数：{arguments}")
        result = TOOL_REGISTRY[name]["function"](**arguments)
        logger.info(f"工具 {name} 执行完成，结果长度：{len(str(result))}")
        return result
    except Exception as e:
        error_msg = f"工具 {name} 执行出错：{type(e).__name__}: {e}"
        logger.error(error_msg)
        return error_msg
