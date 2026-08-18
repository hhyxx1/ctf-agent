"""配置加载

支持两种运行模式:
1. 本地模式: 通过 .env 文件加载配置（开发调试用）
2. 托管模式 (可选): 评测平台注入环境变量，大模型走 .tsecbench.gw 网关（示例）

大模型网关规则 (托管模式, 可选):
- 原域名加 .tsecbench.gw 后缀
- https 改成 http
- 示例: https://api.deepseek.com → http://api.deepseek.com.tsecbench.gw

环境变量 (平台类评测环境可选注入):
- BENCHMARK_TOKEN: 答题 API 鉴权 token
- BENCHMARK_BASE_URL: 答题 API 基地址
- DEEPSEEK_API_KEY: 大模型 API key
"""
import os
import json
from dotenv import load_dotenv

# 本地模式加载 .env（托管环境无此文件，load_dotenv 会静默跳过）
load_dotenv()


def _parse_json_list(raw: str) -> list:
    """把环境变量里的 JSON 列表字符串解析成 list（如 FORBIDDEN_PATHS=["/a","/b"]）

    空/非法输入返回空列表。
    """
    if not raw or not raw.strip():
        return []
    try:
        val = json.loads(raw)
        if isinstance(val, list):
            return [str(x) for x in val if x]
    except (ValueError, TypeError):
        # 兜底：按逗号拆分（兼容非 JSON 写法）
        return [x.strip() for x in raw.split(",") if x.strip()]
    return []


def _apply_gateway(url: str) -> str:
    """根据环境变量决定是否套用 TSecBench 大模型网关

    规则:
    - TSECBENCH_GATEWAY=open 或 ENV GATEWAY_MODE=open 时启用
    - https → http
    - 域名加 .tsecbench.gw 后缀
    """
    if not url:
        return url

    # 显式控制: GATEWAY_MODE=off 时不动
    if os.getenv("GATEWAY_MODE", "").lower() in ("off", "disable", "local"):
        return url

    # 托管模式或显式启用网关
    gateway_on = (
        os.getenv("TSECBENCH_GATEWAY", "").lower() in ("on", "open", "true", "1")
        or os.getenv("GATEWAY_MODE", "").lower() in ("on", "open", "true", "1")
        # 托管环境标志: 平台会注入 BENCHMARK_TOKEN，存在即认定托管模式
        or bool(os.getenv("BENCHMARK_TOKEN"))
    )

    if not gateway_on:
        return url

    # https → http
    if url.startswith("https://"):
        url = "http://" + url[len("https://"):]
    elif url.startswith("http://"):
        pass  #已经是 http
    else:
        url = "http://" + url

    # 加 .tsecbench.gw 后缀（在域名之后、路径之前）
    # 处理形如 http://api.deepseek.com  或  http://api.deepseek.com/v1
    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = parsed.hostname
    if host and ".tsecbench.gw" not in host:
        new_host = host + ".tsecbench.gw"
        url = url.replace(host, new_host, 1)

    return url


class Config:
    # ── 大模型（通用：LLM_* 为主，旧 DEEPSEEK_* 兼容别名）──
    LLM_API_KEY: str = os.getenv("LLM_API_KEY") or os.getenv("DEEPSEEK_API_KEY", "")
    LLM_BASE_URL: str = _apply_gateway(
        os.getenv("LLM_BASE_URL") or os.getenv("DEEPSEEK_BASE_URL", "https://api.openai.com/v1")
    )
    LLM_MODEL: str = os.getenv("LLM_MODEL") or os.getenv("DEEPSEEK_MODEL", "gpt-4o-mini")

    # ── 向后兼容（旧 DEEPSEEK_* 引用仍可用）──
    DEEPSEEK_API_KEY: str = LLM_API_KEY
    DEEPSEEK_BASE_URL: str = LLM_BASE_URL
    DEEPSEEK_MODEL: str = LLM_MODEL

    # ── 答题 API（平台注入）──
    # 平台注入变量名是 BENCHMARK_BASE_URL / BENCHMARK_TOKEN，做两套别名兼容
    COMPETITION_BASE_URL: str = (
        os.getenv("BENCHMARK_BASE_URL")
        or os.getenv("COMPETITION_BASE_URL", "")
    )
    COMPETITION_API_BASE_URL: str = (
        os.getenv("BENCHMARK_API_BASE_URL")
        or os.getenv("COMPETITION_API_BASE_URL", "")
        or os.getenv("BENCHMARK_BASE_URL", "")  # tsecbench 答题 API 和 base 同址
    )
    COMPETITION_TOKEN: str = (
        os.getenv("BENCHMARK_TOKEN")
        or os.getenv("COMPETITION_TOKEN", "")
    )

    # ── AI Agent 平台（slab-match，X-Agent-AccessKey 认证）──
    SLAB_HOST: str = os.getenv("SLAB_HOST", "")            # 平台主机，如 https://xxx.com
    SLAB_ACCESS_KEY: str = os.getenv("SLAB_ACCESS_KEY", "")  # Agent 专用 AccessKey

    # ── Agent 行为 ──
    MAX_ITERATIONS: int = int(os.getenv("MAX_ITERATIONS", "500"))
    LLM_TIMEOUT: int = int(os.getenv("LLM_TIMEOUT", "90"))
    LLM_MAX_TOKENS: int = int(os.getenv("LLM_MAX_TOKENS", "4096"))
    LLM_TEMPERATURE: float = float(os.getenv("LLM_TEMPERATURE", "0.2"))
    TOOL_TIMEOUT: int = int(os.getenv("TOOL_TIMEOUT", "120"))

    # ── 运行控制 ──
    # 自启: 镜像启动后是否立即开始解题（托管模式必须为 true）
    AUTO_START: bool = os.getenv("AUTO_START", "true").lower() in ("true", "1", "yes", "on")
    # 单题最大重试次数
    MAX_ATTEMPTS_PER_CHALLENGE: int = int(os.getenv("MAX_ATTEMPTS", "3"))
    # 总时限（秒），接近时停止开新题，只 finishing
    TOTAL_TIMEOUT_SEC: int = int(os.getenv("TOTAL_TIMEOUT_SEC", "21000"))  # 默认 350min，留 10min 兜底
    # 并发容器上限（tsecbench 平台硬约束 3）
    MAX_CONCURRENT: int = int(os.getenv("MAX_CONCURRENT", "3"))

    # ── 反作弊（通用框架：用户按自己环境配置）──
    # 禁止 Agent 访问的路径（跑分集源码/答案），JSON 列表字符串，如
    #   FORBIDDEN_PATHS=["/data/cybench","/data/xben","metadata/solution"]
    FORBIDDEN_PATHS: list = _parse_json_list(os.getenv("FORBIDDEN_PATHS", ""))
    # 合法工作目录（runner 复制题目的临时目录前缀），JSON 列表
    ALLOWED_WORKDIRS: list = _parse_json_list(os.getenv("ALLOWED_WORKDIRS", "")) or ["/tmp/"]

    # ── 目录 ──
    WORK_DIR: str = os.path.dirname(os.path.abspath(__file__))
    ATTACHMENTS_DIR: str = os.path.join(WORK_DIR, "attachments")
    OUTPUT_DIR: str = os.path.join(WORK_DIR, "output")
    KNOWLEDGE_DIR: str = os.path.join(WORK_DIR, "knowledge")


config = Config()

for d in [config.ATTACHMENTS_DIR, config.OUTPUT_DIR, config.KNOWLEDGE_DIR]:
    os.makedirs(d, exist_ok=True)
