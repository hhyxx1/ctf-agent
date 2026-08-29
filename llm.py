"""LLM 封装 - OpenAI 兼容接口（支持本地直连 + 平台网关两种模式）"""
import json
import random
import time
import logging
from types import SimpleNamespace
from openai import OpenAI
from config import config

logger = logging.getLogger(__name__)

# 网关 URL 特征（llm-gateway 平台透明代理）
GATEWAY_MARKERS = ("/llm-gateway/proxy/e/", "llm-gateway.dasctf.com")

# ── 错误分类关键词 ──────────────────────────────────────────────────────────
# 配额/计费窗口耗尽：不可通过重试恢复，继续重试只是烧时间
_QUOTA_EXHAUSTED_KEYWORDS = (
    "insufficient_quota", "exceeded your current quota", "quota exceeded",
    "usage limit", "usage_limit", "rate limit exceeded for a limit interval",
    "resource exhausted", "balance is insufficient", "insufficient balance",
    "window", "窗口", "额度已用完", "额度不足", "余额不足", "配额已用尽", "配额已用完",
)
# 瞬时故障：值得重试（服务端抖动/过载/临时断连）
_TRANSIENT_KEYWORDS = (
    "429", "rate limit", "too many requests", "500", "502", "503", "504",
    "server overloaded", "overloaded_error", "temporarily", "temporarily unavailable",
    "timed out", "timeout", "connect", "connection", "reset by peer",
    "econnreset", "econnrefused", "eof occurred", "internal error", "try again",
)


class LLMQuotaExhausted(Exception):
    """LLM 配额/计费窗口已耗尽——重试无意义，应终止整轮运行并优雅收尾。"""
    pass


def _classify_error(err) -> str:
    """把异常/错误文本分类为 quota(不可重试) / transient(可重试) / unknown(保守重试)

    注意顺序：先判明确的 429（很多平台 429 报错文本里含 "window" 字样，
    如 "rate limit window exceeded"——若先匹配 quota 关键词会误判成配额耗尽，
    把临时限流当成整轮终止，直接卡死解题率）。
    """
    text = f"{err}".lower()
    # 明确 429 / too many requests → 一定是临时限流，优先于一切 quota 关键词
    status = getattr(err, "status_code", None) or getattr(err, "code", None)
    if str(status) == "429" or "429" in text or "too many requests" in text:
        return "transient"
    for kw in _QUOTA_EXHAUSTED_KEYWORDS:
        if kw.lower() in text:
            return "quota"
    for kw in _TRANSIENT_KEYWORDS:
        if kw.lower() in text:
            return "transient"
    return "unknown"


def _retry_after_seconds(err) -> float:
    """尝试从异常/响应头解析服务端建议的等待时间（429 的 Retry-After），无则返回 0"""
    for attr in ("headers", "response_headers"):
        h = getattr(err, attr, None)
        if h:
            ra = h.get("retry-after") or h.get("Retry-After") if hasattr(h, "get") else None
            if ra:
                try:
                    return max(0.0, float(ra))
                except (TypeError, ValueError):
                    pass
    ra = getattr(err, "retry_after", None)
    if ra:
        try:
            return max(0.0, float(ra))
        except (TypeError, ValueError):
            pass
    return 0.0


def _is_gateway_url(url: str) -> bool:
    """判断 LLM_BASE_URL 是否为平台网关 URL

    网关模式下，base_url 是网关代理地址（如 .../llm-gateway/proxy/e/<code>），
    且平台渠道的原始 URL 已含完整端点（如 https://api.deepseek.com/chat/completions），
    因此 Agent 必须请求 base_url 本身（不再拼 /chat/completions），网关才会原样转发到完整端点。
    """
    if not url:
        return False
    return any(m in url for m in GATEWAY_MARKERS)


class LLM:
    def __init__(self):
        if not config.LLM_API_KEY:
            raise ValueError("LLM_API_KEY 未设置，请检查 .env 文件")
        self.client = OpenAI(
            api_key=config.LLM_API_KEY,
            base_url=self._openai_base(config.LLM_BASE_URL),
            timeout=config.LLM_TIMEOUT,
            max_retries=0,  # 重试统一由本层控制（SDK 内部重试太短，429 时白白消耗 RPM 配额）
        )
        self.max_retries = max(1, config.LLM_MAX_RETRIES)
        self.backoff_base = config.LLM_BACKOFF_BASE_SEC
        self.gateway_mode = _is_gateway_url(config.LLM_BASE_URL)

    @staticmethod
    def _openai_base(url: str) -> str:
        """确保 OpenAI 标准 base_url（SDK 会自动在 base 后拼 /chat/completions）。

        用户常把完整端点填进来（如 https://token.sensenova.cn/v1/chat/completions），
        若原样给 SDK 会再拼一次 /chat/completions → 双重路径 404。
        所以这里统一归一化：剥掉 /chat/completions 后缀；无 /v1 后缀则补 /v1。
        网关类 URL（slab llm-gateway / tsecbench .tsecbench.gw）不做处理。
        """
        if _is_gateway_url(url) or ".tsecbench.gw" in url:
            return url
        url = url.rstrip("/")
        if url.endswith("/chat/completions"):
            url = url[: -len("/chat/completions")].rstrip("/")
        if not url.endswith("/v1"):
            url = url + "/v1"
        return url

    def _chat_via_requests(self, payload: dict):
        """网关模式：直接请求 base_url 本身（原始 URL 已含完整端点，不拼 /chat/completions）"""
        import requests
        headers = {
            "Authorization": f"Bearer {config.LLM_API_KEY}",
            "Content-Type": "application/json",
        }
        resp = requests.post(config.LLM_BASE_URL, json=payload, headers=headers, timeout=config.LLM_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        # 构造兼容 OpenAI SDK 响应对象
        choice = data["choices"][0]
        msg = choice["message"]
        tool_calls = None
        if msg.get("tool_calls"):
            tool_calls = [
                SimpleNamespace(
                    id=tc["id"],
                    type=tc.get("type", "function"),
                    function=SimpleNamespace(
                        name=tc["function"]["name"],
                        arguments=tc["function"].get("arguments", "{}"),
                    ),
                )
                for tc in msg["tool_calls"]
            ]
        message = SimpleNamespace(content=msg.get("content") or "", tool_calls=tool_calls)
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])

    def chat(self, messages, tools=None, tool_choice="auto", temperature=None, stop_event=None):
        """调用大模型，支持 function calling（temperature 传入则覆盖全局配置，重试轮多样性用）
        stop_event: 全局停止信号（Ctrl+C），重试等待期间可被打断，不再死等退避计时"""
        kwargs = {
            "model": config.LLM_MODEL,
            "messages": messages,
            "max_tokens": config.LLM_MAX_TOKENS,
            "temperature": config.LLM_TEMPERATURE if temperature is None else temperature,
            "stream": False,
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = tool_choice

        last_err = None
        for attempt in range(self.max_retries):
            # 停止信号（Ctrl+C）：调用前和退避等待中都检查，收到后立即放弃本调用
            if stop_event is not None and stop_event.is_set():
                raise RuntimeError("LLM 调用被停止信号中断（用户 Ctrl+C）")
            try:
                if self.gateway_mode:
                    resp = self._chat_via_requests(kwargs)
                else:
                    resp = self.client.chat.completions.create(**kwargs)
                # 防御：非标准响应（str/无 choices）→ 抛清晰错误（提示检查 LLM 端点配置）
                if not hasattr(resp, "choices"):
                    raise ValueError(
                        f"LLM 端点返回非标准响应（类型 {type(resp).__name__}，无 choices 字段）——"
                        f"检查 LLM_BASE_URL({config.LLM_BASE_URL}) 是否为 OpenAI 兼容 /chat/completions 端点"
                    )
                return resp
            except Exception as e:
                last_err = e
                # 配额/计费窗口耗尽：重试无意义，立即抛出终止信号（上层收尾并导出日志）
                if _classify_error(e) == "quota":
                    logger.error(f"❌ LLM 配额/计费窗口已耗尽，停止重试: {e}")
                    raise LLMQuotaExhausted(str(e)) from e

                if attempt == self.max_retries - 1:
                    break

                # 等待时间：优先服务端 Retry-After，否则指数退避 + 随机抖动（打散并发重试峰值）
                wait = _retry_after_seconds(e)
                if wait <= 0:
                    wait = self.backoff_base * (2 ** attempt) + random.uniform(0, self.backoff_base)
                # 429/rpm 限流：服务端没给 Retry-After 时，短退避无意义（RPM 窗口是 60s），
                # 保底等 30s，否则像 sensenova 'rpm exhausted' 这种会在 ~10s 内烧光 3 次重试直接放弃
                _err_str = str(e).lower()
                if wait < 30 and ("rpm" in _err_str or "429" in _err_str or "rate limit" in _err_str):
                    wait = max(wait, 30.0)
                wait = min(wait, 300)  # 单次最长等 5min，避免卡死整轮
                logger.warning(f"LLM 调用失败 ({_classify_error(e)}, attempt {attempt+1}/{self.max_retries}): {e}, {wait:.1f}s 后重试")
                # 退避等待切片化：每 0.5s 检查一次停止信号，Ctrl+C 到来立即中止，不再死等
                deadline = time.time() + wait
                while time.time() < deadline:
                    if stop_event is not None and stop_event.is_set():
                        raise RuntimeError("LLM 调用被停止信号中断（用户 Ctrl+C）")
                    time.sleep(min(0.5, max(0.05, deadline - time.time())))
        raise RuntimeError(f"LLM 调用失败，已重试 {self.max_retries} 次: {last_err}")


llm = LLM()
