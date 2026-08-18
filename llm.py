"""LLM 封装 - OpenAI 兼容接口（支持本地直连 + 平台网关两种模式）"""
import json
import time
import logging
from types import SimpleNamespace
from openai import OpenAI
from config import config

logger = logging.getLogger(__name__)

# 网关 URL 特征（llm-gateway 平台透明代理）
GATEWAY_MARKERS = ("/llm-gateway/proxy/e/", "llm-gateway.dasctf.com")


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
            base_url=config.LLM_BASE_URL,
            timeout=config.LLM_TIMEOUT,
        )
        self.max_retries = 3
        self.gateway_mode = _is_gateway_url(config.LLM_BASE_URL)

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

    def chat(self, messages, tools=None, tool_choice="auto"):
        """调用大模型，支持 function calling"""
        kwargs = {
            "model": config.LLM_MODEL,
            "messages": messages,
            "max_tokens": config.LLM_MAX_TOKENS,
            "temperature": config.LLM_TEMPERATURE,
            "stream": False,
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = tool_choice

        last_err = None
        for attempt in range(self.max_retries):
            try:
                if self.gateway_mode:
                    return self._chat_via_requests(kwargs)
                return self.client.chat.completions.create(**kwargs)
            except Exception as e:
                last_err = e
                wait = 2 ** attempt
                logger.warning(f"LLM 调用失败 (attempt {attempt+1}): {e}, {wait}s 后重试")
                time.sleep(wait)
        raise RuntimeError(f"LLM 调用失败，已重试 {self.max_retries} 次: {last_err}")


llm = LLM()
