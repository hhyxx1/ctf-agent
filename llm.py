"""LLM 封装 - DeepSeek 兼容 OpenAI 接口"""
import time
import logging
from openai import OpenAI
from config import config

logger = logging.getLogger(__name__)


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
                return self.client.chat.completions.create(**kwargs)
            except Exception as e:
                last_err = e
                wait = 2 ** attempt
                logger.warning(f"LLM 调用失败 (attempt {attempt+1}): {e}, {wait}s 后重试")
                time.sleep(wait)
        raise RuntimeError(f"LLM 调用失败，已重试 {self.max_retries} 次: {last_err}")


llm = LLM()
