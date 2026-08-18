"""TSecBench 平台 API 对接器

适配 https://tsecbench.zc.tencent.com 的 API:
- 认证: HTTP Header BENCHMARK_TOKEN
- GET  /openapi/v1/challenges        列出题目
- POST /openapi/v1/challenges/start  启动容器
- GET  /openapi/v1/challenges/hint   获取提示(扣分)
- POST /openapi/v1/challenges/submit 提交 flag
- POST /openapi/v1/challenges/close  关闭容器

约束:
- 同时最多 3 道题
- 一道题可能多个 flag
- 任务有总时限
"""
import os
import json
import time
import logging
import requests
from config import config

logger = logging.getLogger(__name__)

PROGRESS_FILE = os.path.join(config.OUTPUT_DIR, "tsecbench_progress.json")


class TSecBenchAPI:
    """TSecBench 平台 API 客户端"""

    def __init__(self):
        self.base_url = config.COMPETITION_BASE_URL or ""
        self.token = config.COMPETITION_TOKEN or ""
        self.session = requests.Session()
        if self.token:
            self.session.headers.update({"BENCHMARK_TOKEN": self.token})
        self.session.headers.update({"Content-Type": "application/json"})

    def is_configured(self) -> bool:
        return bool(self.base_url and self.token)

    def _request(self, method: str, path: str, **kwargs) -> dict:
        """统一请求封装，带重试和错误处理"""
        url = f"{self.base_url}{path}"
        last_err = None
        for attempt in range(3):
            try:
                resp = self.session.request(method, url, timeout=30, **kwargs)
                # 成功
                if resp.status_code == 200:
                    return resp.json()
                # 解析业务错误
                try:
                    err_data = resp.json()
                    err_code = err_data.get("code", "unknown")
                    err_msg = err_data.get("message", resp.text)
                    return {"error": True, "code": err_code, "message": err_msg, "http_status": resp.status_code}
                except json.JSONDecodeError:
                    return {"error": True, "code": "parse_error", "message": resp.text[:500], "http_status": resp.status_code}
            except requests.exceptions.RequestException as e:
                last_err = e
                logger.warning(f"请求失败 (attempt {attempt+1}): {e}, {2**attempt}s 后重试")
                time.sleep(2 ** attempt)
        return {"error": True, "code": "request_failed", "message": str(last_err)}

    def list_challenges(self) -> list:
        """列出所有题目"""
        if not self.is_configured():
            logger.warning("TSecBench API 未配置")
            return []
        data = self._request("GET", "/openapi/v1/challenges")
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and data.get("error"):
            logger.error(f"列出题目失败: {data.get('message')}")
        return []

    def start_challenge(self, unique_code: str) -> dict:
        """启动题目容器"""
        return self._request("POST", "/openapi/v1/challenges/start", params={"unique_code": unique_code})

    def get_hint(self, unique_code: str) -> dict:
        """获取提示（会扣分！）"""
        return self._request("GET", "/openapi/v1/challenges/hint", params={"unique_code": unique_code})

    def submit_flag(self, unique_code: str, flag: str) -> dict:
        """提交 flag"""
        return self._request("POST", "/openapi/v1/challenges/submit",
                            json={"unique_code": unique_code, "flag": flag})

    def close_challenge(self, unique_code: str) -> dict:
        """关闭题目容器"""
        return self._request("POST", "/openapi/v1/challenges/close",
                            params={"unique_code": unique_code})


# ── 进度持久化 ──

def load_progress() -> dict:
    if os.path.exists(PROGRESS_FILE):
        try:
            with open(PROGRESS_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "solved": [],          # 已通关的 unique_code
        "in_progress": [],     # 正在做的
        "failed": [],          # 失败的
        "submitted_flags": {}, # {unique_code: [flag1, flag2]}
        "history": [],         # 详细历史
    }


def save_progress(progress: dict):
    with open(PROGRESS_FILE, "w") as f:
        json.dump(progress, f, indent=2, ensure_ascii=False)


# 全局单例
tsec_api = TSecBenchAPI()
