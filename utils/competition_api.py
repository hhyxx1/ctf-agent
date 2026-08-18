"""比赛平台 API 对接层

测试赛（8/18-19）官方发布 API 文档后，根据实际接口调整此文件。
当前实现基于常见 CTF 平台 API 模式，提供：
- 拉取题目列表
- 获取单道题详情和附件
- 提交 flag
- 查询提交状态
"""
import os
import json
import time
import logging
import requests
from config import config

logger = logging.getLogger(__name__)

# 比赛进度持久化文件（记录已解题、待解题、提交历史）
PROGRESS_FILE = os.path.join(config.OUTPUT_DIR, "progress.json")


class CompetitionAPI:
    """比赛平台 API 客户端"""

    def __init__(self):
        self.base_url = config.COMPETITION_API_BASE_URL or ""
        self.token = config.COMPETITION_TOKEN or ""
        self.session = requests.Session()
        if self.token:
            self.session.headers.update({"Authorization": f"Bearer {self.token}"})
        self.session.headers.update({"Content-Type": "application/json"})

    def _request(self, method: str, path: str, **kwargs) -> dict:
        """统一请求封装，带重试"""
        url = f"{self.base_url}{path}" if self.base_url else path
        last_err = None
        for attempt in range(3):
            try:
                resp = self.session.request(method, url, timeout=30, **kwargs)
                if resp.status_code == 200:
                    return resp.json()
                return {
                    "error": f"HTTP {resp.status_code}",
                    "detail": resp.text[:500],
                }
            except Exception as e:
                last_err = e
                time.sleep(2 ** attempt)
        return {"error": f"请求失败: {last_err}"}

    def list_challenges(self) -> list:
        """拉取所有题目"""
        if not self.base_url:
            logger.warning("比赛 API 未配置，返回空题目列表")
            return []
        data = self._request("GET", "/challenges")
        return data.get("data", data) if isinstance(data, dict) else data

    def get_challenge(self, challenge_id: str) -> dict:
        """获取单道题详情（描述、分值、附件URL等）"""
        if not self.base_url:
            return {}
        return self._request("GET", f"/challenges/{challenge_id}")

    def download_attachment(self, url: str, filename: str = "") -> str:
        """下载题目附件到 attachments/ 目录"""
        try:
            resp = self.session.get(url, timeout=60, stream=True)
            if resp.status_code != 200:
                return f"[下载失败] HTTP {resp.status_code}"

            if not filename:
                filename = url.split("/")[-1].split("?")[0]
            filepath = os.path.join(config.ATTACHMENTS_DIR, filename)

            with open(filepath, "wb") as f:
                for chunk in resp.iter_content(8192):
                    f.write(chunk)

            return f"[下载成功] {filepath} ({os.path.getsize(filepath)} bytes)"
        except Exception as e:
            return f"[下载失败] {e}"

    def submit_flag(self, flag: str, challenge_id: str = "") -> dict:
        """提交 flag 到比赛平台"""
        if not self.base_url:
            return {"status": "local", "message": "比赛 API 未配置，本地模式"}
        payload = {"flag": flag}
        if challenge_id:
            payload["challenge_id"] = challenge_id
        return self._request("POST", "/submit", json=payload)

    def is_configured(self) -> bool:
        """检查比赛 API 是否已配置"""
        return bool(self.base_url and self.token)


# ── 进度持久化 ──

def load_progress() -> dict:
    """加载进度文件"""
    if os.path.exists(PROGRESS_FILE):
        try:
            with open(PROGRESS_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {"solved": [], "failed": [], "submitted": [], "history": []}


def save_progress(progress: dict):
    """保存进度文件"""
    with open(PROGRESS_FILE, "w") as f:
        json.dump(progress, f, indent=2, ensure_ascii=False)


# 全局单例
api = CompetitionAPI()
