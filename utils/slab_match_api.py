"""AI Agent 平台 API 适配器（slab-match，X-Agent-AccessKey 认证）

对接文档 api_doc.md：
- Base URL: {serverHost}/slab-match/api/v1/agent
- 认证 Header: X-Agent-AccessKey
- 接口: match-info / exercise-list / exercise / build-exercise-env /
        answer / recover-exercise-env / notice

配置（.env）:
  SLAB_HOST=https://<serverHost>            # 平台主机
  SLAB_ACCESS_KEY=<你的X-Agent-AccessKey>   # Agent 专用 AccessKey

用法:
  api = SlabMatchAPI()
  api.get_match_info()          # 竞赛注意事项/规则
  api.list_exercises()          # 题目列表
  api.get_exercise(1001)        # 题目详情（含靶机 endpoints）
  api.build_env(1001)           # 启动环境
  api.submit_answer(1001, "flag{...}")  # 提交 flag
  api.recover_env(1001)         # 回收环境
"""
import os
import logging
import requests

from config import config

logger = logging.getLogger(__name__)

API_PREFIX = "/slab-match/api/v1/agent"


class SlabMatchAPI:
    def __init__(self):
        self.host = (getattr(config, "SLAB_HOST", "") or "").rstrip("/")
        self.access_key = getattr(config, "SLAB_ACCESS_KEY", "") or ""
        if not self.host:
            raise ValueError("SLAB_HOST 未配置，请在 .env 中设置平台主机地址")
        if not self.access_key:
            raise ValueError("SLAB_ACCESS_KEY 未配置，请在 .env 中设置 X-Agent-AccessKey")
        self.session = requests.Session()
        # 平台拒绝 python-requests 默认 UA（403），必须用浏览器/curl 风格 UA
        self.session.headers.update({
            "X-Agent-AccessKey": self.access_key,
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Accept": "application/json",
        })

    def _request(self, method: str, path: str, **kwargs) -> dict:
        url = f"{self.host}{API_PREFIX}{path}"
        try:
            resp = self.session.request(method, url, timeout=30, **kwargs)
            resp.raise_for_status()
            body = resp.json()
        except Exception as e:
            logger.error(f"SlabMatch API 请求失败 {method} {path}: {e}")
            raise
        if body.get("code") != "00000":
            raise RuntimeError(f"平台返回错误 code={body.get('code')} msg={body.get('message')}")
        return body.get("data") or {}

    # ── 竞赛信息 ──
    def get_match_info(self) -> dict:
        """查询竞赛注意事项和竞赛规则"""
        return self._request("GET", "/match/notice/match-info")

    def get_overview(self) -> dict:
        """查询得分与排名"""
        return self._request("GET", "/answer-panel/overview")

    # ── 题目 ──
    def list_exercises(self) -> list:
        """查询题目列表（按类别分组）"""
        return self._request("GET", "/ctf/exercise-list")

    def get_exercise(self, exercise_id: int) -> dict:
        """查询题目详情（含附件、靶机 endpoints）"""
        return self._request("GET", "/ctf/exercise", params={"exerciseId": exercise_id})

    # ── 环境 ──
    def build_env(self, exercise_id: int) -> dict:
        """启动题目环境（异步，需轮询详情直到 isNeedCheck=false）"""
        return self._request("POST", "/ctf/build-exercise-env", json={"exerciseId": exercise_id})

    def recover_env(self, exercise_id: int) -> dict:
        """回收题目环境"""
        return self._request("POST", "/ctf/recover-exercise-env", json={"exerciseId": exercise_id})

    # ── 答题 ──
    def submit_answer(self, exercise_id: int, flag: str) -> dict:
        """提交答案，返回 {'isCorrect': bool}"""
        return self._request("POST", "/answer-panel/answer", json={"exerciseId": exercise_id, "flag": flag})

    # ── 公告 ──
    def list_notices(self) -> list:
        return self._request("GET", "/match/notice/now-list")

    def get_notice(self, notice_id: int) -> dict:
        return self._request("GET", "/match/notice/detail", params={"id": notice_id})
