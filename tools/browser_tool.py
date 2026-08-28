"""无头浏览器工具（T2-⑥）：browser_render / browser_screenshot

解决 curl/http_request 打不了需要 JS 渲染、动态 DOM、XSS 触发的 web 题的短板。
实现：chromium --headless CLI（Kali 自带 chromium，无 Python 依赖）。
- browser_render: 渲染页面（执行 JS）后返回 DOM；virtual_time_budget 控制 JS 执行时间预算，
  使 setTimeout/setInterval 里的回调也执行——XSS payload 触发后 DOM 变化能被看到
- browser_screenshot: 截图存文件（返回路径），适合需要视觉确认的场景

外部 JS（如 XSS 外带）仍不可见（比赛禁外联），但页内 JS 执行/DOM 变化完全覆盖。
"""
import os
import re
import shutil
import subprocess
import tempfile
import time

from tools.base import register_tool, _check_external_access

_CHROMIUM_CANDIDATES = ("chromium", "chromium-browser", "google-chrome")


def _chromium_bin() -> str:
    for b in _CHROMIUM_CANDIDATES:
        path = shutil.which(b)
        if path:
            return path
    return ""


def _run_chromium(args: list, timeout: int) -> tuple:
    """跑 chromium headless，返回 (输出, 错误)。用独立 profile 防并发锁冲突。"""
    bin_path = _chromium_bin()
    if not bin_path:
        return "", "[工具未安装] chromium 不存在——sudo apt install chromium"
    profile = tempfile.mkdtemp(prefix="agent_chr_")
    try:
        cmd = [
            bin_path, "--headless=new", "--disable-gpu", "--no-sandbox",
            "--disable-dev-shm-usage", "--no-first-run", "--no-default-browser-check",
            f"--user-data-dir={profile}",
        ] + args
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           start_new_session=True)
        return (r.stdout or "") + (r.stderr or ""), ""
    except subprocess.TimeoutExpired:
        return "", f"[超时] chromium {timeout}s 内未完成"
    except Exception as e:
        return "", f"[执行错误] {e}"
    finally:
        try:
            shutil.rmtree(profile, ignore_errors=True)
        except Exception:
            pass


@register_tool(
    name="browser_render",
    description="无头浏览器渲染网页（执行页面 JS 后返回 DOM）。适合：需要 JS 才能渲染的页面、"
                "XSS payload 触发后的 DOM 变化验证、JS 动态生成内容的读取。比 curl 多了 JS 执行能力。",
    parameters={
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "目标 URL（含 http://）"},
            "js_budget_ms": {"type": "number", "description": "JS 执行时间预算（毫秒，默认 3000；XSS 定时回调可加大）"},
            "timeout": {"type": "number", "description": "最长等待秒数（默认 60）"},
        },
        "required": ["url"],
    },
)
def browser_render(url: str, js_budget_ms: float = 3000, timeout: int = 60) -> str:
    block = _check_external_access(url)
    if block:
        return block
    out, err = _run_chromium([
        f"--virtual-time-budget={int(js_budget_ms)}",
        "--dump-dom", url,
    ], timeout)
    if err:
        return err
    if not out or "<html" not in out.lower():
        return f"[渲染结果异常] chromium 未返回有效 DOM。stderr 摘要: {err or out[-300:]}"
    # DOM 精简：去 script/style 块内容（多是框架噪音），保留结构
    dom = re.sub(r"<script[^>]*>.*?</script>", "<script>[省略]</script>", out, flags=re.S | re.I)
    dom = re.sub(r"<style[^>]*>.*?</style>", "<style>[省略]</style>", dom, flags=re.S | re.I)
    return f"[渲染后 DOM（JS 已执行，预算 {int(js_budget_ms)}ms，共 {len(dom)} 字符）]\n{dom[:8000]}"


@register_tool(
    name="browser_screenshot",
    description="无头浏览器截图（JS 渲染后）并保存到文件，返回路径。适合视觉确认页面状态（如验证码/图形/布局）。",
    parameters={
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "目标 URL（含 http://）"},
            "output_path": {"type": "string", "description": "截图保存路径（默认 /tmp/agent_screenshot_<ts>.png）"},
            "timeout": {"type": "number", "description": "最长等待秒数（默认 60）"},
        },
        "required": ["url"],
    },
)
def browser_screenshot(url: str, output_path: str = "", timeout: int = 60) -> str:
    block = _check_external_access(url)
    if block:
        return block
    if not output_path:
        output_path = f"/tmp/agent_screenshot_{int(time.time())}.png"
    output_path = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(output_path) or "/", exist_ok=True)
    out, err = _run_chromium([
        "--virtual-time-budget=3000",
        f"--screenshot={output_path}",
        "--window-size=1366,900", url,
    ], timeout)
    if err:
        return err
    if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
        return f"[截图成功] {output_path} ({os.path.getsize(output_path)} bytes)——可用 read_file 或后续 OCR/图像工具分析"
    return f"[截图失败] {out[-300:]}"
