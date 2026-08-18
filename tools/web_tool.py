"""Web 安全工具 - HTTP 请求、SQL注入检测、目录扫描

设计:
- http_request: 通用 HTTP 请求，支持自定义 method/header/body
- sqli_scan: SQL 注入自动检测（基于 sqlmap）
- dir_scan: 目录扫描（基于 gobuster）
- url_decode / url_encode: URL 编解码
"""
import os
import json
import subprocess
import urllib.parse
import logging
from config import config
from tools.base import register_tool

logger = logging.getLogger(__name__)


@register_tool(
    name="http_request",
    description="""发送 HTTP 请求。支持 GET/POST/PUT/DELETE，可自定义 headers 和 body。

适合: 测试 Web 应用、查看响应、发送 payload。

返回: 状态码、响应头、响应体（截断到 5000 字符）。
""",
    parameters={
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "目标 URL，如 http://example.com/page?id=1"},
            "method": {
                "type": "string",
                "enum": ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"],
                "description": "HTTP 方法，默认 GET",
            },
            "headers": {
                "type": "object",
                "description": "自定义请求头，如 {\"Authorization\": \"Bearer xxx\"}",
            },
            "body": {"type": "string", "description": "请求体（POST/PUT 用）"},
            "timeout": {"type": "integer", "description": "超时秒数，默认 30"},
            "follow_redirects": {"type": "boolean", "description": "是否跟随重定向，默认 True"},
        },
        "required": ["url"],
    },
)
def http_request(url: str, method: str = "GET", headers: dict = None,
                 body: str = "", timeout: int = 30,
                 follow_redirects: bool = True) -> str:
    """发送 HTTP 请求"""
    # 结果缓存去重：GET 请求按 URL 去重，防止重复探测同一目标浪费轮次
    from tools.base import check_exec_cache, store_exec_cache
    if method.upper() == "GET":
        cache_key = f"http:{method.upper()}:{url}"
        cached = check_exec_cache(cache_key)
        if cached:
            return cached
    try:
        # 用 curl 执行，更通用、更好控制
        cmd = [
            "curl", "-s", "-S",
            "-X", method.upper(),
            "-w", "\n\n[HTTP_CODE:%{http_code}][TIME:%{time_total}s]",
            "--max-time", str(timeout),
        ]

        if follow_redirects:
            cmd.append("-L")

        if headers:
            for k, v in headers.items():
                cmd.extend(["-H", f"{k}: {v}"])

        if body:
            cmd.extend(["-d", body])

        # 输出响应头
        cmd.extend(["-D", "-"])

        cmd.append(url)

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 10,
        )

        output = result.stdout
        if result.stderr:
            output += f"\n[STDERR] {result.stderr}"

        if len(output) > 6000:
            output = output[:3000] + "\n...[截断]...\n" + output[-2500:]

        output = output.strip() or "[无输出]"
        # 存入缓存（GET 成功结果）
        if method.upper() == "GET" and not output.startswith("[HTTP"):
            store_exec_cache(f"http:{method.upper()}:{url}", output[:1500])
        return output

    except subprocess.TimeoutExpired:
        return f"[HTTP 请求超时，{timeout}s 限制]"
    except Exception as e:
        return f"[HTTP 请求错误] {e}"


@register_tool(
    name="sqli_scan",
    description="""SQL 注入自动检测。基于 sqlmap-api，自动测试目标 URL 的注入点。

参数:
- url: 目标 URL，如 http://example.com/page?id=1
- data: POST 数据，如 "username=admin&password=123"
- cookie: Cookie 值

执行 sqlmap --batch 模式，自动检测并尝试获取数据库信息。
""",
    parameters={
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "目标 URL"},
            "data": {"type": "string", "description": "POST 数据（可选）"},
            "cookie": {"type": "string", "description": "Cookie（可选）"},
            "level": {"type": "integer", "description": "测试级别 1-5，默认 1"},
            "risk": {"type": "integer", "description": "风险级别 1-3，默认 1"},
        },
        "required": ["url"],
    },
)
def sqli_scan(url: str, data: str = "", cookie: str = "",
              level: int = 1, risk: int = 1) -> str:
    """SQL 注入扫描"""
    try:
        cmd = [
            "sqlmap", "-u", url,
            "--batch",
            "--level", str(level),
            "--risk", str(risk),
            "--random-agent",
        ]

        if data:
            cmd.extend(["--data", data])
        if cookie:
            cmd.extend(["--cookie", cookie])

        # 限制输出
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=180,
        )

        output = result.stdout
        # 提取关键信息
        lines = output.split("\n")
        key_lines = [l for l in lines if any(k in l.lower() for k in [
            "injectable", "available", "back-end", "web server",
            "web application", "banner", "flag", "found",
        ])]

        if key_lines:
            return "[SQL 注入扫描完成 - 关键发现]\n" + "\n".join(key_lines[:30])

        # 截断输出
        if len(output) > 5000:
            output = output[:2500] + "\n...[截断]...\n" + output[-2000:]
        return output.strip() or "[无输出]"

    except subprocess.TimeoutExpired:
        return "[sqlmap 扫描超时，180s 限制]"
    except FileNotFoundError:
        return "[错误] sqlmap 未安装。安装: apt install sqlmap"
    except Exception as e:
        return f"[sqlmap 错误] {e}"


@register_tool(
    name="dir_scan",
    description="""目录/文件扫描。基于 gobuster，用常见 wordlist 扫描隐藏路径。

参数:
- url: 目标 URL
- wordlist: 字典文件路径，默认 /usr/share/wordlists/dirb/common.txt

适合: 发现隐藏的管理后台、备份文件、配置文件等。
""",
    parameters={
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "目标 URL，如 http://example.com/"},
            "wordlist": {
                "type": "string",
                "description": "字典路径，默认 /usr/share/wordlists/dirb/common.txt",
            },
            "extensions": {
                "type": "string",
                "description": "要扫描的文件扩展名，如 'php,txt,html,bak'",
            },
        },
        "required": ["url"],
    },
)
def dir_scan(url: str, wordlist: str = "",
             extensions: str = "") -> str:
    """目录扫描"""
    try:
        # 默认字典
        if not wordlist:
            candidates = [
                "/usr/share/wordlists/dirb/common.txt",
                "/usr/share/seclists/Discovery/Web-Content/common.txt",
                "/usr/share/wordlists/dirb/big.txt",
            ]
            for c in candidates:
                if os.path.exists(c):
                    wordlist = c
                    break

        if not wordlist or not os.path.exists(wordlist):
            return "[错误] 未找到合适的 wordlist。请指定 wordlist 参数。"

        cmd = [
            "gobuster", "dir",
            "-u", url,
            "-w", wordlist,
            "-q",               # quiet mode
            "-t", "20",         # 20 threads
            "--timeout", "10s",
        ]

        if extensions:
            cmd.extend(["-x", extensions])

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120,
        )

        output = result.stdout
        if not output.strip():
            return "[目录扫描完成] 未发现任何路径"

        return f"[目录扫描结果]\n{output.strip()}"

    except subprocess.TimeoutExpired:
        return "[gobuster 扫描超时，120s 限制]"
    except FileNotFoundError:
        return "[错误] gobuster 未安装。安装: apt install gobuster"
    except Exception as e:
        return f"[gobuster 错误] {e}"
