"""Python 代码执行工具 - 用于 crypto 计算、数据处理等"""
import subprocess
import tempfile
import os
from config import config
from tools.base import register_tool


@register_tool(
    name="run_python",
    description="执行 Python 3 代码并返回输出。已预装 sympy、pwntools、pycryptodome、gmpy2 等 CTF 常用库。适合做 RSA 解密、编码转换、数学计算。",
    parameters={
        "type": "object",
        "properties": {
            "code": {
                "type": "string",
                "description": "要执行的 Python 代码，可以有多行。不要用 input()，直接写逻辑。",
            }
        },
        "required": ["code"],
    },
)
def run_python(code: str) -> str:
    """执行 Python 代码并返回 stdout/stderr"""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, dir="/tmp"
        ) as f:
            f.write(code)
            tmp_path = f.name

        result = subprocess.run(
            [config.WORK_DIR.rstrip('/') and os.path.join(config.WORK_DIR, '.venv/bin/python') or "python3", tmp_path],
            capture_output=True,
            text=True,
            timeout=config.TOOL_TIMEOUT,
            cwd=config.OUTPUT_DIR,
        )

        os.unlink(tmp_path)

        output = ""
        if result.stdout:
            output += result.stdout
        if result.stderr:
            output += f"\n[STDERR]\n{result.stderr}"
        if len(output) > 8000:
            output = output[:4000] + "\n...[截断]...\n" + output[-3000:]
        return output.strip() or "[无输出]"
    except subprocess.TimeoutExpired:
        return f"[Python 执行超时，{config.TOOL_TIMEOUT}s 限制]"
    except Exception as e:
        return f"[执行错误] {e}"
