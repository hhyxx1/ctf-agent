"""文件操作工具 - 读写题目附件、保存中间结果"""
import os
from config import config
from tools.base import register_tool


@register_tool(
    name="read_file",
    description="读取文件内容。用于查看下载的题目附件、配置文件、输出结果等。",
    parameters={
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "文件路径。相对路径基于工作目录。例如 'attachments/challenge.py' 或 '/tmp/test.txt'",
            },
            "max_bytes": {
                "type": "integer",
                "description": "最多读取的字节数，默认 20000。大文件会被截断。",
            },
        },
        "required": ["path"],
    },
)
def read_file(path: str, max_bytes: int = 20000) -> str:
    """读取文件内容"""
    try:
        if not os.path.isabs(path):
            path = os.path.join(config.WORK_DIR, path)

        size = os.path.getsize(path)
        with open(path, "r", errors="replace") as f:
            content = f.read(max_bytes)

        header = f"[文件: {path}, 大小: {size} 字节]\n"
        if size > max_bytes:
            header += f"[注意: 文件被截断，仅显示前 {max_bytes} 字节]\n"
        return header + content
    except FileNotFoundError:
        return f"[错误] 文件不存在: {path}"
    except Exception as e:
        return f"[读取错误] {e}"


@register_tool(
    name="write_file",
    description="写入内容到文件。用于保存解题脚本、中间数据、分析结果等。",
    parameters={
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "文件路径。建议保存到 output/ 目录，例如 'output/solve.py'",
            },
            "content": {
                "type": "string",
                "description": "要写入的完整内容，会覆盖已有文件。",
            },
        },
        "required": ["path", "content"],
    },
)
def write_file(path: str, content: str) -> str:
    """写入文件"""
    try:
        if not os.path.isabs(path):
            path = os.path.join(config.WORK_DIR, path)

        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
        return f"[成功] 已写入 {path} ({len(content)} 字节)"
    except Exception as e:
        return f"[写入错误] {e}"


@register_tool(
    name="list_dir",
    description="列出目录内容。用于查看 attachments/ 有哪些题目附件，或浏览工作目录。",
    parameters={
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "目录路径。默认列出工作目录。例如 'attachments' 或 '/tmp'",
            },
        },
    },
)
def list_dir(path: str = ".") -> str:
    """列出目录"""
    try:
        if not os.path.isabs(path):
            path = os.path.join(config.WORK_DIR, path)

        entries = os.listdir(path)
        lines = [f"[目录: {path}]"]
        for entry in sorted(entries):
            full = os.path.join(path, entry)
            if os.path.isdir(full):
                lines.append(f"  📁 {entry}/")
            else:
                size = os.path.getsize(full)
                lines.append(f"  📄 {entry} ({size} bytes)")
        return "\n".join(lines)
    except Exception as e:
        return f"[列目录错误] {e}"
