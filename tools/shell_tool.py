"""Shell 工具 - 执行系统命令"""
from config import config
from tools.base import register_tool, run_cmd


@register_tool(
    name="run_shell",
    description="在 Kali Linux 上执行 shell 命令。用于运行 nmap、sqlmap、gobuster、hashcat、sage、python、file、strings、binwalk 等所有安全工具。超时 120 秒。",
    parameters={
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "要执行的完整 shell 命令，例如 'nmap -sV target.com' 或 'echo SGVsbG8= | base64 -d'",
            }
        },
        "required": ["command"],
    },
)
def run_shell(command: str) -> str:
    """执行 shell 命令并返回输出（超时整组强杀，防 msfconsole/nc 挂死）"""
    return run_cmd(command, timeout=config.TOOL_TIMEOUT)
