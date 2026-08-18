"""工具注册入口 - 导入此模块会自动注册所有工具"""
from tools.base import TOOL_REGISTRY, get_tools_schema, execute_tool
from tools.shell_tool import run_shell
from tools.python_tool import run_python
from tools.file_tool import read_file, write_file, list_dir
from tools.flag_tool import extract_flag, submit_flag
from tools.crypto_tool import rsa_decrypt
from tools.codec_tool import auto_decode, encode_data
from tools.forensics_tool import analyze_file, steg_check
from tools.web_tool import http_request, sqli_scan, dir_scan
from tools.pentest_tool import (
    nmap_scan, hydra_brute, web_fingerprint,
    vuln_scan, linpeas_check, proxy_scan,
)
from tools.binary_tool import (
    binary_analyze, ghidra_decompile,
    vuln_pattern_scan, rop_gadget_search, exploit_template,
)
from tools.cloud_tool import ssrf_metadata, aws_enum, container_escape
from tools.evasion_tool import (
    shellcode_encode, msfvenom_payload,
    evade_check, tunnel_setup,
)

__all__ = [
    "TOOL_REGISTRY",
    "get_tools_schema",
    "execute_tool",
    # 通用
    "run_shell", "run_python",
    "read_file", "write_file", "list_dir",
    "extract_flag", "submit_flag",
    # Crypto
    "rsa_decrypt", "auto_decode", "encode_data",
    # Forensics
    "analyze_file", "steg_check",
    # Web
    "http_request", "sqli_scan", "dir_scan",
    # Pentest
    "nmap_scan", "hydra_brute", "web_fingerprint",
    "vuln_scan", "linpeas_check", "proxy_scan",
    # Binary
    "binary_analyze", "ghidra_decompile",
    "vuln_pattern_scan", "rop_gadget_search", "exploit_template",
    # Cloud
    "ssrf_metadata", "aws_enum", "container_escape",
    # Evasion
    "shellcode_encode", "msfvenom_payload",
    "evade_check", "tunnel_setup",
]
