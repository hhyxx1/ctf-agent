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
    vuln_scan, linpeas_check, proxy_scan, service_vuln_scan,
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
from tools.recon_tool import (
    full_recon, check_conn, wordlist, searchsploit_query, env_selfcheck,
)
from tools.pwn_kit_tool import (
    pwn_triage, libc_identify, one_gadget, gdb_debug, pwn_local_setup,
)
from tools.forensics_triage_tool import (
    pcap_triage, memory_triage, audio_steg, qr_decode, pdf_office_analyze,
)
from tools.auth_tool import hash_crack, jwt_tool, flask_unsign
from tools.crypto_ext_tool import classical_cipher, lattice_lll, php_filter_chain

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
    "vuln_scan", "linpeas_check", "proxy_scan", "service_vuln_scan",
    # Binary
    "binary_analyze", "ghidra_decompile",
    "vuln_pattern_scan", "rop_gadget_search", "exploit_template",
    # Cloud
    "ssrf_metadata", "aws_enum", "container_escape",
    # Evasion
    "shellcode_encode", "msfvenom_payload",
    "evade_check", "tunnel_setup",
    # Recon / 基建
    "full_recon", "check_conn", "wordlist", "searchsploit_query", "env_selfcheck",
    # Pwn 增强
    "pwn_triage", "libc_identify", "one_gadget", "gdb_debug", "pwn_local_setup",
    # 取证分诊
    "pcap_triage", "memory_triage", "audio_steg", "qr_decode", "pdf_office_analyze",
    # 认证类
    "hash_crack", "jwt_tool", "flask_unsign",
    # Crypto 扩展
    "classical_cipher", "lattice_lll", "php_filter_chain",
]
