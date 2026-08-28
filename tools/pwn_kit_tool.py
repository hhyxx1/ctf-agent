"""Pwn 工具集增强：pwn_triage / libc_identify / one_gadget / gdb_debug / pwn_local_setup

设计约定：
- 三级降级：专用二进制 → python 库 → 本地解析，缺失时给出安装命令而非报错
- checksec 手动解析 readelf 输出（不依赖外部 checksec 命令）
- 输出结构化分节 + [下一步] 建议，pwn_triage 一次顶 5 轮探测
"""
import os
import re
import shutil
import subprocess
import time

from tools.base import register_tool, run_cmd, check_exec_cache, store_exec_cache

FLAG_RE = re.compile(r"(?:flag|FLAG|ctf|CTF)\{[^}]{4,200}\}")


def _which(binname):
    if binname not in _WHICH_CACHE:
        _WHICH_CACHE[binname] = shutil.which(binname)
    return _WHICH_CACHE[binname]


_WHICH_CACHE = {}


def _truncate(s, n=3000):
    s = (s or "").strip()
    return s if len(s) <= n else s[:n] + f"\n...[截断, 原文 {len(s)} 字符]..."


def _readelf(path, *args):
    return run_cmd(["readelf", *args, path], timeout=30)


# ── 1. pwn_triage：二进制一键分诊 ────────────────────────────────────────────

def _manual_checksec(path) -> str:
    """用 readelf 手动解析保护机制（不依赖 checksec 命令）"""
    out = []
    hdr = _readelf(path, "-hW")
    if "[工具未安装]" in hdr or "[执行错误]" in hdr:
        return f"[checksec] readelf 失败: {hdr}"
    if re.search(r"Type:\s+DYN", hdr):
        out.append("PIE: 开启 (DYN)")
    elif re.search(r"Type:\s+EXEC", hdr):
        out.append("PIE: 关闭 (EXEC) → 地址固定，可直接硬编码")
    else:
        out.append("PIE: 未知")

    prog = _readelf(path, "-lW")
    nx = "GNU_STACK" in prog and "RWE" not in prog
    out.append(f"NX: {'开启 (栈不可执行)' if nx else '关闭 (栈可执行!) → 可放 shellcode'}")

    dyn = _readelf(path, "-dW")
    relro_full = "BIND_NOW" in dyn
    relro = "Full" if relro_full and "GNU_RELRO" in prog else ("Partial" if "GNU_RELRO" in prog else "None")
    out.append(f"RELRO: {relro}" + (" → GOT 可写，可打 GOT 覆写" if relro != "Full" else ""))

    sym = _readelf(path, "-sW") + _readelf(path, "--dyn-syms") + _readelf(path, "-rW")
    canary = "__stack_chk_fail" in sym
    out.append(f"Canary: {'开启' if canary else '关闭 → 栈溢出可直接覆盖返回地址'}")
    has_pie_libs = "NEEDED" in dyn
    out.append(f"动态链接: {'是' if has_pie_libs else '静态'}")
    return "\n".join(out)


def _libc_version_from_binary(path) -> str:
    """从二进制/so 的 strings 里提取 glibc 版本特征"""
    out = run_cmd(["bash", "-c", f"strings -a '{path}' 2>/dev/null | "
                                 f"grep -oE 'GNU C Library \\(.*\\) stable release version 2\\.[0-9]+' | head -1"],
                  timeout=20)
    if out and "GNU C Library" in out:
        return out
    out = run_cmd(["bash", "-c", f"strings -a '{path}' 2>/dev/null | grep -oE 'glibc 2\\.[0-9]+' | head -1"],
                  timeout=20)
    return out if "glibc" in out else ""


@register_tool(
    "pwn_triage",
    "二进制一键分诊：file 类型 + 保护机制(checksec) + 关键字符串(bin/sh/system/flag) "
    "+ libc 版本 + ROP gadget 概览 + 利用建议。pwn 题拿到 binary 第一件事就调它，"
    "替代 file/checksec/strings/ROPgadget 多次往返。",
    {
        "type": "object",
        "properties": {
            "binary_path": {"type": "string", "description": "二进制文件路径"},
        },
        "required": ["binary_path"],
    },
)
def pwn_triage(binary_path: str) -> str:
    binary_path = (binary_path or "").strip()
    if not os.path.isfile(binary_path):
        return f"[参数错误] 文件不存在: {binary_path}（先 read_file/list_dir 确认附件已下载）"

    cache_key = f"pwnt:{binary_path}"
    cached = check_exec_cache(cache_key)
    if cached:
        return cached

    sections = []
    finfo = run_cmd(["file", binary_path], timeout=15)
    sections.append(f"[file]\n{finfo}")

    sections.append(f"[保护机制 checksec]\n{_manual_checksec(binary_path)}")

    # 关键字符串
    ks = run_cmd(["bash", "-c",
                  f"strings -a '{binary_path}' | grep -E '/bin/sh|/bin/bash|system|execve|flag|"
                  f"cat |nc |bash -i|setuid' | sort -u | head -30"], timeout=20)
    sections.append(f"[关键字符串]\n{_truncate(ks, 1500) or '[无]'}")

    # 动态符号（可利用函数）
    dyn = run_cmd(["bash", "-c",
                   f"readelf --dyn-syms -W '{binary_path}' 2>/dev/null | grep UND | "
                   f"grep -E 'system|execve|puts|printf|write|read|gets|scanf|setbuf|open|mprotect|"
                   f"mmap|fork|strcmp|strcpy|sprintf|snprintf|atoi|malloc|free' | awk '{{print $8}}' | "
                   f"sort -u | head -40"], timeout=20)
    sections.append(f"[导入函数]\n{_truncate(dyn, 1500) or '[无]'}")

    libc_ver = _libc_version_from_binary(binary_path)
    sections.append(f"[libc 版本]\n{libc_ver or '[二进制内无 glibc 版本特征，远程 libc 需另行确认：libc_identify]'}")

    # gadget 概览（快速、浅层）
    if _which("ROPgadget"):
        rop = run_cmd(["bash", "-c",
                       f"ROPgadget --binary '{binary_path}' 2>/dev/null | "
                       f"grep -E 'pop rdi|pop rsi|pop rdx|pop rax|syscall|ret$' | head -15"],
                      timeout=60)
        sections.append(f"[ROP gadgets (前 15 条)]\n{_truncate(rop, 1500) or '[未找到常用 gadget，可用 rop_gadget_search 深查]'}")

    # flag 泄露检查
    full_strings = run_cmd(["strings", "-a", binary_path], timeout=30)
    flags = list(dict.fromkeys(FLAG_RE.findall(full_strings)))

    # 利用建议（基于保护机制组合）
    advice = []
    if "PIE: 关闭" in "\n".join(sections) and "NX: 关闭" in "\n".join(sections):
        advice.append("无 PIE + 无 NX → 直接栈上 shellcode（jmp esp / 环境变量法）")
    if "NX: 关闭" in "\n".join(sections):
        advice.append("无 NX → shellcode + mprotect 兜底")
    if "Canary: 关闭" in "\n".join(sections):
        advice.append("无 Canary → 栈溢出直接覆盖返回地址，先确定 offset（cyclic 模式）")
    if "Full" not in "\n".join(sections):
        advice.append("非 Full RELRO → GOT 覆写可用")
    if "PIE: 关闭" in "\n".join(sections):
        advice.append("无 PIE → GOT/PLT 地址固定，ret2libc/ret2plt 直接打")
    advice.append("先本地复现（pwn_local_setup 换 libc）再打远程，省一半轮次")

    result = "\n\n".join(sections)
    tail = "[下一步] " + "；".join(advice[:4])
    if flags:
        tail = f"[FLAG] 二进制 strings 中发现疑似 flag: {flags}\n" + tail
    result += f"\n\n{tail}"
    store_exec_cache(cache_key, result)
    return result


# ── 2. libc_identify：泄露地址 → libc 版本 + 关键偏移 ────────────────────────

def _libc_symbols(libc_path):
    """从 libc so 提取关键符号偏移: {puts: 0x.., system: 0x.., ...}"""
    out = run_cmd(["bash", "-c",
                   f"readelf -sW '{libc_path}' 2>/dev/null | grep -E "
                   f"'\\b(puts|system|printf|write|read|execve|__libc_start_main)@@' | "
                   f"awk '{{print $2, $8}}'"], timeout=30)
    syms = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            try:
                name = parts[1].split("@")[0]
                syms[name] = int(parts[0], 16)
            except ValueError:
                continue
    return syms


def _libc_binsh(libc_path):
    out = run_cmd(["bash", "-c", f"strings -t x '{libc_path}' 2>/dev/null | grep -w /bin/sh | head -1"],
                  timeout=20)
    m = re.match(r"\s*([0-9a-f]+)\s+/bin/sh", out)
    return int(m.group(1), 16) if m else None


@register_tool(
    "libc_identify",
    "根据泄露的 libc 函数地址（低 12 位页偏移不变）识别 libc 版本并给出 "
    "puts/system//bin/sh 等关键偏移。ret2libc 必用。"
    "leak 传十六进制（可带 0x 前缀），symbol 传泄露的是哪个函数（默认 puts）。",
    {
        "type": "object",
        "properties": {
            "leak": {"type": "string", "description": "泄露的函数运行时地址，如 0x7f1234567890"},
            "symbol": {"type": "string", "description": "泄露的符号名（puts/write/printf 等）"},
        },
        "required": ["leak"],
    },
)
def libc_identify(leak: str, symbol: str = "puts") -> str:
    leak = leak.strip().replace("0x", "").replace("0X", "")
    try:
        leak_val = int(leak, 16)
    except ValueError:
        return f"[参数错误] 无法解析地址: {leak}"
    page = leak_val & 0xFFF
    sym = (symbol or "puts").strip()

    lines = [f"[输入] {sym} leak=0x{leak_val:x}, 页偏移(低12位)=0x{page:03x}"]

    # 路线 1: LibcSearcher
    try:
        from LibcSearcher import LibcSearcher  # noqa
        try:
            lc = LibcSearcher(sym, leak_val)
            base = leak_val - lc.dump(sym)
            key_syms = {s: lc.dump(s) for s in ("system", "puts", "write", "execve") if s != sym}
            lines.append(f"[LibcSearcher] 命中: {lc.dump('__libc_start_main') and ''}"
                         f"libc base = 0x{base:x}")
            for s, off in key_syms.items():
                if off:
                    lines.append(f"  {s} offset = 0x{off:x} → 运行时 0x{base + off:x}")
            lines.append("[下一步] 用这些地址写 ret2libc；用 pwn_local_setup 本地验证后再打远程。")
            return "\n".join(lines)
        except Exception as e:
            lines.append(f"[LibcSearcher] 无匹配/出错: {e}")
    except ImportError:
        lines.append("[LibcSearcher] 未安装（pip install libcsearcher），改用本地 libc 匹配")

    # 路线 2: 本机 libc 匹配（偏移低 12 位比对）
    candidates = ["/lib/x86_64-linux-gnu/libc.so.6", "/lib64/libc.so.6",
                  "/usr/lib/x86_64-linux-gnu/libc.so.6"]
    for libc_path in candidates:
        if not os.path.isfile(libc_path):
            continue
        syms = _libc_symbols(libc_path)
        if sym not in syms:
            continue
        if syms[sym] & 0xFFF == page:
            base = leak_val - syms[sym]
            lines.append(f"[本地 libc 匹配成功] {libc_path} ({_libc_version_from_binary(libc_path)})")
            lines.append(f"  libc base = 0x{base:x}")
            for s, off in syms.items():
                lines.append(f"  {s} offset = 0x{off:x} → 运行时 0x{base + off:x}")
            bs = _libc_binsh(libc_path)
            if bs:
                lines.append(f"  /bin/sh offset = 0x{bs:x} → 运行时 0x{base + bs:x}")
            lines.append("[下一步] 本地 libc 命中，可先 pwn_local_setup 本地复现。")
            return "\n".join(lines)
        lines.append(f"[不匹配] {libc_path}: {sym} 页偏移 0x{syms[sym] & 0xFFF:03x} ≠ 0x{page:03x}")

    lines.append(
        "[结论] 本地无匹配 libc。远程 libc 与本机不同 → 从题目附件找 libc 文件"
        "（pwn_triage 看附件），或用泄露的两个不同函数地址联合约束后再试。"
    )
    return "\n".join(lines)


# ── 3. one_gadget ────────────────────────────────────────────────────────────

@register_tool(
    "one_gadget",
    "在 libc 中搜索 one_gadget（execve('/bin/sh') 单发 getshell 的地址+约束）。",
    {
        "type": "object",
        "properties": {
            "libc_path": {"type": "string", "description": "libc 文件路径"},
        },
        "required": ["libc_path"],
    },
)
def one_gadget(libc_path: str) -> str:
    libc_path = (libc_path or "").strip()
    if not os.path.isfile(libc_path):
        return f"[参数错误] libc 文件不存在: {libc_path}"
    if not _which("one_gadget"):
        return ("[MISSING] one_gadget 未安装。\n[安装] gem install one_gadget\n"
                "[替代] readelf -sW libc 查 system 偏移 + strings 查 /bin/sh 偏移，"
                "用 libc_identify 拿运行时地址。")
    out = run_cmd(["one_gadget", "--force", libc_path], timeout=60)
    gadgets = [l for l in out.splitlines() if re.match(r"^0x[0-9a-f]+\s+execve", l)]
    return f"[one_gadget {libc_path}]\n{_truncate(out, 2500)}\n[下一步] 每个 gadget 都有约束（如 [rsp+0x30]==NULL），" \
           f"打不通就换下一个或在 gadget 前垫 pop 清栈。"


# ── 4. gdb_debug：脚本化动态调试 ─────────────────────────────────────────────

@register_tool(
    "gdb_debug",
    "headless 运行 gdb 批处理脚本：下断点/运行/读寄存器内存/看崩溃回溯。"
    "commands 用分号或换行分隔 gdb 命令，如 'break main; run; info registers; x/32gx $rsp'。"
    "args 传程序启动参数。exploit 失败时用它看实际行为而不是盲猜。",
    {
        "type": "object",
        "properties": {
            "binary": {"type": "string", "description": "二进制路径"},
            "commands": {"type": "string", "description": "gdb 命令，分号或换行分隔"},
            "args": {"type": "string", "description": "程序参数（可选）"},
        },
        "required": ["binary", "commands"],
    },
)
def gdb_debug(binary: str, commands: str, args: str = "") -> str:
    binary = (binary or "").strip()
    if not os.path.isfile(binary):
        return f"[参数错误] 文件不存在: {binary}"
    if not _which("gdb"):
        return "[MISSING] gdb 未安装（sudo apt install gdb）"
    cmds = [c.strip() for c in re.split(r"[;\n]", commands) if c.strip()]
    cmd = ["gdb", "-q", "-batch"]
    cmd += ["-ex", "set pagination off"]
    for c in cmds:
        cmd += ["-ex", c]
    cmd += ["--args", binary]
    if args:
        cmd += args.split()
    out = run_cmd(cmd, timeout=90)
    return f"[gdb 输出]\n{_truncate(out, 4000)}"


# ── 5. pwn_local_setup：本地复现环境（换 libc） ──────────────────────────────

@register_tool(
    "pwn_local_setup",
    "搭建本地复现环境：把 binary 和题目给的 libc 拷到 /tmp 工作目录，patchelf 换解释器/"
    "libc 后本地可跑。流程：本地打通 → 再打远程（省一半盲试轮次）。",
    {
        "type": "object",
        "properties": {
            "binary": {"type": "string", "description": "二进制路径"},
            "libc_path": {"type": "string", "description": "题目给的 libc 文件路径（可选）"},
        },
        "required": ["binary"],
    },
)
def pwn_local_setup(binary: str, libc_path: str = "") -> str:
    binary = (binary or "").strip()
    if not os.path.isfile(binary):
        return f"[参数错误] 文件不存在: {binary}"
    if not _which("patchelf"):
        return ("[MISSING] patchelf 未安装（sudo apt install patchelf）。"
                "替代方案：pwntools 的 pwn.libc + LD_PRELOAD 环境变量方式本地跑。")

    workdir = "/tmp/pwn_local_" + time.strftime("%H%M%S")
    os.makedirs(workdir, exist_ok=True)
    bname = os.path.basename(binary)
    bdst = os.path.join(workdir, bname)
    shutil.copy2(binary, bdst)
    os.chmod(bdst, 0o755)
    lines = [f"[工作目录] {workdir}", f"[二进制] {bname} 已拷贝"]

    if libc_path:
        libc_path = libc_path.strip()
        if not os.path.isfile(libc_path):
            return "\n".join(lines) + f"\n[参数错误] libc 不存在: {libc_path}"
        ld = os.path.join(os.path.dirname(os.path.abspath(libc_path)), "ld-linux-x86-64.so.2")
        if not os.path.isfile(ld):
            ld = shutil.which("ld-linux-x86-64.so.2") or ""
        if os.path.isfile(ld):
            ldst = os.path.join(workdir, os.path.basename(ld))
            shutil.copy2(ld, ldst)
            os.chmod(ldst, 0o755)
            run_cmd(["patchelf", "--set-interpreter", ldst, "--set-rpath", workdir, bdst], timeout=30)
            run_cmd(["patchelf", "--replace-needed", "libc.so.6", os.path.abspath(libc_path), bdst], timeout=30)
            lines.append(f"[patchelf] 解释器→{ldst}, libc→{libc_path}")
        else:
            run_cmd(["patchelf", "--set-rpath", os.path.dirname(os.path.abspath(libc_path)), bdst], timeout=30)
            lines.append(f"[patchelf] 未找到配套 ld，仅设 rpath={os.path.dirname(libc_path)}")

    ldd = run_cmd(["bash", "-c", f"ldd {bdst} 2>&1 | head -8"], timeout=20)
    lines.append(f"[ldd 验证]\n{_truncate(ldd, 800)}")
    run_result = run_cmd(["bash", "-c", f"cd {workdir} && echo '' | timeout 5 ./{bname} 2>&1 | head -15"], timeout=15)
    lines.append(f"[试运行]\n{_truncate(run_result, 1000)}")
    lines.append("[下一步] 用 run_python + pwntools 对本地文件调试打通，再把脚本目标改成远程地址。")
    return "\n".join(lines)
