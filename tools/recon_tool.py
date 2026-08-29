"""侦察与基建工具：full_recon / check_conn / wordlist / searchsploit_query / env_selfcheck

设计约定：
- 全部本地执行（不访问外部站点，符合比赛外联规则）
- 子进程统一走 base.run_cmd（超时强杀进程组）
- 输出分节结构化（[OPEN]/[INFO]/[结论]/[下一步]），末尾给结论行，减少模型漏看关键信息
"""
import os
import re
import shutil
import socket
import time

from tools.base import register_tool, run_cmd, check_exec_cache, store_exec_cache

FLAG_RE = re.compile(r"(?:flag|FLAG|ctf|CTF)\{[^}]{4,200}\}")


# ── 通用小函数 ──────────────────────────────────────────────────────────────

def _which(binname: str):
    """本地查命令是否存在（返回绝对路径或 None），结果缓存"""
    if binname not in _WHICH_CACHE:
        _WHICH_CACHE[binname] = shutil.which(binname)
    return _WHICH_CACHE[binname]


_WHICH_CACHE = {}


def _grep_flags(text: str) -> list:
    """在文本里找 flag 模式（发现即写入结论，防止漏看）"""
    return list(dict.fromkeys(FLAG_RE.findall(text or "")))


def _truncate(s: str, n: int = 3000) -> str:
    s = (s or "").strip()
    if len(s) <= n:
        return s
    return s[:n] + f"\n...[截断, 原文 {len(s)} 字符]..."


def _parse_target(target: str):
    """把 host / host:port / url 解析成 (host, port, scheme)"""
    target = (target or "").strip()
    scheme = ""
    m = re.match(r"^(https?)://([\w.\-]+)(?::(\d+))?", target)
    if m:
        scheme = m.group(1)
        host = m.group(2)
        port = int(m.group(3)) if m.group(3) else (443 if scheme == "https" else 80)
        return host, port, scheme
    m = re.match(r"^([\w.\-]+):(\d+)$", target)
    if m:
        return m.group(1), int(m.group(2)), ""
    return target.strip("/"), None, ""


# ── 1. check_conn：连通性预检（止损第一道闸） ───────────────────────────────

@register_tool(
    "check_conn",
    "网络连通性预检。访问靶场前先用它确认目标可达（TCP 端口或 ICMP）。"
    "返回不可达时立即止损换题，不要在连接超时上空烧轮次。"
    "target 支持 'host'、'host:port'、'http://host:port/path' 三种格式。",
    {
        "type": "object",
        "properties": {
            "target": {"type": "string",
                       "description": "目标，如 10.0.0.1、10.0.0.1:80、http://10.0.0.1:8080/"},
        },
        "required": ["target"],
    },
)
def check_conn(target: str) -> str:
    target = (target or "").strip()
    if not target:
        return "[参数错误] target 不能为空"

    host, port, _ = _parse_target(target)
    lines = []

    if port:
        try:
            t0 = time.time()
            with socket.create_connection((host, port), timeout=5):
                pass
            ms = int((time.time() - t0) * 1000)
            lines.append(f"[OPEN] TCP {host}:{port} 可达 ({ms}ms)")
            lines.append("[结论] 目标可达，直接开始解题。")
            return "\n".join(lines)
        except Exception as e:
            lines.append(f"[CLOSED] TCP {host}:{port} 连接失败: {type(e).__name__}: {e}")

    if _which("ping"):
        out = run_cmd(["ping", "-c", "2", "-W", "2", host], timeout=10)
        ok = "1 received" in out or "2 received" in out
        lines.append(f"[{'OPEN' if ok else 'CLOSED'}] ICMP {host}: {'在线' if ok else '不在线/禁 ping'}")

    lines.append(
        "[结论] 目标不可达。检查地址/端口是否抄对（常见：http→80, https→443）；"
        "确认无误仍不通 → 网络或容器未就绪，应止损换题，不要反复重试。"
    )
    return "\n".join(lines)


# ── 2. wordlist：字典路径索引（省掉 ls 猜路径的轮次） ────────────────────────

_WORDLIST_CANDIDATES = {
    "dir": [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    ],
    "dir_big": [
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    ],
    "ext": [
        "/usr/share/wordlists/dirb/extensions_common.txt",
        "/usr/share/seclists/Discovery/Web-Content/web-extensions.txt",
    ],
    "pass": [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/rockyou.txt.gz",
        "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
    ],
    "user": [
        "/usr/share/wordlists/metasploit/unix_users.txt",
        "/usr/share/seclists/Usernames/Names/names.txt",
        "/usr/share/wordlists/dirb/others/names.txt",
    ],
    "dns": [
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/usr/share/wordlists/dnsmap.txt",
    ],
    "params": [
        "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
        "/usr/share/wordlists/dirb/others/..",
    ],
}

_wordlist_linecount_cache = {}


def resolve_wordlist(list_type: str):
    """解析字典类型 → 可用绝对路径。返回 (path, note) 或 (None, err)"""
    cands = _WORDLIST_CANDIDATES.get(list_type, [])
    for p in cands:
        if os.path.isfile(p):
            note = ""
            if p.endswith(".gz"):
                # rockyou.txt.gz：john/hashcat 不能直接读 gz，先解压到 /tmp
                plain = "/tmp/" + os.path.basename(p)[:-3]
                if not os.path.isfile(plain):
                    run_cmd(["bash", "-c", f"gunzip -kc {p} > {plain}"], timeout=60)
                if os.path.isfile(plain):
                    return plain, "已从 gz 解压到 /tmp（john/hashcat 不支持 gz）"
                note = "gz 解压失败，可手动: gunzip -k " + p
            return p, note
    return None, f"未找到 {list_type} 类字典，候选路径均不存在: {cands}"


@register_tool(
    "wordlist",
    "返回指定类型字典的绝对路径与行数（dir=目录爆破, dir_big=大字典, ext=后缀, "
    "pass=rockyou密码, user=用户名, dns=子域名, params=参数名）。"
    "爆破/扫描前先用它拿路径，不要自己猜 /usr/share/wordlists 下的文件名。",
    {
        "type": "object",
        "properties": {
            "list_type": {"type": "string",
                          "enum": ["dir", "dir_big", "ext", "pass", "user", "dns", "params"]},
        },
        "required": ["list_type"],
    },
)
def wordlist(list_type: str) -> str:
    path, note = resolve_wordlist(list_type)
    if not path:
        return f"[MISSING] {note}\n[下一步] 安装: sudo apt install seclists wordlists"
    if path not in _wordlist_linecount_cache:
        out = run_cmd(["bash", "-c", f"wc -l < '{path}'"], timeout=15)
        try:
            _wordlist_linecount_cache[path] = int(out.strip() or 0)
        except ValueError:
            _wordlist_linecount_cache[path] = 0
    lines = [f"[OK] {path} ({_wordlist_linecount_cache[path]} 行)"]
    if note:
        lines.append(f"[INFO] {note}")
    usage = {
        "dir": "gobuster dir -u URL -w <path> -t 30 -q",
        "dir_big": "目录多时用大字典（耗时更长，先试 dir）",
        "ext": "gobuster dir -x php,txt,bak,html -w <path>",
        "pass": "hydra -L users.txt -P <path> ... / john --wordlist=<path> hash.txt",
        "user": "hydra -L <path> -P pass.txt ...",
        "dns": "gobuster dns -d domain -w <path>",
        "params": "ffuf -u 'URL?FUZZ=test' -w <path> -fs <size>",
    }.get(list_type, "")
    if usage:
        lines.append(f"[用法] {usage}")
    return "\n".join(lines)


# ── 3. searchsploit_query：本地 exploit-db 检索 ──────────────────────────────

@register_tool(
    "searchsploit_query",
    "本地 Exploit-DB 检索。nmap -sV 拿到服务版本后用它找现成 exploit。"
    "返回 EDB 编号与本地 exploit 路径（/usr/share/exploitdb/exploits/... 可直接 read_file）。",
    {
        "type": "object",
        "properties": {
            "query": {"type": "string",
                      "description": "检索词，带版本号更准，如 'Apache 2.4.49' 'vsftpd 2.3.4'"},
        },
        "required": ["query"],
    },
)
def searchsploit_query(query: str) -> str:
    if not _which("searchsploit"):
        return "[MISSING] searchsploit 未安装（sudo apt install exploitdb）"
    cache_key = f"sxp:{query}"
    cached = check_exec_cache(cache_key)
    if cached:
        return cached
    out = run_cmd(["searchsploit", "-j", query], timeout=60)
    # searchsploit -j 输出 JSON；解析出前 10 条：标题 + 本地路径
    import json as _json
    results = []
    try:
        data = _json.loads(out[out.index("{"):])
        for e in (data.get("RESULTS_EXPLOIT") or [])[:10]:
            path = e.get("Path") or ""
            if path and not path.startswith("/"):
                path = f"/usr/share/exploitdb/exploits/{path}"
            results.append(f"- {e.get('Title')} | {e.get('Type')} | EDB-{e.get('EDB-ID')} | {path}")
    except Exception:
        pass
    if not results:
        body = _truncate(out, 2000)
        result = f"[EMPTY] 未检索到 '{query}' 相关 exploit。\n[原文]\n{body}"
    else:
        flags = _grep_flags(out)
        body = "\n".join(results)
        result = f"[FOUND] {len(results)} 条（显示前 10）:\n{body}\n" \
                 f"[下一步] 用 read_file 读取对应 exploit 路径，看使用条件后适配目标。"
        if flags:
            result += f"\n[FLAG] 输出中出现疑似 flag: {flags}"
    store_exec_cache(cache_key, result)
    return result


# ── 4. full_recon：组合侦察流水线（把 5 轮变 1 轮） ──────────────────────────

@register_tool(
    "full_recon",
    "一键组合侦察：Web 目标=whatweb指纹+响应头+robots.txt+目录扫描；"
    "主机目标=nmap服务版本识别。第一步侦察就用它，替代多次单工具往返。"
    "target 支持 URL 或 host[:port]。mode: auto(按格式判断)/web/host。",
    {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "如 http://10.0.0.1:8080/ 或 10.0.0.1"},
            "mode": {"type": "string", "enum": ["auto", "web", "host"]},
        },
        "required": ["target"],
    },
)
def full_recon(target: str, mode: str = "auto") -> str:
    target = (target or "").strip()
    if not target:
        return "[参数错误] target 不能为空"

    cache_key = f"recon:{target}:{mode}"
    cached = check_exec_cache(cache_key)
    if cached:
        return cached

    host, port, scheme = _parse_target(target)
    if mode == "auto":
        mode = "web" if (scheme or (port and port in (80, 443, 8080, 8000, 8443, 5000, 3000))) else "host"

    sections = []
    all_text = ""

    if mode == "web":
        url = target if scheme else f"http://{host}" + (f":{port}" if port else "")
        # 连通性预检（失败直接止损，不浪费时间扫）
        pre = check_conn(url)
        if "[CLOSED]" in pre and "[OPEN]" not in pre:
            return f"[RECON-ABORT] 目标不可达，侦察中止。\n{pre}"

        if _which("whatweb"):
            out = run_cmd(["whatweb", "--color=never", "-a", "1", url], timeout=45)
            sections.append(f"[指纹 whatweb]\n{_truncate(out, 1200)}")
            all_text += out
        else:
            sections.append("[指纹 whatweb] 未安装，跳过")

        headers = run_cmd(["curl", "-sI", "-m", "10", url], timeout=15)
        sections.append(f"[响应头]\n{_truncate(headers, 1200)}")
        all_text += headers

        body = run_cmd(["curl", "-s", "-m", "10", url], timeout=15)
        sections.append(f"[首页 HTML 前 2000 字符]\n{_truncate(body, 2000)}")
        all_text += body

        robots = run_cmd(["curl", "-s", "-m", "10", f"{url}/robots.txt"], timeout=15)
        if robots and "[无输出]" not in robots and "<html" not in robots.lower():
            sections.append(f"[robots.txt]\n{_truncate(robots, 800)}")
            all_text += robots

        wl, _ = resolve_wordlist("dir")
        if wl and _which("gobuster"):
            gob = run_cmd(["gobuster", "dir", "-u", url, "-w", wl, "-t", "20",
                           "-q", "--no-error", "-b", "404,403", "--timeout", "10s"],
                          timeout=90)
            sections.append(f"[目录 gobuster(common)]\n{_truncate(gob, 2000) or '[无发现]'}")
            all_text += gob

        common_files = ["/flag", "/flag.txt", "/console", "/.git/HEAD", "/admin",
                        "/login", "/index.php.bak", "/www.zip", "/.env"]
        found = []
        for f in common_files:
            code = run_cmd(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                            "-m", "5", url + f], timeout=10).strip()
            if code and code not in ("404", "000", "301", "302"):
                found.append(f"{f} → HTTP {code}")
        if found:
            sections.append("[常见敏感路径命中]\n" + "\n".join(found))
            all_text += "\n".join(found)
    else:
        # host 模式：nmap 服务版本
        pre = check_conn(target if port else host)
        if "[CLOSED]" in pre and "[OPEN]" not in pre:
            return f"[RECON-ABORT] 目标不可达，侦察中止。\n{pre}"
        if _which("nmap"):
            out = run_cmd(["nmap", "-sV", "--top-ports", "100", "-T4",
                           "--host-timeout", "90s", host], timeout=120)
            sections.append(f"[nmap -sV top100]\n{_truncate(out, 3000)}")
            all_text += out
        else:
            sections.append("[nmap] 未安装")
        # 常见 web 端口顺手探一下指纹
        if _which("whatweb"):
            for p in (80, 443, 8080, 8000):
                out = run_cmd(["curl", "-sI", "-m", "5", f"http://{host}:{p}/"], timeout=10)
                if "HTTP/" in out:
                    sections.append(f"[端口 {p} 响应头]\n{_truncate(out, 600)}")
                    all_text += out

    flags = _grep_flags(all_text)
    sections.append("[结论] " + (
        f"⚠️ 输出中出现疑似 flag: {flags}" if flags
        else "侦察完成。基于以上指纹/版本/目录决定下一步：有版本号→searchsploit_query；"
             "有登录页→弱口令/注入；有可疑目录→read_file/curl 深入。"))
    result = "\n\n".join(sections)
    store_exec_cache(cache_key, result)
    return result


# ── 5. env_selfcheck：环境自检（防「必败」事故） ─────────────────────────────

@register_tool(
    "env_selfcheck",
    "检查本机解题环境：常用工具是否安装、字典是否在位、Python 库是否可用。"
    "开始解题前调用一次；发现缺失时避开依赖该工具的路线（或提示用户安装），"
    "避免跑到一半才发现工具不存在。",
    {"type": "object", "properties": {}},
)
def env_selfcheck() -> str:
    bins = ["nmap", "gobuster", "whatweb", "curl", "sqlmap", "hydra", "john", "hashcat",
            "hashid", "tshark", "binwalk", "exiftool", "gdb", "one_gadget", "patchelf",
            "searchsploit", "php", "zbarimg", "steghide", "foremost", "zsteg", "7z",
            "pdfimages", "mutool", "openssl", "strings", "file"]
    py_mods = ["pwn", "Crypto", "sympy", "gmpy2", "itsdangerous", "fpylll"]

    ok, missing = [], []
    for b in bins:
        (ok if _which(b) else missing).append(b)

    mod_missing = []
    for m in py_mods:
        try:
            __import__(m)
        except ImportError:
            mod_missing.append(m)
        except ValueError as e:
            # pwntools import 时注册 signal handler，非主线程会抛
            # "signal only works in main thread"——库本身在位，不算缺失
            # （d-03 就死在这里：env_selfcheck 被并发 worker 线程调用）
            print(f"[env_selfcheck] {m} 在子线程无法 import（signal 限制），视为可用: {e}")

    lines = [f"[OK] 可用工具 ({len(ok)}): {' '.join(ok)}"]
    if missing:
        lines.append(f"[MISSING] 缺失命令 ({len(missing)}): {' '.join(missing)}")
        install_map = {
            "gdb": "gdb", "patchelf": "patchelf", "zbarimg": "zbar-tools",
            "steghide": "steghide", "foremost": "foremost", "one_gadget": "gem install one_gadget",
            "zsteg": "gem install zsteg", "sqlmap": "sqlmap", "tshark": "wireshark-cli",
        }
        apt_pkgs = [install_map.get(b) for b in missing if install_map.get(b)]
        if apt_pkgs:
            lines.append("[安装] sudo apt install -y " + " ".join(dict.fromkeys(apt_pkgs)))
    if mod_missing:
        pip_map = {"pwn": "pwntools", "Crypto": "pycryptodome", "gmpy2": "gmpy2",
                   "itsdangerous": "itsdangerous", "fpylll": "fpylll"}
        lines.append("[MISSING] Python 库: " + " ".join(mod_missing))
        lines.append("[安装] pip install " + " ".join(pip_map.get(m, m) for m in mod_missing))

    # 字典
    wl_status = []
    for t in ("dir", "pass"):
        p, _ = resolve_wordlist(t)
        wl_status.append(f"{t}={'OK:' + p if p else 'MISSING'}")
    lines.append("[字典] " + "  ".join(wl_status))
    if any("MISSING" in s for s in wl_status):
        lines.append("[安装字典] sudo apt install -y seclists wordlists && gunzip /usr/share/wordlists/rockyou.txt.gz")

    lines.append(
        "[结论] 缺失项对应的解题路线不可用：解题时避开依赖缺失工具的路线"
        "（结果里已列出安装命令，可转告运维安装）。"
    )
    return "\n".join(lines)
