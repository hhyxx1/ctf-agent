"""Agent 主循环 - ReAct 范式，支持 function calling"""
import json
import logging
import re
import threading
import time
from typing import List, Dict
from config import config
from llm import llm, LLMQuotaExhausted
from tools import get_tools_schema, execute_tool
from tools.flag_tool import FLAG_PATTERNS, filter_flags
from utils.knowledge_base import search_knowledge

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """你是一个专业的 CTF（夺旗赛）自动解题 Agent，运行在 Kali Linux 上。

## 解题三阶段元策略（强制，省 token + 提命中率）

不许无方向 trial-error。每轮先自问"我在三阶段的哪一段"，再决定动作。

### 阶段 A · 定类（轮次 1-3，最多 3 轮就给出定类结论）
目标：**判定漏洞类**，不是解题。读题干/源码/探服务，输出一行结论：
`[定类] 类别=XXX 子类=YYY 关键入口=ZZZ`
- crypto: RSA / AES-CBC / AES-ECB / 古典 / 哈希 / 椭圆曲线 / 密码分析
- web: SQLi / XSS / SSRF / LFI/RFI / RCE / 反序列化 / SSTI/模板注入 / IDOR / 路径穿越 / 命令注入 / SpEL/表达式注入 / WAF绕过 / XSS(JSFuck黑名单绕过)
- pwn: 栈溢出 / 格式化字符串 / 堆 / ROP / ret2libc / ret2shellcode
- reverse: 伪代码分析 / z3 约束求解 / 二进制补丁 / 自修改代码 / ECS/VM 逆向
- forensics: 隐写 / 流量分析 / 内存分析 / 文件雕刻 / 加密容器
- misc: 编码谜题 / 脚本沙箱逃逸 / pickle 等危险反序列化

**定类要快**：源码题先 read_file/dist 源码 → grep 漏洞关键词（eval/exec/pickle/spel/template/waf/blacklist/process/runtime/flag）→ 3 轮内必须给出定类结论。
没定类前不要构造 payload，否则你在烧 token。

### 阶段 B · 套法（轮次 4-8，一次性构造 payload）
目标：**套对应方法论库（见下）构造 payload**，一次性构造完整，不要逐个试。
- 定类结论选方法论库中对应套路，按套路直接写 payload
- 一次构造好（爆破字典/注入串/绕过串/反序列链），别"试一个看一个"地浪费轮次
- payload 构造完立即进入阶段 C 验证

### 阶段 C · 验证（轮次 9-12，定向修正）
目标：**curl/提交验证**，失败则定向修正（不回阶段 A 重侦察）。
- 验证失败 = payload 不对，不是类没定准。直接改 payload（编码/绕过变体），别重读源码
- flag 命中后立即 extract_flag → submit_flag 收尾

### 早停信号（省 token，违反必烧）
- **连续 2 轮无新信息/无工具调用** → 你卡住了，输出 `[放弃] 类别=XXX 原因=YYY` 终止
- **同一 payload 变体连续 3 次失败** → 这条套路不通，换方法论库里的下一条
- **爆破类工具（hydra/hashcat/john）只在题干明示凭证场景用 1 次**，不中就弃
- 钻牛角尖 = 同一思路连续 3 轮没进展，必换思路或换题

## 通用方法论库（按类套用，不是按题）

> **重要约束**：方法论只描述技术套路（怎么构造 payload、绕过哪些过滤），**绝不指向具体题目的答案**。
> 你解的是"某一类问题"不是"某一题"，禁止从知识里抄答案 flag。

### Web · WAF/黑名单绕过（通用套路）
- 先读 WAF/过滤器源码：拦截哪些关键词？检查 query string 还是 body？黑名单 vs 白名单？
- 路径混淆：`/flag.txt` `/./flag.txt` `//flag.txt` `/%66lag.txt` `..;/flag.txt`
- 大小写/编码：`/FLAG.TXT` `/%2e%2e%2fflag` `/f%6cag.txt`（URL编码）
- 参数污染/双写：`?file=flag.txt&file=...` `?page=flflagag.txt`
- 若 WAF 只检查 query string：payload 放 POST body 或路径里绕过
- 若禁字母数字 `<>`：用 JSFuck 编码（`[]()!+` 构造），`pip install jsfuck` 失败就用在线 jsfuck.com
- 若禁单引号：用反引号 `alert(`+chr(96)+"XSS"+chr(96)+")` 或 `String.fromCharCode(88,83,83)`
- 可用冷门事件：`ontoggle/onfocus/onpointerenter`（如 details 标签 open+ontoggle=alert）

### Web · SpEL/表达式注入（Spring 应用）
- Spring `@Value` / 模板 `#{}` 是 SpEL，测试 country/name/email 等可控字段是否 SpEL 解析
- 读文件：`T(java.nio.file.Files).readAllLines(T(java.nio.file.Paths).get('/flag'))`
- 执行命令：`T(java.lang.Runtime).getRuntime().exec('cat /flag')`
- 若 Runtime/Process 被 WAF 禁：用 `javax.script.ScriptEngineManager` 加载 JS 引擎，或 `Thread.currentThread()` 链

### Web · SQLi / SSRF / IDOR / SSTI / 反序列化（通用套路）
- SQLi：sqlmap 一把梭，注入点用 `--data` 指定 POST body；dump 所有表找 admin 凭证和 flag
- SSRF：先读云元数据（169.254.169.254），拿 IAM 凭证后枚举 S3/对象存储
- IDOR：遍历 id 参数 `?id=1..100`，找其他用户数据/flag
- SSTI：`{{7*7}}` `{{config}}` 测试模板注入，Jinja2 `{{}}`、Twig `{{}}`、Freemarker `${}`
- 反序列化：pickle 用 `__reduce__` 构造 RCE 链；Java 用 ysoserial；PHP 用 phpggc

### Crypto · 各类套路
- RSA：第一步用 rsa_decrypt（自动 factordb/sympy/Fermat/小指数/共模），失败再 run_python
- AES-CBC：CBC 长度攻击（服务器对 padding error 不同响应）→ 逐字节恢复明文
- AES-ECB：ECB 重排攻击 / 块替换
- 古典/哈希：先 auto_decode，再 run_python 写解密脚本

### Pwn · 各类套路
- 栈溢出：binary_analyze → rop_gadget_search → exploit_template(ret2libc) → pwntools 调试
- 格式化字符串：读栈 → 泄露 canary/libc 基址 → 写 GOT/返回地址
- 堆：use after free / fastbin attack / unsorted bin leak

### Reverse · 各类套路
- 伪代码：ghidra_decompile → 读 main/validation 函数 → 找比较逻辑
- z3 约束求解：条件分支多 → 把约束喂 z3 求满足条件的输入
- 二进制补丁：jz/jnz 改跳转绕过校验；ECS/VM 逆向先识别 dispatch 表再 patch

### Forensics · 各类套路
- 隐写：steg_check（zsteg/steghide/foremost）→ 优先 LSB
- 流量：tshark `-r pcap -T fields -e data` 提取；TLS 私钥文件解密
- 内存：volatility `imageinfo → pslist → filescan → dumpfiles`
- 文件雕刻：foremost/photorec 恢复删除文件

### Misc · 沙箱逃逸
- pickle 沙箱：`__reduce__` 调用 `os.system`，若禁 os 用 `subprocess`/`builtins.eval` 链
- Python 沙箱：找 `__builtins__` / `__import__` / `subprocess` 残留，构造逃逸链

## 你的工具（按优先级使用）

### 专用工具（优先用这些，效率更高）
- **rsa_decrypt**: RSA 解密。自动尝试 factordb 在线查询 → sympy 小 n 分解 → Fermat 分解 → 小指数攻击 → 共模攻击。**RSA 题首选此工具，不要手写 sympy 分解大 n，会卡死。**
- **auto_decode**: 自动识别并解码 base64/hex/url/html/rot13/morse 等。收到不明字符串先试这个。
- **encode_data**: 编码数据（base64/hex/rot13 等）。
- **analyze_file**: 文件分析。自动执行 file + 文件头识别 + strings + binwalk + exiftool。拿到未知文件首选。
- **steg_check**: 隐写检测。zsteg + steghide + foremost + 文件末尾追加数据检查。图片题首选。

### 通用工具
- **run_shell**: 执行 shell 命令（nmap/sqlmap/hashcat/sage/file/strings/binwalk 等所有 Kali 工具）
- **run_python**: 执行 Python 代码（已装 sympy/pycryptodome/gmpy2/pwntools）
- **read_file / write_file / list_dir**: 读写文件、浏览目录
- **extract_flag**: 从文本中提取 flag
- **submit_flag**: 提交 flag 完成题目

### 组合分诊工具（一次调用顶多次往返，优先用）
- **check_conn**: 连通性预检。**首次访问靶场地址前先调它**，不可达立即报告止损，不要在超时上空烧
- **full_recon**: 一键侦察。web 目标=whatweb+响应头+robots+目录扫描+敏感路径；主机目标=nmap -sV。第一步侦察就调它
- **pwn_triage**: 二进制一键分诊：保护机制(checksec)+关键字符串+libc 版本+gadget+利用建议。pwn 题拿到附件第一件事调它
- **libc_identify**: 泄露地址 → libc 版本 + system//bin/sh 偏移。ret2libc 必用
- **one_gadget**: libc 一键找单发 getshell gadget（注意满足约束）
- **gdb_debug**: gdb 批处理调试（断点/寄存器/内存/崩溃回溯）。exploit 打不通时用它看真相，不要盲猜
- **pwn_local_setup**: 本地复现环境（patchelf 换 libc）。**先本地打通再打远程**
- **pcap_triage**: 流量包一键分诊（协议分布+HTTP/DNS+对象导出）。取证流量题先调它
- **memory_triage**: 内存镜像一键分诊（volatility3 管道或 strings 降级）
- **audio_steg / qr_decode / pdf_office_analyze**: 音频隐写 / 二维码 / PDF-Office 文档取证
- **hash_crack**: 哈希识别+自动破解（john/hashcat + rockyou 自动解压）
- **jwt_tool**: JWT 解码+弱密钥爆破+alg:none 变体构造
- **flask_unsign**: Flask session 解码/弱密钥爆破/伪造 admin
- **classical_cipher**: 古典密码自动求解（凯撒/维吉尼亚/单表替换/栅栏/Atbash，卡方打分）
- **lattice_lll**: LLL 格基规约（格密码/HNP/背包，自己构造好格再传）
- **php_filter_chain**: 生成 php://filter RCE 利用链（LFI 无写权限直接 RCE，生成后填进 include 参数）
- **wordlist**: 拿字典绝对路径（爆破/扫描前先调，不要猜路径）
- **searchsploit_query**: 本地 Exploit-DB 检索（nmap 出版本号后查现成 exploit）
- **env_selfcheck**: 环境自检（工具/字典/Python 库缺失会列出来，缺什么就避开依赖它的路线）

## 解题流程
1. **识别题型**: crypto / web / pwn / reverse / forensics / misc
2. **选择工具**: 根据题型选专用工具，通用需求用 run_shell/run_python
3. **逐步执行**: 每次调用一个工具，根据结果决定下一步
4. **提取 flag**: 找到 flag 后用 extract_flag 确认，再用 submit_flag 提交

## 认题硬规则（违反则必败）
**先读题干决定题型，再决定打法。题干里有什么就打什么，题干里没的端口/服务绝对不要碰。**
- 题干说"Web 应用/网站/审批系统/API/登录页"→ 只打 Web, 不碰 telnet(23)/SSH(22)/RDP(3389)/数据库(3306)/Redis(6379)等
- 题干说"数据库/SQL/图数据库/Gremlin"→ 打数据库注入/默认凭证, 不打其他端口
- 题干说"二进制/ELF/可执行文件/缓冲区"→ 打 pwn, 不扫 Web
- 题干明示某端口号/服务名→ 专心打它, 不分散扫别的
- 没扫到题干明示的端口/服务≠去碰其他端口, 是你的扫描姿势错了重扫即可

**钻牛角尖信号: 同一思路连续 3 轮没新进展, 必须换思路或换题。爆破类工具(hydra/hashcat/john)只允许在题干明示登录凭证场景下用一次, 不中就弃绝不再试。**

## 六大能力维度与工具选择

### 1. Web 漏洞挖掘
- **http_request**: 发送 HTTP 请求，测试 Web 应用
- **sqli_scan**: SQL 注入自动检测（sqlmap）
- **dir_scan**: 目录/文件扫描（gobuster）
- **web_fingerprint**: Web 指纹识别（whatweb）
- **vuln_scan**: 综合漏洞扫描（nikto）
- 流程: full_recon(一键侦察) → 按结果用 http_request 测试注入点 → sqli_scan / dir_scan 深挖

### 2. 二进制漏洞挖掘
- **pwn_triage**: 一键分诊（保护机制+libc 版本+gadget+建议）替代手动 file/checksec/strings
- **binary_analyze**: 综合分析（file/checksec/strings/readelf/objdump）
- **ghidra_decompile**: Ghidra headless 反编译为 C 伪代码
- **vuln_pattern_scan**: 危险函数和漏洞模式自动扫描
- 流程: pwn_triage → vuln_pattern_scan → ghidra_decompile (针对性反编译可疑函数)

### 3. 漏洞利用
- **rop_gadget_search**: 搜索 ROP gadget（ROPgadget）
- **exploit_template**: 生成 pwntools exploit 骨架（buffer_overflow/format_string/ret2libc/ret2shellcode）
- **run_python + pwntools**: 编写和运行 exploit
- **msfvenom_payload**: 生成反弹 shell payload
- **流程（铁律）**: pwn_triage → pwn_local_setup(有 libc 就换) → **本地打通** → 远程利用 → 失败用 gdb_debug 看回溯

### 4. 多阶段渗透
- **nmap_scan**: 网络端口和服务扫描（quick/full/vuln/stealth/udp）
- **hydra_brute**: 弱口令爆破（ssh/ftp/http/mysql/rdp）
- **linpeas_check**: Linux 提权检测
- **proxy_scan**: 通过 socks 代理扫描内网
- **tunnel_setup**: 建立加密隧道（ssh_reverse/ssh_dynamic/icmp/dns）
- 流程: nmap_scan → hydra_brute → 拿到 shell → linpeas_check → proxy_scan 横向移动

### 5. 云攻击
- **ssrf_metadata**: SSRF 打云元数据（aws/aliyun/tencent/gcp/azure）
- **aws_enum**: AWS 环境枚举和利用（whoami/s3_list/iam_enum/ec2_meta）
- **container_escape**: 容器逃逸检测（docker.sock/capabilities/privileged）
- 流程: ssrf_metadata 拿凭证 → aws_enum 枚举资源 → container_escape 尝试逃逸

### 6. 对抗规避
- **shellcode_encode**: Shellcode 编码混淆（xor/alpha/base64）
- **msfvenom_payload**: 生成免杀 payload（编码器: shikata_ga_nai 等）
- **evade_check**: 检测 AV/EDR/沙箱/调试器
- **tunnel_setup**: 加密隧道绕过网络监控
- 流程: evade_check 侦察 → shellcode_encode/msfvenom_payload 生成免杀 payload → tunnel_setup 建立隐蔽通道

## 按传统题型的工具选择

### Crypto (RSA)
- **第一步永远用 rsa_decrypt**，它会自动尝试多种攻击
- 传参: n, e, c 都用字符串传（大数）
- 如果 rsa_decrypt 失败，再用 run_python 手动尝试 Wiener 攻击等
- **绝对不要用 run_python + sympy.factorint 分解大 n，会卡死**

### Crypto (其他)
- AES/DES: 用 run_python + pycryptodome
- 编码题: 先用 auto_decode，失败再手动分析
- 古典密码: 用 classical_cipher（凯撒/维吉尼亚/单表/栅栏自动打分），失败再 run_python

### Forensics / Misc
- **拿到文件第一步用 analyze_file**
- 图片题用 steg_check 检测隐写
- 流量题用 **pcap_triage**（一键协议分布/HTTP 对象导出），深挖再 run_shell tshark 逐流
- 内存题用 **memory_triage**（volatility3 管道）
- 音频/二维码/Office 宏: audio_steg / qr_decode / pdf_office_analyze
- 编码题用 auto_decode

## 重要规则
- **一次只调用一个工具**，等结果出来再决定下一步
- 每步简短说明你在做什么、为什么
- 如果一个方法失败，分析原因后换思路
- **找到 flag 后必须调用 submit_flag 提交**
- 不要编造结果，只报告工具实际返回的内容
- 大数运算用字符串传参，避免 JSON 精度问题

## 漏洞利用深度原则（重要）
发现漏洞后不要只停留在"证明漏洞存在"，必须深入利用拿 flag:
- **LFI/文件读取**: 读到源码后继续读 config.php/数据库配置/环境变量文件/flag 文件
  - 常见 flag 路径: /flag, /flag.txt, /var/www/html/flag, /app/flag, /home/*/flag*
  - 读 config.php 找数据库凭证，再读数据库
  - 读 .env / /proc/self/environ 找环境变量中的凭证
- **SQL 注入**: 注入成功后立即 dump 所有表，找 admin凭证和 flag
- **命令注入**: 执行 `cat /flag*; cat /app/flag*; ls -la /; find / -name "flag*" 2>/dev/null`
- **SSRF**: 读完元数据后用拿到的 IAM 凭证枚举 S3/对象存储里的 flag
- **JDWP/RCE**: 拿到 shell 后第一件事 `cat /flag*; find / -name "flag*" 2>/dev/null`

**发现可利用漏洞后，下一步必须是利用它拿 flag，而不是继续找别的漏洞。**

## 高效工具用法
- **交互式会话**：pwn 本地调试、nc/数据库/ssh 多步交互用 shell_open（会话保持存活）→ shell_send 发输入 → shell_read 读回显，不要反复 run_shell 重建状态
- **JS 渲染页面**：页面内容靠 JS 生成、或要验证 XSS 触发后的 DOM 变化，用 browser_render（执行 JS 后返回 DOM），curl 看不到的它能看到
- **flag 自动提交**：任何工具输出里出现 flag{...}，系统会自动提交平台并回填结果——你无需重复提交同一个 flag；看到【自动提交】里"平台确认正确"即可继续找剩余 flag 或收尾
"""


# 题型专用 system_prompt 补充（子 Agent 工厂用；分类仅供参考，避免分类错无解）
CATEGORY_PROMPTS = {
    "web": "\n\n## 题型聚焦（Web）\n专注于 Web 漏洞利用：源码泄露(.bak/.swp/www.zip)、文件上传(后缀/图片马+触发执行)、"
           "反序列化(POP链)、LFI/php://filter、SSRF、SQLi。分类仅供参考——若发现实际是其他类型，用 run_shell 探索。",
    "pwn": "\n\n## 题型聚焦（Pwn）\n专注于二进制利用：栈溢出/格式化字符串/堆UAF(见方法) → 泄露地址 → RCE。"
           "注意单轮提速（≤3 变体、socket timeout 收紧）。分类仅供参考——若发现实际是其他类型，用 run_shell 探索。",
    "crypto": "\n\n## 题型聚焦（Crypto）\n专注于密码学：RSA(弱密钥/共模/小指数)、AES、编码套娃(base64/hex/rot)、"
              "从加密脚本源码找算法。分类仅供参考——若发现实际是其他类型，用 run_shell 探索。",
    "misc": "\n\n## 题型聚焦（Misc/取证）\n专注于：附件分析(file/steg/流量pcap/压缩包)、隐写、编码解码、"
            "解压套娃。分类仅供参考——若发现实际是其他类型，用 run_shell 探索。",
}


# 压缩时保留的关键行模式（flag/凭证/URL/泄露地址/错误——丢了会触发模型重做侦察）
_SUMMARY_KEY_LINE_RE = re.compile(
    r"flag|passw|secret|token|key[=:\s]|credential|http|url|jdbc|mysql|admin"
    r"|0x[0-9a-f]{6,}|uid=|error|exception|denied|success|confirmed",
    re.I,
)


def _summarize_tool_output(content: str, max_len: int = 400) -> str:
    """长 tool 结果的摘要：头部 + 关键行（替代纯硬截断，保住侦察关键信息）"""
    orig = len(content)
    head = content[:int(max_len * 0.55)]
    keep = [ln.strip()[:200] for ln in content.splitlines()
            if _SUMMARY_KEY_LINE_RE.search(ln)][:14]
    summary = head + ("\n" + "\n".join(keep) if keep else "")
    if len(summary) > max_len:
        summary = summary[:max_len]
    return summary + f"\n...[已压缩: 原文 {orig} 字符，仅保留头部与关键行]..."


# 中文否定词（窗口内出现则不算"找到"）
_SIGNAL_NEGATIONS = ("没", "未", "尚", "别", "无法", "难", "找不到")
# 英文否定前缀（"haven't found the flag" 不算迹象）
_SIGNAL_NEG_EN = ("not ", "n't", "haven", "couldn", "didn", "fail")


def _flag_text_positive(content: str) -> bool:
    """文本级「快找到 flag」迹象判定，带否定排除：
    - 明确正句（"flag 候选"/"已命中 flag"/"found the flag"）→ 迹象
    - 中文"找到"+附近"flag" → 排除否定前缀（"还没找到 flag" 不算！否则止损永不触发）
    """
    if "flag 候选" in content or "已命中 flag" in content or "已获得 flag" in content:
        return True
    # 英文正句（含否定排除）
    for m in re.finditer(r"found the flag|got the flag|flag captured", content, re.I):
        window = content[max(0, m.start() - 20):m.start()].lower()
        if not any(neg in window for neg in _SIGNAL_NEG_EN):
            return True
    # 中文「找到 ... flag」（含否定排除）
    for m in re.finditer(r"找到", content):
        window = content[max(0, m.start() - 4):m.start()]
        if any(neg in window for neg in _SIGNAL_NEGATIONS):
            continue
        tail = content[m.end():m.end() + 12].lower()
        if "flag" in tail:
            return True
    return False


def _detect_signal(messages: List[Dict]) -> bool:
    """检测快解出迹象（并行方向暂停其他方向用，省 token）——只认强事件：
    - assistant 消息里出现真 flag 文本（tool 输出不算：web 题读二进制时 0x7f/垃圾太常见）
    - 提交/提取 flag 的工具调用（submit_flag / extract_flag）
    注意：不再把「写 exploit 脚本」「输出含 0x7f 泄露地址」当迹象——这些在 web/多阶段题里
    每几轮就出现一次，会让并行方向永远不提前停。
    """
    for m in messages[-8:]:  # 只看最近几轮
        if m.get("role") == "assistant":
            content = m.get("content", "")
            if isinstance(content, str) and _flag_text_positive(content):
                return True
        for tc in m.get("tool_calls", []) or []:
            fn = (tc.get("function") or {}).get("name", "")
            if fn in ("submit_flag", "extract_flag"):
                return True
    return False


# 无进展换思路提示：按题型给攻击面方向（避免 agent 在同一终点的变体里打转）
CATEGORY_TIPS = {
    "web": "flag 若不在当前方向（如文件系统/接口），换攻击面：试 admin 登录(弱口令/SQLi 绕过 admin'-- -)/其他功能/接口/dashboard——登录后页面常藏 flag。",
    "pwn": "flag 若不在当前方向，换利用链：泄露→覆盖→RCE（试其他漏洞点/偏移/堆风水）。",
    "crypto": "flag 若不在当前方向，换算法思路：弱密钥/共模/小指数/编码套娃。",
    "misc": "flag 若不在当前方向，换数据来源：隐写/流量/压缩包/编码。",
    "unknown": "多阶段渗透/漏洞利用链题: 每阶段 1 个 flag——记录阶段进度逐步推进（提权/横向/进内网），提取 flag 后继续找下一阶段（total_flag_count 提示剩余），勿提交一个就停。",
}
GENERIC_TIP = "flag 若不在当前方向，换攻击面而非同一终点的变体（试其他功能/入口/接口）。"

# 卡死时并行子 Agent 的备选方向（按题型；每题只补一个方向，防 token 翻倍）
_ALT_DIRECTIONS = {
    "web": ["专注 SQL 注入/后台弱口令 → 进数据库或后台 dump flag",
            "专注文件上传/LFI/命令注入 → 拿 webshell 读 flag 文件"],
    "pwn": ["专注格式化字符串/泄露 → ret2libc 完整利用链",
            "专注堆利用（tcache/UAF/fastbin）→ 劫持执行流"],
    "crypto": ["专注 RSA 参数弱点（Wiener/共模/小指数/Fermat）",
               "专注编码套娃/古典密码/哈希分析"],
    "misc": ["专注隐写（通道分离/zsteg/binwalk/音频）",
             "专注流量/内存取证 → 文件提取"],
}


def _maybe_spawn_parallel_child(agent: "Agent", task: str) -> str:
    """T2-⑦ 卡死时同题多方向并行：主方向无迹象达阈值 → 起一个不同方向的子 Agent 并行。

    两个方向共享 _solved_event：任一方向提交正确 → 事件置位 → 另一方下轮退出。
    返回附加到换思路提示末尾的说明文字（不追加独立 user 消息，避免消息错乱）。
    """
    if not config.MULTI_DIRECTION_ENABLED or agent.direction or agent._child_thread:
        return ""
    # easy 题预算紧（快速止损换题），不值得多方向并行烧 token
    if agent.budget["no_progress_hint"] <= 30:
        return ""
    if agent.category not in _ALT_DIRECTIONS:
        return ""
    direction = _ALT_DIRECTIONS[agent.category][0]
    task_text = agent._task_text
    solved_event = agent._solved_event
    ch_id = agent.challenge_id
    cat = agent.category

    def _run_child():
        try:
            child = build_agent(cat, direction=direction, challenge_id=ch_id)
            child._task_text = task_text
            child._solved_event = solved_event
            child.global_stop = agent.global_stop  # 继承全局停止信号（Ctrl+C 时一起停）
            child.run(task_text, verbose=False,
                      max_iterations=config.PARALLEL_ROUNDS, stop_event=solved_event)
        except LLMQuotaExhausted:
            pass  # 子方向配额耗尽不炸主方向；主方向下次调用会自行抛出
        except Exception as e:
            logger.warning(f"并行方向子 Agent 异常退出: {e}")

    agent._child_thread = threading.Thread(
        target=_run_child, daemon=True, name=f"alt-{cat}-{ch_id}")
    agent._child_thread.start()
    print(f"  🌿 卡死触发：已并行启动不同方向子 Agent（{direction}）")
    return (f" 同时已另起一个不同方向并行的子 Agent（{direction}），"
            "哪个方向先提交成功即完成解题——专注本方向，不要等对方。")


def build_agent(category: str = "", direction: str = "", **kwargs):
    """子 Agent 工厂：按题型生成专用 system_prompt + 工具子集。

    - category: 题型（web/pwn/crypto/misc），决定工具子集 + 题型聚焦 prompt
    - direction: 附加解题方向（多方向并行用，如 "专注 tcache poisoning → free_hook"），
      方法论语——让该子 Agent 只专注一个方向不跑偏
    """
    cat = (category or "").lower()
    sys_prompt = SYSTEM_PROMPT + CATEGORY_PROMPTS.get(cat, "")
    if direction:
        sys_prompt += f"\n\n## 本次解题方向（专注此方向，不要跑偏）\n{direction}"
    return Agent(system_prompt=sys_prompt, category=cat, direction=direction, **kwargs)


class Agent:
    def __init__(self, system_prompt: str = SYSTEM_PROMPT, category: str = "", direction: str = "",
                 challenge_id: str = "", temperature: float = None, budget: dict = None):
        # KV Cache 友好：system prompt 必须是静态常量，工具注册也静态生成（勿动态注入时间/状态）。
        # 动态信息（时间戳/变色内容）只能作为新消息 append 到 messages 末尾，绝不改 system prompt。
        self.messages: List[Dict] = [{"role": "system", "content": system_prompt}]
        self.iteration = 0
        # 子 Agent：按题型过滤工具子集（题型优先生成 + 通用兜底 run_shell 等，分类错也能解）
        self.tools = get_tools_schema(category)
        self.direction = direction  # 并行方向（多方向并行时各自专注；无进展提示带方向约束用）
        self.category = category  # 题型（换思路提示按题型给攻击面方向用）
        self.challenge_id = challenge_id  # 自动提交 flag 用（平台提交 API 需要 unique_code）
        self.llm_temperature = temperature  # None→全局配置；重试轮传更高温强制方向多样性
        # 动态预算（按难度）：无迹象提示轮数 / 提示后止损轮数（easy 紧、hard 松）
        self.budget = {"no_progress_hint": 50, "no_progress_giveup": 15}
        if budget:
            self.budget.update(budget)
        self.found_flag = False
        self.submitted = False
        self._last_has_tool_calls = False  # 本轮是否调用工具（空转/无进展判定用）
        self._no_flag_rounds = 0  # 连续无 extract_flag/submit_flag 动作的轮数（B1 失败收敛检测）
        self._flag_hint_done = False  # 聚焦提 flag 提示只发一次
        self._run_log: List[Dict] = []  # per-round 详细日志（用于导出，不进入 LLM 上下文）
        self._auto_submitted: set = set()  # 自动提交钩子已提交过的 flag（防重复提交）
        self._solved_event = None  # 多方向并行：任一方向提交正确 → set，其他方向提前停
        self._child_thread = None  # 多方向并行子 Agent 线程（run 结束时 join 收尾）
        self._task_text = ""  # 原始任务（多方向并行子 Agent 需要同一题目任务）
        self.global_stop: threading.Event = None  # 全局停止信号（solver 在用户 Ctrl+C 时 set）

    def _compress_history(self, threshold: int = 40, keep_tail: int = 10, max_len: int = 400):
        """上下文压缩（P1a）：messages 超阈值时，把早期 tool 结果压缩为摘要。

        - 只压缩"system 之后、尾部 keep_tail 条之前"的 tool 消息 content
        - 保留 role/tool_call_id 结构 → assistant.tool_calls → tool 响应链完整（deepseek 要求）
        - 摘要 = 头部 + 关键行（flag/凭证/URL/泄露地址等），而非硬截断——
          硬截断会丢掉早期侦察关键信息，模型会重做侦察多烧轮次
        """
        if len(self.messages) <= threshold:
            return
        for i in range(1, len(self.messages) - keep_tail):
            m = self.messages[i]
            role = m.get("role")
            content = m.get("content")
            if role == "tool" and isinstance(content, str) and len(content) > max_len:
                m["content"] = _summarize_tool_output(content, max_len)
            elif role == "assistant" and isinstance(content, str) and len(content) > 600 \
                    and not m.get("tool_calls"):
                # assistant 长分析同样压缩（c-03 跑到 98 轮时单轮 141k token 的主因之一：
                # 每轮几百字的分析全文永久留在上下文里，只压 tool 消息拦不住线性膨胀）
                m["content"] = _summarize_tool_output(content, max_len)

    def _auto_submit_flags(self, raw_result: str, result_str: str) -> str:
        """T1 自动提交钩子：工具输出里出现新 flag → 直接提交平台，结果回填 tool 消息。

        不依赖模型自觉调 submit_flag（实测模型常找到 flag 后先写长分析甚至忘提交）。
        错提无惩罚（平台判 incorrect 不扣分），漏提/晚提才亏轮次。
        """
        if not self.challenge_id or self.submitted:
            return result_str
        found: List[str] = []
        for pat in FLAG_PATTERNS:
            try:
                found.extend(re.findall(pat, raw_result))
            except re.error:
                pass
        found = filter_flags(found)  # 丢弃 flag{...}/flag{xxx} 之类占位符
        outs = []
        for flag in dict.fromkeys(found):
            if flag in self._auto_submitted:
                continue
            self._auto_submitted.add(flag)
            _t0 = time.time()
            sr = execute_tool("submit_flag", {"flag": flag, "challenge_id": self.challenge_id})
            sr_str = str(sr)
            # 「提交成功」只代表平台收到；是否真的正确要看 correct_flag_count（为 0 就是错的，
            # 之前 CSS 片段被判「成功」就是这个原因——平台对任何格式都返回提交成功）
            _mc = re.search(r'"correct_flag_count":\s*(\d+)', sr_str)
            _tc = re.search(r'"total_flag_count":\s*(\d+)', sr_str)
            ok = "[提交成功]" in sr_str and (_mc is None or int(_mc.group(1)) > 0)
            if self._run_log:
                self._run_log[-1]["tool_calls"].append({
                    "name": "_auto_submit",
                    "arguments": {"flag": flag},
                    "elapsed_sec": round(time.time() - _t0, 2),
                    "result_preview": sr_str[:500],
                    "result_full_len": len(sr_str),
                })
            logger.info(f"自动提交 flag: {flag} → {'成功' if ok else '不正确'}")
            if ok:
                self.found_flag = True
                if not (_mc and _tc and int(_mc.group(1)) < int(_tc.group(1))):
                    self.submitted = True
                    if self._solved_event:
                        self._solved_event.set()
                outs.append(f"{flag} → ✅ 平台确认正确")
            else:
                outs.append(f"{flag} → ❌ 平台判定不正确")
        if outs:
            result_str = result_str + (
                "\n\n【自动提交】" + "；".join(outs)
                + ("\n已全部提交成功，若题目确认完成可停止解题。"
                   if self.submitted else
                   "\n不正确说明该 flag 是假的/中间产物，需通过真实漏洞利用拿最终输出。继续解题。")
            )
        return result_str

    def _call_llm(self) -> str:
        """调用 LLM，处理 tool_calls"""
        import time as _time
        _t0 = _time.time()
        response = llm.chat(self.messages, tools=self.tools, temperature=self.llm_temperature)
        _llm_elapsed = round(_time.time() - _t0, 2)
        choice = response.choices[0]
        msg = choice.message
        # 记录本轮是否调用了工具（空转判定用——不能看 messages[-1]，调工具后末尾是 tool 结果消息）
        self._last_has_tool_calls = bool(msg.tool_calls)
        # ── 日志记录 ──
        _usage = getattr(response, "usage", None)
        _usage_dict = {}
        if _usage:
            _usage_dict = {
                "prompt_tokens": getattr(_usage, "prompt_tokens", None),
                "completion_tokens": getattr(_usage, "completion_tokens", None),
                "total_tokens": getattr(_usage, "total_tokens", None),
            }
        self._run_log.append({
            "round": self.iteration,
            "timestamp": _time.strftime("%Y-%m-%d %H:%M:%S"),
            "llm_elapsed_sec": _llm_elapsed,
            "usage": _usage_dict,
            "has_tool_calls": self._last_has_tool_calls,
            "llm_reasoning": (getattr(msg, "reasoning_content", None) or "")[:2000],
            "llm_output": (msg.content or "")[:3000],
            "tool_calls": [],
        })

        # 把 assistant 消息加入历史（包括 tool_calls）
        assistant_msg = {"role": "assistant", "content": msg.content or ""}
        # deepseek thinking 模式要求回传 reasoning_content（否则 400: must be passed back to the API）
        rc = getattr(msg, "reasoning_content", None)
        if rc:
            assistant_msg["reasoning_content"] = rc
        if msg.tool_calls:
            assistant_msg["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
                for tc in msg.tool_calls
            ]
        self.messages.append(assistant_msg)

        # 如果没有 tool_calls，说明 Agent 在说话，直接返回内容
        if not msg.tool_calls:
            return msg.content or ""

        # 处理每个 tool_call
        results = []
        for tc in msg.tool_calls:
            name = tc.function.name
            _t_tool0 = _time.time()
            # JSON 解析失败先尝试宽松恢复（ast 兼容单引号/尾逗号——模型写长代码时转义常出错）；
            # 仍失败则不执行工具，把原文片段回显给模型（c-04/b-01 死因：静默置 {} 让模型
            # 一直看到"missing arguments"却不知道自己的 JSON 坏了，死循环到预算烧完）
            raw_args = tc.function.arguments or ""
            args = None
            try:
                args = json.loads(raw_args)
            except json.JSONDecodeError:
                try:
                    import ast
                    args = ast.literal_eval(raw_args)
                    if not isinstance(args, dict):
                        args = None
                except Exception:
                    args = None
            if args is None:
                result_str = (
                    "[参数解析失败] 你这次 tool_call 的 arguments 不是有效 JSON，工具没有执行。"
                    f"原始内容（前 400 字符）：{raw_args[:400]!r}\n"
                    "常见原因：代码/文本里的引号或换行没有正确 JSON 转义。"
                    "请修正转义（或改用 run_shell heredoc 写文件）后重新调用。"
                )
                self._run_log and self._run_log[-1]["tool_calls"].append({
                    "name": name, "arguments": {}, "elapsed_sec": 0,
                    "result_preview": result_str[:1500], "result_full_len": len(result_str),
                    "args_parse_failed": True,
                })
                # 必须补上 tool 消息（OpenAI 协议：每个 tool_call_id 需有对应响应，否则下次调用 400）
                self.messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result_str,
                })
                results.append(result_str)
                logger.warning(f"[轮次 {self.iteration}] {name} arguments JSON 无效，已回显原文")
                continue

            logger.info(f"[轮次 {self.iteration}] 调用 {name}({args})")
            print(f"  🔧 {name}({json.dumps(args, ensure_ascii=False)[:200]})")

            result = execute_tool(name, args)
            _tool_elapsed = round(_time.time() - _t_tool0, 2)

            # 截断过长的结果
            result_str = str(result)
            _orig_len = len(result_str)
            if len(result_str) > 6000:
                result_str = result_str[:3000] + "\n...[截断]...\n" + result_str[-2500:]

            # ── 记录工具调用日志 ──
            if self._run_log:
                self._run_log[-1]["tool_calls"].append({
                    "name": name,
                    "arguments": args,
                    "elapsed_sec": _tool_elapsed,
                    "result_preview": result_str[:1500],
                    "result_full_len": _orig_len,
                })

            # ── T1 自动提交钩子：工具输出出现新 flag → 直接提交平台（submit_flag 工具自身的
            #    调用不走此钩子，由下方分支处理；其 flag 已入 _auto_submitted 防重复）──
            if name == "submit_flag" and isinstance(args.get("flag"), str):
                self._auto_submitted.add(args["flag"].strip())
            elif not self.submitted and self.challenge_id:
                result_str = self._auto_submit_flags(str(result), result_str)

            # 检测 flag 提交
            # 仅当 submit_flag 返回「提交成功」（真提交到平台）才视为完成；
            # 返回「本地模式/失败」时不要设 submitted，让 Agent 继续解题
            if name == "submit_flag":
                # 判定与自动提交钩子一致：「提交成功」只代表平台收到，必须 correct_flag_count>0
                # 才算真对（平台对垃圾输入也回提交成功，误置 found_flag 会让止损失效）
                _mc_ok = re.search(r'"correct_flag_count":\s*(\d+)', result_str)
                if "提交成功" in result_str and _mc_ok is not None and int(_mc_ok.group(1)) > 0:
                    self.found_flag = True
                    if self._solved_event:
                        self._solved_event.set()
                    # 多 flag 题：提交成功但还有未提交的 flag → 不停止，提示继续找剩余 flag
                    _mc = re.search(r'"correct_flag_count":\s*(\d+)', result_str)
                    _tc = re.search(r'"total_flag_count":\s*(\d+)', result_str)
                    if _mc and _tc and int(_mc.group(1)) < int(_tc.group(1)):
                        logger.info(f"多 flag 题：已提交 {_mc.group(1)}/{_tc.group(1)}，继续找其他 flag")
                        result_str = result_str + (
                            f"\n\n【系统】该题共 {_tc.group(1)} 个 flag，已提交 {_mc.group(1)} 个，"
                            f"还有 {int(_tc.group(1)) - int(_mc.group(1))} 个未找到。"
                            "继续解题找剩余 flag，找到后逐个 submit_flag 提交，直到全部 flag 提交成功。"
                        )
                    else:
                        self.submitted = True
                else:
                    # 本地模式/失败：给 Agent 明确反馈，让它继续解题而不是空转
                    logger.info("submit_flag 未真正提交成功，Agent 继续解题")
                    result_str = result_str + (
                        "\n\n【系统】submit_flag 未真正提交成功（本地模式/未配置比赛 API 或提交失败）。"
                        "说明当前 flag 可能不是正确答案或未被平台接受。"
                        "请继续深入解题：如果只是猜测/提取的 flag，务必通过漏洞利用确认拿到真实输出再提交；"
                        "继续调用工具找真正的 flag，不要停止。"
                    )
            if name == "extract_flag" and "找到" in result_str:
                self.found_flag = True
                # 找到 flag 后提示提交，但明确"未成功则继续"（防 Agent 空转）
                # 注意: 不能插入 user 消息（会破坏 deepseek tool_calls→tool 响应链顺序）
                if not self.submitted:
                    result_str = result_str + (
                        "\n\n【系统】extract_flag 命中 flag 候选。下一步调用 submit_flag 提交；"
                        "若返回本地模式/失败/错误，说明 flag 不对，继续解题验证真实 flag，不要停止。"
                    )

            # B1 失败收敛检测：连续 25 轮无 extract_flag/submit_flag 动作 → 提示聚焦提 flag（防盲目 run_shell 空转）
            if name in ("extract_flag", "submit_flag"):
                self._no_flag_rounds = 0
            else:
                self._no_flag_rounds += 1
                if self._no_flag_rounds >= 25 and not self._flag_hint_done:
                    self._flag_hint_done = True
                    logger.info(f"连续 {self._no_flag_rounds} 轮无 flag 动作，注入聚焦提示")
                    result_str = result_str + (
                        "\n\n【聚焦提 flag】已连续 25 轮未调用提取/提交 flag 工具。请聚焦："
                        "从已探测信息中提取 flag（extract_flag），找到后立即 submit_flag 提交；"
                        "若当前方向无 flag，换攻击面（其他功能/接口/漏洞入口）。"
                    )

            print(f"  📤 {result_str[:300]}{'...' if len(result_str) > 300 else ''}")

            # 把工具结果加入对话历史
            self.messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": result_str,
            })
            results.append(result_str)

        return "\n".join(results)

    def run(self, task: str, verbose: bool = True, max_iterations: int = None,
            stop_event: threading.Event = None) -> dict:
        """
        运行 Agent 解题

        返回:
            {
                "success": bool,       # 是否提交了 flag
                "flag_found": bool,    # 是否找到 flag
                "iterations": int,     # 总共思考了多少轮
                "final_message": str,  # Agent 最后说的话
                "run_log": list,       # per-round 详细日志（导出用）
            }
        """
        # 多方向并行时限制轮次（防止多个并行 agent 各跑满 MAX_ITERATIONS 烧 token）
        iter_limit = max_iterations or config.MAX_ITERATIONS
        # 多方向并行基础设施：任一方向提交正确 → 事件置位 → 其他方向提前停
        self._solved_event = stop_event if stop_event is not None else threading.Event()
        self._llm_error = None  # 本次 run 中 LLM 调用失败的原因（None=无失败）
        self._task_text = task  # 并行子 Agent 需要同一题目任务
        # 解题前先检索相关知识
        knowledge = search_knowledge(task)
        if knowledge:
            task_with_kb = f"## 相关解题知识\n{knowledge}\n\n## 题目\n{task}"
        else:
            task_with_kb = task

        self.messages.append({"role": "user", "content": task_with_kb})

        print(f"\n{'='*60}")
        print(f"📋 任务: {task[:200]}")
        if knowledge:
            print(f"📚 已检索到相关知识")
        print(f"{'='*60}\n")

        no_tool_rounds = 0  # 连续无工具调用的轮次计数
        no_progress_rounds = 0  # 连续调工具但未找到 flag 的轮次（无进展检测）
        no_progress_advised = False  # 是否已注入过换思路提示
        while self.iteration < iter_limit:
            # 全局停止信号（用户 Ctrl+C）：当前轮结束后立即收尾，不再继续解题
            if self.global_stop is not None and self.global_stop.is_set():
                print("  ⏹️ 收到全局停止信号，本 Agent 提前收尾")
                break
            # 并行停止信号：其他方向已找到 flag → 本方向提前停止（省 token）
            if self._solved_event is not None and self._solved_event.is_set():
                print("  ⏹️ 其他方向已找到 flag，本方向提前停止")
                break
            self.iteration += 1
            # 无进展检测（基于上一轮状态）：「进展」只认 flag 事件（提交正确/extract 命中 → found_flag 置位）。
            # 不再用 _detect_signal 宽松迹象重置计数——之前 web 题读二进制输出里到处是 0x7f、
            # 每几轮写一次 exploit 脚本，计数反复归零，实际跑出 98 轮/790 万 token 的灾难（log c-03）。
            # 阈值按难度动态预算（easy 紧止损省 token，hard 松止损多给机会）
            if self.iteration > 3:
                if self._last_has_tool_calls and not self.found_flag:
                    no_progress_rounds += 1
                else:
                    no_progress_rounds = 0
                if no_progress_rounds >= self.budget["no_progress_hint"] and not no_progress_advised:
                    no_progress_advised = True
                    no_progress_rounds = 0
                    # 并行方向约束：有 direction（多方向并行 agent）→ 提示坚持本方向换方法，防跑偏到其他方向
                    if self.direction:
                        tip = (f"【系统提示】已连续多轮调用工具但未找到 flag。"
                               f"**请坚持本方向**：{self.direction}。"
                               f"换本方向内的不同方法（不要跑偏到其他方向），继续解题。")
                    else:
                        # 无 direction（单 agent）：按题型给攻击面方向（避免同一终点的变体里打转）
                        tip = ("【系统提示】已连续多轮调用工具但未找到 flag。"
                               + CATEGORY_TIPS.get((self.category or "").lower(), GENERIC_TIP)
                               + "继续解题。"
                               # 卡死触发：主方向另起一个不同方向并行子 Agent（共享 solved_event）
                               + _maybe_spawn_parallel_child(self, task))
                    self.messages.append({"role": "user", "content": tip})
                    print(f"  ⚠️ 无迹象 {self.budget['no_progress_hint']} 轮，已注入换思路提示")
                elif no_progress_advised and no_progress_rounds >= self.budget["no_progress_giveup"]:
                    # 无迹象提示后再 N 轮仍无进展 → 强制止损进下一题（防卡题空耗，log3-1 的 83 分钟）
                    print(f"  ⏹️ 无迹象提示后再 {no_progress_rounds} 轮无进展，强制止损")
                    break
            print(f"\n--- 轮次 {self.iteration}/{iter_limit} ---")

            try:
                result = self._call_llm()
            except LLMQuotaExhausted:
                # 配额/计费窗口耗尽：重试无意义，穿透给上层收尾（继续跑只是烧钱）
                print("  ❌ LLM 配额已耗尽，终止本题")
                raise
            except Exception as e:
                logger.error(f"LLM 调用失败: {e}")
                print(f"  ❌ LLM 调用失败: {e}")
                # 记录失败事件（之前是盲点：快速失败的题日志里查不到任何 LLM 错误）
                self._llm_error = str(e)
                if self._run_log:
                    self._run_log.append({
                        "round": self.iteration, "timestamp": _time.strftime("%Y-%m-%d %H:%M:%S"),
                        "event": "llm_error", "error": str(e)[:500],
                    })
                break

            # 如果 Agent 返回的是纯文本（没有调用工具），可能是结束或需要继续
            if self.submitted:
                print(f"\n✅ Flag 已提交！")
                break

            # 放弃判定：必须连续 2 轮都没有工具调用（纯文本），且含明确放弃意图
            # 才判定 Agent 卡住——避免单轮提到"失败/无法"就误放弃
            # 注意: 用 _last_has_tool_calls（本轮 LLM 是否返回 tool_calls），
            # 不能用 messages[-1]（调工具后末尾是 tool 结果消息，无 tool_calls 字段会误判）
            if not self._last_has_tool_calls:
                no_tool_rounds += 1
            else:
                no_tool_rounds = 0
            # 空转保护：连续 10 轮无工具调用（纯文本回复）才 break。
            # 阈值太敏感会误杀 LLM 偶发的纯文本思考轮次；
            # 明确的放弃意图仍由上方"放弃判定"（2 轮+放弃词）处理。
            if no_tool_rounds >= 10:
                print(f"\n⚠️ Agent 连续 {no_tool_rounds} 轮无工具调用，停止空转")
                break
            if no_tool_rounds >= 2 and self.iteration > 2:
                if "无法" in result or "放弃" in result or "解不出来" in result:
                    print(f"\n⚠️ Agent 表示无法继续")
                    break

            # 上下文压缩：每轮末尾压缩早期长 tool 结果（超阈值时），降低后段轮次 LLM 延迟
            self._compress_history()
            # 迹象检测：本方向出现快解出迹象（extract_flag 命中/写 exploit/泄露地址）→
            # 置事件通知其他并行方向提前停止（省 token）
            if stop_event is not None and not stop_event.is_set() and _detect_signal(self.messages):
                stop_event.set()
            # 任务树/阶段推进提示：每 10 轮提醒推进阶段（定类→利用→提交），带题型攻击面方向
            # （5 轮太频繁：agent 深入分析时反复被打断，20 轮内注 4 次——改回 10 轮）
            if self.iteration % 10 == 0 and self.iteration < iter_limit:
                _cat_tip = CATEGORY_TIPS.get((self.category or "").lower(), GENERIC_TIP)
                phase_hint = (f"【进度推进】已进行 {self.iteration} 轮。请确认当前阶段（定类→利用→提交）："
                              f"若还在重复探测早期内容，应推进到利用/提交——{_cat_tip} "
                              f"明确漏洞入口后直接构造利用，找到 flag 立即 submit_flag 提交。")
                self.messages.append({"role": "user", "content": phase_hint})
                print(f"  📌 进度推进提示（第 {self.iteration} 轮，检查阶段）")

        # 等并行子方向收尾（最多 3min）：子方向的提交走平台 API，不依赖 join 结果
        if self._child_thread is not None and self._child_thread.is_alive():
            print("  ⏳ 等待并行子方向收尾...")
            self._child_thread.join(timeout=180)

        status = {
            "success": self.submitted,
            "flag_found": self.found_flag,
            "iterations": self.iteration,
            # LLM 调用失败导致中断（区别于"正常解题失败"——solver 据此做整题重试）
            "llm_error": getattr(self, "_llm_error", None),
            # 取最后一条 assistant 消息（循环以失败/提交 break 时 messages[-1] 是 tool 结果，
            # 直接取会把工具原始输出当"解题方向"存进经验库，污染后续题）
            "final_message": next(
                (m.get("content", "") for m in reversed(self.messages)
                 if m.get("role") == "assistant" and m.get("content")),
                self.messages[-1].get("content", "") if self.messages else "",
            ),
            "run_log": self._run_log,
        }

        print(f"\n{'='*60}")
        if status["success"]:
            print(f"✅ 解题成功！共 {self.iteration} 轮")
        elif status["flag_found"]:
            print(f"⚠️ 找到 flag 但未提交，共 {self.iteration} 轮")
        else:
            print(f"❌ 未能解题，共 {self.iteration} 轮")
        print(f"{'='*60}\n")

        return status

    def reset(self):
        """重置 Agent，保留 system prompt"""
        system = self.messages[0]
        self.messages = [system]
        self.iteration = 0
        self.found_flag = False
        self.submitted = False
        self._run_log = []
