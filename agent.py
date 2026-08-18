"""Agent 主循环 - ReAct 范式，支持 function calling"""
import json
import logging
from typing import List, Dict
from config import config
from llm import llm
from tools import get_tools_schema, execute_tool
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
- 流程: web_fingerprint → dir_scan → http_request 测试注入点 → sqli_scan

### 2. 二进制漏洞挖掘
- **binary_analyze**: 综合分析（file/checksec/strings/readelf/objdump）
- **ghidra_decompile**: Ghidra headless 反编译为 C 伪代码
- **vuln_pattern_scan**: 危险函数和漏洞模式自动扫描
- 流程: binary_analyze → vuln_pattern_scan → ghidra_decompile (针对性反编译可疑函数)

### 3. 漏洞利用
- **rop_gadget_search**: 搜索 ROP gadget（ROPgadget）
- **exploit_template**: 生成 pwntools exploit 骨架（buffer_overflow/format_string/ret2libc/ret2shellcode）
- **run_python + pwntools**: 编写和运行 exploit
- **msfvenom_payload**: 生成反弹 shell payload
- 流程: binary_analyze → rop_gadget_search → exploit_template → 调试 → 远程利用

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
- 古典密码: run_python 写解密脚本

### Forensics / Misc
- **拿到文件第一步用 analyze_file**
- 图片题用 steg_check 检测隐写
- 流量题用 run_shell 执行 tshark / wireshark
- 内存题用 run_shell 执行 volatility
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
"""


class Agent:
    def __init__(self, system_prompt: str = SYSTEM_PROMPT):
        self.messages: List[Dict] = [{"role": "system", "content": system_prompt}]
        self.iteration = 0
        self.tools = get_tools_schema()
        self.found_flag = False
        self.submitted = False

    def _call_llm(self) -> str:
        """调用 LLM，处理 tool_calls"""
        response = llm.chat(self.messages, tools=self.tools)
        choice = response.choices[0]
        msg = choice.message

        # 把 assistant 消息加入历史（包括 tool_calls）
        assistant_msg = {"role": "assistant", "content": msg.content or ""}
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
            try:
                args = json.loads(tc.function.arguments)
            except json.JSONDecodeError:
                args = {}

            logger.info(f"[轮次 {self.iteration}] 调用 {name}({args})")
            print(f"  🔧 {name}({json.dumps(args, ensure_ascii=False)[:200]})")

            result = execute_tool(name, args)

            # 截断过长的结果
            result_str = str(result)
            if len(result_str) > 6000:
                result_str = result_str[:3000] + "\n...[截断]...\n" + result_str[-2500:]

            # 检测 flag 提交
            # 仅当 submit_flag 返回「提交成功」（真提交到平台）才视为完成；
            # 返回「本地模式/失败」时不要设 submitted，让 Agent 继续解题
            if name == "submit_flag":
                if "提交成功" in result_str or "correct" in str(result_str).lower():
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

            print(f"  📤 {result_str[:300]}{'...' if len(result_str) > 300 else ''}")

            # 把工具结果加入对话历史
            self.messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": result_str,
            })
            results.append(result_str)

        return "\n".join(results)

    def run(self, task: str, verbose: bool = True) -> dict:
        """
        运行 Agent 解题

        返回:
            {
                "success": bool,       # 是否提交了 flag
                "flag_found": bool,    # 是否找到 flag
                "iterations": int,     # 总共思考了多少轮
                "final_message": str,  # Agent 最后说的话
            }
        """
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
        while self.iteration < config.MAX_ITERATIONS:
            self.iteration += 1
            print(f"\n--- 轮次 {self.iteration}/{config.MAX_ITERATIONS} ---")

            try:
                result = self._call_llm()
            except Exception as e:
                logger.error(f"LLM 调用失败: {e}")
                print(f"  ❌ LLM 调用失败: {e}")
                break

            # 如果 Agent 返回的是纯文本（没有调用工具），可能是结束或需要继续
            if self.submitted:
                print(f"\n✅ Flag 已提交！")
                break

            # 放弃判定：必须连续 2 轮都没有工具调用（纯文本），且含明确放弃意图
            # 才判定 Agent 卡住——避免单轮提到"失败/无法"就误放弃
            if not self.messages[-1].get("tool_calls"):
                no_tool_rounds += 1
            else:
                no_tool_rounds = 0
            # 空转保护：连续 3 轮无工具调用（纯文本回复）直接 break，防止空转烧轮次
            if no_tool_rounds >= 3:
                print(f"\n⚠️ Agent 连续 {no_tool_rounds} 轮无工具调用，停止空转")
                break
            if no_tool_rounds >= 2 and self.iteration > 2:
                if "无法" in result or "放弃" in result or "解不出来" in result:
                    print(f"\n⚠️ Agent 表示无法继续")
                    break

        status = {
            "success": self.submitted,
            "flag_found": self.found_flag,
            "iterations": self.iteration,
            "final_message": self.messages[-1].get("content", "") if self.messages else "",
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
