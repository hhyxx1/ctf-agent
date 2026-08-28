# CTF Agent

一个通用的 CTF（夺旗赛）自动解题 Agent 框架，基于 **ReAct 循环**（推理→行动→观察）驱动大模型调用 33 个工具完成探测、利用、拿 flag 的完整流程。

## 核心特性

- **ReAct 主循环**：三阶段元策略（定类 → 套法 → 验证）+ 早停信号，避免无方向 trial-error
- **33 个工具**：Web 漏洞挖掘、二进制分析、漏洞利用、多阶段渗透、云攻击、对抗规避、Crypto/编码、Forensics、通用 shell/python/文件
- **反作弊层**：所有工具调用走统一入口，路径隔离 + 全量审计 + 作弊拦截（防止 Agent 读取跑分集源码/答案）
- **方法论知识库**：内置 12 类 CTF 解题方法论（WAF 绕过/SpEL/SQLi/SSRF/IDOR/SSTI/CBC/JSFuck 等）
- **模型无关**：基于 OpenAI 兼容接口，可接入任意兼容服务（OpenAI/通义/本地 vLLM 等），通过 `.env` 配置

## 快速开始（本地模式）

```bash
cd ctf_agent
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# 配置环境变量
cp .env.example .env
# 编辑 .env：至少填 LLM_API_KEY

# 跑一个通用测试任务
.venv/bin/python main.py test
```

## 如何接你的题目

框架不绑定任何特定平台/跑分集。接入方式：

### 方式一：直接用命令行给 Agent 单个题目
```bash
.venv/bin/python main.py task "请解这道 CTF 题并提交 flag：<题目描述>"
```

### 方式二：实现一个 Target 适配器（推荐，可复用）
```python
class MyTarget:
    def describe(self) -> str: ...        # 题目描述/提示
    def start(self) -> str: ...           # 返回靶场入口（本地端口/URL）
    def submit(self, flag: str) -> bool:  # 提交判定
```
然后在主循环里循环：`describe → Agent 解题 → submit`。

### 方式三：使用仓库内置的跑分集适配器（可选）
`benchmark_runner.py` / `xben_runner.py` / `tsecbench_solver.py` 分别是 cybench / XBEN / 平台类评测的接入示例，可参考其题面准备与判分逻辑，改造成你自己的适配器。

## 工具一览（33 个）

| 维度 | 工具 |
|------|------|
| Web 漏洞挖掘 | http_request, sqli_scan, dir_scan, web_fingerprint, vuln_scan |
| 二进制漏洞挖掘 | binary_analyze, ghidra_decompile, vuln_pattern_scan, rop_gadget_search |
| 漏洞利用 | exploit_template, msfvenom_payload, run_python(pwntools) |
| 多阶段渗透 | nmap_scan, hydra_brute, linpeas_check, proxy_scan, tunnel_setup |
| 云攻击 | ssrf_metadata, aws_enum, container_escape |
| 对抗规避 | shellcode_encode, msfvenom_payload, evade_check, tunnel_setup |
| Crypto/编码 | rsa_decrypt, auto_decode, encode_data |
| Forensics | analyze_file, steg_check |
| 通用 | run_shell, run_python, read_file, write_file, list_dir, extract_flag, submit_flag |

## 关键文件

```
ctf_agent/
├── main.py                  # 入口
├── config.py                # 配置（环境变量、反作弊路径）
├── agent.py                 # ReAct Agent 主循环
├── llm.py                   # LLM 封装（OpenAI 兼容）
├── tools/                   # 33 个工具 + 反作弊层（base.py）
├── utils/                   # 平台 API 封装（示例）、知识库
├── knowledge/               # CTF 解题方法论知识库
├── benchmark_runner.py      # cybench 接入示例（可选）
├── xben_runner.py           # XBEN 接入示例（可选）
├── tsecbench_solver.py      # 平台类评测接入示例（可选）
├── .env.example             # 环境变量模板（复制为 .env 填写）
└── requirements.txt
```

## 配置说明

编辑 `.env`（参考 `.env.example`）：

| 变量 | 必填 | 说明 |
|------|------|------|
| `LLM_API_KEY` | ✅ | OpenAI 兼容接口的 API Key（OpenAI/通义/本地 vLLM 等均可） |
| `LLM_BASE_URL` | 可选 | OpenAI 兼容接口地址（默认 `https://api.openai.com/v1`） |
| `LLM_MODEL` | 可选 | 模型名（默认 `gpt-4o-mini`，按你的服务填） |
| `FORBIDDEN_PATHS` | 可选 | 禁止 Agent 访问的路径（JSON 列表），如你的跑分集源码/答案目录 |
| `ALLOWED_WORKDIRS` | 可选 | 合法工作目录前缀（JSON 列表） |
| `MAX_ITERATIONS` | 可选 | 单题最大推理轮次（默认 25） |

### 反作弊配置

框架默认只拦截通用答案目录（`metadata/solution` 等）。如果你要防止 Agent 读取某个目录（如你的题目源码/答案），在 `.env` 配置：

```
FORBIDDEN_PATHS=["/data/my-benchmark","/data/answers","metadata/solution"]
ALLOWED_WORKDIRS=["/tmp/chal_"]
```

所有工具调用都会经过 `tools/base.py` 的反作弊检查：命中禁止路径即拦截并记入审计日志 `output/logs_<运行时间戳>/anti_cheat.log`（每次运行独立目录）。

## 大模型网关（可选，托管环境专用）

如果你的运行环境不能直连公网（例如某些隔离评测沙箱），可通过网关代理访问大模型：

- `GATEWAY_MODE=off`：直连 `LLM_BASE_URL`（默认）
- `GATEWAY_MODE=open`：按 `config.py` 中的 `_apply_gateway()` 规则转换 URL（https→http、域名加网关后缀）

本地开发保持 `GATEWAY_MODE=off` 即可。

## 安全注意

- **不要在 prompt 或对话中塞敏感信息**（API Key、私人数据）——大模型对话可能被记录
- API Key 只通过环境变量注入，不进对话内容
- 解题日志落盘到 `output/`，该目录已被 `.gitignore` 忽略，不会提交
