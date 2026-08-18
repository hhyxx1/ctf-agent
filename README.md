# CTF Agent 使用指南

## 两种运行模式

### 本地模式（开发调试）
```bash
cd ctf_agent
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
# 编辑 .env 填入 DEEPSEEK_API_KEY
.venv/bin/python main.py test
```

### 托管模式（TSecBench 平台）
平台拉起 Docker 镜像，注入环境变量，Agent 自启解题。无需人工触发。

---

## 托管模式部署步骤

### 1. 本地先装 Docker
```bash
sudo apt install -y docker.io
```

### 2. 构建镜像
```bash
cd ctf_agent
sudo docker build -t tsecbench-agent:latest .
```

### 3. 本地模式评测（平台强制前置要求）

平台要求：必须先完成本地模式评测、接入答题 API，再做托管。

#### 3.1 在 tsecbench 平台创建"本地模式"跑分任务，拿到：
- `BENCHMARK_TOKEN`
- `BENCHMARK_BASE_URL`
- 靶场 VPN 配置

#### 3.2 本地跑（注入平台下发的 token）
```bash
export BENCHMARK_TOKEN=平台下发的token
export BENCHMARK_BASE_URL=https://tsecbench.zc.tencent.com
export DEEPSEEK_API_KEY=sk-你的deepseek-key
export GATEWAY_MODE=off        # 本地模式不走网关
.venv/bin/python main.py tsecbench-list    # 验证连通
.venv/bin/python main.py tsecbench         # 跑完整解题
```

连 VPN 后，Agent 才能访问 container_addr。

#### 3.3 本地调通后，导出镜像
```bash
sudo docker save tsecbench-agent:latest | gzip > agent.tar.gz
```

### 4. 托管模式上传

在 tsecbench 平台「制作并上传 Docker 镹像」处上传 `agent.tar.gz`。

### 5. 配置运行时环境变量

在平台「运行时环境变量」处填入：
```
DEEPSEEK_API_KEY=sk-你的deepseek-key
```

`BENCHMARK_TOKEN` 和 `BENCHMARK_BASE_URL` 平台自动注入，不要填。

### 6. 启托管评测

平台拉取镜像 → 部署沙箱 → 容器启动 → entrypoint.sh 调 `python main.py auto` → Agent 自启解题。

---

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

---

## 关键文件

```
ctf_agent/
├── Dockerfile               # 托管镜像构建
├── entrypoint.sh            # 托管模式启动脚本
├── main.py                  # 入口（auto/本地命令）
├── config.py                # 配置（网关逻辑、环境变量）
├── agent.py                 # ReAct Agent 主循环
├── tsecbench_solver.py      # TSecBench 解题循环
├── tools/                   # 33 个工具
├── utils/tsecbench_api.py   # TSecBench API 对接
├── knowledge/               # CTF 解题知识库
└── .env                     # 本地模式配置（不上传）
```

## 大模型网关（托管必读）

托管环境不能访公网。原 `https://api.deepseek.com` 自动转为 `http://api.deepseek.com.tsecbench.gw`。

`config.py` 中 `_apply_gateway()` 的触发条件：
- `GATEWAY_MODE=on/off/auto`
- 或检测到 `BENCHMARK_TOKEN` 已注入（自动判定托管模式）
- `auto` 模式下：有 token 就走网关，没 token 就走公网

## 审计注意

托管全程网络流量和大模型对话会被审计/部分公开：
- 不要在 prompt 或对话中塞敏感信息（API Key、私人数据）
- `DEEPSEEK_API_KEY` 通过环境变量注入，不会进对话内容
- 解题日志会落盘到 `output/`，但不会回传给 LLM

## 超时守护

- 总时限 360min（平台硬限）
- `config.py` 的 `TOTAL_TIMEOUT_SEC` 默认 21000s（350min），留 10min 兜底
- `tsecbench_solver.py` 在剩余时间 < 3min 时停止开新题，尝试关闭活跃容器
- 平台沙箱超时后会强杀进程，所以别指望能跑满 360min
