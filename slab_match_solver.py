"""AI Agent 平台（slab-match）自动解题循环

流程（对照 api_doc.md）:
1. GET exercise-list 拉题目列表（按类别分组）
2. 逐题: GET exercise 查详情 → 若 isNeedInit 则 build-exercise-env 启动环境
   → 轮询详情直到 isNeedCheck=false 且 endpoints 可用
3. Agent 解题（目标地址用 endpoints 的 proxyIps:portMappings[].proxy 或 exposeIps:ports）
4. POST answer-panel/answer 提交 flag
5. POST recover-exercise-env 回收环境（不再用时）
6. 进度持久化，支持断点续跑

用法:
  python main.py slab          运行完整解题循环
  python main.py slab-list     仅列出题目
"""
import os
import re
import json
import time
import threading
import logging
from typing import Dict, List

from agent import Agent
from config import config
from utils.slab_match_api import SlabMatchAPI

logger = logging.getLogger(__name__)

# 进度文件
PROGRESS_FILE = os.path.join(config.OUTPUT_DIR, "slab_progress.json")

# 单题整体超时（秒），防止一道题拖死整个评测
CHALLENGE_TIMEOUT_SEC = int(os.getenv("CHALLENGE_TIMEOUT_SEC", "900"))

# 环境就绪轮询上限
MAX_ENV_POLL = 60  # 每 10s 一次，最多 10min（环境构建通常 1-5min）


def _load_progress() -> Dict:
    if os.path.exists(PROGRESS_FILE):
        try:
            with open(PROGRESS_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {"solved": [], "failed": [], "in_progress": [], "submitted_flags": {}, "history": []}


def _save_progress(progress: Dict) -> None:
    os.makedirs(config.OUTPUT_DIR, exist_ok=True)
    with open(PROGRESS_FILE, "w") as f:
        json.dump(progress, f, ensure_ascii=False, indent=2)


def list_challenges(api: SlabMatchAPI) -> List[Dict]:
    """拉题目列表，拍平成 [(exerciseId, name, 分类)] 列表（跳过未开放的题）"""
    groups = api.list_exercises()
    flat = []
    for g in groups or []:
        cat = g.get("name", "")
        for ex in g.get("corpus", []) or []:
            # isOpen=false 的题未开放，跳过（避免提交报错/无效操作）
            if ex.get("isOpen", True) is False:
                logger.info(f"⏭️ [{cat}] {ex.get('name')} (id={ex.get('id')}) 未开放，跳过")
                continue
            flat.append({
                "exercise_id": ex.get("id"),
                "name": ex.get("name"),
                "category": cat,
                "has_solved": ex.get("hasSolved", False),
            })
    return flat


def _extract_endpoint_target(exercise: Dict) -> str:
    """从题目详情里提取 Agent 可访问的目标地址

    优先 proxyIps:portMappings[].proxy（平台代理），否则 exposeIps:ports[0]。
    """
    eps = exercise.get("endpoints") or []
    if not eps:
        return ""
    ep = eps[0]
    proxy_ips = ep.get("proxyIps") or []
    mappings = ep.get("portMappings") or []
    if proxy_ips and mappings:
        m = mappings[0]
        return f"{proxy_ips[0]}:{m.get('proxy', m.get('port', ''))}"
    expose = ep.get("exposeIps") or []
    ports = ep.get("ports") or []
    if expose and ports:
        return f"{expose[0]}:{ports[0]}"
    return ""


def _wait_env_ready(api: SlabMatchAPI, exercise_id: int) -> Dict:
    """启动环境后轮询详情直到 isNeedCheck=false 且 endpoints 可用（最长 MAX_ENV_POLL*10s）"""
    for i in range(MAX_ENV_POLL):
        time.sleep(10)
        try:
            d = api.get_exercise(exercise_id)
        except Exception as e:
            logger.warning(f"轮询详情失败: {e}")
            continue
        need_check = d.get("isNeedCheck", False)
        has_endpoint = bool(d.get("endpoints"))
        if not need_check and has_endpoint:
            return d
        logger.info(f"环境准备中... ({(i+1)}/{MAX_ENV_POLL}, isNeedCheck={need_check})")
    raise TimeoutError(f"exercise {exercise_id} 环境 {MAX_ENV_POLL*10}s 未就绪")


def _build_strategy_hint(name: str, desc: str, category: str) -> str:
    """按题目名/描述/分类注入专项解题思路（方法论级，不指向单题答案）"""
    text = f"{name} {desc} {category}".lower()
    hints = []

    # PHP 反序列化 / POP 链
    if any(k in text for k in ["unserialize", "serialize", "pop", "反序列化", "php"]):
        hints.append(
            "- PHP 反序列化/POP 链题: 找反序列化入口(通常 cookie 或参数里 base64 的序列化串)\n"
            "  → 读源码找可利用的魔术方法(__destruct/__wakeup/__toString/__call)\n"
            "  → 用 php filter 读源码: index.php?file=php://filter/convert.base64-encode/resource=index.php\n"
            "  → 构造 POP 链 payload(序列化对象数组触发魔术方法链), 常见终点是文件包含/命令执行\n"
            "  → 序列化串要 URL 编码后放入参数; 注意 _ 和 \\0 特殊字符处理\n"
            "  → **payload 必须用 PHP 原生 serialize 生成（长度精确）**: 手写序列化串的 s:N:\"..\" 长度极易算错,\n"
            "     unserialize 会失败导致 RCE 不触发。正确做法: 把题目源码的 class 定义复制到本地,\n"
            "     用 run_shell 执行 `php -r` 构造对象并 serialize, 例如:\n"
            "     `php -r 'class A{public \\$func;} class B{public \\$a;} class C{public \\$cmd;} $a=new A; $a->func=new B; $a->func->a=new C; $a->func->a->cmd=\"cat /flag\"; echo serialize($a);'`\n"
            "     → 输出精确的序列化串, 再 URL 编码 POST 提交\n"
            "  → **禁止提交猜测值**: 页面/源码/响应里出现的 DASCTF{数字} 很可能是干扰项(如哈希/随机数),\n"
            "    **不是真 flag**。必须真正构造并发送 POP 链 payload, 从响应中确认命令/文件读取已执行,\n"
            "    拿到漏洞利用产生的真实输出(如 cat flag 的文件内容)才能提交。\n"
            "    若只看到 DASCTF{数字} 而没有经过漏洞利用确认, 严禁提交, 继续构造 payload\n"
        )
    # Web 通用
    if any(k in text for k in ["web", "upload", "include", "command", "注入", "flag"]) or category.lower() == "web":
        hints.append(
            "- Web 题通用: 先抓首页+JS 源码看路由, dir_scan 找隐藏文件, 测常见参数\n"
            "  → 优先看源码泄露(备份文件 .bak/.swp/~, php://filter, 报错信息)\n"
            "  → 上传题: 测后缀绕过/内容绕过/解析漏洞; 包含题: 测 php://filter/php://input/data://\n"
            "  → **轻量探测优先**: 先 curl 直接测常见路径(/index.php /upload.php /view.php /robots.txt /www.zip 等),\n"
            "    慎用 gobuster 全量目录扫描(慢); 只有 curl 探测无果再考虑 dir_scan\n"
            "- **文件上传题专项（实战验证套路）**: 上传只是第一步, **必须触发执行**才能 RCE 读 flag\n"
            "  → 上传木马后找触发点: ①直接访问上传路径 ②找 include/require 包含点 ③LFI 包含上传文件\n"
            "  → 后缀绕过: .php/.phtml/.php5/.phar 变体, 大小写 .PHP, 双写 .pphphp, 尾部空格/点/::$DATA\n"
            "  → 内容检查绕过: 图片马(PNG/GIF 文件头 + PHP 代码), 短标签 <?=, 在合法图片后追加 <?php system($_GET['cmd'])?>\n"
            "  → 上传成功看响应 Location 拿上传路径, 访问该路径带 cmd 参数验证代码执行\n"
            "  → 若 view.php 有 LFI(file 参数): 用 LFI include 上传的图片马文件路径触发执行\n"
        )
    # Pwn
    if any(k in text for k in ["pwn", "栈", "溢出", "fmt", "heap"]) or category.lower() == "pwn":
        hints.append(
            "- Pwn 题: 先确定题目类型(栈溢出/格式化字符串/堆), 用 checksec 看保护\n"
            "  → 本地/远程连接后分析交互协议, 构造 exploit(pwntools)\n"
        )
    # Crypto
    if any(k in text for k in ["crypto", "rsa", "aes", "cipher", "加密"]) or category.lower() == "crypto":
        hints.append(
            "- Crypto 题: 先看加密脚本源码确定算法, rsa_decrypt/auto_decode 试常见套路\n"
            "  → 弱密钥/小指数/共模/已知明文优先\n"
        )
    # Misc / Forensics
    if any(k in text for k in ["misc", "forensic", "隐写", "流量", "pcap", "压缩"]) or category.lower() in ("misc", "forensics"):
        hints.append(
            "- Misc/取证题: 附件先 file/analyze_file 看类型, 隐写用 steg_check, 流量用 tshark\n"
            "  → 压缩包注意伪加密/暴力破解; 注意 base64/hex/编码套娃\n"
        )

    if hints:
        return "\n".join(hints) + "\n"
    return ""


def solve_challenge(api: SlabMatchAPI, ch: Dict, progress: Dict) -> Dict:
    """解单道题: 启环境 → Agent 解题 → 提交 flag → 回收"""
    ex_id = ch["exercise_id"]
    name = ch.get("name", "")
    cat = ch.get("category", "")

    # 跳过已通关
    if ex_id in progress["solved"] or ch.get("has_solved"):
        return {"status": "skipped", "exercise_id": ex_id}

    print(f"\n{'='*60}")
    print(f"🎯 解题: [{cat}] {name} (id={ex_id})")
    print(f"{'='*60}")

    # 1. 查详情
    print(f"\n[1/5] 查题目详情...")
    try:
        detail = api.get_exercise(ex_id)
    except Exception as e:
        logger.error(f"❌ 详情失败: {e}")
        progress["failed"].append(ex_id)
        _save_progress(progress)
        return {"status": "detail_failed", "exercise_id": ex_id, "error": str(e)}

    desc = detail.get("description", "")
    diff = detail.get("difficulty", "?")
    score = detail.get("score", "")
    has_solved = detail.get("hasSolved", False)
    if has_solved:
        progress["solved"].append(ex_id)
        _save_progress(progress)
        return {"status": "solved_before", "exercise_id": ex_id}

    # 2. 启动环境（如需要）
    if detail.get("isNeedInit"):
        print(f"\n[2/5] 启动环境...")
        try:
            # build 返回 "已构建/请勿频繁点击"(40409) 属正常幂等，继续轮询即可
            try:
                api.build_env(ex_id)
            except RuntimeError as e:
                if "40409" not in str(e) and "已构建" not in str(e):
                    raise
                logger.info(f"环境已构建（幂等），继续等待就绪")
            detail = _wait_env_ready(api, ex_id)
        except Exception as e:
            logger.error(f"❌ 环境启动失败: {e}")
            progress["failed"].append(ex_id)
            _save_progress(progress)
            return {"status": "env_failed", "exercise_id": ex_id, "error": str(e)}
    else:
        print(f"\n[2/5] 环境已就绪（无需启动）")

    target = _extract_endpoint_target(detail)
    print(f"  目标地址: {target or '(无端点)'}")

    # 附件信息
    att_files = []
    att = detail.get("attachment") or {}
    for f in att.get("files") or []:
        att_files.append(f"{f.get('name')} ({f.get('url','')})")

    # 3. 构造题目描述（含专项思路注入，省轮次）
    strategy = _build_strategy_hint(name, desc, cat)
    task = f"""请解以下 CTF 题目并提交 flag。

题目 ID: {ex_id}
题目名称: {name}
题目描述: {desc}
难度: {diff}
分值: {score}
靶场地址: {target}

附件:
{chr(10).join(att_files) if att_files else '（无附件）'}

## 解题思路提示（按题目类型，方法论）
{strategy if strategy else '（通用: 先探测入口, 再定向利用）'}

注意:
- 靶场地址通过平台代理访问（HTTP 服务直接 curl / 探测）
- 找到 flag 后必须调用 submit_flag 提交，flag 格式一般为 flag{{...}}
- 如果卡住可以尝试不同方向，不要在一种方法上死磕"""
    print(f"\n[3/5] Agent 解题（超时 {CHALLENGE_TIMEOUT_SEC}s）...")
    agent = Agent()
    result = agent.run(task, verbose=True)
    agent_success = result.get("success", False)
    final_msg = result.get("final_message", "")

    # 4. 提取 flag 并提交
    # 优先：Agent 显式调用 submit_flag 工具的 flag（最可靠，不误抓示例）
    explicit_flags = set()
    for m in agent.messages:
        for tc in m.get("tool_calls", []) or []:
            fn = (tc.get("function") or {}).get("name", "")
            if fn == "submit_flag":
                try:
                    args = json.loads((tc.get("function") or {}).get("arguments", "{}"))
                    f = args.get("flag", "")
                    if f:
                        explicit_flags.add(f)
                except Exception:
                    pass

    # 兜底：只从 Agent 最终输出(final_message)正则提取——不再拼所有 messages 内容，
    # 因为 messages 里是工具结果/源码/注释，会被正则误抓成垃圾候选（如注释里的 "CTF{ 的子串..."）
    print(f"\n[4/5] 提交 flag...")
    all_text = final_msg or ""
    flag_patterns = [
        r"\bDASCTF\{[^}]+\}", r"\bdasctf\{[^}]+\}",   # 平台前缀（DASCTF）
        r"\bflag\{[^}]+\}", r"\bFLAG\{[^}]+\}",
        r"\bctf\{[^}]+\}", r"\bCTF\{[^}]+\}",
    ]
    regex_flags = set()
    for pattern in flag_patterns:
        regex_flags.update(re.findall(pattern, all_text))

    # 合并：显式提交优先，正则兜底
    found_flags = explicit_flags or regex_flags

    # 过滤占位符/示例/垃圾候选（注释、代码片段、超长文本等误抓）
    PLACEHOLDERS = {"flag{...}", "FLAG{...}", "flag{flag}", "flag{your_flag}", "flag{example}",
                    "flag{example_flag}", "ctf{...}", "CTF{...}", "DASCTF{...}", "FLAG{{...}"}
    filtered = set()
    for f in found_flags:
        fl = f.lower()
        # 排除: 占位符 / 含"..." / 含 example / 含换行/代码特征 / 含中文注释词 / 超长(>100)
        if f in PLACEHOLDERS or "..." in f or "example" in fl:
            continue
        if "\n" in f or "\\" in f or "print(" in f or "{" in f.replace("flag{", "", 1):
            continue
        if any(w in f for w in ["子串", "误匹配", "非词边界", "注释", "源码"]):
            continue
        if len(f) > 100:
            continue
        filtered.add(f)
    found_flags = filtered
    if not found_flags:
        print(f"\n[4/5] 提交 flag...（无有效 flag 候选，跳过提交）")
    if explicit_flags:
        print(f"  (使用 Agent 显式 submit_flag: {sorted(explicit_flags)})")
    elif regex_flags:
        print(f"  (从输出提取候选: {sorted(regex_flags)})")

    submitted = progress["submitted_flags"].get(str(ex_id), [])
    # 已失败的 flag（平台拒绝过）——同题重复值不再提交，省提交次数
    failed_flags = progress.get("failed_flags", {}).get(str(ex_id), [])
    correct = False
    seen = set()  # 本回合内已提交过的值（防同一 flag 重复提交）
    for flag in found_flags:
        # 剥离 DASCTF{}/flag{} 包裹得到纯内容（平台答案库存纯数字，实测确认）
        inner = re.sub(r"^(?:DASCTF|dasctf|flag|FLAG|ctf|CTF)\{|\}$", "", flag)
        cand = inner or flag  # 同一 flag 只提交剥离后的纯内容一次（不再试完整格式，省提交次数）
        if cand in submitted or cand in failed_flags or cand in seen:
            if cand in failed_flags:
                print(f"  ⏭️ 跳过 {cand}（此前已提交失败）")
            continue
        seen.add(cand)
        try:
            sr = api.submit_answer(ex_id, cand)
            is_correct = sr.get("isCorrect", False)
            if is_correct:
                print(f"  ✅ 正确! {cand}")
                submitted.append(cand)
                correct = True
                break
            else:
                print(f"  ❌ 错误: {cand}")
                if cand not in failed_flags:
                    failed_flags.append(cand)
        except Exception as e:
            logger.warning(f"提交异常: {e}")
            if cand not in failed_flags:
                failed_flags.append(cand)

    if submitted:
        progress["submitted_flags"][str(ex_id)] = submitted
    if failed_flags:
        progress.setdefault("failed_flags", {})[str(ex_id)] = failed_flags

    # 5. 判定通关
    try:
        fresh = api.get_exercise(ex_id)
        has_solved = fresh.get("hasSolved", False)
    except Exception:
        has_solved = correct

    if has_solved:
        progress["solved"].append(ex_id)
        if ex_id in progress["in_progress"]:
            progress["in_progress"].remove(ex_id)
        status = "solved"
    elif correct:
        # 至少一个 flag 被平台确认正确 → partial（可能还有 flag 没拿到）
        status = "partial"
        if ex_id not in progress["in_progress"]:
            progress["in_progress"].append(ex_id)
    else:
        # 提交的 flag 全错（或未提交）→ failed，下次运行会重试
        status = "failed"
        progress["failed"].append(ex_id)

    # 6. 回收环境（仅独占场景可回收；共享/非独占场景平台自动回收，跳过）
    ep_type = (detail.get("endpointType") or "").lower()
    print(f"\n[5/5] 回收环境... (endpointType={detail.get('endpointType') or '?'})")
    if ep_type not in ("monopoly", "exclusive", "独占"):
        print("  非独占场景，跳过回收（平台自动回收）")
    else:
        try:
            api.recover_env(ex_id)
            print("  环境已回收")
        except Exception as e:
            # 40409 = 非独占/已回收，忽略即可
            if "40409" in str(e) or "非独占" in str(e) or "无权" in str(e):
                print("  环境无需回收（已由平台处理）")
            else:
                logger.warning(f"回收异常: {e}")

    progress["history"].append({
        "exercise_id": ex_id,
        "name": name,
        "status": status,
        "flags_found": len(found_flags),
        "agent_iterations": result.get("iterations", 0),
        "timestamp": time.strftime("%H:%M:%S"),
    })
    _save_progress(progress)
    print(f"\n✅ 完成: {status}")
    return {"status": status, "exercise_id": ex_id}


def _prebuild_env(ex_id: int, ready: dict):
    """后台预启动下一题环境（P2a）：独立 API 实例，幂等 build + 轮询就绪

    被平台拒绝（build 报错且非幂等）或异常时，标记 'denied'——
    上层 run_slab 检测到 denied 即禁用后续预构建（恢复解题时才 build）。
    """
    try:
        api2 = SlabMatchAPI()
        d = api2.get_exercise(ex_id)
        if d.get("isNeedInit"):
            try:
                api2.build_env(ex_id)
            except Exception as e:
                if "40409" not in str(e) and "已构建" not in str(e):
                    ready[ex_id] = "denied"  # 平台拒绝预构建
                    return
            for _ in range(9):  # 最多 90s 轮询就绪
                time.sleep(10)
                try:
                    d = api2.get_exercise(ex_id)
                    if not d.get("isNeedCheck") and d.get("endpoints"):
                        break
                except Exception:
                    pass
        ready[ex_id] = True
    except Exception:
        ready[ex_id] = "denied"  # 异常也视为不可预构建


def run_slab(timeout_sec: int = 0, start_time: float = 0):
    """运行完整解题循环"""
    if start_time == 0:
        start_time = time.time()

    def time_left() -> float:
        if timeout_sec <= 0:
            return float("inf")
        return timeout_sec - (time.time() - start_time)

    print("\n" + "="*60)
    print("🚀 AI Agent 平台（slab-match）自动解题")
    print("="*60)

    api = SlabMatchAPI()
    challenges = list_challenges(api)
    if not challenges:
        print("无题目")
        return

    progress = _load_progress()
    print(f"\n📊 进度: 已解 {len(progress['solved'])}, 失败 {len(progress['failed'])}")
    print(f"📋 题目总数: {len(challenges)}")

    stats = {"solved": 0, "partial": 0, "failed": 0, "skipped": 0}
    ready = {}  # 记录后台已预启动就绪的题
    prebuild_denied = False  # 平台拒绝预构建时禁用后续预启动
    for i, ch in enumerate(challenges, 1):
        left = time_left()
        if left < 60:
            print(f"\n⚠️ 剩余时间不足 ({left/60:.1f}min)，停止开新题")
            break
        print(f"\n  题目 {i}/{len(challenges)} (剩 {left/60:.1f}min)")
        # P2a：解题前，后台线程预启动下一题环境（省环境等待 50s/题）
        if i < len(challenges) and not prebuild_denied:
            nxt = challenges[i]["exercise_id"]
            if nxt not in progress["solved"] and nxt not in ready:
                t = threading.Thread(target=_prebuild_env, args=(nxt, ready), daemon=True)
                t.start()
                print(f"   ⟳ 后台预启动下一题环境 (id={nxt})")
        # 兜底：若平台拒绝预构建（denied），禁用后续预启动，恢复解题时才 build
        if any(v == "denied" for v in ready.values()):
            prebuild_denied = True
            print("   ⛔ 平台拒绝预构建环境，已禁用预启动（恢复解题时才 build）")
        try:
            r = solve_challenge(api, ch, progress)
            stats[r.get("status", "failed")] = stats.get(r.get("status", "failed"), 0) + 1
        except KeyboardInterrupt:
            print("\n\n⚠️ 用户中断，保存进度...")
            _save_progress(progress)
            break
        except Exception as e:
            logger.error(f"❌ 题目 {ch['exercise_id']} 出错: {e}", exc_info=True)
            stats["failed"] = stats.get("failed", 0) + 1
        time.sleep(2)

    elapsed = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"📊 解题汇总")
    print(f"  总题数: {len(challenges)}")
    print(f"  ✅ 通关: {stats.get('solved', 0)}")
    print(f"  ⚠️ 部分: {stats.get('partial', 0)}")
    print(f"  ❌ 失败: {stats.get('failed', 0)}")
    print(f"  ⏭️ 跳过: {stats.get('skipped', 0)}")
    print(f"  ⏱️ 耗时: {elapsed/60:.1f}min")
    print(f"  进度文件: {PROGRESS_FILE}")
    print(f"{'='*60}\n")
