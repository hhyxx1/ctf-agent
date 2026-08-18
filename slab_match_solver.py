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

from agent import Agent, build_agent
from config import config
from utils.slab_match_api import SlabMatchAPI

logger = logging.getLogger(__name__)

# 进度文件
PROGRESS_FILE = os.path.join(config.OUTPUT_DIR, "slab_progress.json")

# 单题整体超时（秒），防止一道题拖死整个评测
CHALLENGE_TIMEOUT_SEC = int(os.getenv("CHALLENGE_TIMEOUT_SEC", "900"))

# 环境就绪轮询上限
MAX_ENV_POLL = 120  # 每 10s 一次，最多 20min（平台环境构建可能 >10min）


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


# ── 解题经验库（P1 经验沉淀 + P2 失败卡点；方法论级，不含单题答案/flag）──
LESSONS_FILE = os.path.join(config.OUTPUT_DIR, "slab_lessons.json")


def _load_lessons() -> Dict:
    """读经验库: {category: {"solved_paths": [工具路径], "failed": 失败次数}}"""
    if os.path.exists(LESSONS_FILE):
        try:
            with open(LESSONS_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_lessons(lessons: Dict) -> None:
    os.makedirs(config.OUTPUT_DIR, exist_ok=True)
    with open(LESSONS_FILE, "w") as f:
        json.dump(lessons, f, ensure_ascii=False, indent=2)


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
    empty_rounds = 0  # isNeedCheck=False 但 endpoints 空的连续次数（环境异常信号）
    reset_done = False  # 是否已尝试过"回收+重建"重置
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
        # 环境异常：isNeedCheck=False 但 endpoints 空——平台认为不再构建却无端点。
        # 先重置（回收+重建）让平台重新分配端点；重置后仍异常才放弃，不空等 20min
        if not need_check and not has_endpoint:
            empty_rounds += 1
            if empty_rounds >= 5 and not reset_done:
                reset_done = True
                empty_rounds = 0
                logger.warning(f"exercise {exercise_id} 环境异常(isNeedCheck=False 无 endpoints)，尝试重置重建...")
                try:
                    api.recover_env(exercise_id)
                except Exception:
                    pass
                time.sleep(3)
                try:
                    api.build_env(exercise_id)
                except Exception:
                    pass
                print(f"  ⟳ 环境异常，已重置重建 {exercise_id}（等待重新就绪）")
                continue
            if empty_rounds >= 5 and reset_done:
                raise TimeoutError(
                    f"exercise {exercise_id} 环境异常: 重置后仍 isNeedCheck=False 且 endpoints 空（平台构建问题）"
                )
        else:
            empty_rounds = 0
        logger.info(f"环境准备中... ({(i+1)}/{MAX_ENV_POLL}, isNeedCheck={need_check})")
    raise TimeoutError(f"exercise {exercise_id} 环境 {MAX_ENV_POLL*10}s 未就绪")


def _build_denied(e: Exception) -> bool:
    """build 被平台拒绝（如'创建靶机台数已达3数量，请销毁一台'）——不是幂等，继续等也没用"""
    s = str(e)
    return any(w in s for w in ["数量", "销毁", "已达", "上限", "创建靶机"])


def _is_rate_limited(e: Exception) -> bool:
    """平台限流（429）：请求太频繁被拒，临时性——跳过/重试，不是永久拒绝"""
    return "429" in str(e)


def _try_recover_env(api: SlabMatchAPI, ex_id: int):
    """尽力回收环境（每完成一题销毁一台，防止占满平台 3 台上限）；失败静默忽略"""
    try:
        api.recover_env(ex_id)
    except Exception:
        pass


# ── 复杂题多方向并行：题型 → 2-3 个解题方向（方法论语，多方向 agent 各打一个）──
DIRECTIONS = {
    "pwn": [
        "专注 tcache poisoning：泄露 libc 后，edit 覆写 tcache 头 → free_hook/malloc_hook → 写入 system → 触发 free(/bin/sh) 拿 shell 读 flag",
        "专注 fastbin attack / unsorted bin：覆写 malloc_hook/free_hook 或伪造 chunk，用 one_gadget/system 拿 shell 读 flag",
        "专注堆风水 + 对象指针覆写：通过 UAF/堆重叠覆写对象字段使其指向 /flag 或控制流，直接读 flag 或 RCE",
    ],
    "web": [
        "专注文件上传 → 触发执行：上传图片马/后缀绕过后，找 include/LFI 包含点或直接访问触发 PHP 执行读 flag",
        "专注 LFI/文件读取：php://filter 读源码找漏洞 → 读 config/flag 文件；配合伪协议/日志包含",
        "专注反序列化/POP 链：找 unserialize 入口 → php serialize 生成长度精确 payload → 触发 RCE 读 flag",
    ],
    "crypto": [
        "专注 RSA：factordb/sympy 分解 n、共模/小指数/低加密指数攻击，解出明文 flag",
        "专注编码套娃：base64/hex/rot/摩斯/URL 层层解码，找隐藏 flag",
        "专注对称加密脚本审计：从加密脚本找弱密钥/IV/已知明文 → 解密得到 flag",
    ],
}


def _parallel_solve(task: str, cat: str, max_rounds: int = None) -> (list, dict):
    """复杂题多方向并行：2-3 个方向子 agent 同时打同一靶场（共享 task 里的 target）。

    返回 (找到的显式 flag 列表, 各方向结果 dict)——多方向并行提升复杂题解出率。
    """
    if max_rounds is None:
        max_rounds = config.PARALLEL_ROUNDS  # 默认 100（难题需要更多轮）
    dirs = DIRECTIONS.get((cat or "").lower(), [])
    if not dirs:
        return [], {}
    stop_event = threading.Event()  # 任一方向找到 flag → 置事件，其他方向提前停止（省 token）
    results = {}
    flags = []
    lock = threading.Lock()

    def worker(direction: str, i: int):
        try:
            ag = build_agent(cat, direction=direction)
            r = ag.run(task, verbose=False, max_iterations=max_rounds, stop_event=stop_event)
            fs = set()
            for m in ag.messages:
                for tc in m.get("tool_calls", []) or []:
                    fn = (tc.get("function") or {}).get("name", "")
                    if fn == "submit_flag":
                        try:
                            args = json.loads((tc.get("function") or {}).get("arguments", "{}"))
                            f = args.get("flag", "")
                            if f:
                                fs.add(f)
                        except Exception:
                            pass
            if fs:
                stop_event.set()  # 本方向找到 flag → 通知其他方向停止
            with lock:
                results[i] = {
                    "direction": direction[:30],
                    "success": r.get("success"),
                    "flag_found": r.get("flag_found"),
                    "iterations": r.get("iterations"),
                }
                flags.extend(fs)
        except Exception as e:
            with lock:
                results[i] = {"direction": direction[:30], "error": str(e)}

    threads = [
        threading.Thread(target=worker, args=(d, i), daemon=True)
        for i, d in enumerate(dirs[:3])
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return list(set(flags)), results


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
    if any(k in text for k in ["pwn", "栈", "溢出", "fmt", "heap", "uaf"]) or category.lower() == "pwn":
        hints.append(
            "- Pwn 题: 先确定题目类型(栈溢出/格式化字符串/堆), 用 checksec 看保护\n"
            "  → 本地/远程连接后分析交互协议, 构造 exploit(pwntools)\n"
            "- **堆 UAF 题专项（shopping 类购物车/商品管理题常用）**: add/remove/edit 操作管理对象,\n"
            "  remove 后未清指针 → UAF。利用链:\n"
            "  → 先摸清 add(对象大小/字段布局)、remove(是否置 NULL)、edit(读写原语) 的交互协议\n"
            "  → 触发 UAF: add 两个对象 A/B, remove A 再通过 B 的悬空指针读写 A 的 freed chunk\n"
            "  → 泄露: 用 UAF 读 freed chunk 里的地址(如 tcache/fastbin fd 指针、unsorted bin main_arena) 拿 libc/堆基址\n"
            "  → 覆盖: 伪造 tcache/fastbin chunk 或对象 vtable/函数指针 → 控制执行流(RCE) 或直接改 flag 指针读取\n"
            "  → 地址计算: 用 run_python 精确算 hex 偏移(LE 字节序), 差量(如对象间隔 0x140) 辅助堆风水\n"
            "  → 目标是拿 flag: 先泄露, 再 RCE 执行 cat /flag 或用 UAF 直接读 flag 内存\n"
            "- **Pwn 提速要点（重要，避免单轮 60s+）**:\n"
            "  → 每次 run_python 只测 ≤3 个变体(如 offset/extra 最多试 2-3 个), 不要 for 循环跑 7 个变体\n"
            "  → socket recv 用 timeout=0.1~0.2s(不要 0.5s), 减少 recv_all 累积等待\n"
            "  → 一次连接内完成多次交互(复用连接), 不要每个变体都重新 connect(重连很慢)\n"
            "  → 先想清楚 payload 再执行, 用 run_python 调试逻辑, 确认关键地址后再打远程\n"
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


def solve_challenge(api: SlabMatchAPI, ch: Dict, progress: Dict, ready: dict = None) -> Dict:
    """解单道题: 启环境 → Agent 解题 → 提交 flag → 回收"""
    ex_id = ch["exercise_id"]
    name = ch.get("name", "")
    cat = ch.get("category", "")

    # 跳过已通关（回收环境：每完成一题销毁一台，防占满 3 台上限）
    if ex_id in progress["solved"] or ch.get("has_solved"):
        _try_recover_env(api, ex_id)
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
        _try_recover_env(api, ex_id)
        progress["failed"].append(ex_id)
        _save_progress(progress)
        return {"status": "detail_failed", "exercise_id": ex_id, "error": str(e)}

    desc = detail.get("description", "")
    diff = detail.get("difficulty", "?")
    score = detail.get("score", "")
    has_solved = detail.get("hasSolved", False)
    if has_solved:
        _try_recover_env(api, ex_id)
        progress["solved"].append(ex_id)
        _save_progress(progress)
        return {"status": "solved_before", "exercise_id": ex_id}

    # 2. 启动环境（如需要）
    if detail.get("isNeedInit"):
        # 预启动线程已就绪（ready[ex_id]=True）→ 直接复用，跳过 build + 轮询
        if ready and ready.get(ex_id) is True:
            print(f"\n[2/5] 环境已由预启动就绪（复用）")
            try:
                detail = api.get_exercise(ex_id)
            except Exception:
                pass
        else:
            print(f"\n[2/5] 启动环境...")
            try:
                # build 返回 "已构建/请勿频繁点击"(40409) 属正常幂等，继续轮询即可
                try:
                    api.build_env(ex_id)
                except RuntimeError as e:
                    # 429 限流：临时性，快速失败进下一题（下次运行重试），不空等
                    if _is_rate_limited(e):
                        raise RuntimeError(f"平台限流(429): {e}")
                    # 数量上限（"创建靶机台数已达3数量"）不是幂等——等也没用，快速失败
                    if _build_denied(e):
                        raise
                    if "40409" not in str(e) and "已构建" not in str(e):
                        raise
                    logger.info(f"环境已构建（幂等），继续等待就绪")
                detail = _wait_env_ready(api, ex_id)
            except Exception as e:
                logger.error(f"❌ 环境启动失败: {e}")
                _try_recover_env(api, ex_id)
                progress["failed"].append(ex_id)
                _save_progress(progress)
                return {"status": "env_failed", "exercise_id": ex_id, "error": str(e)}
    else:
        print(f"\n[2/5] 环境已就绪（无需启动）")

    target = _extract_endpoint_target(detail)
    print(f"  目标地址: {target or '(无端点)'}")

    # 附件信息：下载 attachment.files[].url 到本地工作目录，Agent 直接用 read_file/file 处理
    import os as _os, requests as _requests
    att_dir = _os.path.join(config.OUTPUT_DIR, "attachments", str(ex_id))
    _os.makedirs(att_dir, exist_ok=True)
    att_files = []
    att = detail.get("attachment") or {}
    for f in att.get("files") or []:
        fname = f.get("name", "attachment")
        furl = f.get("url", "")
        fpath = _os.path.join(att_dir, fname)
        if furl and not _os.path.exists(fpath):
            try:
                r = _requests.get(furl, timeout=30)
                if r.status_code == 200:
                    with open(fpath, "wb") as fh:
                        fh.write(r.content)
                    print(f"  📎 附件已下载: {fpath} ({len(r.content)} bytes)")
                else:
                    print(f"  ⚠️ 附件下载失败 HTTP {r.status_code}: {furl}")
            except Exception as e:
                print(f"  ⚠️ 附件下载异常: {e}")
        if _os.path.exists(fpath):
            att_files.append(f"{fname} -> {fpath}")
        elif furl:
            att_files.append(f"{fname} ({furl})")

    # 3. 构造题目描述（含专项思路注入，省轮次）
    strategy = _build_strategy_hint(name, desc, cat)
    # 注入同类题经验（P1+P2：成功路径引导 + 失败提醒换思路）
    lessons_hint = ""
    try:
        lessons = _load_lessons()
        entry = lessons.get((cat or "unknown").lower())
        if entry:
            parts = []
            paths = entry.get("solved_paths") or []
            if paths:
                parts.append(f"此类题此前成功路径参考: {' → '.join(paths[-1])}")
            if entry.get("notes"):
                parts.append(f"此类题经验笔记: {entry['notes']}")
            if entry.get("failed", 0) > 0:
                parts.append(f"⚠️ 此类题此前失败 {entry['failed']} 次，注意换思路，避免重复踩坑")
            if parts:
                lessons_hint = "\n".join(parts) + "\n"
    except Exception:
        pass
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

## 同类题经验（沉淀自之前运行，方法论级）
{lessons_hint if lessons_hint else '（无此前同类题经验）'}

注意:
- 靶场地址通过平台代理访问（HTTP 服务直接 curl / 探测）
- **附件已下载到本地路径**（见上方"附件:"里的 -> 路径），用 read_file/file/analyze_file 直接处理本地文件
- 找到 flag 后必须调用 submit_flag 提交，flag 格式一般为 flag{{...}}
- **不要读无关文件**（.env、tasks.json、output/ 等不是本题内容）
- 如果卡住可以尝试不同方向，不要在一种方法上死磕"""
    # 已知难题（经验库 failed>0 且该题型有多方向）→ 开局直接并行（方案 B，不等单 agent）
    lessons = _load_lessons()
    entry = lessons.get((cat or "unknown").lower(), {})
    hard = entry.get("failed", 0) > 0 and bool(DIRECTIONS.get((cat or "").lower()))

    parallel_flags = []
    if hard:
        dirs = DIRECTIONS.get((cat or "").lower(), [])
        print(f"\n  🔀 已知难题（同类此前失败 {entry['failed']} 次），开局 {len(dirs)} 方向并行...")
        parallel_flags, pres = _parallel_solve(task, cat)
        agent = None  # 难题开局并行，无单 agent
        result = {"success": False, "flag_found": bool(parallel_flags)}
        if parallel_flags:
            print(f"  🔀 并行方向找到 flag: {sorted(parallel_flags)}")
        else:
            print(f"  🔀 并行未找到 flag（方向结果: {[v.get('success') or v.get('error', '') for v in pres.values()]}）")
    else:
        print(f"\n[3/5] Agent 解题（超时 {CHALLENGE_TIMEOUT_SEC}s）...")
        agent = build_agent(cat)  # 规则分派子 Agent（按题型专用 prompt + 工具子集，独立上下文）
        result = agent.run(task, verbose=True)
        # 多方向并行：单 Agent 未解出（无 success 无 flag）→ 复杂题切 2-3 方向并行打同一靶场
        if not result.get("success") and not result.get("flag_found"):
            dirs = DIRECTIONS.get((cat or "").lower(), [])
            if dirs:
                print(f"\n  🔀 单 Agent 未解出，启动多方向并行（{len(dirs)} 方向 × 40 轮）...")
                parallel_flags, pres = _parallel_solve(task, cat)
                if parallel_flags:
                    print(f"  🔀 并行方向找到 flag: {sorted(parallel_flags)}")
                else:
                    print(f"  🔀 并行未找到 flag（方向结果: {[v.get('success') or v.get('error', '') for v in pres.values()]}）")
    agent_success = result.get("success", False)
    final_msg = result.get("final_message", "")

    # 4. 提取 flag 并提交
    # 优先：Agent 显式调用 submit_flag 工具的 flag（最可靠，不误抓示例）
    explicit_flags = set()
    for m in (agent.messages if agent else []):
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
    explicit_flags.update(parallel_flags)  # 合并并行方向找到的 flag

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
        if "\n" in f or "\\" in f or "print(" in f or f.count("{") > 1:
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

    # 7. 沉淀解题经验（P1+P2：方法论级工具路径，不含单题答案/flag）
    try:
        lessons = _load_lessons()
        cat_key = (cat or "unknown").lower()
        entry = lessons.setdefault(cat_key, {"solved_paths": [], "failed": 0})
        if status in ("solved", "partial"):
            path = []
            for m in agent.messages:
                for tc in m.get("tool_calls", []) or []:
                    fn = (tc.get("function") or {}).get("name", "")
                    if fn and fn not in path:
                        path.append(fn)
            path = path[:8]  # 保留关键路径
            if path and path not in entry["solved_paths"]:
                entry["solved_paths"].append(path)
                entry["solved_paths"] = entry["solved_paths"][-5:]  # 每类保留最近 5 条
                _save_lessons(lessons)
        else:
            entry["failed"] += 1
            _save_lessons(lessons)
    except Exception:
        pass

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
                # 429 限流：不是平台拒绝，跳过该题预启动即可（不禁用全局预启动）
                if _is_rate_limited(e):
                    return
                # 数量上限（"创建靶机台数已达3数量"）→ denied（禁用预启动，等主循环回收后再 build）
                if _build_denied(e):
                    ready[ex_id] = "denied"
                    return
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
            r = solve_challenge(api, ch, progress, ready=ready)
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
