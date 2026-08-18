"""RAG 知识库模块 - 存储和检索 CTF 解题知识

knowledge/ 目录结构:
  knowledge/
    crypto.md        # crypto 题型解题套路
    web.md           # web 题型解题套路
    pwn.md           # pwn 题型解题套路
    reverse.md       # reverse 题型解题套路
    forensics.md     # forensics 题型解题套路
    misc.md          # misc 题型解题套路

检索方式: 简单关键词匹配（无需向量数据库，轻量够用）
"""
import os
import logging
from config import config

logger = logging.getLogger(__name__)


def _load_all_knowledge() -> dict:
    """加载 knowledge/ 下所有 .md 文件"""
    knowledge = {}
    if not os.path.exists(config.KNOWLEDGE_DIR):
        return knowledge
    for fname in os.listdir(config.KNOWLEDGE_DIR):
        if fname.endswith(".md"):
            path = os.path.join(config.KNOWLEDGE_DIR, fname)
            try:
                with open(path, "r", errors="replace") as f:
                    knowledge[fname[:-3]] = f.read()
            except Exception as e:
                logger.warning(f"加载知识文件 {fname} 失败: {e}")
    return knowledge


_KNOWLEDGE_CACHE = None


def get_knowledge() -> dict:
    """获取知识库（带缓存）"""
    global _KNOWLEDGE_CACHE
    if _KNOWLEDGE_CACHE is None:
        _KNOWLEDGE_CACHE = _load_all_knowledge()
    return _KNOWLEDGE_CACHE


def search_knowledge(query: str, max_results: int = 3) -> str:
    """
    根据题目描述检索相关解题知识

    参数:
        query: 题目描述或关键词
        max_results: 最多返回几段知识

    返回:
        拼接好的知识文本，供 Agent 参考
    """
    knowledge = get_knowledge()
    if not knowledge:
        return ""

    query_lower = query.lower()
    scored = []

    for category, content in knowledge.items():
        score = 0
        # 类别名称直接匹配
        if category.lower() in query_lower:
            score += 10
        # 关键词匹配
        keywords = {
            "crypto": ["rsa", "aes", "des", "encrypt", "decrypt", "cipher",
                       "n=", "e=", "c=", "p=", "q=", "mod", "base64", "hex"],
            "web": ["sql", "xss", "ssrf", "ssti", "injection", "cookie",
                    "session", "url", "http", "request", "burp", "lfi", "rfi"],
            "pwn": ["overflow", "buffer", "stack", "heap", "shellcode",
                    "ret2", "libc", "gadget", "rop", "canary"],
            "reverse": ["reverse", "decompile", "ida", "ghidra", "radare",
                        "assembly", "binary", "elf", "exe", "crack"],
            "forensics": ["forensic", "memory", "disk", "volatility",
                          "wireshark", "pcap", "steg", "hidden", "recover"],
            "misc": ["misc", "puzzle", "encoding", "decode", "qr", "barcode"],
        }
        for kw in keywords.get(category, []):
            if kw in query_lower:
                score += 2
        if score > 0:
            scored.append((score, category, content))

    if not scored:
        # 没有精确匹配，返回所有知识的前 max_results 段
        results = list(knowledge.items())[:max_results]
    else:
        scored.sort(key=lambda x: x[0], reverse=True)
        results = [(cat, content) for _, cat, content in scored[:max_results]]

    output_parts = []
    for cat, content in results:
        # 截断过长的知识文本
        if len(content) > 3000:
            content = content[:3000] + "\n...[知识截断]..."
        output_parts.append(f"=== {cat} 解题知识 ===\n{content}")

    return "\n\n".join(output_parts)


def add_knowledge(category: str, content: str):
    """添加或更新某个类别的知识"""
    path = os.path.join(config.KNOWLEDGE_DIR, f"{category}.md")
    with open(path, "w") as f:
        f.write(content)
    # 刷新缓存
    global _KNOWLEDGE_CACHE
    _KNOWLEDGE_CACHE = None
    logger.info(f"知识已保存: {path}")
