"""writeup 经验合成（Cyber-Zero 借鉴）：从公开 CTF writeup 提取方法论进经验库。

用法:
    .venv/bin/python extract_writeup_lessons.py writeup.md       # 单文件
    .venv/bin/python extract_writeup_lessons.py writeups_dir/    # 目录（递归 .md/.txt）

反作弊：只提方法论句子（含漏洞/利用/绕过等关键词），过滤 flag{...} 值/单题细节。
"""
import sys
import os
import re
import glob
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 方法论关键词（提取包含这些的句子）
METHOD_KEYWORDS = [
    "漏洞", "注入", "绕过", "利用", "泄露", "上传", "反序列化", "rce", "lfi", "ssrf",
    "sql", "unserialize", "溢出", "uaf", "堆", "栈", "格式化", "弱口令", "口令",
    "认证", "授权", "目录", "接口", "api", "gremlin", "序列化", "shell", "伪协议",
    "注释", "绕过waf", "路径穿越", "任意文件", "权限",
]
# 反作弊：flag 值
FLAG_PATTERN = re.compile(r"(?:flag|ctf|dasctf|flag)\{[^}]{0,200}\}", re.I)
# 题型关键词
CATEGORY_KEYWORDS = {
    "web": ["web", "http", "登录", "上传", "注入", "反序列化", "接口", "api", "sql", "面板", "门户", "下载", "文件"],
    "pwn": ["内存安全", "二进制", "溢出", "沙箱", "uaf", "堆", "栈", "格式化", "pwn", "exploit"],
    "crypto": ["加密", "密钥", "rsa", "aes", "cipher", "密码", "解密", "共模"],
    "misc": ["隐写", "流量", "压缩", "取证", "steg", "pcap", "编码"],
}


def infer_category(text: str) -> str:
    t = text.lower()
    for cat, kws in CATEGORY_KEYWORDS.items():
        if any(k in t for k in kws):
            return cat
    return "unknown"


def extract_methods(writeup_text: str) -> list:
    """提取方法论句子（含关键词、无 flag 值）"""
    text = FLAG_PATTERN.sub("[FLAG]", writeup_text)  # 去 flag 值
    sentences = re.split(r"[。\n；;]", text)
    methods = []
    for s in sentences:
        s = s.strip()
        if len(s) < 8 or len(s) > 200:
            continue
        low = s.lower()
        # flag 值已被 FLAG_PATTERN 替换成 [FLAG]，句子本身不泄露——方法论句保留
        if any(k in low for k in METHOD_KEYWORDS):
            methods.append(s)
    return methods


def process(path: str) -> dict:
    """处理 writeup 文件/目录，返回更新后的经验库"""
    from config import config

    lessons_file = os.path.join(config.OUTPUT_DIR, "slab_lessons.json")
    lessons = {}
    if os.path.exists(lessons_file):
        try:
            lessons = json.load(open(lessons_file))
        except Exception:
            pass

    files = [path] if os.path.isfile(path) else sorted(
        glob.glob(os.path.join(path, "**", "*.md"), recursive=True)
        + glob.glob(os.path.join(path, "**", "*.txt"), recursive=True))
    total = 0
    for fp in files:
        try:
            text = open(fp, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        methods = extract_methods(text)
        if not methods:
            continue
        cat = infer_category(text)
        entry = lessons.setdefault(cat, {"solved_paths": [], "failed": 0, "notes": ""})
        new = "【writeup 合成】" + "；".join(methods[:8])
        if new not in entry.get("notes", ""):
            entry["notes"] = (entry.get("notes", "") + "\n" + new).strip()[:3000]
            total += 1

    os.makedirs(os.path.dirname(lessons_file), exist_ok=True)
    json.dump(lessons, open(lessons_file, "w"), ensure_ascii=False, indent=2)
    return {"files": len(files), "extracted": total, "categories": list(lessons.keys())}


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    result = process(sys.argv[1])
    print(f"✅ writeup 经验合成完成: 处理 {result['files']} 个文件, 新增 {result['extracted']} 条方法论")
    print(f"   经验库分类: {result['categories']}")


if __name__ == "__main__":
    main()
