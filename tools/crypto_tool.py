"""Crypto 工具 - 封装 RSA/AES 等常见密码学攻击

设计原则：
- 优先用在线服务（factordb）分解 n，避免本地卡死
- 本地分解只对小 n (< 10^18) 使用 sympy
- 大 n 尝试 Fermat 分解（p,q 接近时有效）
- 自动识别 RSA 参数并尝试多种攻击
"""
import json
import logging
import urllib.request
import urllib.parse
from tools.base import register_tool

logger = logging.getLogger(__name__)


def _factordb_query(n: int) -> dict:
    """查询 factordb.com 分解 n

    返回:
        {
            "status": "FF" | "CF" | "P" | "U" | "C" | "Unit",
            "factors": [(p, exp), ...]
        }
    status 含义:
        FF = 完全分解
        CF = 部分分解
        P = 质数
        U = 未分解
        C = 合数
        Unit = 1
    """
    try:
        url = f"http://factordb.com/api?query={n}"
        req = urllib.request.Request(url, headers={"User-Agent": "ctf-agent/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        return data
    except Exception as e:
        logger.warning(f"factordb 查询失败: {e}")
        return {"status": "error", "factors": []}


@register_tool(
    name="rsa_decrypt",
    description="""RSA 解密工具。自动尝试多种方法分解 n 并解密 c。

支持的攻击方式（按优先级）：
1. factordb 在线查询（大 n 首选）
2. sympy 本地分解（仅小 n < 10^18）
3. Fermat 分解（p, q 接近时）
4. 小公钥指数攻击（e=3 且 m^e < n）
5. 共模攻击（两个 c, 两个 e, 同 n）

输出:
- 找到明文时返回 m 和 bytes 形式
- 失败时返回尝试过的方法和错误信息
""",
    parameters={
        "type": "object",
        "properties": {
            "n": {"type": "string", "description": "RSA 模数 n（大数用字符串传）"},
            "e": {"type": "string", "description": "公钥指数 e"},
            "c": {"type": "string", "description": "密文 c"},
            "c2": {"type": "string", "description": "共模攻击用的第二个密文（可选）"},
            "e2": {"type": "string", "description": "共模攻击用的第二个公钥（可选）"},
            "p": {"type": "string", "description": "已知 p（可选）"},
            "q": {"type": "string", "description": "已知 q（可选）"},
        },
        "required": ["n", "e", "c"],
    },
)
def rsa_decrypt(n: str, e: str, c: str, c2: str = "", e2: str = "",
                p: str = "", q: str = "") -> str:
    """RSA 自动解密"""
    try:
        from Crypto.Util.number import long_to_bytes, inverse
        from sympy import factorint, isprime
        import gmpy2

        n = int(n)
        e = int(e)
        c = int(c)

        results = []
        factors = None

        # ── 方法 0: 已知 p, q ──
        if p and q:
            p, q = int(p), int(q)
            if p * q == n:
                factors = {p: 1, q: 1}
                results.append("✅ 使用已知的 p, q")

        # ── 方法 1: factordb 在线查询 ──
        if not factors:
            results.append("尝试 factordb 在线查询...")
            fd = _factordb_query(n)
            if fd.get("status") == "FF" and fd.get("factors"):
                factors = {}
                for prime, exp in fd["factors"]:
                    factors[int(prime)] = int(exp)
                results.append(f"✅ factordb 分解成功: {factors}")
            elif fd.get("status") == "P":
                # n 本身是质数
                factors = {n: 1}
                results.append(f"✅ n 是质数")
            else:
                results.append(f"❌ factordb 未完全分解 (status={fd.get('status')})")

        # ── 方法 2: 小 n 本地分解 (< 10^18) ──
        if not factors and n < 10**18:
            results.append("尝试 sympy 本地分解（小 n）...")
            try:
                f = factorint(n, limit=10**6)
                if f and all(isprime(p) for p in f):
                    factors = f
                    results.append(f"✅ sympy 分解成功: {factors}")
            except Exception as ex:
                results.append(f"❌ sympy 分解失败: {ex}")

        # ── 方法 3: Fermat 分解（p, q 接近）──
        if not factors and n < 10**50:
            results.append("尝试 Fermat 分解...")
            try:
                a = gmpy2.isqrt(n) + 1
                for _ in range(100000):
                    b2 = a * a - n
                    b = gmpy2.isqrt(b2)
                    if b * b == b2:
                        p_f = int(a - b)
                        q_f = int(a + b)
                        if p_f * q_f == n and p_f > 1:
                            factors = {p_f: 1, q_f: 1}
                            results.append(f"✅ Fermat 分解成功: p={p_f}, q={q_f}")
                            break
                    a += 1
                if not factors:
                    results.append("❌ Fermat 分解失败（p, q 不够接近）")
            except Exception as ex:
                results.append(f"❌ Fermat 分解出错: {ex}")

        # ── 方法 4: Pollard's rho 本地分解（factordb 联网失败时的兜底）──
        # 适合 n < 10^50，不联网，托管沙箱可用
        if not factors and n < 10**50:
            results.append("尝试 Pollard's rho 本地分解...")
            try:
                import gmpy2
                def _pollard_rho(nn):
                    """Pollard's rho 算法，返回 nn 的一个非凡因子或 None"""
                    if nn % 2 == 0:
                        return 2
                    import random
                    x = random.randint(2, nn - 1)
                    y = x
                    c = random.randint(1, nn - 1)
                    d = 1
                    while d == 1:
                        x = (x * x + c) % nn
                        y = (y * y + c) % nn
                        y = (y * y + c) % nn
                        d = gmpy2.gcd(abs(x - y), nn)
                        if d == nn:
                            # 重新随机再来
                            return None
                    return int(d)

                # 跑 rho，限制总轮数防卡死
                p_found = None
                for attempt in range(200):
                    if n.bit_length() > 200:
                        # 超过 200 bit，rho 太慢，跳过
                        results.append("❌ Pollard's rho: n 太大 (>200bit)，跳过")
                        break
                    f = _pollard_rho(n)
                    if f and 1 < f < n:
                        p_found = f
                        break

                if p_found:
                    q_found = n // p_found
                    if p_found * q_found == n:
                        factors = {p_found: 1, q_found: 1}
                        results.append(f"✅ Pollard's rho 分解成功: p={p_found}, q={q_found}")
                    else:
                        results.append("❌ Pollard's rho 分解结果校验失败")
                else:
                    results.append("❌ Pollard's rho 未找到因子（n 可能太大）")
            except Exception as ex:
                results.append(f"❌ Pollard's rho 出错: {ex}")

        # ── 尝试解密 ──
        if factors:
            # 计算 phi(n)
            phi = 1
            for prime, exp in factors.items():
                phi *= (prime - 1) * (prime ** (exp - 1))

            try:
                d = inverse(e, phi)
                m = pow(c, d, n)
                m_bytes = long_to_bytes(m)
                results.append(f"\n✅ 解密成功！")
                results.append(f"m = {m}")
                results.append(f"bytes = {m_bytes}")

                # 检查是否是可读的 flag
                try:
                    decoded = m_bytes.decode('utf-8', errors='replace')
                    if 'flag' in decoded.lower() or 'ctf' in decoded.lower():
                        results.append(f"\n🎯 发现 flag: {decoded}")
                except:
                    pass
                return "\n".join(results)
            except Exception as ex:
                results.append(f"❌ 解密失败 (e 和 phi 不互素?): {ex}")
                return "\n".join(results)

        # ── 方法 4: 小公钥指数攻击 (e=3, m^e < n) ──
        if e == 3:
            results.append("尝试小公钥指数攻击 (e=3)...")
            try:
                root, exact = gmpy2.iroot(c, 3)
                if exact:
                    m_bytes = long_to_bytes(int(root))
                    results.append(f"✅ 开三次方成功: {m_bytes}")
                    return "\n".join(results)
                # 尝试 c + k*n
                for k in range(10000):
                    root, exact = gmpy2.iroot(c + k * n, 3)
                    if exact:
                        m_bytes = long_to_bytes(int(root))
                        results.append(f"✅ c+{k}*n 开三次方成功: {m_bytes}")
                        return "\n".join(results)
                results.append("❌ 小指数攻击失败")
            except Exception as ex:
                results.append(f"❌ 小指数攻击出错: {ex}")

        # ── 方法 5: 共模攻击 ──
        if c2 and e2:
            results.append("尝试共模攻击...")
            try:
                from Crypto.Util.number import long_to_bytes
                e2_val = int(e2)
                c2_val = int(c2)
                # 扩展欧几里得: s1*e1 + s2*e2 = 1
                import gmpy2
                gcd, s1, s2 = gmpy2.gcdext(e, e2_val)
                if gcd == 1:
                    m = (pow(c, int(s1), n) * pow(c2_val, int(s2), n)) % n
                    m_bytes = long_to_bytes(int(m))
                    results.append(f"✅ 共模攻击成功: {m_bytes}")
                    return "\n".join(results)
                else:
                    results.append(f"❌ gcd(e1,e2)={gcd} != 1")
            except Exception as ex:
                results.append(f"❌ 共模攻击出错: {ex}")

        results.append("\n❌ 所有方法均失败。建议:")
        results.append("  - 手动查 factordb.com")
        results.append("  - 检查是否有其他已知参数")
        results.append("  - 考虑 Wiener 攻击 (d 很小时)")
        return "\n".join(results)

    except Exception as ex:
        return f"[rsa_decrypt 出错] {type(ex).__name__}: {ex}"
