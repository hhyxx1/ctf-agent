# Crypto 解题套路

## RSA 系列

### 1. 小 n 分解（n < 2^64）
```python
from sympy import factorint
factors = factorint(n)  # 返回 {p: 指数}
```

### 2. 大 n 分解
- 先查 factordb.com（`pip install factordb`）
- Fermat 分解：p 和 q 接近时有效
- Pollard's p-1 / rho 算法

### 3. 低公钥指数攻击（e=3，m小）
- m^3 < n 时直接对 c 开三次方
- `gmpy2.iroot(c, 3)`

### 4. 共模攻击（同一明文，两个 e，同 n）
- 用扩展欧几里得求 s1*e1 + s2*e2 = 1
- m = c1^s1 * c2^s2 mod n

### 5. Wiener 攻击（d < n^0.25）
- 连分数展开 e/n，逐项验证

### 6. 已知 p 或 d 相关
- 已知 p: phi = (p-1)*(q-1), q = n//p
- 已知 e,d: k = e*d - 1, 分解 n

## AES

### ECB 模式
- 相同明文块产生相同密文块
- 可逐块爆破或利用模式

### CBC 模式
- IV 可控时可做 bit flipping
- Padding Oracle 攻击

### 常见考点
- 弱密钥（key 可爆破）
- key 泄露（其他文件中）
- 随机数预测

## 编码识别

| 特征 | 编码 |
|------|------|
| 0-9a-f，偶数长度 | hex |
| A-Za-z0-9+/= | base64 |
| A-Za-z0-9-_ | base64url |
| !-~ 可见字符 | ascii85 / base85 |
| 偶数个 0-9a-f | hex |

## 常用工具

```bash
# 在线分解
curl "http://factordb.com/api?query=$N"

# Sage（更强大的数学计算）
sage script.sage
```

## 解题流程

1. 识别加密算法（RSA/AES/DES/自定义）
2. 提取参数（n, e, c, p, q, key, iv）
3. 查找弱点（小参数、低指数、密钥泄露）
4. 编写解密脚本
5. 提取 flag
