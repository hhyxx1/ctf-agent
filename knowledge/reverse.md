# Reverse 解题套路

## 通用流程

1. **file 命令** - 识别文件类型
2. **strings** - 提取可见字符串
3. **反编译/反汇编** - IDA / Ghidra / radare2
4. **动态调试** - gdb / lldb / strace

## 常见文件类型

| 文件头 | 类型 | 工具 |
|--------|------|------|
| 7f 45 4c 46 | ELF | IDA, radare2 |
| 4d 5a | PE/EXE | x64dbg, IDA |
| 43 41 46 45 | Java class | jadx, jd-gui |
| 50 4b | APK/JAR | apktool, jadx |
| 1f 8b | gzip | gunzip |

## 静态分析

### radare2
```bash
r2 -A binary       # 分析
aaa                # 自动分析和命名
pdf @main          # 反汇编 main 函数
```

### Ghidra（免费）
- 反编译为 C 代码
- 自动识别函数

## 常见考点

### 1. 简单异或/加减密
```python
cipher = [...]  # 从二进制中提取
key = 0x42      # 猜测的 key
flag = ''.join(chr(c ^ key) for c in cipher)
```

### 2. 算法逆向
- 找到加密函数
- 理解算法逻辑
- 写对应的解密函数

### 3. 迷宫/约束
- 识别迷宫结构
- DFS/BFS 求解

### 4. 反调试
- ptrace 检测：`ptrace(PTRACE_TRACEME)`
- 时间检测：`rdtsc`
- 跳过或 patch 掉

### 5. UPX 脱壳
```bash
upx -d packed_binary
```

## 动态调试

### gdb
```bash
gdb ./binary
break main
run
stepi        # 单步指令
```

### strace（查看系统调用）
```bash
strace ./binary
```

## Python 逆向

### .pyc 文件
```bash
pip install uncompyle6
uncompyle6 file.pyc > source.py
```

### 反混淆
- 识别混淆模式（变量名替换、控制流平坦化）
- 手动恢复或写脚本自动化

## 常用工具

```bash
file binary
strings binary | grep -i flag
checksec binary          # 查保护机制
ghidra                   # 反编译
r2 binary                # radare2
gdb binary               # 动态调试
```

## 解题流程

1. file + strings 快速侦察
2. 用 IDA/Ghidra 反编译，找 main 和关键函数
3. 理解加密/校验逻辑
4. 写解密脚本或 patch 程序
5. 运行获取 flag
