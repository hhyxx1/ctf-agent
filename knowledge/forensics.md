# Forensics / Misc 解题套路

## Forensics 取证

### 通用流程
1. **file 命令** - 识别文件类型
2. **binwalk** - 查看内嵌文件
3. **foremost** - 提取文件
4. **strings** - 查看可见字符串

### 图片隐写

| 工具 | 用途 |
|------|------|
| `zsteg image.png` | PNG/BMP LSB 隐写检测 |
| `stegsolve` | 多通道查看 |
| `steghide extract -sf image.jpg` | JPEG 隐写提取 |
| `pngcheck` | PNG 文件结构检查 |

**常见手法：**
- LSB（最低有效位）隐写
- 图片末尾追加文件（binwalk 提取）
- 修改图片宽高（CRC 校验）
- 颜色通道隐藏信息

### 流量分析（pcap）

```bash
# 提取 HTTP 对象
tshark -r capture.pcap --export-objects http,output_dir/

# 查找 flag
tshark -r capture.pcap -Y "frame contains \"flag\"" -V

# 提取 TCP 流
tshark -r capture.pcap -z "follow,tcp,ascii,0"
```

**常见考点：**
- HTTP 明文传输的 flag
- 文件传输还原（FTP、SMB）
- DNS 隧道
- TLS 私钥解密

### 内存取证（volatility）

```bash
volatility -f memory.dmp imageinfo          # 识别系统
volatility -f memory.dmp --profile=Win7SP1x64 pslist      # 进程列表
volatility -f memory.dmp --profile=Win7SP1x64 filescan    # 文件扫描
volatility -f memory.dmp --profile=Win7SP1x64 hashdump    # 提取密码哈希
```

### 磁盘取证

```bash
# 挂载镜像
mount -o loop image.raw /mnt

# 查看分区
fdisk -l image.raw

# 恢复删除文件
foremost -i image.raw -o output/
```

## Misc 杂项

### 编码识别

| 特征 | 编码 |
|------|------|
| 0-9a-f 偶数长度 | hex |
| A-Za-z0-9+/= | base64 |
| `\\x` 开头 | hex escape |
| `&#x` 或 `&#` | HTML 实体 |
| `U+` | Unicode |
| `\u` | Unicode escape |

### 常见题型

1. **编码转换题** - 多层 base64/hex 编码
2. **脑洞题** - 需要联想（二维码、键盘坐标等）
3. **数据恢复** - 修复损坏的文件头
4. **隐写** - 各种载体隐写
5. **PPC（编程题）** - 算法题或脚本题

### 二维码修复
- 补全定位点（三个角的方块）
- 用 `zbarimg` 解码

### 压缩包分析
```bash
# 伪加密：压缩源文件目录区的全局方式位标记（第9字节）
# 把 01 00 改成 00 00

# 暴力破解
fcrackzip -u -D -p wordlist.zip archive.zip
```

## 常用工具清单

```bash
# 文件分析
file binary
binwalk binary
strings binary | grep -i flag
exiftool image.jpg

# 隐写
zsteg image.png
steghide extract -sf image.jpg
stegsolve

# 取证
volatility -f memory.dmp ...
tshark -r capture.pcap ...

# 压缩包
fcrackzip -u -D -p wordlist.zip archive.zip
```

## 解题流程

1. `file` 识别文件类型
2. 根据类型选择对应工具
3. 提取隐藏内容或修复文件
4. 多次解码/解密
5. 获取 flag

## 注意事项

- 先 `file` 和 `strings` 再深入分析
- 隐写题多尝试几种工具
- 流量分析注意时间和协议
- 内存取证先确认操作系统版本
