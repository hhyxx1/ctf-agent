# Misc 杂项解题套路

## 编码识别速查

| 特征 | 编码 | 解码方式 |
|------|------|---------|
| `0-9a-f` 偶数长度 | hex | `bytes.fromhex(s)` |
| `A-Za-z0-9+/=` | base64 | `base64.b64decode(s)` |
| `A-Za-z0-9-_=` | base64url | `base64.urlsafe_b64decode(s)` |
| `!-~` 可见字符 | ascii85 | `base64.a85decode(s)` |
| `0-9A-Za-z!#$%&()*+-` | base91 | `base91.decode(s)` |
| `\x41\x42` | hex escape | `codecs.decode(s, 'unicode_escape')` |
| `&#x41;` 或 `&#65;` | HTML 实体 | `html.unescape(s)` |
| `U+4E2D` | Unicode | `chr(int(s[2:], 16))` |
| `\u4e2d` | Unicode escape | `s.encode().decode('unicode_escape')` |
| `41 42 43` 空格分隔 | hex 空格分隔 | `bytes([int(x,16) for x in s.split()])` |
| 摩斯码 `... --- ...` | Morse | 查表转换 |
| `培根密码` ABABBA | Bacon | 5 位一组查表 |
| 栅栏密码 | Rail Fence | 分组重组 |

## 常见编码处理脚本

```python
import base64, codecs, html

# 多层 base64 自动解码
def auto_decode(s, max_depth=10):
    for _ in range(max_depth):
        try:
            new_s = base64.b64decode(s).decode()
            if new_s == s:
                break
            s = new_s
        except:
            break
    return s

# hex 转 bytes
b = bytes.fromhex("414243")  # b'ABC'

# bytes 转可读字符串
b.decode('utf-8', errors='replace')
```

## 文件头识别

| 文件头 (hex) | 类型 |
|-------------|------|
| `FF D8 FF` | JPEG |
| `89 50 4E 47` | PNG |
| `47 49 46 38` | GIF |
| `42 4D` | BMP |
| `50 4B 03 04` | ZIP |
| `1F 8B` | GZIP |
| `52 61 72 21` | RAR |
| `37 7A BC AF 27 1C` | 7z |
| `25 50 44 46` | PDF |
| `4D 5A` | EXE/DLL |
| `7F 45 4C 46` | ELF |
| `CA FE BA BE` | Java class |
| `PK 03 04` | JAR/APK (ZIP) |

## 压缩包处理

### 伪加密
ZIP 文件中：
- 压缩源文件数据区：第 7 字节为全局方式位标记
- 压缩源文件目录区：第 9 字节
- 把 `01 00` 改成 `00 00` 即可解压

### 暴力破解
```bash
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt archive.zip
# 或用 john
zip2john archive.zip > hash.txt
john hash.txt
```

### 嵌套压缩包
```python
import zipfile, os
current = "start.zip"
while True:
    try:
        with zipfile.ZipFile(current) as z:
            z.extractall("extracted")
            files = os.listdir("extracted")
            if not files: break
            current = os.path.join("extracted", files[0])
    except:
        break
```

## 隐写速查

### 图片
```bash
binwalk image.png              # 查内嵌文件
zsteg image.png                # PNG LSB 隐写
steghide extract -sf image.jpg # JPEG 隐写（需要密码）
foremost image.png -o out/     # 提取文件
exiftool image.jpg             # 查看 EXIF
```

### PNG 宽高修复
CRC 校验在 IHDR chunk，修改宽高后 CRC 不匹配：
```python
import struct, zlib
# 暴力尝试正确的宽高
```

### 音频隐写
```bash
# 频谱图（可能藏图片）
sox audio.wav -n spectrogram
# LSB 隐写
stegolsb wavsteg -h 2 -i audio.wav -o output.txt
# 摩斯码
# 听音频识别长短音
```

## 脑洞题常见套路

1. **键盘坐标** - 字符在键盘上的位置
2. **手机九宫格** - 数字对应字母
3. **二维码** - 补全定位点后扫描
4. **颜文字/emoji** - 对应字母
5. **拼图还原** - 用 `gaps` 或 montage+python
6. **ASCII art** - 字符画藏信息

## 常用工具

```bash
# 文件识别
file binary
binwalk binary
strings binary | grep -i "flag\|ctf"

# 编码转换
python3 -c "import base64; print(base64.b64decode('...'))"

# 隐写
zsteg image.png
steghide extract -sf image.jpg
stegsolve

# 破解
fcrackzip -u -D -p wordlist.zip archive.zip
john --wordlist=wordlist hash.txt
```

## 解题流程

1. `file` 识别文件类型
2. 根据文件头判断是否损坏
3. `strings` + `binwalk` 快速侦察
4. 根据类型选择对应工具
5. 提取隐藏内容
6. 多次解码/解密
7. 获取 flag
