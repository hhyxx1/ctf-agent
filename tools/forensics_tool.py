"""Forensics / 文件分析工具

功能:
- 文件类型识别（file 命令）
- 字符串提取（strings + grep flag）
- binwalk 内嵌文件检测
- 文件头/魔数识别
- 图片元数据（exiftool）
- 隐写检测提示
"""
import os
import subprocess
import logging
from config import config
from tools.base import register_tool

logger = logging.getLogger(__name__)


# 常见文件头（魔数）
FILE_SIGNATURES = {
    b"\xff\xd8\xff": "JPEG 图片",
    b"\x89PNG\r\n\x1a\n": "PNG 图片",
    b"GIF87a": "GIF 图片",
    b"GIF89a": "GIF 图片",
    b"BM": "BMP 图片",
    b"PK\x03\x04": "ZIP 压缩包 / DOCX / JAR",
    b"\x1f\x8b": "GZIP 压缩包",
    b"Rar!\x1a\x07": "RAR 压缩包",
    b"7z\xbc\xaf\x27\x1c": "7z 压缩包",
    b"\x25\x50\x44\x46": "PDF 文档",
    b"\x4d\x5a": "PE 可执行文件 (Windows EXE/DLL)",
    b"\x7f\x45\x4c\x46": "ELF 可执行文件 (Linux)",
    b"\xca\xfe\xba\xbe": "Java class 文件",
    b"\x00\x00\x01\x00": "ICO 图标",
    b"RIFF": "WAV 音频 / AVI 视频",
    b"\x49\x44\x33": "MP3 音频 (ID3)",
    b"ftyp": "MP4 视频 (可能是 ftyp 在第 5 字节)",
    b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a": "PNG",
    b"\xff\xfb": "MP3 音频",
    b"\xfd\x37\x7a\x58\x5a\x00": "XZ 压缩包",
    b"OggS": "OGG 音频",
    b"\x1a\x45\xdf\xa3": "WebM / MKV 视频",
}


def _detect_file_type(filepath: str) -> str:
    """通过文件头识别文件类型"""
    try:
        with open(filepath, "rb") as f:
            header = f.read(16)

        for sig, desc in FILE_SIGNATURES.items():
            if header.startswith(sig):
                return f"{desc} (魔数: {sig.hex()})"

        # 检查是否是文本文件
        try:
            with open(filepath, "r") as f:
                f.read(1024)
            return "文本文件"
        except UnicodeDecodeError:
            pass

        return f"未知文件类型 (文件头: {header[:8].hex()})"
    except Exception as e:
        return f"识别失败: {e}"


@register_tool(
    name="analyze_file",
    description="""分析文件: 识别类型、提取字符串、检查内嵌文件。

自动执行:
1. file 命令识别文件类型
2. 通过文件头(魔数)识别
3. strings 提取可见字符串，搜索 flag/ctf
4. binwalk 检测内嵌文件
5. exiftool 查看元数据(如有)

适合: 拿到一个未知文件，想快速了解它的内容。
""",
    parameters={
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "文件路径。相对路径基于工作目录，如 'attachments/challenge.bin'",
            },
        },
        "required": ["path"],
    },
)
def analyze_file(path: str) -> str:
    """分析文件"""
    if not os.path.isabs(path):
        path = os.path.join(config.WORK_DIR, path)

    if not os.path.exists(path):
        return f"[错误] 文件不存在: {path}"

    size = os.path.getsize(path)
    results = [f"📄 文件: {path}", f"📏 大小: {size} bytes ({size/1024:.1f} KB)"]

    # 1. file 命令
    try:
        r = subprocess.run(["file", path], capture_output=True, text=True, timeout=10)
        results.append(f"🔍 file: {r.stdout.strip()}")
    except Exception as e:
        results.append(f"file 命令失败: {e}")

    # 2. 文件头识别
    file_type = _detect_file_type(path)
    results.append(f"🏷️ 类型: {file_type}")

    # 3. strings + grep flag
    try:
        r = subprocess.run(
            ["bash", "-c", f"strings '{path}' | head -50"],
            capture_output=True, text=True, timeout=30,
        )
        if r.stdout.strip():
            results.append(f"\n📝 strings (前50行):\n{r.stdout.strip()}")
    except Exception:
        pass

    # 搜索 flag 关键词
    try:
        r = subprocess.run(
            ["bash", "-c", f"strings '{path}' | grep -iE 'flag|ctf|key' | head -20"],
            capture_output=True, text=True, timeout=30,
        )
        if r.stdout.strip():
            results.append(f"\n🎯 发现 flag 相关字符串:\n{r.stdout.strip()}")
    except Exception:
        pass

    # 4. binwalk
    try:
        r = subprocess.run(
            ["binwalk", path], capture_output=True, text=True, timeout=30,
        )
        if r.stdout and "0x" in r.stdout:
            results.append(f"\n📦 binwalk 内嵌文件检测:\n{r.stdout.strip()}")
    except Exception:
        results.append("⚠️ binwalk 未安装或执行失败")

    # 5. exiftool (图片/文档元数据)
    try:
        r = subprocess.run(
            ["exiftool", path], capture_output=True, text=True, timeout=10,
        )
        if r.stdout and r.returncode == 0:
            exif = r.stdout.strip()
            if exif and len(exif) < 3000:
                results.append(f"\n📋 exiftool 元数据:\n{exif}")
    except Exception:
        pass

    return "\n".join(results)


@register_tool(
    name="steg_check",
    description="""隐写检测工具。检查图片/文件中是否藏有数据。

执行的检查:
1. zsteg (PNG/BMP 的 LSB 隐写)
2. steghide extract (JPEG 隐写，需要密码)
3. pngcheck (PNG 文件结构)
4. foremost (文件雕刻提取)
5. 文件末尾追加数据检查

适合: 题目给了一张图片，怀疑里面藏了 flag。
""",
    parameters={
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "图片/文件路径"},
            "password": {"type": "string", "description": "steghide 使用的密码（可选，默认空密码尝试）"},
        },
        "required": ["path"],
    },
)
def steg_check(path: str, password: str = "") -> str:
    """隐写检测"""
    if not os.path.isabs(path):
        path = os.path.join(config.WORK_DIR, path)

    if not os.path.exists(path):
        return f"[错误] 文件不存在: {path}"

    results = [f"🔍 隐写检测: {path}"]
    output_dir = os.path.join(config.OUTPUT_DIR, "steg_extract")
    os.makedirs(output_dir, exist_ok=True)

    # 1. zsteg (PNG/BMP LSB)
    try:
        r = subprocess.run(
            ["zsteg", path], capture_output=True, text=True, timeout=30,
        )
        out = (r.stdout + r.stderr).strip()
        if out and "nothing" not in out.lower():
            results.append(f"\n🌈 zsteg (LSB 隐写):\n{out[:2000]}")
    except FileNotFoundError:
        results.append("⚠️ zsteg 未安装。安装: gem install zsteg")
    except Exception as e:
        results.append(f"zsteg 出错: {e}")

    # 2. steghide (JPEG)
    try:
        steg_out = os.path.join(output_dir, "steghide_output.txt")
        cmd = ["steghide", "extract", "-sf", path, "-xf", steg_out, "-f"]
        if password:
            cmd.extend(["-p", password])
        else:
            cmd.extend(["-p", ""])  # 空密码
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, input="")
        if os.path.exists(steg_out):
            with open(steg_out, "r", errors="replace") as f:
                content = f.read()
            results.append(f"\n🕵️ steghide 提取成功:\n{content[:1000]}")
    except FileNotFoundError:
        results.append("⚠️ steghide 未安装。安装: apt install steghide")
    except Exception as e:
        results.append(f"steghide 出错: {e}")

    # 3. pngcheck
    try:
        r = subprocess.run(
            ["pngcheck", "-v", path], capture_output=True, text=True, timeout=10,
        )
        out = (r.stdout + r.stderr).strip()
        if out:
            results.append(f"\n🖼️ pngcheck:\n{out[:1000]}")
    except FileNotFoundError:
        pass  # pngcheck 不常用，忽略
    except Exception:
        pass

    # 4. foremost 文件雕刻
    try:
        foremost_dir = os.path.join(output_dir, "foremost")
        os.makedirs(foremost_dir, exist_ok=True)
        r = subprocess.run(
            ["foremost", "-i", path, "-o", foremost_dir, "-t", "all"],
            capture_output=True, text=True, timeout=60,
        )
        # 检查提取的文件
        extracted = []
        for root, _, files in os.walk(foremost_dir):
            for f in files:
                fp = os.path.join(root, f)
                extracted.append(f"{fp} ({os.path.getsize(fp)} bytes)")
        if extracted:
            results.append(f"\n🔪 foremost 提取的文件:\n" + "\n".join(extracted[:10]))
    except FileNotFoundError:
        results.append("⚠️ foremost 未安装。安装: apt install foremost")
    except Exception as e:
        results.append(f"foremost 出错: {e}")

    # 5. 检查文件末尾追加的数据
    try:
        file_type = _detect_file_type(path)
        if "PNG" in file_type or "JPEG" in file_type or "GIF" in file_type:
            # 图片文件，检查 EOF 后的数据
            with open(path, "rb") as f:
                content = f.read()
            # PNG: IEND 是最后一个 chunk
            # JPEG: FFD9 是结束标记
            # GIF: 3B 是结束标记
            eof_markers = [b"IEND", b"\xff\xd9", b"\x3b"]
            append_data = None
            for marker in eof_markers:
                idx = content.rfind(marker)
                if idx > 0:
                    after = content[idx + len(marker):]
                    if after and len(after) > 2:
                        append_data = after
                        break

            if append_data:
                results.append(f"\n📎 文件末尾发现追加数据 ({len(append_data)} bytes):")
                # 尝试解码
                try:
                    text = append_data.decode("utf-8", errors="strict")
                    results.append(f"  文本: {text[:500]}")
                except:
                    results.append(f"  HEX: {append_data[:200].hex()}")
    except Exception as e:
        results.append(f"检查追加数据出错: {e}")

    return "\n".join(results)
