"""编码/解码工具 - 自动识别并解码常见编码

支持:
- base64 / base32 / base85 / base64url
- hex
- URL 编码
- HTML 实体
- ROT13 / ROT47
- 摩斯码
- 多层嵌套自动解码
"""
import re
import base64
import codecs
import html
import urllib.parse
import logging
from tools.base import register_tool

logger = logging.getLogger(__name__)


def _try_base64(s: str) -> str | None:
    """尝试 base64 解码"""
    try:
        # 补齐 padding
        padded = s + "=" * (4 - len(s) % 4) if len(s) % 4 else s
        decoded = base64.b64decode(padded)
        # 检查是否是可读文本
        text = decoded.decode("utf-8", errors="strict")
        if text.isprintable() or "\n" in text:
            return text
    except Exception:
        pass
    return None


def _try_base32(s: str) -> str | None:
    try:
        decoded = base64.b32decode(s + "=" * (8 - len(s) % 8) if len(s) % 8 else s)
        return decoded.decode("utf-8", errors="strict")
    except Exception:
        return None


def _try_base85(s: str) -> str | None:
    try:
        decoded = base64.b85decode(s)
        return decoded.decode("utf-8", errors="strict")
    except Exception:
        return None


def _try_hex(s: str) -> str | None:
    """hex 字符串解码，支持 '414243' 和 '41 42 43' 两种格式"""
    clean = s.replace(" ", "").replace("0x", "").replace("\\x", "")
    if not re.match(r"^[0-9a-fA-F]+$", clean) or len(clean) % 2:
        return None
    try:
        return bytes.fromhex(clean).decode("utf-8", errors="strict")
    except Exception:
        return None


def _try_url_decode(s: str) -> str | None:
    if "%" not in s:
        return None
    try:
        decoded = urllib.parse.unquote(s)
        return decoded if decoded != s else None
    except Exception:
        return None


def _try_html_unescape(s: str) -> str | None:
    if "&" not in s or ";" not in s:
        return None
    try:
        decoded = html.unescape(s)
        return decoded if decoded != s else None
    except Exception:
        return None


def _try_rot13(s: str) -> str | None:
    try:
        decoded = codecs.decode(s, "rot_13")
        return decoded if decoded != s else None
    except Exception:
        return None


def _try_rot47(s: str) -> str | None:
    try:
        decoded = "".join(
            chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c
            for c in s
        )
        return decoded if decoded != s else None
    except Exception:
        return None


def _try_morse(s: str) -> str | None:
    """摩斯码解码"""
    MORSE = {
        ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
        "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
        "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
        ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
        "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
        "--..": "Z", "-----": "0", ".----": "1", "..---": "2", "...--": "3",
        "....-": "4", ".....": "5", "-....": "6", "--...": "7", "---..": "8",
        "----.": "9",
    }
    if not re.match(r"^[.\-\s/|]+$", s):
        return None
    try:
        words = re.split(r"\s{2,}|/|\|", s.strip())
        result = []
        for word in words:
            chars = word.strip().split()
            decoded_word = "".join(MORSE.get(c, "?") for c in chars)
            result.append(decoded_word)
        return " ".join(result)
    except Exception:
        return None


# 编码尝试顺序
DECODERS = [
    ("base64", _try_base64),
    ("base32", _try_base32),
    ("hex", _try_hex),
    ("url", _try_url_decode),
    ("html", _try_html_unescape),
    ("rot13", _try_rot13),
    ("rot47", _try_rot47),
    ("morse", _try_morse),
    ("base85", _try_base85),
]


@register_tool(
    name="auto_decode",
    description="""自动识别并解码常见编码。

支持: base64, base32, base85, hex, URL编码, HTML实体, ROT13, ROT47, 摩斯码。
会尝试所有编码方式，返回所有成功解码的结果。
对于多层嵌套编码，会递归解码最多 5 层。

适合: 收到一串看不懂的字符，想快速试试是不是某种编码。
""",
    parameters={
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "待解码的字符串"},
            "max_depth": {"type": "integer", "description": "递归解码最大深度，默认 5"},
        },
        "required": ["text"],
    },
)
def auto_decode(text: str, max_depth: int = 5) -> str:
    """自动解码"""
    results = []
    seen = set()

    def _decode_recursive(s: str, depth: int, path: list):
        if depth >= max_depth or s in seen:
            return
        seen.add(s)

        for name, decoder in DECODERS:
            try:
                decoded = decoder(s)
            except Exception:
                decoded = None
            if decoded and decoded != s and len(decoded) > 0:
                new_path = path + [name]
                results.append((depth, " → ".join(new_path), decoded))
                _decode_recursive(decoded, depth + 1, new_path)

    _decode_recursive(text, 0, [])

    if not results:
        return f"[未识别] 无法解码: {text[:100]}"

    # 按深度排序，浅层优先
    results.sort(key=lambda x: x[0])

    output = [f"找到 {len(results)} 种解码结果:"]
    for depth, path, decoded in results[:20]:  # 最多显示 20 条
        # 截断过长的解码结果
        show = decoded[:200] + "..." if len(decoded) > 200 else decoded
        output.append(f"  [{path}] {show}")

    return "\n".join(output)


@register_tool(
    name="encode_data",
    description="""编码工具。支持: base64, base32, hex, url, rot13, rot47, morse。

用法: encode_data("hello", "base64") → "aGVsbG8="
""",
    parameters={
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "待编码的字符串"},
            "method": {
                "type": "string",
                "enum": ["base64", "base32", "hex", "url", "rot13", "rot47", "morse"],
                "description": "编码方式",
            },
        },
        "required": ["text", "method"],
    },
)
def encode_data(text: str, method: str) -> str:
    """编码数据"""
    try:
        if method == "base64":
            return base64.b64encode(text.encode()).decode()
        elif method == "base32":
            return base64.b32encode(text.encode()).decode()
        elif method == "hex":
            return text.encode().hex()
        elif method == "url":
            return urllib.parse.quote(text)
        elif method == "rot13":
            return codecs.decode(text, "rot_13")
        elif method == "rot47":
            return "".join(
                chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c
                for c in text
            )
        elif method == "morse":
            MORSE_ENCODE = {
                "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".",
                "F": "..-.", "G": "--.", "H": "....", "I": "..", "J": ".---",
                "K": "-.-", "L": ".-..", "M": "--", "N": "-.", "O": "---",
                "P": ".--.", "Q": "--.-", "R": ".-.", "S": "...", "T": "-",
                "U": "..-", "V": "...-", "W": ".--", "X": "-..-", "Y": "-.--",
                "Z": "--..", "0": "-----", "1": ".----", "2": "..---",
                "3": "...--", "4": "....-", "5": ".....", "6": "-....",
                "7": "--...", "8": "---..", "9": "----.",
            }
            return " ".join(
                MORSE_ENCODE.get(c.upper(), "?") for c in text if c.isalnum()
            )
        else:
            return f"[错误] 不支持的编码方式: {method}"
    except Exception as e:
        return f"[编码错误] {e}"
