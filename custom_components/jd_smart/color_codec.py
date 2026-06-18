"""京东彩虹网关 ciphertype:5 编解码器（ep / body 的 cipher 字段）。

本质是【自定义字母表的标准 Base64】——换表混淆，不是加密。逆向自 App 的 decode()，
ep/body 的 cipher 可完全离线 decode/encode，无需 hook。

集成内置副本（与仓库根 color_codec.py 同源，纯标准库），便于装进 HA 后自包含运行。
不内置任何真实设备指纹值。
"""

# char[] ALPHABET（KLMNOPQRST ABCDEFGHIJ UVWXYZ abcd opqrstuvwx efghijklmn yz 0-9 +/）
ALPHABET = (
    "KLMNOPQRST"
    "ABCDEFGHIJ"
    "UVWXYZ"
    "abcd"
    "opqrstuvwx"
    "efghijklmn"
    "yz"
    "0123456789"
    "+/"
)
assert len(ALPHABET) == 64 and len(set(ALPHABET)) == 64, "字母表必须是 64 个互不相同字符"

_INV = {c: i for i, c in enumerate(ALPHABET)}


def decode(text: str) -> bytes:
    """与 App 的 decode(String) 一比一：跳过 '='/非法字符，6bit 大端拼装。"""
    out = bytearray()
    buffer = 0
    bits = 0
    for ch in text:
        v = _INV.get(ch, -1)
        if ch == "=" or ord(ch) >= 128 or v < 0:
            continue
        buffer = (buffer << 6) | v
        bits += 6
        if bits >= 8:
            bits -= 8
            out.append((buffer >> bits) & 0xFF)
    return bytes(out)


def encode(data: bytes) -> str:
    """decode 的逆：标准 base64 打包（大端 6bit）+ 自定义表 + '=' 补齐到 4 的倍数。"""
    out = []
    buffer = 0
    bits = 0
    for byte in data:
        buffer = (buffer << 8) | byte
        bits += 8
        while bits >= 6:
            bits -= 6
            out.append(ALPHABET[(buffer >> bits) & 0x3F])
    if bits > 0:  # 末尾不足 6bit，左移补零成一个字符
        out.append(ALPHABET[(buffer << (6 - bits)) & 0x3F])
    s = "".join(out)
    while len(s) % 4 != 0:
        s += "="
    return s


def dec_str(text: str, encoding: str = "utf-8", errors: str = "replace") -> str:
    return decode(text).decode(encoding, errors)


def enc_str(text: str, encoding: str = "utf-8") -> str:
    return encode(text.encode(encoding))
