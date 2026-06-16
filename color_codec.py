#!/usr/bin/env python3
"""
京东彩虹网关 ciphertype:5 编解码器（jdsmart.house.getHouses 的 ep / body cipher）。

逆向自 App 的 decode()：本质就是【自定义字母表的标准 Base64】——不是加密，是换表混淆。
ALPHABET 是被打乱的 64 字符表；解码 = 标准 base64 位拼装（大端 6bit）但用这张表查 6bit 值。
=> ep / body 的 cipher 字段可完全离线 decode，也能 encode（自己生成），无需 hook 加密函数。

  decode(text)  -> bytes     # 与 App 的 decode 一比一
  encode(data)  -> str       # 逆运算（标准 base64 打包 + '=' 补齐），用于自造 ep/body
  dec_str/enc_str            # 文本便捷版（UTF-8）

注意：不在本文件内置任何真实设备指纹值；测试向量只用通用常量（"android"/"wifi"）。
真实 ep/body 的解码请在本地跑（值含设备信息，勿提交/外传）。
"""

# 逐行对应源码 char[] ALPHABET（KLMNOPQRST ABCDEFGHIJ UVWXYZ abcd opqrstuvwx efghijklmn yz 0-9 +/）
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


if __name__ == "__main__":
    # 自测：通用常量（非设备数据）。client="android" / networkType="wifi" 的真实密文。
    VECTORS = {
        "client(android)": ("YW5ucw9fZK==", "android"),
        "networkType(wifi)": ("d2vwaG==", "wifi"),
    }
    ok = True
    for name, (cipher, plain) in VECTORS.items():
        got = dec_str(cipher)
        rt = encode(decode(cipher))  # 往返：encode(decode(x)) 应 == 原密文
        line = f"  {name:20} decode({cipher!r}) -> {got!r}"
        if got != plain:
            ok = False
            line += f"   [FAIL] 期望 {plain!r}"
        elif rt != cipher:
            ok = False
            line += f"   [FAIL] 往返失败 encode->{rt!r}"
        else:
            line += "   [OK] (含往返)"
        print(line)
    # 纯往返（随机字节）：encode/decode 互逆
    sample = bytes(range(0, 256))
    if decode(encode(sample)) != sample:
        ok = False
        print("  [FAIL] 字节往返失败")
    else:
        print("  字节往返(0..255)            [OK]")
    print("\n自测", "通过(PASS)" if ok else "失败(FAIL)")
    raise SystemExit(0 if ok else 1)
