#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
refreshLoginStatus的流程：
// {"k":"c97961b6396b78fc","d":"5A9D34DD0BF31D4AA0669FB33ABA237CC4BA3C022EAB84419A5411A9B609C84ABC03AA3BD12D1EFF92BF157669D2EFC39DA2FA1531ED83983440CC79221114CF934065F228FD7DEFC9DFA932E88B05EF86A4F3DB2F73390527E4549F4B6A3421E312E683000341A8D4DC27727A4753DDA554E0BB12C9C518AE0B0A125CAC18AE21F2B7D8F1E5064F6E07E313A01690D5D9F8DB429CA231AC1507D8058DED65E7D784434A0D0F1ADC05EC9B276C3DD96B934A25754C88F4314D2F74A97B463C0ECE2B0B74D8FCC5B53CE8D16A4745AA5303D0A1620966AA655699E5382308582115639DE8ADAE91F2A144C5A5E7F6957A95EBA4BC967BA90AA689DEBF4A0EF1FEDC9E6E67C685C3D1FFFC124AFF4D1AC4645408474ED3616F04640BFD049202A0D9FEA847EDC743D05D85902B90B13E931F86B290D7681C1445EFB050F458C6B70A8897F19EE07F4D06A1D15EE93CCC4C8AC0DC3AF108644B2E1A48DEF83E8567"}
1. 读取硬盘加密数据：jd.wjlogin_sdk.util.v.g(String jsonContent)
// users: jd.wjlogin_sdk.model.WUserSigInfo[]
// {"users":["{\"Account\":\"18877811997\",\"A2\":\"AAJqMg6dAEBJGn6xq-vgu1HcHwMqZXKJK-Ojc_rctMiITNtqWj0HmlspDcZ-xhgEmQOktneOCJoG7vMiid9h4YY9uzhhFnYp\",\"Pin\":\"6a645f36353333303231363666333530\",\"A2TimeOut\":15768000,\"A2RefreshTime\":7884000,\"countryCode\":\"86\",\"A2CreateDate\":\"2026-06-17 11:03:57\",\"isCurrentMainUser\":true}"]}
2. 解密硬盘数据：jd.wjlogin_sdk.b.b.a(String k, String d)
2.1 解密算法

对应原 Java EncryptorV6 解密流程：
    AES/CBC/PKCS5Padding
    key  = PBKDF2WithHmacSHA1(password, salt, iter=10, keyLen=128bit)
    salt = g.b().a()        （build_salt 复刻）
    iv   = 无参 a()          （固定串 "1653678145712191"）

依赖: pip install pycryptodome
"""
import argparse
import base64
import hashlib

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# 无参 a() 拼出来的固定 IV（16 字节）
IV = b"1653678145712191"

# 默认口令（即你调用时传入的第一个参数）
DEFAULT_PASSWORD = "c97961b6396b78fc"


def build_salt() -> bytes:
    """复刻 g.b().a()，输出 16 字节盐值。"""
    b1 = b"!q@w"                              # [0..3]
    b2 = b"#e$r"                              # [4..7]
    a10 = base64.b64decode("JXReeQ==")        # [8..11]  -> %t^y
    b3 = bytes(((b1[i] + b2[i] + a10[i]) // 3) & 0xFF for i in range(4))  # [12..15]
    return b1 + b2 + a10[:4] + b3             # = b"!q@w#e$r%t^y#n@v"


def derive_key(password: str) -> bytes:
    """PBKDF2WithHmacSHA1，迭代 10 次，输出 16 字节(128位) AES 密钥。"""
    return hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"),
                               build_salt(), 10, dklen=16)


def decrypt(password: str, encrypted: bytes) -> str:
    cipher = AES.new(derive_key(password), AES.MODE_CBC, IV)
    plain = unpad(cipher.decrypt(encrypted), AES.block_size, style="pkcs7")
    return plain.decode("utf-8")


def main():
    parser = argparse.ArgumentParser(description="AES/CBC + PBKDF2 解密测试")
    parser.add_argument("hex", help="待解密的十六进制密文字符串")
    parser.add_argument("-p", "--password", default=DEFAULT_PASSWORD,
                        help="口令 (默认: %(default)s)")
    parser.add_argument("--show-salt", action="store_true",
                        help="同时打印 salt / iv 自检信息")
    args = parser.parse_args()

    if args.show_salt:
        print("SALT(hex) =", build_salt().hex().upper())
        print("IV        =", IV.decode())

    encrypted = bytes.fromhex(args.hex)
    print(decrypt(args.password, encrypted))


if __name__ == "__main__":
    main()