#!/usr/bin/env python3
"""
京东「设备指纹 / device finger（eid）」离线生成器 —— device-finger.md 里 Kotlin 的 Python 一比一移植。

整条链路（对应 device-finger.md 各节）:

  1. 造 ds.json 的 body.data（of.d.a）:
        data = "AKS*_*" + base64( PKCS#7-EnvelopedData( deviceInfo ) )
     -> build_device_finger_req_data(cert, content) / build_ds_json_data(device_info)
     PKCS#7 信封 = 3DES-CBC 内容加密 + RSA(PKCS1v1.5) 密钥传输，收件人证书 = 内置公开常量 JD_RECIPIENT_CERT。

  2. POST 这些接口拿回 {token, ccoToken, time}（qf.c.a = HTTP 壳，本模块不联网，只给算法）:
        https://sdkfp.jd.com/tk.json | ds.json | cp.json ...

  3. 用 ccoToken + time 解出设备指纹 eid（of.g.b = PayloadCodec.decodeWithHeader）:
        eid = ccoToken[:8] + "81" + XOR( Base62.decode(ccoToken[10:]), time%255 )
     -> device_finger_from_cco_token(cco_token, time)
     同款变换的 token 版（of.g.a = decodeWithSuffix）也一并提供。

逆向名称对照（原代码混淆过）:
    of.d.a(Context,byte[])           -> build_device_finger_req_data
    com.wangyin.platform.CryptoUtils.p7Envelope(String,byte[])
                                     -> native_p7_envelope
    of.e.c(byte[],int,int,int)       -> encode_bytes_to_bytes  (Robert-Harder Base64)
    of.f.a(byte[])                   -> base64 便捷壳（options=0）
    of.g.a(String,String,String)     -> decode_with_suffix     (token, 布局 A)
    of.g.b(String,String,String)     -> decode_with_header     (eid,   布局 B)
    PayloadCodec.Base62.STANDARD     -> _B62_ALPHABET（GMP 表 0-9A-Za-z，大整数进制转换）
    PayloadCodec.XorCipher.toString  -> _xor_bytes（逐字节 XOR (time%255)，再按 charset 解码）

依赖:
    PayloadCodec / Base64 部分纯标准库（解 eid 只用得到这块，零三方依赖）。
    仅 native_p7_envelope（造 ds.json 用）需要 pycryptodome + asn1crypto（惰性 import）。

不内置任何真实设备值。JD_RECIPIENT_CERT 是 App 里写死的“收件人公开证书”（device-finger.md 已公开），非密钥。
真实 ccoToken/eid/deviceInfo 请只在本地跑；`--verify-db jd_smart_traffic.db`（已 .gitignore）可对抓包实测。

用法:
    python device_finger.py selftest                       # 离线自检（不联网、不需真实数据）
    python device_finger.py verify-db jd_smart_traffic.db  # 拿本地抓包逐条核对算法（of.e.c/of.g/of.d.a）
    python device_finger.py eid <ccoToken> <time>          # ccoToken+time -> 设备指纹 eid
    python device_finger.py reqdata '<deviceInfo-json>'    # 造 ds.json 的 body.data（AKS*_*...）
"""
import argparse
import json
import os
import sys

# App 内写死的 PKCS#7 收件人证书（of.d.f51672a，公开常量，非密钥）。RSA-2048，
# issuer=WangYin User CA, serial=0x6fd6a101b729e0f6e6282b8646cf86681acf3018。
JD_RECIPIENT_CERT = (
    "MIIESTCCAzGgAwIBAgIUb9ahAbcp4PbmKCuGRs+GaBrPMBgwDQYJKoZIhvcNAQELBQAwXjEYMBYG"
    "A1UEAwwPV2FuZ1lpbiBVc2VyIENBMR8wHQYDVQQLDBZXYW5nWWluIFNlY3VyaXR5Q2VudGVyMRQw"
    "EgYDVQQKDAtXYW5nWWluLmNvbTELMAkGA1UEBhMCQ04wHhcNMTgwODI5MTAyOTE2WhcNMTkwODI5"
    "MTAyOTE2WjCBlDF0MHIGA1UEAwxr5Lqs5Lic6YeR6J6NLeaKgOacr+eglOWPkemDqC3kuKrkurrk"
    "uJrliqHnu7zlkIjnoJTlj5Hpg6gt6aOO5o6n56CU5Y+R6YOoLeaZuuiDveivhuWIq+WunumqjOWu"
    "pChBS1MwMDAwMEFLUykxDzANBgNVBAsMBmpyIHRvcDELMAkGA1UECgwCamQwggEgMA0GCSqGSIb3"
    "DQEBAQUAA4IBDQAwggEIAoIBAQC40b+9fdJRXY+AOdC5I3mfwZVFWMzpc+8CSBseuMdKEX57stGo"
    "KAVilElvUVCM4amrBqb90/18Ji9fQ+Ra/hiOxjsaDkhrMkSwi1b+VT4Zg3orn/Gpt9/A7UpfRCZ"
    "lhKVTI370k6vfTZgKtXOtowDtksPLhYffu/vJbCuSN2gMq0WmZ55WWXWE6QRB/0r9nOtBjjs6Eb"
    "sj3M99TUbZtgt6MKsOmsK9bfyYiNhZdq2L7F77JcbM7ZRil//xI4ET5ks1hYzrt4rXrg26ATLZh"
    "kjSmsDTuuMfk1QkqIRLlQdIDuaWpU6rTg8u8lUDsTSd2gsk71EAaeP2dfWaL60++ZDHAgEDo4HJ"
    "MIHGMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgbAMGwGA1UdHwRlMGMwYaBfoF2GW2h0dHA6Ly90b3Bj"
    "YS5kLmNoaW5hYmFuay5jb20uY24vcHVibGljL2l0cnVzY3JsP0NBPTFFRTQ1QjcxNkQwOUE0OTI4"
    "MkIxMzQ2QTJDQzNDNjI3MzExMzgwRUIwHwYDVR0jBBgwFoAUCKxvAe67vsOUVzpp1dx/r34ctOAw"
    "HQYDVR0OBBYEFOxwX51lfkiPGzdSHJp/aoWEy7yGMA0GCSqGSIb3DQEBCwUAA4IBAQAQFz4OkKRm"
    "F1eahWwFes7ZMLmYuc+wc1Jfa166Ylefjb79zu3p+P+Acb07hhbKioHIdsw6IszzYqMntmP9OfC"
    "AkXhxEmAeZNAgsHdw5aIoD4Uzg0pD7oVKjCaStFsadaPUa3vVJR/grKFAQRPunsGC8pLb8X2WjB"
    "OeYLZNgAwUhrtJZzjeog+zYvQRo55Ed/kXVHrdgSVA9vCmhKwnmRhe6kzJj7GUikqm4GdQhjJIf"
    "kV/0eULsrLEhM+dHn4qKDdZzNBIa/AEQDpC9pmD8ZnIzxAAdeuPOhOuv/DyCvQwIv4KymYASHIl"
    "4ouMOYV8hPgau2W5H4bUyPKbz4HiM/Gf"
)

# ============================================================================
# Base64（of.e.c = encodeBytesToBytes / of.e.e = encode3to4，Robert-Harder 风）
#   options=0 即标准 Base64；这里把 GZIP 之外的标志位都按原版实现，便于与抓包逐字节对齐。
# ============================================================================
_ENCODE = 1
_GZIP = 2
_DO_BREAK_LINES = 8
_URL_SAFE = 16
_ORDERED = 32
_MAX_LINE_LENGTH = 76
_NEW_LINE = ord("\n")
_EQUALS_SIGN = ord("=")

_STANDARD_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_URL_SAFE_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_ORDERED_ALPHABET = b"-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz"


def _b64_alphabet(options: int) -> bytes:
    if (options & _URL_SAFE) == _URL_SAFE:
        return _URL_SAFE_ALPHABET
    if (options & _ORDERED) == _ORDERED:
        return _ORDERED_ALPHABET
    return _STANDARD_ALPHABET


def _encode3to4(source, src_off, num_sig, dest, dst_off, options):
    """of.e.e：最多 3 个有效字节 -> 4 个 Base64 字节，写进 dest[dst_off:dst_off+4]。"""
    a = _b64_alphabet(options)
    # 左移 24 再无符号右移，清掉 byte->int 的符号扩展高位（与 Kotlin ushr 等价）
    in_buff = (
        ((source[src_off] << 24) >> 8 if num_sig > 0 else 0)
        | ((source[src_off + 1] << 24) >> 16 if num_sig > 1 else 0)
        | ((source[src_off + 2] << 24) >> 24 if num_sig > 2 else 0)
    ) & 0xFFFFFFFF
    if num_sig == 3:
        dest[dst_off] = a[in_buff >> 18]
        dest[dst_off + 1] = a[(in_buff >> 12) & 0x3F]
        dest[dst_off + 2] = a[(in_buff >> 6) & 0x3F]
        dest[dst_off + 3] = a[in_buff & 0x3F]
    elif num_sig == 2:
        dest[dst_off] = a[in_buff >> 18]
        dest[dst_off + 1] = a[(in_buff >> 12) & 0x3F]
        dest[dst_off + 2] = a[(in_buff >> 6) & 0x3F]
        dest[dst_off + 3] = _EQUALS_SIGN
    elif num_sig == 1:
        dest[dst_off] = a[in_buff >> 18]
        dest[dst_off + 1] = a[(in_buff >> 12) & 0x3F]
        dest[dst_off + 2] = _EQUALS_SIGN
        dest[dst_off + 3] = _EQUALS_SIGN


def encode_bytes_to_bytes(source: bytes, off: int = 0, length=None, options: int = 0) -> bytes:
    """of.e.c：把 source[off:off+length] 编码为 Base64 字节串（options 见上方标志位）。"""
    if source is None:
        raise ValueError("Cannot serialize a null array.")
    if length is None:
        length = len(source) - off
    if off < 0:
        raise ValueError(f"Cannot have negative offset: {off}")
    if length < 0:
        raise ValueError(f"Cannot have length offset: {length}")
    if off + length > len(source):
        raise ValueError(
            f"Cannot have offset of {off} and length of {length} with array of length {len(source)}"
        )

    if options & _GZIP:
        import gzip
        import io

        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=_Base64OutputStream(buf, options | _ENCODE), mode="wb") as gz:
            gz.write(source[off:off + length])
        return buf.getvalue()

    break_lines = (options & _DO_BREAK_LINES) != 0
    enc_len = (length // 3) * 4 + (4 if length % 3 > 0 else 0)
    if break_lines:
        enc_len += enc_len // _MAX_LINE_LENGTH
    out_buff = bytearray(enc_len)

    d = 0
    e = 0
    line_length = 0
    len2 = length - 2
    while d < len2:
        _encode3to4(source, d + off, 3, out_buff, e, options)
        line_length += 4
        if break_lines and line_length >= _MAX_LINE_LENGTH:
            out_buff[e + 4] = _NEW_LINE
            e += 1
            line_length = 0
        d += 3
        e += 4
    if d < length:
        _encode3to4(source, d + off, length - d, out_buff, e, options)
        e += 4
    return bytes(out_buff[:e]) if e <= len(out_buff) - 1 else bytes(out_buff)


class _Base64OutputStream:
    """仅供 GZIP 路径用的极简 Base64 流（边写边 3->4 编码，flush 补尾），其余路径走 encode_bytes_to_bytes。"""

    def __init__(self, downstream, options):
        self._down = downstream
        self._options = options
        self._buf = bytearray()

    def write(self, data):
        self._buf += data
        n = (len(self._buf) // 3) * 3
        if n:
            self._down.write(encode_bytes_to_bytes(bytes(self._buf[:n]), 0, n, self._options & ~_GZIP))
            del self._buf[:n]

    def flush(self):
        if self._buf:
            self._down.write(
                encode_bytes_to_bytes(bytes(self._buf), 0, len(self._buf), self._options & ~_GZIP)
            )
            self._buf = bytearray()
        if hasattr(self._down, "flush"):
            self._down.flush()

    def close(self):
        self.flush()


def base64_encode(data: bytes) -> bytes:
    """of.f.a：options=0 的标准 Base64（无换行）。"""
    return encode_bytes_to_bytes(data, 0, len(data), 0)


# ============================================================================
# PKCS#7 EnvelopedData（of.d.a -> CryptoUtils.p7Envelope）
#   native 返回 = ASCII 状态码("00000"=成功) + DER(EnvelopedData)。
#   3DES-CBC 随机 CEK+IV 加密内容 + RSA(PKCS1v1.5) 用收件人证书加密 CEK（issuerAndSerialNumber 寻址）。
#   注：每次随机 CEK/IV，输出不可复现；正确性靠“自造证书往返解密”验证（见 selftest）。
# ============================================================================
_STATUS_OK = b"00000"


def _pkcs7_pad(data: bytes, block: int = 8) -> bytes:
    pad = block - (len(data) % block)
    return data + bytes([pad]) * pad


def _pkcs7_unpad(data: bytes) -> bytes:
    return data[: -data[-1]]


def _gen_3des_key() -> bytes:
    """24 随机字节，避开 pycryptodome 拒绝的退化密钥（k1==k2 或 k2==k3）。"""
    from Crypto.Cipher import DES3

    while True:
        k = os.urandom(24)
        try:
            DES3.new(k, DES3.MODE_ECB)
            return k
        except ValueError:
            continue


def native_p7_envelope(key_b64: str, content: bytes) -> bytes:
    """CryptoUtils.p7Envelope(key, content)：返回 "00000" + DER(PKCS#7 EnvelopedData)。

    key_b64 = Base64(DER 收件人证书)。需要 pycryptodome + asn1crypto。
    """
    import base64

    from asn1crypto import cms, core, x509
    from Crypto.Cipher import DES3, PKCS1_v1_5
    from Crypto.PublicKey import RSA

    cert = x509.Certificate.load(base64.b64decode(key_b64))
    cek = _gen_3des_key()
    iv = os.urandom(8)
    enc_content = DES3.new(cek, DES3.MODE_CBC, iv).encrypt(_pkcs7_pad(content))
    enc_cek = PKCS1_v1_5.new(RSA.import_key(cert.public_key.dump())).encrypt(cek)

    ktri = cms.KeyTransRecipientInfo({
        "version": "v0",
        "rid": cms.RecipientIdentifier({
            "issuer_and_serial_number": cms.IssuerAndSerialNumber({
                "issuer": cert.issuer,
                "serial_number": cert.serial_number,
            })
        }),
        "key_encryption_algorithm": {"algorithm": "rsaes_pkcs1v15", "parameters": core.Null()},
        "encrypted_key": enc_cek,
    })
    eci = cms.EncryptedContentInfo({
        "content_type": "data",
        "content_encryption_algorithm": {
            "algorithm": "tripledes_3key",
            "parameters": core.OctetString(iv),
        },
        "encrypted_content": enc_content,
    })
    ed = cms.EnvelopedData({
        "version": "v0",
        "recipient_infos": [cms.RecipientInfo({"ktri": ktri})],
        "encrypted_content_info": eci,
    })
    return _STATUS_OK + cms.ContentInfo({"content_type": "enveloped_data", "content": ed}).dump()


def payload_of(result: bytes) -> bytes:
    """去掉 5 字节状态前缀，得纯 PKCS#7 DER。"""
    return result[5:]


def status_of(result: bytes) -> str:
    return result[:5].decode("ascii", "replace")


def build_device_finger_req_data(key_b64: str, content: bytes) -> str:
    """of.d.a：data = "AKS*_*" + base64( p7Envelope(content)[5:] )。"""
    ret = native_p7_envelope(key_b64, content)
    return "AKS*_*" + base64_encode(payload_of(ret)).decode("ascii")


def build_ds_json_data(device_info, key_b64: str = JD_RECIPIENT_CERT) -> str:
    """ds.json/tk.json 的 body.data 值。device_info 传 dict 则紧凑序列化，传 bytes 则原样。"""
    content = (
        json.dumps(device_info, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if isinstance(device_info, (dict, list))
        else device_info
    )
    return build_device_finger_req_data(key_b64, content)


# ============================================================================
# PayloadCodec（of.g.a/.b）：Base62 解码 + XOR(time%255)
#   Base62.STANDARD = GMP 表 0-9A-Za-z，按“大整数进制转换”（含前导零保留）。
#   XorCipher.toString(bytes, key, charset) = bytes 逐字节 ^ key，再按 charset 解码成字符串。
#   实测：对抓包 of.g.a/.b 全部 20 条逐字节命中。
# ============================================================================
_B62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_B62_INV = {c: i for i, c in enumerate(_B62_ALPHABET)}


def base62_decode(text: str) -> bytes:
    """Base62.STANDARD.decode：把 base62 串当大端大整数 -> 字节；前导 '0' -> 前导 0x00。"""
    n = 0
    for ch in text:
        n = n * 62 + _B62_INV[ch]
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    lead = 0
    for ch in text:
        if ch == _B62_ALPHABET[0]:
            lead += 1
        else:
            break
    return b"\x00" * lead + body


def base62_encode(data: bytes) -> str:
    """base62_decode 的逆（前导 0x00 -> 前导 '0'）。"""
    n = int.from_bytes(data, "big") if data else 0
    if n == 0:
        body = ""
    else:
        chars = []
        while n:
            n, r = divmod(n, 62)
            chars.append(_B62_ALPHABET[r])
        body = "".join(reversed(chars))
    lead = 0
    for b in data:
        if b == 0:
            lead += 1
        else:
            break
    return _B62_ALPHABET[0] * lead + body


def _xor_bytes(data: bytes, key: int) -> bytes:
    return bytes((b ^ key) & 0xFF for b in data)


def _normalize_key(key) -> int:
    """key（毫秒时间戳字符串/数字）-> time % 255。"""
    return int(key) % 255


def _decode_payload(payload: str, key: int, charset: str) -> str:
    return _xor_bytes(base62_decode(payload), key).decode(charset)


def _encode_payload(plain: str, key: int, charset: str) -> str:
    return base62_encode(_xor_bytes(plain.encode(charset), key))


# 布局常量（与 device-finger.md PayloadCodec 对齐）
_A_DROP_PREFIX_LEN = 5   # 布局 A：丢前 5、留后 8
_A_KEEP_SUFFIX_LEN = 8
_B_KEEP_HEADER_LEN = 8   # 布局 B：留前 8、丢中间 2
_B_PAYLOAD_OFFSET = 10
_A_MARKER = "jdd01"
_B_MARKER = "81"


def decode_with_suffix(text: str, key, charset: str = "utf-8") -> str:
    """of.g.a / PayloadCodec.decodeWithSuffix（布局 A，token）:
        输出 = "jdd01" + 变换(中段) + 原末 8 字节。"""
    if not text:
        return ""
    try:
        k = _normalize_key(key)
        payload = text[_A_DROP_PREFIX_LEN:len(text) - _A_KEEP_SUFFIX_LEN]
        suffix = text[len(text) - _A_KEEP_SUFFIX_LEN:]
        return _A_MARKER + _decode_payload(payload, k, charset) + suffix
    except Exception:
        return ""


def decode_with_header(text: str, key, charset: str = "utf-8") -> str:
    """of.g.b / PayloadCodec.decodeWithHeader（布局 B，eid/设备指纹）:
        输出 = 原前 8 字节 + "81" + 变换(从第 10 字节起)。"""
    if not text:
        return ""
    try:
        k = _normalize_key(key)
        header = text[:_B_KEEP_HEADER_LEN]
        payload = text[_B_PAYLOAD_OFFSET:]
        return header + _B_MARKER + _decode_payload(payload, k, charset)
    except Exception:
        return ""


def device_finger_from_cco_token(cco_token: str, time, charset: str = "utf-8") -> str:
    """便捷入口：ds.json/tk.json 响应里的 ccoToken + time -> 设备指纹 eid（= decode_with_header）。"""
    return decode_with_header(cco_token, time, charset)


# ============================================================================
# 自检 / CLI
# ============================================================================
def selftest() -> bool:
    """离线自检：不联网、不需真实设备数据。"""
    import base64 as _b64

    ok = True

    def check(name, cond):
        nonlocal ok
        ok = ok and bool(cond)
        print(f"  [{'ok' if cond else 'FAIL'}] {name}")

    # 1) Base64：对齐 Python 标准库（标准/urlsafe/换行/偏移）
    sample = os.urandom(500)
    check("Base64 标准表 == base64.b64encode", base64_encode(sample) == _b64.b64encode(sample))
    check("Base64 urlsafe 表 == base64.urlsafe_b64encode",
          encode_bytes_to_bytes(sample, 0, len(sample), _URL_SAFE) == _b64.urlsafe_b64encode(sample))
    check("Base64 off/len 切片正确",
          encode_bytes_to_bytes(b"XX" + sample, 2, len(sample), 0) == _b64.b64encode(sample))
    bl = encode_bytes_to_bytes(sample, 0, len(sample), _DO_BREAK_LINES).decode()
    check("Base64 换行：每行 <=76", all(len(x) <= 76 for x in bl.split("\n")) and "\n" in bl)

    # 2) Base62 + PayloadCodec：往返自洽（含前导零）
    rt_ok = all(base62_decode(base62_encode(v)) == v for v in
                [b"", b"\x00", b"\x00\x00\xff", b"hello", os.urandom(64), b"\x00" * 3 + os.urandom(20)])
    check("Base62 encode/decode 往返（含前导零）", rt_ok)
    # 变换层往返：_decode_payload∘_encode_payload == id（任意 ASCII 文本 + 任意 key）
    txt = "eidA0099Xy+/zZ09abcABC=="
    pay_rt = all(_decode_payload(_encode_payload(txt, k, "utf-8"), k, "utf-8") == txt
                 for k in (0, 1, 112, 254))
    check("XOR+Base62 变换层往返（多 key）", pay_rt)
    # 布局切片：header/marker 位置正确
    cco = "eidAb7ad82" + base62_encode(_xor_bytes(b"PAYLOAD-DATA", 112))
    fp = decode_with_header(cco, "1781665381177")  # 1781665381177 % 255 == 112
    check("decodeWithHeader 头部保留 + 81 标记", fp[:8] == "eidAb7ad" and fp[8:10] == "81")
    check("decodeWithHeader 载荷正确还原", fp[10:] == "PAYLOAD-DATA")
    check("空输入 -> 空串", decode_with_header("", "1") == "" and decode_with_suffix("", "1") == "")

    # 3) P7Envelope：自造 RSA-2048 证书 -> 信封 -> 解密还原（端到端证明 CMS 正确）；
    #    再用内置真证书核对线格式（recipient/算法 OID/密钥长度）。
    try:
        import datetime

        from asn1crypto import cms, core, keys, x509
        from Crypto.Cipher import DES3, PKCS1_v1_5
        from Crypto.PublicKey import RSA

        priv = RSA.generate(2048)
        spki = keys.PublicKeyInfo.load(priv.publickey().export_key("DER"))
        nm = x509.Name.build({"common_name": "selftest"})
        utc = datetime.timezone.utc
        tbs = x509.TbsCertificate({
            "version": "v3", "serial_number": 1, "signature": {"algorithm": "sha256_rsa"},
            "issuer": nm,
            "validity": {"not_before": {"utc_time": datetime.datetime(2020, 1, 1, tzinfo=utc)},
                         "not_after": {"utc_time": datetime.datetime(2030, 1, 1, tzinfo=utc)}},
            "subject": nm, "subject_public_key_info": spki,
        })
        tc = _b64.b64encode(x509.Certificate({
            "tbs_certificate": tbs, "signature_algorithm": {"algorithm": "sha256_rsa"},
            "signature_value": b"\x00",
        }).dump()).decode()

        def _decrypt(env):
            ed = cms.ContentInfo.load(payload_of(env))["content"]
            ri = ed["recipient_infos"][0].chosen
            cek = PKCS1_v1_5.new(priv).decrypt(ri["encrypted_key"].native, None)
            eci = ed["encrypted_content_info"]
            iv = eci["content_encryption_algorithm"]["parameters"].native
            return _pkcs7_unpad(DES3.new(cek, DES3.MODE_CBC, iv).decrypt(eci["encrypted_content"].native))

        rt = all(_decrypt(native_p7_envelope(tc, pt)) == pt for pt in
                 [b'{"appId":"com.jd.iots","bizId":"CCO-RISK","deviceInfo":{"sdk_version":"8.1.0"}}',
                  b"", b"x", os.urandom(300)])
        check("P7Envelope 自造证书往返解密（4 组明文）", rt)

        env = build_ds_json_data({"appId": "com.jd.iots", "bizId": "CCO-RISK",
                                  "deviceInfo": {"sdk_version": "8.1.0"}})
        check("build_ds_json_data 以 'AKS*_*' 开头", env.startswith("AKS*_*"))
        der = payload_of(_STATUS_OK + _b64.b64decode(env[len("AKS*_*"):]))
        ci = cms.ContentInfo.load(der)
        ed = ci["content"]
        ri = ed["recipient_infos"][0].chosen
        check("信封 = enveloped_data / ktri / issuerAndSerial",
              ci["content_type"].native == "enveloped_data"
              and ed["recipient_infos"][0].name == "ktri"
              and ri["rid"].name == "issuer_and_serial_number")
        check("收件人 serial == 内置真证书 serial",
              ri["rid"].chosen["serial_number"].native
              == 638484360695715291083765028044904424613522386968)
        check("keyEncAlg=rsaEncryption(+NULL) / encKey=256B",
              ri["key_encryption_algorithm"].dump().hex() == "300d06092a864886f70d0101010500"
              and len(ri["encrypted_key"].native) == 256)
        check("contentEncAlg=3DES-CBC / IV=8B",
              ed["encrypted_content_info"]["content_encryption_algorithm"]["algorithm"].native
              == "tripledes_3key"
              and len(ed["encrypted_content_info"]["content_encryption_algorithm"]["parameters"].native) == 8)
    except ImportError as e:
        check(f"P7Envelope 需要 pycryptodome+asn1crypto（{e}）", False)

    print("\nself-test", "PASS" if ok else "FAIL")
    return ok


def verify_against_db(db_path: str) -> bool:
    """拿本地抓包库逐条核对算法（of.e.c / of.g.a/.b / of.d.a）。库已 .gitignore，仅本地用。"""
    import base64 as _b64
    import sqlite3

    if not os.path.exists(db_path):
        sys.exit(f"[!] 找不到 {db_path}")
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    ok = True

    def line(name, hit, tot):
        nonlocal ok
        ok = ok and (tot > 0 and hit == tot)
        print(f"  [{'ok' if tot and hit == tot else 'FAIL' if tot else '--'}] {name}: {hit}/{tot}")

    # of.e.c：Base64（确定性）
    hit = tot = 0
    for r in con.execute("SELECT arg0,arg1,arg2,arg3,ret_txt FROM hook_log "
                         "WHERE clazz='of.e' AND method='c' AND ret_txt IS NOT NULL"):
        tot += 1
        got = encode_bytes_to_bytes(bytes.fromhex(r["arg0"]), int(r["arg1"]), int(r["arg2"]),
                                    int(r["arg3"])).decode("ascii")
        hit += got == r["ret_txt"]
    line("of.e.c Base64", hit, tot)

    # of.g.a/.b：PayloadCodec（确定性）
    hit = tot = 0
    for r in con.execute("SELECT method,arg0,arg1,arg2,ret_txt FROM hook_log "
                         "WHERE clazz='of.g' AND ret_txt IS NOT NULL"):
        tot += 1
        fn = decode_with_suffix if r["method"] == "a" else decode_with_header
        try:
            hit += fn(r["arg0"], r["arg1"], r["arg2"] or "utf-8") == r["ret_txt"]
        except Exception:
            pass
    line("of.g.a/.b PayloadCodec", hit, tot)

    # of.d.a：信封非确定性 -> 只验“AKS*_* 前缀 + 余下可解析为我们认得的 EnvelopedData”
    hit = tot = 0
    try:
        from asn1crypto import cms
        for r in con.execute("SELECT ret_txt FROM hook_log WHERE clazz='of.d' AND method='a' "
                             "AND sig LIKE '%byte%' AND ret_txt LIKE 'AKS*_*%'"):
            tot += 1
            try:
                der = _b64.b64decode(r["ret_txt"][len("AKS*_*"):])
                ci = cms.ContentInfo.load(der)
                ed = ci["content"]
                hit += (ci["content_type"].native == "enveloped_data"
                        and ed["recipient_infos"][0].name == "ktri")
            except Exception:
                pass
        line("of.d.a 信封结构可解析", hit, tot)
    except ImportError:
        print("  [--] of.d.a 信封结构: 跳过（缺 asn1crypto）")

    print("\nverify-db", "PASS" if ok else "FAIL")
    return ok


def main() -> None:
    ap = argparse.ArgumentParser(description="京东设备指纹 device finger(eid) 离线生成/校验")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest", help="离线自检（不联网、不需真实数据）")
    p_db = sub.add_parser("verify-db", help="拿本地抓包库逐条核对算法")
    p_db.add_argument("db", nargs="?", default="jd_smart_traffic.db")
    p_eid = sub.add_parser("eid", help="ccoToken + time -> 设备指纹 eid")
    p_eid.add_argument("cco_token")
    p_eid.add_argument("time")
    p_tok = sub.add_parser("token", help="jade 密文(jdd02...) + time -> 明文 token(jdd01...)")
    p_tok.add_argument("jade")
    p_tok.add_argument("time")
    p_req = sub.add_parser("reqdata", help="deviceInfo JSON -> ds.json 的 body.data（AKS*_*...）")
    p_req.add_argument("device_info", help='如 {"appId":"com.jd.iots","bizId":"CCO-RISK","deviceInfo":{"sdk_version":"8.1.0"}}')
    args = ap.parse_args()

    if args.cmd == "selftest":
        sys.exit(0 if selftest() else 1)
    elif args.cmd == "verify-db":
        sys.exit(0 if verify_against_db(args.db) else 1)
    elif args.cmd == "eid":
        print(device_finger_from_cco_token(args.cco_token, args.time))
    elif args.cmd == "token":
        print(decode_with_suffix(args.jade, args.time))
    elif args.cmd == "reqdata":
        try:
            di = json.loads(args.device_info)
        except ValueError:
            di = args.device_info.encode("utf-8")
        print(build_ds_json_data(di))


if __name__ == "__main__":
    main()
