"""设备指纹 eid 生成 + ds.json 联网取 eid —— HA 集成内置副本（runtime）。

离线算法一比一移植自仓库根 `device_finger.py`（of.e.c/of.g/of.d.a 已对抓包逐条实测命中），
这里裁掉 CLI / verify-db，只留运行时需要的：

    build_ds_json_data(device_info)           造 ds.json 的 body.data（"AKS*_*"+base64(p7信封)）
    device_finger_from_cco_token(cco, time)   ccoToken+time -> 设备指纹 eid（of.g.b）
    async_fetch_eid(session)                  POST sdkfp.jd.com/ds.json 取 ccoToken+time -> eid（新增）

实测（2026-06）：ds.json 现铸的全新 eid 也能直接通过彩虹 getHouses（code=0），故 eid 可全自动获取，
用户填 eid 只是逃生口。

依赖：解码 eid 纯标准库；造 ds.json 的 P7 信封需 pycryptodome + asn1crypto（仅 build_ds_json_data /
async_fetch_eid 用到，惰性 import）。JD_RECIPIENT_CERT 是 App 写死的收件人公开证书（非密钥）。
"""
from __future__ import annotations

import json
import os

# ds.json 联网常量
DS_JSON_URL = "https://sdkfp.jd.com/ds.json"
# 抓包原样的最小 deviceInfo（够铸 eid；多填字段也可，但此最小集已实测可用）
DEFAULT_DEVICE_INFO = {
    "appId": "com.jd.iots",
    "bizId": "CCO-RISK",
    "deviceInfo": {"sdk_version": "8.1.0"},
}

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


class EidFetchError(Exception):
    """ds.json 取 eid 失败（网络 / HTTP / 响应缺字段 / 解出 eid 非法）。"""


# ============================================================================
# Base64（of.e.c / of.e.e，Robert-Harder 风；options=0 即标准 Base64）
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
    """of.e.c：把 source[off:off+length] 编码为 Base64 字节串。"""
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
    """仅供 GZIP 路径用的极简 Base64 流（造 ds.json 用不到 GZIP，留作与原版对齐）。"""

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
#   3DES-CBC 随机 CEK/IV 加密内容 + RSA(PKCS1v1.5) 用收件人证书加密 CEK。
#   native 返回 = ASCII 状态码("00000"=成功) + DER(EnvelopedData)。每次随机，输出不可复现。
# ============================================================================
_STATUS_OK = b"00000"


def _pkcs7_pad(data: bytes, block: int = 8) -> bytes:
    pad = block - (len(data) % block)
    return data + bytes([pad]) * pad


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


def build_device_finger_req_data(key_b64: str, content: bytes) -> str:
    """of.d.a：data = "AKS*_*" + base64( p7Envelope(content)[5:] )。"""
    ret = native_p7_envelope(key_b64, content)
    return "AKS*_*" + base64_encode(payload_of(ret)).decode("ascii")


def build_ds_json_data(device_info, key_b64: str = JD_RECIPIENT_CERT) -> str:
    """ds.json 的 body.data 值。device_info 传 dict 则紧凑序列化，传 bytes 则原样。"""
    content = (
        json.dumps(device_info, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if isinstance(device_info, (dict, list))
        else device_info
    )
    return build_device_finger_req_data(key_b64, content)


# ============================================================================
# PayloadCodec（of.g.b）：Base62 解码 + XOR(time%255)
#   Base62.STANDARD = GMP 表 0-9A-Za-z（大整数进制转换，含前导零保留）。
# ============================================================================
_B62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_B62_INV = {c: i for i, c in enumerate(_B62_ALPHABET)}


def base62_decode(text: str) -> bytes:
    """Base62.STANDARD.decode：base62 串当大端大整数 -> 字节；前导 '0' -> 前导 0x00。"""
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
    """base62_decode 的逆（前导 0x00 -> 前导 '0'）。仅 selftest 用。"""
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


# 布局 B：留前 8、丢中间 2、第 10 字节起是载荷；输出在第 8 位插 "81"
_B_KEEP_HEADER_LEN = 8
_B_PAYLOAD_OFFSET = 10
_B_MARKER = "81"


def decode_with_header(text: str, key, charset: str = "utf-8") -> str:
    """of.g.b / PayloadCodec.decodeWithHeader（布局 B，eid）:
        输出 = 原前 8 字节 + "81" + XOR(Base62.decode(从第 10 字节起), time%255)。"""
    if not text:
        return ""
    try:
        k = _normalize_key(key)
        header = text[:_B_KEEP_HEADER_LEN]
        payload = text[_B_PAYLOAD_OFFSET:]
        return header + _B_MARKER + _xor_bytes(base62_decode(payload), k).decode(charset)
    except Exception:
        return ""


def device_finger_from_cco_token(cco_token: str, time, charset: str = "utf-8") -> str:
    """便捷入口：ds.json 响应里的 ccoToken + time -> 设备指纹 eid。"""
    return decode_with_header(cco_token, time, charset)


# ============================================================================
# 联网取 eid（新增；qf.c.a HTTP 壳的 Python 版）
# ============================================================================
async def async_fetch_eid(session, *, device_info=None, timeout: int = 25) -> tuple[str, int]:
    """POST sdkfp.jd.com/ds.json，解出设备指纹 eid。返回 (eid, time_ms)。

    session = aiohttp.ClientSession。device_info 不给则用 DEFAULT_DEVICE_INFO（抓包最小集，实测可用）。
    失败抛 EidFetchError。
    """
    import aiohttp

    data = build_ds_json_data(device_info or DEFAULT_DEVICE_INFO)
    body = json.dumps({"data": data, "visaType": "1"}).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "okhttp/4.10.0"}
    try:
        async with session.post(
            DS_JSON_URL, data=body, headers=headers,
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as resp:
            text = await resp.text()
            if resp.status != 200:
                raise EidFetchError(f"ds.json HTTP {resp.status}: {text[:200]}")
    except aiohttp.ClientError as err:
        raise EidFetchError(f"ds.json 网络错误: {err}") from err
    try:
        obj = json.loads(text)
    except ValueError as err:
        raise EidFetchError(f"ds.json 响应非 JSON: {text[:200]}") from err

    d = obj.get("data") or {}
    cco = d.get("ccoToken")
    t = obj.get("time")
    if not cco or not t:
        raise EidFetchError(
            f"ds.json 缺 ccoToken/time（code={obj.get('code')} msg={obj.get('msg')}）"
        )
    eid = device_finger_from_cco_token(cco, t)
    if not eid.startswith("eid"):
        raise EidFetchError(f"解出的 eid 非法: {eid[:24]!r}")
    return eid, int(t)


# ============================================================================
# 离线自检（不联网、不需真实数据）
# ============================================================================
def selftest() -> bool:
    import base64 as _b64

    ok = True

    def check(name, cond):
        nonlocal ok
        ok = ok and bool(cond)
        print(f"  [{'ok' if cond else 'FAIL'}] {name}")

    # Base64 对齐标准库
    sample = os.urandom(400)
    check("Base64 标准表 == base64.b64encode", base64_encode(sample) == _b64.b64encode(sample))

    # Base62 往返（含前导零）
    rt = all(base62_decode(base62_encode(v)) == v
             for v in [b"", b"\x00", b"\x00\x00\xff", b"hello", os.urandom(48)])
    check("Base62 encode/decode 往返", rt)

    # decodeWithHeader 布局：头 8 + "81" + 还原载荷
    cco = "eidAb7ad82" + base62_encode(_xor_bytes(b"PAYLOAD-DATA", 112))
    fp = decode_with_header(cco, "1781665381177")  # %255 == 112
    check("decodeWithHeader 头部保留 + 81 + 载荷",
          fp[:8] == "eidAb7ad" and fp[8:10] == "81" and fp[10:] == "PAYLOAD-DATA")
    check("空输入 -> 空串", decode_with_header("", "1") == "")

    # P7 信封：以 "AKS*_*" 开头 + 自造证书往返解密
    try:
        import datetime

        from asn1crypto import cms, keys, x509
        from Crypto.Cipher import DES3, PKCS1_v1_5
        from Crypto.PublicKey import RSA

        env = build_ds_json_data(DEFAULT_DEVICE_INFO)
        check("build_ds_json_data 以 'AKS*_*' 开头", env.startswith("AKS*_*"))

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
        pt = b'{"appId":"com.jd.iots","bizId":"CCO-RISK","deviceInfo":{"sdk_version":"8.1.0"}}'
        e = native_p7_envelope(tc, pt)
        ed = cms.ContentInfo.load(payload_of(e))["content"]
        ri = ed["recipient_infos"][0].chosen
        cek = PKCS1_v1_5.new(priv).decrypt(ri["encrypted_key"].native, None)
        eci = ed["encrypted_content_info"]
        iv = eci["content_encryption_algorithm"]["parameters"].native
        dec = DES3.new(cek, DES3.MODE_CBC, iv).decrypt(eci["encrypted_content"].native)
        check("P7Envelope 自造证书往返解密", dec[: -dec[-1]] == pt)
    except ImportError as err:
        check(f"P7Envelope 需要 pycryptodome+asn1crypto（{err}）", False)

    print("\ndevice_finger self-test", "PASS" if ok else "FAIL")
    return ok


if __name__ == "__main__":
    import sys

    sys.exit(0 if selftest() else 1)
