#!/usr/bin/env python3
"""
复现 彩虹/jdupgrade 网关的 query `sign`（com.jingdong.sdk.jdupgrade.inner.c.a + utils.d.a）。

算法（逆自源码，见 docs/GETHOUSES_PROGRESS.md §7.1）:
    treeMap = TreeMap(比较器 b){ functionId, *query(map 非空值), body? }
    body    = modBase64(gzip(jsonObject.toString().getBytes()))      # f.a(f.b(...))，仅当有 body
    preimage = "&".join(各 value，按 treeMap 的 key 顺序)            # 只拼 value，不含 key，去尾随 &
    sign    = HmacSHA256(preimage_utf8, key_utf8).hexdigest()        # 64 hex
    key     = 固定 secret（c.W() 决定 prod/test），32 字符 hex 串的【UTF-8 字节】(32B)，非解码后 16B

关键点：
  - HMAC 的 key 是那串 32 字符 hex 文本本身的字节，不是 bytes.fromhex(...)。用 --key-as-text(默认)。
  - value 顺序 = 比较器 b（未知）。**最可靠**是直接用 hook 抓到的 preimage：
        SELECT input_txt FROM sign WHERE kind='HMAC.a' ORDER BY id DESC LIMIT 1;   -- 这就是 preimage
    把它喂 --preimage，再换新 t 重算即可，无需逆 b。
  - body 的 gzip 必须与 Java GZIPOutputStream 逐字节一致（mtime=0），否则 sign 对不上；
    所以 build-body 仅作旁证，真值优先用 hook 抓到的 body value（color.body_cipher / HMAC.a 的 input_txt）。

用法:
    python verify_color_sign.py --selftest
    python verify_color_sign.py --preimage "<hook 抓到的 input_txt>" --key-name prod [--expect <wire sign>]
    python verify_color_sign.py --values a b c --key <32charSecret>

密钥来源（优先级 --key > --key-name 读文件/env > 报错），均不硬编码、不提交：
    jd_smart_secrets.json: {"upgrade_secret_prod":"...", "upgrade_secret_test":"..."}（已 .gitignore）
    或环境变量 JD_UPGRADE_SECRET / JD_UPGRADE_SECRET_TEST
"""
import argparse
import base64
import gzip
import hashlib
import hmac
import json
import os
import sys

_STD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_SECRETS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "jd_smart_secrets.json")


def hmac_sign(preimage: str, key: str) -> str:
    """sign = hex(HmacSHA256(preimage_utf8, key_utf8))。key 是文本本身的 UTF-8 字节（非 fromhex）。"""
    return hmac.new(key.encode("utf-8"), preimage.encode("utf-8"), hashlib.sha256).hexdigest()


def build_preimage(values) -> str:
    """各 value 用 '&' 拼接（顺序须为 treeMap 的 key 序；这里按调用方给的顺序原样拼）。"""
    return "&".join(values)


def encode_body(body_json: str, alphabet: str = _STD_B64) -> str:
    """body = modBase64(gzip(json))。gzip mtime=0 对齐 Java GZIPOutputStream；alphabet 传 f.a 的换表（默认标准表）。

    注意：Java/Python 的 deflate 实现/级别可能产生不同字节 → 本函数仅旁证，sign 真值优先用 hook 抓到的 body。
    """
    gz = gzip.compress(body_json.encode("utf-8"), mtime=0)
    b64 = base64.b64encode(gz).decode("ascii")
    if alphabet and alphabet != _STD_B64 and len(alphabet) == 64:
        table = {_STD_B64[i]: alphabet[i] for i in range(64)}
        b64 = "".join(table.get(c, c) for c in b64)
    return b64


def _load_secret(name: str) -> str:
    """name: 'prod' | 'test'。从 jd_smart_secrets.json 或环境变量取，取不到返回 ''。"""
    file_key = "upgrade_secret_prod" if name == "prod" else "upgrade_secret_test"
    env_key = "JD_UPGRADE_SECRET" if name == "prod" else "JD_UPGRADE_SECRET_TEST"
    if os.path.exists(_SECRETS):
        try:
            with open(_SECRETS, encoding="utf-8") as f:
                v = json.load(f).get(file_key, "")
            if v and not v.startswith("<"):
                return v
        except Exception:
            pass
    return os.environ.get(env_key, "")


def _resolve_key(args) -> str:
    if args.key:
        return args.key
    if args.key_name:
        k = _load_secret(args.key_name)
        if not k:
            sys.exit(f"[!] 未取到 {args.key_name} 密钥：填 jd_smart_secrets.json 的 upgrade_secret_{args.key_name} "
                     f"或设环境变量，或用 --key 直接给（勿提交真实值）。")
        return k
    sys.exit("[!] 需要密钥：--key <secret> 或 --key-name prod|test（后者读 jd_smart_secrets.json/env）。")


def _selftest() -> None:
    # RFC 风格 HMAC-SHA256 已知向量，验证本脚本的 HMAC 实现（无需任何真实密钥）。
    got = hmac_sign("The quick brown fox jumps over the lazy dog", "key")
    want = "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
    assert got == want, f"HMAC self-test FAILED: {got}"
    # preimage 拼接形状
    assert build_preimage(["jdsmart.house.getHouses", "1781528966944", "ef42"]) == \
        "jdsmart.house.getHouses&1781528966944&ef42"
    print("[ok] HMAC-SHA256 + preimage 拼接 self-test 通过。")
    print("     提示：把 hook 抓到的 input_txt 喂 --preimage，--key-name prod，--expect <wire sign> 即可比对真值。")


def main() -> None:
    ap = argparse.ArgumentParser(description="复现彩虹/jdupgrade 的 HmacSHA256 query sign")
    ap.add_argument("--selftest", action="store_true", help="仅验证 HMAC 实现（无需密钥）")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--preimage", help="直接给被签字符串（最可靠：用 sign 表 kind='HMAC.a' 的 input_txt）")
    g.add_argument("--values", nargs="+", help="给一组 value，按给定顺序用 & 拼成 preimage")
    ap.add_argument("--key", help="HMAC 密钥（32 字符 secret 文本本身）；勿提交真实值")
    ap.add_argument("--key-name", choices=["prod", "test"], help="从 jd_smart_secrets.json/env 取密钥")
    ap.add_argument("--expect", help="期望的 wire sign（64hex），给了就比对")
    args = ap.parse_args()

    if args.selftest:
        _selftest()
        return
    if not args.preimage and not args.values:
        ap.error("给 --preimage 或 --values（或用 --selftest）")

    preimage = args.preimage if args.preimage else build_preimage(args.values)
    key = _resolve_key(args)
    sig = hmac_sign(preimage, key)
    print("preimage :", preimage)
    print("sign     :", sig)
    if args.expect:
        ok = sig.lower() == args.expect.lower()
        print("expect   :", args.expect)
        print("match    :", ok)
        sys.exit(0 if ok else 2)


if __name__ == "__main__":
    main()
