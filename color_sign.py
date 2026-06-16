#!/usr/bin/env python3
"""
彩虹网关（api.m.jd.com）query `sign` 离线生成器。

算法（已实测锁定，见 docs/GETHOUSES_PROGRESS.md §7.3）:
    sign = HMAC-SHA256(preimage, secret) 转 64hex
    secret   = NativeAlgorithmHelper.getSecretKey() 的返回（按 App 构建固定、内嵌 so）
               当「32 字符 ASCII 文本」用（key.encode()），不是 bytes.fromhex(key)
    preimage = 一张 18 键的表，**按 key 字母序排序、只拼 value、用 '&' 连接**
               （= App 里的 TreeMap 行为；`aid` 与 `uuid` 同值=设备 uuid，故首尾各现一次）

18 个 key（字母序）及来源：
    aid           设备 uuid(32hex)         ┐ 设备/会话固定（= ep.cipher.aid）
    appid         jdsmart-android          │
    area          LBS 区域码 20_1720_..    │ ← ep.cipher.area
    build         381                      │ ← ep.cipher.build
    client        android                  │
    clientVersion 1.17.0                   │
    d_brand       HUAWEI                   │
    d_model       HWI-AL00                 │
    eid           设备指纹 eidA005..       │ ← ep.cipher.eid
    ext           {"prstate":"0"}          │
    networkType   wifi                     │
    osVersion     28(=SDK_INT)             │
    partner       xjgw-android             │
    screen        1080*2160                ┘
    uuid          = aid（设备 uuid）
    functionId    每请求变（如 jdsmart.init.commonConfigs）  ← per-request
    body          每请求变（真实请求体 JSON，如 {} / {"houseId":"1388207"}） ← per-request
    t             每请求变（毫秒时间戳）                      ← per-request

⇒ 测试接口时：设备 14 项「固定」一次（从抓包 ep 里取，--from-db 可自动解出），
   每次只换 functionId / body / t 重算 sign。device finger / JMA finger 是 **Cookie 鉴权层**，
   与本 sign 正交——sign 只吃上面这 18 个 value，固定设备项即可先打通 sign。

密钥/设备档来源（均不硬编码、不提交；优先级 --secret/--profile-* > jd_smart_secrets.json > env）:
    jd_smart_secrets.json (已 .gitignore):
        "color_sign_secret": "<native getSecretKey 的 32 字符>",
        "color_profile": { aid/appid/area/build/client/clientVersion/d_brand/d_model/
                           eid/ext/networkType/osVersion/partner/screen/uuid }
    或 --from-db jd_smart_traffic.db 直接从最新 ep 解出 color_profile（设备档），secret 仍需另给。

用法:
    python color_sign.py --selftest                       # 验证排序+HMAC（合成值，无需真实数据）
    python color_sign.py --from-db jd_smart_traffic.db --dump-profile   # 看 db 解出的设备档
    python color_sign.py --function-id jdsmart.init.commonConfigs --body "{}" \
                         --from-db jd_smart_traffic.db --secret <32char>  # 现算一条 sign
    python color_sign.py --function-id jdsmart.house.getAllDevices \
                         --body '{"houseId":"1388207"}' --t 1781595295703 \
                         --expect <wire sign>             # 比对 wire sign（密钥/设备档读 secrets.json）
"""
import argparse
import hashlib
import hmac
import json
import os
import sys
import time

_SECRETS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "jd_smart_secrets.json")

# preimage 的 14 个「设备/会话固定」键（其余 3 个 functionId/body/t 每请求变）
DEVICE_KEYS = (
    "aid", "appid", "area", "build", "client", "clientVersion", "d_brand",
    "d_model", "eid", "ext", "networkType", "osVersion", "partner", "screen", "uuid",
)
PER_REQUEST_KEYS = ("functionId", "body", "t")
ALL_KEYS = tuple(sorted(DEVICE_KEYS + PER_REQUEST_KEYS))


def build_preimage(fields: dict) -> str:
    """preimage = 各 value 按 key 字母序、用 '&' 连接（= App TreeMap）。缺键即报错。"""
    missing = [k for k in ALL_KEYS if k not in fields]
    if missing:
        raise KeyError(f"缺少字段: {', '.join(missing)}")
    return "&".join(str(fields[k]) for k in sorted(fields))


def color_sign(preimage: str, secret: str) -> str:
    """sign = hex(HMAC-SHA256(preimage_utf8, secret_utf8))。secret 当文本字节，非 fromhex。"""
    return hmac.new(secret.encode("utf-8"), preimage.encode("utf-8"), hashlib.sha256).hexdigest()


def profile_from_db(db_path: str) -> dict:
    """从抓包库最新一条 ep（ciphertype:5 信封）解出 14 项设备档（含 aid/uuid）。"""
    import sqlite3
    import color_codec as cc
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    row = con.execute(
        "SELECT ep FROM color WHERE ep IS NOT NULL AND ep<>'' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    if not row:
        sys.exit(f"[!] {db_path} 里没有可用的 ep（color 表为空？）")
    cipher = json.loads(row["ep"]).get("cipher", {})
    prof = {}
    for k, v in cipher.items():
        prof[k] = cc.dec_str(v) if isinstance(v, str) else v
    # ep.cipher 用 aid 作设备 uuid；preimage 还要一个同值的 uuid 键
    if "aid" in prof:
        prof.setdefault("uuid", prof["aid"])
    prof.setdefault("appid", "jdsmart-android")
    # 只保留设备档需要的键
    return {k: prof[k] for k in DEVICE_KEYS if k in prof}


def _load_profile_and_secret(args) -> tuple:
    """返回 (profile: dict, secret: str)。--from-db / jd_smart_secrets.json / --secret 叠加。"""
    profile, secret = {}, None
    if os.path.exists(_SECRETS):
        try:
            with open(_SECRETS, encoding="utf-8") as f:
                d = json.load(f)
            if isinstance(d.get("color_profile"), dict):
                profile.update({k: v for k, v in d["color_profile"].items() if not str(v).startswith("<")})
            s = d.get("color_sign_secret", "")
            if s and not s.startswith("<"):
                secret = s
        except Exception:
            pass
    if args.from_db:
        profile.update(profile_from_db(args.from_db))  # db 优先于 secrets.json 的设备档
    secret = args.secret or os.environ.get("JD_COLOR_SIGN_SECRET") or secret
    return profile, secret


def _selftest() -> None:
    # 1) HMAC-SHA256 已知向量（RFC 风格，无需真实密钥）
    assert color_sign("The quick brown fox jumps over the lazy dog", "key") == \
        "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
    # 2) 排序拼接：合成设备档（非真实值），验证 18 段顺序 == App 形态
    syn = {k: k.upper() for k in DEVICE_KEYS}
    syn.update(functionId="FN", body="{}", t="123")
    pre = build_preimage(syn)
    want = "AID&APPID&AREA&{}&BUILD&CLIENT&CLIENTVERSION&D_BRAND&D_MODEL&EID&EXT&FN&NETWORKTYPE&OSVERSION&PARTNER&SCREEN&123&UUID"
    assert pre == want, f"排序拼接 FAILED:\n got={pre}\nwant={want}"
    print("[ok] HMAC-SHA256 + 18 键字母序拼接 self-test 通过（合成值）。")
    print("     字母序:", " ".join(ALL_KEYS))


def main() -> None:
    ap = argparse.ArgumentParser(description="彩虹网关 query sign 离线生成（HMAC-SHA256 + 18 键字母序拼接）")
    ap.add_argument("--selftest", action="store_true", help="验证排序+HMAC（合成值，无需真实数据）")
    ap.add_argument("--from-db", metavar="DB", help="从抓包库最新 ep 解出设备档（14 项）")
    ap.add_argument("--dump-profile", action="store_true", help="打印当前解析到的设备档后退出")
    ap.add_argument("--function-id", help="functionId，如 jdsmart.init.commonConfigs")
    ap.add_argument("--body", default="{}", help="真实请求体 JSON（默认 {}），需与实际下发一致")
    ap.add_argument("--t", help="毫秒时间戳（默认取当前时间）")
    ap.add_argument("--secret", help="native getSecretKey 的 32 字符（勿提交真实值）")
    ap.add_argument("--expect", help="期望 wire sign（64hex），给了就比对")
    args = ap.parse_args()

    if args.selftest:
        _selftest()
        return

    profile, secret = _load_profile_and_secret(args)

    if args.dump_profile:
        print(json.dumps(profile, ensure_ascii=False, indent=2, sort_keys=True))
        miss = [k for k in DEVICE_KEYS if k not in profile]
        print("\n缺少的设备字段:", ", ".join(miss) if miss else "（无，14 项齐全）")
        return

    if not args.function_id:
        ap.error("给 --function-id（或用 --selftest / --dump-profile）")
    if not secret:
        sys.exit("[!] 缺 secret：--secret <32char> 或填 jd_smart_secrets.json 的 color_sign_secret / 设 JD_COLOR_SIGN_SECRET")

    t = args.t or str(int(time.time() * 1000))
    fields = dict(profile, functionId=args.function_id, body=args.body, t=t)
    try:
        preimage = build_preimage(fields)
    except KeyError as e:
        sys.exit(f"[!] {e}\n    用 --from-db <db> 自动补设备档，或在 jd_smart_secrets.json 的 color_profile 里补齐。")
    sig = color_sign(preimage, secret)

    print("functionId :", args.function_id)
    print("t          :", t)
    print("body       :", args.body)
    print("preimage   :", preimage)
    print("sign       :", sig)
    if args.expect:
        ok = sig.lower() == args.expect.lower()
        print("expect     :", args.expect)
        print("match      :", ok)
        sys.exit(0 if ok else 2)


if __name__ == "__main__":
    main()
