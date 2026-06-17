#!/usr/bin/env python3
"""
京东「小京鱼 / IOTS」家庭 & 设备查询客户端 —— Python 封装 test.http 里的 4 条请求。

把抓包定下来的「固定料」一次性放进 jd_smart_secrets.json（已 .gitignore），
本模块每次调用只重算两样东西：**毫秒时间戳 t** 与 **签名 sign**，其余照搬。

覆盖的 4 个接口（对应 test.http）:
    彩虹网关 api.m.jd.com（HMAC-SHA256 sign，算法见 docs/GETHOUSES_PROGRESS.md §7.3）:
        jdsmart.house.getHouses        家庭列表    -> get_houses()
        jdsmart.house.getHouseDetails  家庭详情    -> get_house_details(house_id)
        jdsmart.house.getAllDevices    设备列表    -> get_all_devices(house_id)
    旧接口 api.smart.jd.com（HmacSHA1 authorization，算法见 query_device.py / README §1）:
        getHouseAddressAndWeatherInfo  天气        -> get_house_weather(house_id)

签名/编解码逻辑直接复用仓库已有模块，不重复实现:
    color_codec.py   ciphertype:5 换表 base64（ep/body 的 cipher 离线 encode/decode）
    color_sign.py    彩虹 sign = HMAC-SHA256(18 键字母序拼接, secret)
    query_device.py  旧接口 HmacSHA1 authorization

「每请求只变 t/sign」之所以成立（实测，§7.3）:
    sign 的原文只吃 14 项设备字段 + functionId + 真实 body + t；
    ep 信封、body 信封的 hdid/ts/ridx、cookie、tgt 都不进 sign，可整块重放。
    => ep.cipher 解出来就是 14 项设备档（本模块据此推导，单一真源），body 固定则 cipher.body 也固定。

用法（CLI）:
    python jd_iots_client.py selftest                 # 不联网，校验签名/编解码/请求装配
    python jd_iots_client.py houses --dry-run         # 只打印签好名的 URL+body，不发包
    python jd_iots_client.py houses                   # 真发请求（需 secrets.json 里 tgt/wskey 有效）
    python jd_iots_client.py house-details 1388207
    python jd_iots_client.py devices 1388207
    python jd_iots_client.py weather 1388207
    python jd_iots_client.py raw jdsmart.house.getHouses '{"pageSize":100,"page":1}'

用法（库）:
    import jd_iots_client as jc
    cfg = jc.load_config()
    print(jc.get_all_devices(cfg, 1388207))
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# 同目录模块：保证从任意 cwd 运行都能 import
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import color_codec as cc      # noqa: E402
import color_sign as cs       # noqa: E402
import query_device as qd     # noqa: E402

_SECRETS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "jd_smart_secrets.json")

# ---- 彩虹网关常量（按 App 构建固定，非设备相关）----
COLOR_API = "https://api.m.jd.com/api"
APPID = "jdsmart-android"
CIPHERTYPE = 5
ENVELOPE_VERSION = "1.2.0"
APPNAME = "com.jd.iots"
BODY_RIDX = 1                 # body 信封固定 ridx=1（ep 信封是 -1，两者各自的 hdid 也不同）
UA = "okhttp/4.10.0"

# ---- 旧接口（api.smart.jd.com）----
SMART_BASE = "https://api.smart.jd.com"
WEATHER_PATH = "/s/service/getHouseAddressAndWeatherInfo"

# 18 键里的 15 个「设备/会话固定」键（含 uuid，= color_sign.DEVICE_KEYS，保持同步）
DEVICE_KEYS = cs.DEVICE_KEYS


# ====================== 通用小工具 ======================
def _compact(obj) -> str:
    """紧凑 JSON（无空格），必须与 App 下发字节一致——否则 sign/cipher 对不上。"""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def _as_body_str(body) -> str:
    """dict/list 紧凑序列化；已是字符串则原样当真实请求体。"""
    return _compact(body) if isinstance(body, (dict, list)) else str(body)


def now_ms() -> int:
    return int(time.time() * 1000)


def load_config(path: str = _SECRETS) -> dict:
    """读 jd_smart_secrets.json（已 .gitignore）。缺文件给出可操作提示。"""
    if not os.path.exists(path):
        sys.exit(f"[!] 缺 {os.path.basename(path)}：拷 jd_smart_secrets.example.json 填真实值。")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _require(cfg: dict, keys, where: str) -> None:
    miss = [k for k in keys if not cfg.get(k) or str(cfg[k]).startswith("<")]
    if miss:
        sys.exit(f"[!] {where} 需要 secrets.json 字段: {', '.join(miss)}（见 *.example.json）")


# ====================== 彩虹网关（api.m.jd.com）======================
def profile_from_ep(ep: dict) -> dict:
    """解 ep.cipher（ciphertype:5）得 14 项设备档，补 uuid(=aid)/appid。设备档单一真源。"""
    cipher = ep["cipher"]
    prof = {k: (cc.dec_str(v) if isinstance(v, str) else v) for k, v in cipher.items()}
    prof.setdefault("uuid", prof.get("aid"))
    prof.setdefault("appid", APPID)
    return prof


def _build_cookie(cfg: dict, profile: dict) -> str:
    """复刻 test.http 的 Cookie：pin / wskey(=tgt) / whwswswws(=jmafinger) / unionwsws。
    devicefinger == 设备 eid（= ep.cipher.eid），故从设备档推，不另存。"""
    jma = cfg["color_jmafinger"]
    union = _compact({"devicefinger": profile["eid"], "jmafinger": jma})
    return f"pin={cfg['color_pin']};wskey={cfg['tgt']};whwswswws={jma};unionwsws={union};"


def build_color_request(cfg: dict, function_id: str, body, t=None,
                        refresh_ep_ts: bool = True) -> dict:
    """装配一条彩虹网关请求。返回 {url, headers, data, t, sign, preimage, body}。
    只有 t/sign（以及 body 变了才连带的 cipher.body）随请求变，其余照搬 secrets。"""
    _require(cfg, ["color_ep", "color_sign_secret", "color_body_hdid",
                   "color_pin", "color_jmafinger", "tgt"], "彩虹网关")
    body_str = _as_body_str(body)
    t = int(t) if t is not None else now_ms()

    ep = json.loads(json.dumps(cfg["color_ep"]))   # 深拷贝，免改到 cfg
    if refresh_ep_ts:
        ep["ts"] = t                               # ep 不进 sign，刷新 ts 只为过新鲜度校验，零风险
    profile = profile_from_ep(ep)

    # sign：18 键字母序拼 value -> HMAC-SHA256（复用 color_sign 的实现）
    fields = dict({k: profile[k] for k in DEVICE_KEYS if k in profile},
                  functionId=function_id, body=body_str, t=str(t))
    preimage = cs.build_preimage(fields)
    sign = cs.color_sign(preimage, cfg["color_sign_secret"])

    # query（顺序对齐 test.http）
    query = {
        "functionId": function_id, "appid": APPID, "t": str(t),
        "uuid": profile["uuid"], "sign": sign, "ep": _compact(ep),
        "ef": "1", "bef": "1",
    }
    url = COLOR_API + "?" + urllib.parse.urlencode(query)

    # form body：body=<信封JSON>，信封内 cipher.body = 换表 base64(真实 body)
    envelope = {
        "hdid": cfg["color_body_hdid"], "ts": t, "ridx": BODY_RIDX,
        "cipher": {"body": cc.enc_str(body_str)},
        "ciphertype": CIPHERTYPE, "version": ENVELOPE_VERSION, "appname": APPNAME,
    }
    data = "body=" + urllib.parse.quote(_compact(envelope), safe="")

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Cookie": _build_cookie(cfg, profile),
        "User-Agent": UA,
    }
    return {"url": url, "headers": headers, "data": data,
            "t": t, "sign": sign, "preimage": preimage, "body": body_str}


def _send(req: dict, timeout: int = 15) -> dict:
    r = urllib.request.Request(req["url"], data=req["data"].encode("utf-8"),
                               method="POST", headers=req["headers"])
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return {"_http_error": e.code, "_body": e.read().decode("utf-8", "replace")}
    except urllib.error.URLError as e:
        return {"_url_error": str(e.reason)}
    try:
        return json.loads(raw)
    except ValueError:
        return {"_raw": raw}


def call_color(cfg, function_id, body, dry_run=False, timeout=15, **kw):
    req = build_color_request(cfg, function_id, body, **kw)
    return req if dry_run else _send(req, timeout)


def get_houses(cfg, page=1, page_size=100, **kw):
    """家庭列表。真实 body = {"pageSize":100,"page":1}。"""
    return call_color(cfg, "jdsmart.house.getHouses",
                      {"pageSize": page_size, "page": page}, **kw)


def get_house_details(cfg, house_id, is_new=0, **kw):
    """家庭详情。真实 body = {"houseId":<int>,"isNew":0}（houseId 是数字）。"""
    return call_color(cfg, "jdsmart.house.getHouseDetails",
                      {"houseId": int(house_id), "isNew": is_new}, **kw)


def get_all_devices(cfg, house_id, **kw):
    """设备列表。真实 body = {"houseId":"<str>"}（houseId 是字符串，与详情接口不同）。
    注：test.http 里这条原本报错，是因为它的 sign 是旧的、与 body 对不上；本函数按 body 现算 sign。"""
    return call_color(cfg, "jdsmart.house.getAllDevices",
                      {"houseId": str(house_id)}, **kw)


# ====================== 旧接口（api.smart.jd.com，HmacSHA1）======================
def build_smart_request(cfg, path, query, body, ts=None) -> dict:
    """旧接口装配：authorization = smart seg1:::HmacSHA1(...):::ts（复用 query_device）。"""
    _require(cfg, ["seg1", "key", "tgt"], "旧接口")
    body_str = _as_body_str(body)
    ts = ts or qd.now_ts()
    url = f"{SMART_BASE}{path}?{urllib.parse.urlencode(query)}"
    headers = {
        "app_identity": "WL",
        "authorization": qd.authorization(body_str, ts, cfg),
        "tgt": cfg["tgt"],
        "content-type": "application/json; charset=utf-8",
        "User-Agent": UA,
    }
    return {"url": url, "headers": headers, "data": body_str, "ts": ts}


def call_smart(cfg, path, query, body, dry_run=False, timeout=15, ts=None):
    req = build_smart_request(cfg, path, query, body, ts=ts)
    return req if dry_run else _send(req, timeout)


def get_house_weather(cfg, house_id, **kw):
    """天气 / 地址。device_id = 设备 uuid（从 ep 推），body = {"houseId":"<str>"}。"""
    device_id = profile_from_ep(cfg["color_ep"])["uuid"] if cfg.get("color_ep") else cfg.get("uuid")
    query = {
        "plat": cfg.get("plat", "Android"),
        "hard_platform": cfg["hard_platform"],
        "app_version": cfg["app_version"],
        "plat_version": cfg["plat_version"],
        "device_id": device_id,
        "channel": cfg["channel"],
    }
    return call_smart(cfg, WEATHER_PATH, query, {"houseId": str(house_id)}, **kw)


# ====================== self-test（不联网、不需要真实凭据）======================
def selftest() -> bool:
    ok = True

    def check(name, cond):
        nonlocal ok
        ok = ok and cond
        print(f"  [{'ok' if cond else 'FAIL'}] {name}")

    # 1) 换表 base64 字节往返
    sample = bytes(range(256))
    check("color_codec encode/decode 往返", cc.decode(cc.encode(sample)) == sample)

    # 2) HMAC-SHA256 已知向量（RFC 风格）
    check("HMAC-SHA256 已知向量", cs.color_sign(
        "The quick brown fox jumps over the lazy dog", "key") ==
        "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")

    # 3) 用合成设备档（非真实值）装配彩虹请求，校验 sign 拼接 + ep/body 往返
    syn_prof = {k: k.upper() for k in DEVICE_KEYS}
    syn_ep = {
        "hdid": "EPHDID", "ts": 1, "ridx": -1,
        "cipher": {k: cc.enc_str(v) for k, v in syn_prof.items() if k != "appid"},
        "ciphertype": CIPHERTYPE, "version": ENVELOPE_VERSION, "appname": APPNAME,
    }
    syn_cfg = {"color_ep": syn_ep, "color_sign_secret": "k" * 32,
               "color_body_hdid": "BODYHDID", "color_pin": "pin",
               "color_jmafinger": "jma", "tgt": "TGT"}
    req = build_color_request(syn_cfg, "fn.test", {"a": 1}, t=123, refresh_ep_ts=False)
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(req["url"]).query)
    check("彩虹 query 含 functionId/t/uuid/sign/ep/ef/bef",
          all(k in q for k in ("functionId", "t", "uuid", "sign", "ep", "ef", "bef")))
    check("彩虹 sign=64hex", len(req["sign"]) == 64 and int(req["sign"], 16) >= 0)
    # body 信封里的 cipher.body 解回真实 body
    env = json.loads(urllib.parse.unquote(req["data"][len("body="):]))
    check("body 信封 cipher.body 解回真实 body",
          cc.dec_str(env["cipher"]["body"]) == '{"a":1}')
    # preimage = 18 段、字母序、合成设备档的大写值都在
    check("preimage 18 段字母序",
          req["preimage"].split("&")[0] == "AID" and req["preimage"].count("&") == 17)

    # 4) 旧接口 authorization 形态（合成密钥）
    syn_cfg2 = {"seg1": "SEG1", "key": "k" * 20, "tgt": "TGT",
                "app_version": "1.17.0", "hard_platform": "HWI-AL00", "plat_version": "9"}
    sreq = build_smart_request(syn_cfg2, "/p", {"a": "b"}, {"houseId": "1"})
    parts = sreq["headers"]["authorization"].split(":::")
    check("旧接口 authorization=smart seg1:::sign:::ts",
          sreq["headers"]["authorization"].startswith("smart SEG1") and len(parts) == 3)

    print("\nself-test", "PASS" if ok else "FAIL")
    return ok


# ====================== CLI ======================
def _print(result) -> None:
    print(json.dumps(result, ensure_ascii=False, indent=2))


def main() -> None:
    # 公共开关放进 parent，挂到每个子命令上 —— 这样 `houses --dry-run` 这种写法（开关在子命令后）才生效
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--secrets", default=_SECRETS, help="凭据文件（默认 jd_smart_secrets.json）")
    common.add_argument("--dry-run", action="store_true", help="只打印签好名的请求，不联网")
    common.add_argument("--timeout", type=int, default=15)
    common.add_argument("--no-refresh-ep-ts", action="store_true",
                        help="ep.ts 保持抓包原值（默认刷新为当前 t；ep 不进 sign，二者皆可）")

    ap = argparse.ArgumentParser(description="小京鱼 IOTS 家庭/设备/天气查询（封装 test.http）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest", parents=[common], help="离线自检（不需真实凭据）")
    sub.add_parser("houses", parents=[common], help="家庭列表 getHouses") \
        .add_argument("--page", type=int, default=1)
    sub.add_parser("house-details", parents=[common], help="家庭详情 getHouseDetails") \
        .add_argument("house_id")
    sub.add_parser("devices", parents=[common], help="设备列表 getAllDevices") \
        .add_argument("house_id")
    sub.add_parser("weather", parents=[common], help="天气/地址 getHouseAddressAndWeatherInfo") \
        .add_argument("house_id")
    p_raw = sub.add_parser("raw", parents=[common], help="任意彩虹接口：raw <functionId> <body-json>")
    p_raw.add_argument("function_id")
    p_raw.add_argument("body", help='真实请求体 JSON，如 {"pageSize":100,"page":1}')
    args = ap.parse_args()

    if args.cmd == "selftest":
        sys.exit(0 if selftest() else 1)

    cfg = load_config(args.secrets)
    kw = dict(dry_run=args.dry_run, timeout=args.timeout)
    color_kw = dict(kw, refresh_ep_ts=not args.no_refresh_ep_ts)

    if args.cmd == "houses":
        _print(get_houses(cfg, page=args.page, **color_kw))
    elif args.cmd == "house-details":
        _print(get_house_details(cfg, args.house_id, **color_kw))
    elif args.cmd == "devices":
        _print(get_all_devices(cfg, args.house_id, **color_kw))
    elif args.cmd == "weather":
        _print(get_house_weather(cfg, args.house_id, **kw))
    elif args.cmd == "raw":
        try:
            body = json.loads(args.body)
        except ValueError:
            body = args.body
        _print(call_color(cfg, args.function_id, body, **color_kw))


if __name__ == "__main__":
    main()
