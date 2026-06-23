#!/usr/bin/env python3
"""彩虹网关（api.m.jd.com）随手测试器 —— 输入 functionId + 参数，自动签名/加密/发送/打印。

直接驱动集成里的新客户端 custom_components/jd_smart/color_api.py（即将接进 HA 的那一份），
所以这脚本同时也是它的「联网验收」：签名、ciphertype:5 信封、Cookie 全走 color_api 的真逻辑，
仅发包用标准库 urllib（免装 aiohttp）。凭据读 jd_smart_secrets.json（已 .gitignore）。

用法:
    python color_test.py                          # 交互模式（REPL，最方便）
    python color_test.py houses                   # 家庭列表
    python color_test.py devices 1388207          # 某家庭的设备列表（含实时快照）
    python color_test.py details 1388207          # 家庭详情
    python color_test.py <functionId> '<body-json>'   # 任意接口，如：
        python color_test.py jdsmart.house.getHouses '{"pageSize":100,"page":1}'

    交互模式里也支持：直接敲 `devices 1388207`，或先敲 functionId 再按提示输 body。

jd_smart_secrets.json 需要的字段（彩虹网关）:
    必填:
      color_sign_secret   native getSecretKey() 的 32 字符（HMAC 密钥）
      color_pin           Cookie 的 pin（如 jd_xxx）
      color_jmafinger     Cookie 的 whwswswws / jmafinger（一个 UUID）
      tgt                 登录票据（会过期，需刷新）
    设备档（二选一）:
      ① color_profile（推荐，明文易改）+ color_ep_hdid
         color_profile = {aid,uuid,appid,area,build,client,clientVersion,d_brand,
                          d_model,eid,ext,networkType,osVersion,partner,screen}
         color_ep_hdid = ep 信封的 hdid（一串 base64 token，原样填）
      ② color_ep（旧格式，抓包的 ciphertype:5 密文信封，自动解出 profile）
    可选:
      color_body_hdid     不填则自动按 base64(sha256(eid)) 派生

    没有明文 color_profile？跑一次把现有密文 color_ep 转成可粘贴的明文块:
        python color_test.py --dump-profile

选项:
    --dump-profile       打印可粘贴进 secrets 的明文 color_profile/ep_hdid/body_hdid，然后退出
    --dry-run            只打印签好名的请求（URL/Cookie/body 信封），不发送
    --t <ms>             固定毫秒时间戳（默认取当前）
    --no-refresh-ep-ts   ep.ts 保持抓包原值（默认刷新为当前 t；ep 不进 sign，二者皆可）
    --raw                响应不美化，原样打印
    --timeout N          秒（默认 20）
    --secrets PATH       凭据文件（默认 jd_smart_secrets.json）
"""
import argparse
import importlib.util
import json
import os
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
_PKG = os.path.join(HERE, "custom_components", "jd_smart")
_SECRETS = os.path.join(HERE, "jd_smart_secrets.json")

# 必填凭据（设备档另算：color_profile 明文 或 color_ep 密文，二选一）
_REQUIRED_KEYS = ("color_sign_secret", "color_pin", "color_jmafinger", "tgt")

# 快捷词 -> (真 functionId, 由参数构造 body)
SHORTCUTS = {
    "houses":  ("jdsmart.house.getHouses",       lambda a: {"pageSize": 100, "page": 1}),
    "details": ("jdsmart.house.getHouseDetails", lambda a: {"houseId": int(a), "isNew": 0}),
    "devices": ("jdsmart.house.getAllDevices",   lambda a: {"houseId": str(a)}),
}


def _load_color_api():
    """加载 custom_components/jd_smart/color_api.py，绕开包 __init__（免依赖 voluptuous/aiohttp）。"""
    # 让 color_api 里 `from . import color_codec` 的 fallback `import color_codec` 命中内置副本
    sys.path.insert(0, _PKG)
    spec = importlib.util.spec_from_file_location("jd_color_api", os.path.join(_PKG, "color_api.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _filled(v):
    return v not in (None, "") and not str(v).startswith("<")


def _load_client(color_api, secrets_path):
    if not os.path.exists(secrets_path):
        sys.exit(f"[!] 缺 {os.path.basename(secrets_path)}：拷 jd_smart_secrets.example.json 填真实值。")
    with open(secrets_path, encoding="utf-8") as f:
        cfg = json.load(f)
    name = os.path.basename(secrets_path)

    miss = [k for k in _REQUIRED_KEYS if not _filled(cfg.get(k))]
    if miss:
        sys.exit(f"[!] {name} 缺必填字段: {', '.join(miss)}（见 *.example.json）")

    common = dict(
        sign_secret=cfg["color_sign_secret"],
        pin=cfg["color_pin"],
        jmafinger=cfg["color_jmafinger"],
        tgt=cfg["tgt"],
        body_hdid=cfg["color_body_hdid"] if _filled(cfg.get("color_body_hdid")) else None,
    )

    prof = cfg.get("color_profile")
    if isinstance(prof, dict) and prof and all(_filled(v) for v in prof.values()):
        # ① 明文设备档（推荐）：ep_hdid 取 color_ep_hdid，或仍兼容从 color_ep.hdid 拿
        ep_hdid = cfg.get("color_ep_hdid") or (cfg.get("color_ep") or {}).get("hdid", "")
        if not _filled(ep_hdid):
            sys.exit(f"[!] {name} 有 color_profile 但缺 color_ep_hdid（ep 信封 hdid token）。")
        return color_api.JdColorClient(None, profile=prof, ep_hdid=ep_hdid, **common)

    ep = cfg.get("color_ep")
    if isinstance(ep, dict) and ep.get("cipher"):
        # ② 旧格式密文信封（自动解出 profile）
        return color_api.JdColorClient(None, ep=ep, **common)

    sys.exit(f"[!] {name} 缺设备档：填明文 color_profile(+color_ep_hdid) 或密文 color_ep（见 *.example.json）。")


def dump_profile(color_api, client):
    """把当前生效的设备档导成可粘贴进 secrets 的明文块（密文 color_ep -> 明文 color_profile）。"""
    snippet = {
        "color_profile": {k: client.profile[k] for k in color_api.DEVICE_KEYS if k in client.profile},
        "color_ep_hdid": client.ep_hdid,
        "color_body_hdid": client.body_hdid,
    }
    print("# 把下面三项粘进 jd_smart_secrets.json（可删掉旧的密文 color_ep）：")
    print(json.dumps(snippet, ensure_ascii=False, indent=2))


def _resolve(function_id, body_arg):
    """快捷词展开；否则 body_arg 当 JSON（空则 {}）。返回 (function_id, body_obj)。"""
    if function_id in SHORTCUTS:
        real, make_body = SHORTCUTS[function_id]
        if function_id in ("details", "devices") and not body_arg:
            raise ValueError(f"`{function_id}` 需要 houseId，例如：{function_id} 1388207")
        return real, make_body(body_arg)
    if not body_arg:
        return function_id, {}
    try:
        return function_id, json.loads(body_arg)
    except ValueError:
        return function_id, body_arg  # 不是 JSON 就当原始字符串体


def _send(req, timeout):
    r = urllib.request.Request(req["url"], data=req["data"].encode("utf-8"),
                               method="POST", headers=req["headers"])
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.getcode(), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except urllib.error.URLError as e:
        return None, f"URLError: {e.reason}"


def _print_devices(color_api, client, resp):
    """getAllDevices 响应：额外打印拍平后的设备表。"""
    try:
        devs = color_api.parse_device_list(resp, requester_device_id=client.profile.get("uuid"))
    except Exception as e:
        print(f"  (设备解析失败: {e})")
        return
    if not devs:
        print("  (未解析出设备；看上面原始响应)")
        return
    print(f"\n解析出 {len(devs)} 台设备（feed_id | 名称 | 房间 | 类目 | Power | streams 数）:")
    for d in devs:
        power = (d.get("snapshot") or {}).get("Power", "-")
        print(f"  {str(d['feed_id']):<20} {str(d.get('name','')):<14} "
              f"{str(d.get('room') or '-'):<8} {str(d.get('category') or '-'):<6} "
              f"P={power:<4} streams={len(d.get('streams', []))}")


def do_request(color_api, client, function_id, body, args):
    real, body_obj = _resolve(function_id, body)
    req = client.build_request(real, body_obj, t=args.t,
                               refresh_ep_ts=not args.no_refresh_ep_ts)
    body_str = req["body"] if isinstance(req["body"], str) else json.dumps(body_obj, ensure_ascii=False)
    print(f"\n>>> {real}  body={body_str}")
    print(f"    t={req['t']}  sign={req['sign']}")

    if args.dry_run:
        print("--- DRY RUN（不发送）---")
        print("URL   :", req["url"])
        print("Cookie:", req["headers"]["Cookie"])
        print("DATA  :", req["data"])
        return

    code, text = _send(req, args.timeout)
    print(f"<<< HTTP {code}")
    if args.raw:
        print(text)
        return
    try:
        data = json.loads(text)
    except ValueError:
        print(text)
        return
    print(json.dumps(data, ensure_ascii=False, indent=2))
    if real == "jdsmart.house.getAllDevices" and isinstance(data, dict) and data.get("result"):
        _print_devices(color_api, client, data)


def repl(color_api, client, args):
    print("彩虹网关测试器（交互模式）。敲 functionId 或快捷词，空行/q 退出。")
    print("快捷词: houses | details <houseId> | devices <houseId>")
    print('示例:  devices 1388207   或   jdsmart.house.getHouses {\"page\":1,\"pageSize\":100}\n')
    while True:
        try:
            line = input("fn> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line or line.lower() in ("q", "quit", "exit"):
            break
        parts = line.split(None, 1)
        fid = parts[0]
        arg = parts[1].strip() if len(parts) > 1 else None
        # 通用 functionId 且未带 body：再提示输一行 body
        if fid not in SHORTCUTS and arg is None:
            try:
                arg = input("   body(JSON, 回车=空)> ").strip() or None
            except (EOFError, KeyboardInterrupt):
                print()
                break
        try:
            do_request(color_api, client, fid, arg, args)
        except ValueError as e:
            print(f"  [!] {e}")
        except Exception as e:  # 单次失败不退出 REPL
            print(f"  [!] 请求出错: {e}")


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    ap = argparse.ArgumentParser(
        description="彩虹网关随手测试器（驱动 color_api.py：自动签名/加密/发送/打印）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="无参数进入交互模式。快捷词: houses / details <id> / devices <id>。",
    )
    ap.add_argument("function_id", nargs="?", help="functionId 或快捷词（省略=交互模式）")
    ap.add_argument("body", nargs="?", help="body JSON；或快捷词 details/devices 的 houseId")
    ap.add_argument("--dump-profile", action="store_true",
                    help="打印可粘贴的明文 color_profile/ep_hdid/body_hdid，然后退出")
    ap.add_argument("--dry-run", action="store_true", help="只打印签好名的请求，不发送")
    ap.add_argument("--t", help="固定毫秒时间戳（默认当前）")
    ap.add_argument("--no-refresh-ep-ts", action="store_true", help="ep.ts 保持抓包原值")
    ap.add_argument("--raw", action="store_true", help="响应原样打印，不美化")
    ap.add_argument("--timeout", type=int, default=20)
    ap.add_argument("--secrets", default=_SECRETS, help="凭据文件（默认 jd_smart_secrets.json）")
    args = ap.parse_args()

    color_api = _load_color_api()
    client = _load_client(color_api, args.secrets)

    if args.dump_profile:
        dump_profile(color_api, client)
    elif args.function_id is None:
        repl(color_api, client, args)
    else:
        do_request(color_api, client, args.function_id, args.body, args)


if __name__ == "__main__":
    main()
