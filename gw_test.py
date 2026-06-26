#!/usr/bin/env python3
"""gw.smart.jd.com 轻量发现接口测试器（**不走彩虹网关**）。

验证两条接口只凭「少量参数」就能拿到家庭/设备列表：
    POST /s/service/getHousesAndRooms                 -> 家庭 + 房间
    POST /c/service/devmanager/v2/getDevicesAndCategory -> 设备 + 类目

它们与现有 getDeviceSnapshot **同一套 HmacSHA1 签名**（已离线验签命中抓包）：
    Authorization: smart <seg1>:::Base64(HmacSHA1(key, device_md+"postjson_body"+body+ts+seg1+device_md)):::<ts>
    device_md = md5("Android"+app_version+hard_platform+plat_version+":"+当年第几天)
所以**完全不需要**彩虹网关那套 eid / aid / ep 信封 / color_sign_secret / jmafinger，
只要：seg1 + key + tgt + device_id(仅放 query，不参与签名) + app 档位。

凭据读 jd_smart_secrets.json（已 .gitignore）——复用 color_test.py 同一个文件：
    必读：seg1、key、tgt
    app 档（缺省用集成默认）：hard_platform、app_version、plat_version、channel、plat
    device_id：优先顶层 "device_id"，否则 md5(android_id)，再否则占位（不影响签名）

用法:
    python gw_test.py                 # 自动：先列家庭，再用家庭列表里第一个 houseId 列设备
    python gw_test.py 3979083         # 指定 houseId 列设备（家庭列表仍会先打印）
    python gw_test.py --dry-run       # 只打印签好名的请求（不发送、tgt 隐藏），离线自检
    python gw_test.py --raw           # 响应原样打印，不美化
    python gw_test.py --secrets PATH  # 指定凭据文件
"""
import argparse
import base64
import gzip
import hashlib
import hmac
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
_SECRETS = os.path.join(HERE, "jd_smart_secrets.json")

BASE = "https://gw.smart.jd.com"
TAG = "postjson_body"  # 与 api.py 一致：postJson 请求的签名标记
PATH_HOUSES = "/s/service/getHousesAndRooms"
PATH_DEVICES = "/c/service/devmanager/v2/getDevicesAndCategory"

_REQUIRED = ("seg1", "key", "tgt")


def _load_secrets(path):
    if not os.path.exists(path):
        sys.exit(f"[!] 缺 {os.path.basename(path)}：拷 jd_smart_secrets.example.json 填真实值。")
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)
    miss = [k for k in _REQUIRED if not (cfg.get(k) or "").strip()]
    if miss:
        sys.exit(f"[!] {os.path.basename(path)} 缺字段: {', '.join(miss)}（见 *.example.json）")
    return cfg


def _resolve_device_id(cfg):
    """device_id 只放 query、不参与签名：优先顶层 device_id，其次 md5(android_id)，再否则占位。"""
    did = (cfg.get("device_id") or "").strip()
    if did:
        return did
    aid = (cfg.get("android_id") or "").strip()
    if aid:
        return hashlib.md5(aid.encode("utf-8")).hexdigest()
    return "00000000-0000-0000-0000-000000000000"


class GwClient:
    """gw.smart.jd.com 客户端（HmacSHA1 签名与 api.JdSmartClient 同源；标准库 urllib 发包）。"""

    def __init__(self, cfg):
        self.seg1 = cfg["seg1"]
        self.key = cfg["key"]
        self.tgt = cfg["tgt"]
        self.hard_platform = cfg.get("hard_platform") or "HWI-AL00"
        self.app_version = cfg.get("app_version") or "1.17.0"
        self.plat_version = cfg.get("plat_version") or "9"
        self.channel = cfg.get("channel") or "xjgw-android"
        self.plat = cfg.get("plat") or "Android"
        self.device_id = _resolve_device_id(cfg)

    @staticmethod
    def _now_ts():
        # 京东这套发的是「北京时间(UTC+8)墙上时钟 + Z 后缀」，与 api.py now_ts 对齐
        n = datetime.now(timezone(timedelta(hours=8)))
        return n.strftime("%Y-%m-%dT%H:%M:%S.") + f"{n.microsecond // 1000:03d}Z"

    def _device_md(self):
        doy = datetime.now(timezone(timedelta(hours=8))).timetuple().tm_yday
        raw = f"Android{self.app_version}{self.hard_platform}{self.plat_version}:{doy}"
        return hashlib.md5(raw.encode()).hexdigest()

    def _authorization(self, body, ts):
        dmd = self._device_md()
        msg = dmd + TAG + body + ts + self.seg1 + dmd
        sig = base64.b64encode(hmac.new(self.key.encode(), msg.encode(), hashlib.sha1).digest()).decode()
        return f"smart {self.seg1}:::{sig}:::{ts}"

    def _query(self):
        return urllib.parse.urlencode({
            "hard_platform": self.hard_platform,
            "app_version": self.app_version,
            "device_id": self.device_id,
            "plat_version": self.plat_version,
            "channel": self.channel,
            "plat": self.plat,
        })

    def build(self, path, body_obj):
        """装配一条请求（不发送）。body 紧凑、键序固定——签名按整串字节算。"""
        body = json.dumps(body_obj, separators=(",", ":"), ensure_ascii=False)
        ts = self._now_ts()
        url = f"{BASE}{path}?{self._query()}"
        headers = {
            "app_identity": "WL",
            "Authorization": self._authorization(body, ts),
            "tgt": self.tgt,
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "okhttp/4.10.0",
        }
        return {"url": url, "headers": headers, "body": body, "ts": ts}

    def send(self, req, timeout=20):
        r = urllib.request.Request(req["url"], data=req["body"].encode("utf-8"),
                                   method="POST", headers=req["headers"])
        try:
            with urllib.request.urlopen(r, timeout=timeout) as resp:
                raw = resp.read()
                if resp.headers.get("Content-Encoding") == "gzip":
                    raw = gzip.decompress(raw)
                return resp.getcode(), raw.decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                if (e.headers.get("Content-Encoding") or "") == "gzip":
                    raw = gzip.decompress(raw)
            except (OSError, EOFError):
                pass
            return e.code, raw.decode("utf-8", "replace")
        except urllib.error.URLError as e:
            return None, f"URLError: {e.reason}"


def _find_house_ids(obj):
    """递归全文搜 houseId 值（响应形状未抓过，稳妥起见不假设结构）。去重保序。"""
    found = []

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k in ("houseId", "house_id") and isinstance(v, (str, int)):
                    found.append(str(v))
                else:
                    walk(v)
        elif isinstance(o, list):
            for x in o:
                walk(x)

    walk(obj)
    seen, out = set(), []
    for h in found:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


def _show(title, status, text, raw_mode):
    print(f"\n===== {title}  (HTTP {status}) =====")
    if raw_mode:
        print(text[:8000])
        return None
    try:
        obj = json.loads(text)
    except ValueError:
        print(text[:4000])
        return None
    print(json.dumps(obj, ensure_ascii=False, indent=2)[:8000])
    return obj


def request(cli, path, title, body_obj, args):
    """build → 打印（dry-run 隐藏 tgt）→ send → 展示。返回解析后的 JSON 或 None。"""
    req = cli.build(path, body_obj)
    print(f"\n>>> {title}")
    print(f"    URL  : {req['url']}")
    print(f"    Auth : {req['headers']['Authorization']}")
    print(f"    tgt  : <{len(cli.tgt)} chars, hidden>")
    print(f"    body : {req['body']}")
    if args.dry_run:
        print("    (--dry-run：不发送)")
        return None
    status, text = cli.send(req, args.timeout)
    return _show(title, status, text, args.raw)


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:  # noqa: BLE001
            pass

    ap = argparse.ArgumentParser(
        description="gw.smart.jd.com 轻量发现接口测试器（不走彩虹；HmacSHA1 同 getDeviceSnapshot）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("house_id", nargs="?", help="指定 houseId 列设备；省略则用家庭列表里第一个")
    ap.add_argument("--dry-run", action="store_true", help="只打印签好名的请求，不发送（tgt 隐藏）")
    ap.add_argument("--raw", action="store_true", help="响应原样打印，不美化")
    ap.add_argument("--secrets", default=_SECRETS, help="凭据文件（默认 jd_smart_secrets.json）")
    ap.add_argument("--timeout", type=int, default=20)
    args = ap.parse_args()

    cfg = _load_secrets(args.secrets)
    cli = GwClient(cfg)
    print(f"[i] device_id(query,不签名)={cli.device_id}  "
          f"app={cli.app_version}/{cli.hard_platform}/{cli.plat_version}/{cli.channel}")
    print("[i] 仅用 seg1/key/tgt/app档/device_id —— 无任何彩虹网关参数")

    # 1) 家庭 + 房间（空 body 期望列出该账号全部家庭；失败可改传具体 houseId）
    houses_obj = request(cli, PATH_HOUSES, "getHousesAndRooms  body={}", {}, args)
    house_ids = _find_house_ids(houses_obj) if houses_obj else []
    if house_ids:
        print(f"\n[i] 从家庭响应解析到 houseId: {', '.join(house_ids)}")

    # 2) 设备 + 类目（用 CLI 指定的 houseId，否则家庭列表第一个）
    hid = args.house_id or (house_ids[0] if house_ids else None)
    if not hid:
        if not args.dry_run:
            print("\n[!] 无可用 houseId（家庭接口未返回/解析失败）。手动指定：python gw_test.py <houseId>")
        hid = args.house_id or "3979083"  # dry-run 用抓包里的占位，便于看请求形态
        if not args.dry_run:
            return
    request(cli, PATH_DEVICES, f"getDevicesAndCategory  houseId={hid}", {"houseId": str(hid)}, args)


if __name__ == "__main__":
    main()
