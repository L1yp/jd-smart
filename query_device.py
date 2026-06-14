#!/usr/bin/env python3
"""
小京鱼(com.jd.smart) 设备快照查询 —— 独立版（仅标准库，可直接联网测）。
复用已逆向出的 HmacSHA1 签名，调 getDeviceSnapshot_v1。

把 CONFIG 里的常量换成你自己的；seg1/key/device_md 重新登录也不变，tgt 每次登录会变、会过期。

用法:
    python query_device.py --selftest                      # 不联网，校验签名算法
    python query_device.py --device-id <id> --feed-id <fid>  # 真正查询
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

CONFIG = {
    # 真实凭据放到同目录 jd_smart_secrets.json（已 .gitignore），不要写进本文件、不要提交。
    # 用 frida_capture.js + host.py 抓 sign 表得到 seg1/key/device_md；tgt 抓请求头得到。
    "seg1": "<your_seg1>",
    "key": "<your_hmac_key>",
    # device_md = md5("Android" + app_version + hard_platform + plat_version + ":" + versionCode)
    "device_md": "<your_device_md>",
    "tgt": "<your_tgt>",  # 登录票据，会过期
    # 设备指纹（拼进 query string）——按你的设备改
    "hard_platform": "HWI-AL00",
    "app_version": "1.17.0",
    "plat_version": "9",
    "channel": "xjgw-android",
    "plat": "Android",
}

# 真实值从 jd_smart_secrets.json 覆盖进来（该文件不入库）。
_SECRETS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "jd_smart_secrets.json")
if os.path.exists(_SECRETS):
    with open(_SECRETS, encoding="utf-8") as _f:
        CONFIG.update(json.load(_f))

API = "https://api.smart.jd.com/c/service/integration/v1/getDeviceSnapshot_v1"
TAG = "postjson_body"  # 注意：这是 postJson 请求的标记；其它请求类型可能不同


def now_ts(local: bool = False) -> str:
    # 默认 UTC（Z 的本义）。若 App 实际是“本地时间贴 Z”，传 local=True。
    n = datetime.now().astimezone() if local else datetime.now(timezone.utc)
    return n.strftime("%Y-%m-%dT%H:%M:%S.") + f"{n.microsecond // 1000:03d}Z"


def build_body(feed_id) -> str:
    # 顺序/紧凑格式必须与 App 完全一致：{"json":{"feed_id":<int>,"version":"2.0","digest":""}}
    return json.dumps(
        {"json": {"feed_id": int(feed_id), "version": "2.0", "digest": ""}},
        separators=(",", ":"), ensure_ascii=False,
    )


def sign(body: str, ts: str, cfg=CONFIG) -> str:
    msg = cfg["device_md"] + TAG + body + ts + cfg["seg1"] + cfg["device_md"]
    mac = hmac.new(cfg["key"].encode(), msg.encode(), hashlib.sha1).digest()
    return base64.b64encode(mac).decode()


def authorization(body: str, ts: str, cfg=CONFIG) -> str:
    return f"smart {cfg['seg1']}:::{sign(body, ts, cfg)}:::{ts}"


def query(device_id: str, feed_id, cfg=CONFIG, timeout=15, local_time=False):
    ts = now_ts(local_time)
    body = build_body(feed_id)
    qs = urllib.parse.urlencode({
        "hard_platform": cfg["hard_platform"],
        "app_version": cfg["app_version"],
        "device_id": device_id,
        "plat_version": cfg["plat_version"],
        "channel": cfg["channel"],
        "plat": cfg["plat"],
    })
    req = urllib.request.Request(
        f"{API}?{qs}", data=body.encode(), method="POST",
        headers={
            "app_identity": "WL",
            "authorization": authorization(body, ts, cfg),
            "tgt": cfg["tgt"],
            "content-type": "application/json; charset=utf-8",
            "user-agent": "okhttp/4.10.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return {"_http_error": e.code, "_body": e.read().decode(errors="replace")}


def selftest() -> bool:
    # 仅校验 body 拼装格式（不含任何真实设备/密钥数据）。
    body = build_body(100000000000000000)
    assert body == '{"json":{"feed_id":100000000000000000,"version":"2.0","digest":""}}', body
    print("body 格式 OK:", body)
    if CONFIG["key"].startswith("<"):
        print("[i] 未配置真实 key（见 jd_smart_secrets.json），跳过签名计算。")
        return True
    ts = "2026-01-01T00:00:00.000Z"
    print("sample ts  :", ts)
    print("sample seg2:", sign(body, ts))
    print("（真正验证请联网：--device-id <id> --feed-id <feed_id>）")
    return True


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--device-id")
    ap.add_argument("--feed-id")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--local", action="store_true",
                    help="时间戳用本地时间贴 Z（默认 UTC）；若服务器嫌时间戳过期就试这个")
    a = ap.parse_args()
    if a.selftest:
        sys.exit(0 if selftest() else 1)
    if not (a.device_id and a.feed_id):
        ap.error("需要 --device-id 和 --feed-id（或 --selftest）")
    print(json.dumps(query(a.device_id, a.feed_id, local_time=a.local), ensure_ascii=False, indent=2))
