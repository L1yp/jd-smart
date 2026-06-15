#!/usr/bin/env python3
"""
复现 小京鱼(com.jd.smart) 的 Authorization 签名（com.jd.smart.base.net.http.RestClient）。

格式:  Authorization: smart <seg1>:::<seg2>:::<ts>
算法:  device_md = md5("Android"+app_version+hard_platform+plat_version+":"+当年第几天)  # 每天滚动
       message   = device_md + tag + body + ts + seg1 + device_md
       seg2      = Base64( HMAC-SHA1(key, message) )     # 标准 base64，带 '=' 填充

用法:
    1) 把下面 KEY_TXT 或 KEY_HEX 填成从 sign 表 Mac.init 抓到的密钥；
    2) python verify_sign.py   # 用抓到的样本自测，match=True 即完全复现。
"""
import base64
import hashlib
import hmac
from datetime import datetime, timedelta, timezone

# ==== 已抓到的稳定值（从 hook / header 得到）====
SEG1 = "<your_seg1>"        # 恒定账号/设备标识，=header 里的 seg1
TAG  = "postjson_body"                              # 请求类型标记（postJson 用这个；GET 多半不同，需另抓）
# device_md 不是固定值：含“当年第几天”每天滚动，由 device_md() 用下面三个设备参数实时算。
HARD_PLATFORM = "HWI-AL00"  # = App 的 BaseInfo.getDeviceModel()
APP_VERSION   = "1.17.0"    # = App 版本
PLAT_VERSION  = "9"         # = Build.VERSION.RELEASE

# ==== !!! 待填：HMAC 密钥（从 sign 表 kind='Mac.init' 的 key_txt/key_hex）====
KEY_TXT = ""   # 抓到的 HmacSHA1 密钥（可见字符串就填这里）；勿提交真实值
KEY_HEX = ""   # 若 key 是二进制就填 hex（与 KEY_TXT 二选一）

# 真实值从 jd_smart_secrets.json 覆盖进来（该文件已 .gitignore，不提交）。
import json as _json
import os as _os

_S = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "jd_smart_secrets.json")
if _os.path.exists(_S):
    with open(_S, encoding="utf-8") as _f:
        _s = _json.load(_f)
    SEG1 = _s.get("seg1", SEG1)
    KEY_TXT = _s.get("key", KEY_TXT)
    HARD_PLATFORM = _s.get("hard_platform", HARD_PLATFORM)
    APP_VERSION = _s.get("app_version", APP_VERSION)
    PLAT_VERSION = _s.get("plat_version", PLAT_VERSION)


def _key() -> bytes:
    if KEY_HEX:
        return bytes.fromhex(KEY_HEX)
    return KEY_TXT.encode("utf-8")


def device_md() -> str:
    """设备指纹 = md5("Android"+app_version+hard_platform+plat_version+":"+当年第几天)。

    末尾 DAY_OF_YEAR 每天 +1，所以每天滚动——必须实时算。验证历史样本时给 sign() 传
    当天的 uuid 即可。用 Asia/Shanghai 对齐 App(设备本地时区)与京东服务端。
    """
    # UTC+8(中国标准时，无夏令时，等价 Asia/Shanghai)；固定偏移免依赖系统 IANA 时区库
    doy = datetime.now(timezone(timedelta(hours=8))).timetuple().tm_yday
    raw = f"Android{APP_VERSION}{HARD_PLATFORM}{PLAT_VERSION}:{doy}"
    return hashlib.md5(raw.encode("utf-8")).hexdigest()


def sign(body: str, ts: str, *, uuid: str = "", seg1: str = SEG1, tag: str = TAG) -> str:
    """算出 seg2。uuid 省略则按今天动态算 device_md。"""
    if not uuid:
        uuid = device_md()
    message = uuid + tag + body + ts + seg1 + uuid
    digest = hmac.new(_key(), message.encode("utf-8"), hashlib.sha1).digest()
    return base64.b64encode(digest).decode()


def authorization(body: str, ts: str) -> str:
    return f"smart {SEG1}:::{sign(body, ts)}:::{ts}"


if __name__ == "__main__":
    sample_body = '{"json":{"feed_id":100000000000000000,"version":"2.0","digest":""}}'
    sample_ts = "2026-01-01T00:00:00.000Z"
    if not (KEY_TXT or KEY_HEX):
        print("[!] 先填 KEY_TXT/KEY_HEX 或放好 jd_smart_secrets.json 再运行。")
    else:
        print("seg2 实算    :", sign(sample_body, sample_ts))
        print("Authorization:", authorization(sample_body, sample_ts))
