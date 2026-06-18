"""彩虹网关（api.m.jd.com）async 客户端 —— getHouses / getHouseDetails / getAllDevices。

移植自仓库根 jd_iots_client.py（同算法、4 接口已实测 code=0），改为 aiohttp 异步 + 自包含
（codec 内置 color_codec.py），为下一步「HA 配置流程里选设备绑定 + 协调器走彩虹轮询」打底；
本步只做客户端 + 设备列表解析 + 自检，**不**接 config_flow / coordinator。

算法（详见 docs/GETHOUSES_PROGRESS.md §7.3）:
    sign     = HMAC-SHA256(preimage, secret) -> 64hex
    preimage = 18 键（14 设备项 + functionId/body/t）按 key 字母序、只拼 value、'&' 连接（= TreeMap）
    ep/body 的 cipher = ciphertype:5 换表 base64（color_codec 离线可造）
每请求只重算 t/sign；ep 信封 ts 刷新只为过新鲜度校验（ep 不进 sign）。cookie/tgt 整块复用——
设备指纹（devicefinger=eid / jmafinger）是 Cookie 鉴权层，与 sign 正交。

凭据均来自抓包、放 HA 配置项（本模块不内置真实值）:
    ep           ciphertype:5 信封 dict（含 cipher.{aid,eid,area,build,...}）—— 设备档单一真源
    sign_secret  native getSecretKey() 的 32 字符文本
    body_hdid    body 信封 hdid（= base64(sha256(eid))，与 ep.hdid 不同）
    pin / jmafinger / tgt   Cookie 三件套（unionwsws.devicefinger = ep.cipher.eid，自动推）

get_all_devices 响应已含「设备列表 + 房间/类目 + 实时快照(snapshot)」——
parse_device_list() 直接拍平成 {feed_id, device_id, name, room, category, streams, snapshot} 列表。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.parse
from copy import deepcopy

try:
    from . import color_codec as cc           # 包内（HA 运行时）
except ImportError:                            # 直接 `python color_api.py` 跑自检时
    import color_codec as cc                    # 脚本目录已在 sys.path

# ---- 彩虹网关常量（按 App 构建固定，非设备相关）----
COLOR_API = "https://api.m.jd.com/api"
APPID = "jdsmart-android"
CIPHERTYPE = 5
ENVELOPE_VERSION = "1.2.0"
APPNAME = "com.jd.iots"
BODY_RIDX = 1            # body 信封固定 ridx=1（ep 信封是 -1）
UA = "okhttp/4.10.0"

# 18 键里的 15 个「设备/会话固定」键（含 uuid=aid）；其余 3 个 functionId/body/t 每请求变
DEVICE_KEYS = (
    "aid", "appid", "area", "build", "client", "clientVersion", "d_brand",
    "d_model", "eid", "ext", "networkType", "osVersion", "partner", "screen", "uuid",
)


class JdColorError(Exception):
    """彩虹网关调用 / 网络 / HTTP / 业务码错误。"""


# ====================== 纯算工具（离线可测，不依赖 aiohttp）======================
def _compact(obj) -> str:
    """紧凑 JSON（无空格），必须与 App 下发字节一致，否则 sign/cipher 对不上。"""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def _as_body_str(body) -> str:
    return _compact(body) if isinstance(body, (dict, list)) else str(body)


def now_ms() -> int:
    return int(time.time() * 1000)


def profile_from_ep(ep: dict) -> dict:
    """解 ep.cipher（ciphertype:5）得设备档，补 uuid(=aid)/appid。设备档单一真源。"""
    cipher = ep.get("cipher", {})
    prof = {k: (cc.dec_str(v) if isinstance(v, str) else v) for k, v in cipher.items()}
    prof.setdefault("uuid", prof.get("aid"))
    prof.setdefault("appid", APPID)
    return prof


def build_preimage(fields: dict) -> str:
    """preimage = 各 value 按 key 字母序、用 '&' 连接（= App TreeMap）。"""
    return "&".join(str(fields[k]) for k in sorted(fields))


def color_sign(preimage: str, secret: str) -> str:
    """sign = hex(HMAC-SHA256(preimage_utf8, secret_utf8))。secret 当文本字节，非 fromhex。"""
    return hmac.new(secret.encode("utf-8"), preimage.encode("utf-8"), hashlib.sha256).hexdigest()


def parse_device_list(resp: dict, requester_device_id: str | None = None) -> list[dict]:
    """把 getAllDevices 响应拍平成设备列表（供 HA 选设备绑定 / 轮询用）。

    每项:
        feed_id        真正的设备选择子（getDeviceSnapshot body 的 feed_id；getAllDevices 的 feedId）
        device_id      请求方手机 uuid（= ep.cipher.aid，对所有设备恒定；旧 getDeviceSnapshot 的 query device_id）
        hw_device_id   设备硬件短 id（如 EC0BAE3A8374，仅参考）
        name/room/category/sku/product_id
        streams        快照里有哪些流（如 Voltage/Electric/Power/CurrentPowerSum）
        snapshot       getAllDevices 内联的实时值（彩虹轮询可直接读，免再发 getDeviceSnapshot）
    """
    result = (resp or {}).get("result") or {}
    devices: list[dict] = []
    rooms = result.get("roomList") or []
    # 个别响应把设备直接挂在 result.deviceList（无房间），一并兜底
    if not rooms and result.get("deviceList"):
        rooms = [{"roomName": None, "deviceList": result.get("deviceList")}]
    for room in rooms:
        room_name = room.get("roomName")
        for d in room.get("deviceList") or []:
            si = d.get("smartInfo") or {}
            snap = si.get("snapshot") or {}
            feed_id = d.get("feedId") or si.get("feed_id")
            devices.append({
                "feed_id": feed_id,
                "device_id": requester_device_id,
                "hw_device_id": d.get("deviceId") or si.get("device_id"),
                "name": d.get("deviceName") or si.get("card_name") or (str(feed_id) if feed_id else ""),
                "room": room_name,
                "category": d.get("categoryName") or si.get("category_name"),
                "sku": d.get("sku") or si.get("sku_id"),
                "product_id": si.get("product_id"),
                "streams": list(snap.keys()),
                "snapshot": snap,
            })
    return devices


# ====================== 客户端 ======================
class JdColorClient:
    """无状态（除凭据外）。凭据可运行时更新（tgt 会过期、ep 可重抓）。

    aiohttp 仅在真正发包的 call() 里惰性 import，故离线只用 build_request/解析/签名时零三方依赖。
    """

    def __init__(
        self,
        session=None,
        *,
        ep: dict,
        sign_secret: str,
        body_hdid: str,
        pin: str,
        jmafinger: str,
        tgt: str,
    ) -> None:
        self._session = session
        self.ep = ep
        self.sign_secret = sign_secret
        self.body_hdid = body_hdid
        self.pin = pin
        self.jmafinger = jmafinger
        self.tgt = tgt

    # ---- cookie ----
    def _build_cookie(self, profile: dict) -> str:
        """复刻 Cookie：pin / wskey(=tgt) / whwswswws(=jmafinger) / unionwsws。
        devicefinger == 设备 eid（= ep.cipher.eid），从设备档推，不另存。"""
        union = _compact({"devicefinger": profile["eid"], "jmafinger": self.jmafinger})
        return f"pin={self.pin};wskey={self.tgt};whwswswws={self.jmafinger};unionwsws={union};"

    # ---- 装配（纯算，离线可测）----
    def build_request(self, function_id: str, body, t=None, refresh_ep_ts: bool = True) -> dict:
        """装配一条彩虹请求，返回 {url, headers, data, t, sign, preimage, body}。不发包。"""
        body_str = _as_body_str(body)
        t = int(t) if t is not None else now_ms()

        ep = deepcopy(self.ep)
        if refresh_ep_ts:
            ep["ts"] = t                      # ep 不进 sign，刷新 ts 只为过新鲜度校验
        profile = profile_from_ep(ep)

        fields = dict({k: profile[k] for k in DEVICE_KEYS if k in profile},
                      functionId=function_id, body=body_str, t=str(t))
        preimage = build_preimage(fields)
        sign = color_sign(preimage, self.sign_secret)

        query = {
            "functionId": function_id, "appid": APPID, "t": str(t),
            "uuid": profile["uuid"], "sign": sign, "ep": _compact(ep),
            "ef": "1", "bef": "1",
        }
        url = COLOR_API + "?" + urllib.parse.urlencode(query)

        envelope = {
            "hdid": self.body_hdid, "ts": t, "ridx": BODY_RIDX,
            "cipher": {"body": cc.enc_str(body_str)},
            "ciphertype": CIPHERTYPE, "version": ENVELOPE_VERSION, "appname": APPNAME,
        }
        data = "body=" + urllib.parse.quote(_compact(envelope), safe="")

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Cookie": self._build_cookie(profile),
            "User-Agent": UA,
        }
        return {"url": url, "headers": headers, "data": data,
                "t": t, "sign": sign, "preimage": preimage, "body": body_str}

    # ---- 发包（async）----
    async def call(self, function_id: str, body, *, t=None, refresh_ep_ts: bool = True,
                   timeout: int = 20) -> dict:
        import aiohttp

        if self._session is None:
            raise JdColorError("JdColorClient 未注入 aiohttp session")
        req = self.build_request(function_id, body, t=t, refresh_ep_ts=refresh_ep_ts)
        try:
            async with self._session.post(
                req["url"], data=req["data"].encode("utf-8"), headers=req["headers"],
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as resp:
                text = await resp.text()
                if resp.status != 200:
                    raise JdColorError(f"HTTP {resp.status}: {text[:300]}")
        except aiohttp.ClientError as err:
            raise JdColorError(str(err)) from err
        try:
            data = json.loads(text)
        except ValueError as err:
            raise JdColorError(f"响应非 JSON: {text[:200]}") from err
        # 彩虹网关业务码：code=='0' 成功（注意是字符串）
        if isinstance(data, dict) and str(data.get("code")) not in ("0", "1", "None"):
            raise JdColorError(f"业务失败 code={data.get('code')} msg={data.get('errMsg') or data.get('msg')}")
        return data

    async def get_houses(self, page: int = 1, page_size: int = 100, **kw) -> dict:
        return await self.call("jdsmart.house.getHouses", {"pageSize": page_size, "page": page}, **kw)

    async def get_house_details(self, house_id, is_new: int = 0, **kw) -> dict:
        return await self.call("jdsmart.house.getHouseDetails",
                               {"houseId": int(house_id), "isNew": is_new}, **kw)

    async def get_all_devices(self, house_id, **kw) -> dict:
        # 注意：getAllDevices 的 houseId 是字符串（与 getHouseDetails 的数字不同）
        return await self.call("jdsmart.house.getAllDevices", {"houseId": str(house_id)}, **kw)

    # ---- 高层便捷：直接拿拍平后的设备列表 ----
    async def fetch_devices(self, house_id, **kw) -> list[dict]:
        resp = await self.get_all_devices(house_id, **kw)
        return parse_device_list(resp, requester_device_id=profile_from_ep(self.ep).get("uuid"))


# ====================== 离线自检（不联网、不需 aiohttp、不需真实凭据）======================
def selftest() -> bool:
    ok = True

    def check(name, cond):
        nonlocal ok
        ok = ok and bool(cond)
        print(f"  [{'ok' if cond else 'FAIL'}] {name}")

    # 1) codec 字节往返
    sample = bytes(range(256))
    check("color_codec encode/decode 往返", cc.decode(cc.encode(sample)) == sample)

    # 2) HMAC-SHA256 已知向量
    check("HMAC-SHA256 已知向量",
          color_sign("The quick brown fox jumps over the lazy dog", "key")
          == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")

    # 3) 用合成设备档装配请求（非真实值），验签名拼接 + ep/body 往返
    syn_prof = {k: k.upper() for k in DEVICE_KEYS}
    syn_ep = {
        "hdid": "EPHDID", "ts": 1, "ridx": -1,
        "cipher": {k: cc.enc_str(v) for k, v in syn_prof.items() if k != "appid"},
        "ciphertype": CIPHERTYPE, "version": ENVELOPE_VERSION, "appname": APPNAME,
    }
    client = JdColorClient(None, ep=syn_ep, sign_secret="k" * 32, body_hdid="BODYHDID",
                           pin="pin", jmafinger="jma", tgt="TGT")
    req = client.build_request("jdsmart.house.getAllDevices", {"houseId": "1388207"},
                               t=123, refresh_ep_ts=False)
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(req["url"]).query)
    check("query 含 functionId/t/uuid/sign/ep/ef/bef",
          all(k in q for k in ("functionId", "t", "uuid", "sign", "ep", "ef", "bef")))
    check("sign = 64hex", len(req["sign"]) == 64 and int(req["sign"], 16) >= 0)
    check("preimage 18 段字母序", req["preimage"].count("&") == 17
          and req["preimage"].split("&")[0] == "AID")
    env = json.loads(urllib.parse.unquote(req["data"][len("body="):]))
    check("body 信封 cipher.body 解回真实 body",
          cc.dec_str(env["cipher"]["body"]) == '{"houseId":"1388207"}')
    check("cookie 含 pin/wskey/whwswswws/unionwsws",
          all(s in req["headers"]["Cookie"] for s in ("pin=", "wskey=TGT", "whwswswws=jma", "unionwsws=")))

    # 4) 设备列表解析：合成一条 getAllDevices 响应（非真实值，结构同抓包）
    fake_resp = {
        "code": "0",
        "result": {
            "categoryList": [{"categoryName": "插座", "categoryId": 102010, "categoryDeviceCount": 1}],
            "roomList": [
                {"roomName": "客厅", "roomId": 1, "deviceList": [
                    {"categoryName": "插座", "deviceName": "测试插座", "deviceId": "AABBCCDDEEFF",
                     "feedId": 563221780494556020, "sku": "100009400433",
                     "smartInfo": {"feed_id": 563221780494556020, "device_id": "AABBCCDDEEFF",
                                   "category_name": "插座", "product_id": 180600011,
                                   "snapshot": {"Voltage": "235899", "Power": "1", "Electric": "82"}}},
                ]},
                {"roomName": "卧室", "deviceList": []},   # 空房间应被跳过
            ],
        },
    }
    devs = parse_device_list(fake_resp, requester_device_id="PHONEUUID")
    check("解析出 1 个设备（空房间跳过）", len(devs) == 1)
    d0 = devs[0] if devs else {}
    check("feed_id / device_id / name 正确",
          d0.get("feed_id") == 563221780494556020
          and d0.get("device_id") == "PHONEUUID"
          and d0.get("name") == "测试插座")
    check("snapshot 内联可读 + streams 列出",
          d0.get("snapshot", {}).get("Power") == "1"
          and set(d0.get("streams", [])) == {"Voltage", "Power", "Electric"})

    print("\ncolor_api self-test", "PASS" if ok else "FAIL")
    return ok


if __name__ == "__main__":
    import sys

    # 直接跑：`python custom_components/jd_smart/color_api.py`（脚本目录在 sys.path，codec 走 fallback import）
    sys.exit(0 if selftest() else 1)
