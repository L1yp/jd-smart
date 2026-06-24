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

import base64
import hashlib
import hmac
import json
import time
import urllib.parse

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
    """解 ep.cipher（ciphertype:5）得明文设备档，补 uuid(=aid)/appid。"""
    cipher = ep.get("cipher", {})
    prof = {k: (cc.dec_str(v) if isinstance(v, str) else v) for k, v in cipher.items()}
    prof.setdefault("uuid", prof.get("aid"))
    prof.setdefault("appid", APPID)
    return prof


def ep_from_profile(profile: dict, hdid: str, ts: int = 0, ridx: int = -1) -> dict:
    """明文设备档 -> ciphertype:5 ep 信封（profile_from_ep 的逆）。

    cipher 各字段 enc_str 换表编码；uuid/appid 是派生项不进 cipher。
    因 color_codec 往返自洽，由明文重建出的 ep 与抓包线格式逐字节一致（ep 本就不进 sign）。
    """
    cipher = {k: cc.enc_str(str(v)) for k, v in profile.items() if k not in ("uuid", "appid")}
    return {"hdid": hdid, "ts": ts, "ridx": ridx, "cipher": cipher,
            "ciphertype": CIPHERTYPE, "version": ENVELOPE_VERSION, "appname": APPNAME}


def hdid_from_eid(eid: str) -> str:
    """body 信封 hdid = base64(sha256(eid))（标准表、无换行）。见 memory jd-hdid-eid-derivation。"""
    return base64.b64encode(hashlib.sha256(eid.encode("utf-8")).digest()).decode("ascii")


def aid_from_android_id(android_id: str) -> str:
    """aid = uuid = md5HexLower(AndroidId)。
    来源：da.m2.b() 取 com.jingdong.sdk.baseinfo.BaseInfo.getAndroidId()（=Settings.Secure.ANDROID_ID）
    再 MD5 小写十六进制；da.m2.h() 存进 SP(jdiots/uuid)。AndroidId 取不到时 App 返回空字符串。"""
    return hashlib.md5(android_id.encode("utf-8")).hexdigest()


def build_preimage(fields: dict) -> str:
    """preimage = 各 value 按 key 字母序、用 '&' 连接（= App TreeMap）。"""
    return "&".join(str(fields[k]) for k in sorted(fields))


def color_sign(preimage: str, secret: str) -> str:
    """sign = hex(HMAC-SHA256(preimage_utf8, secret_utf8))。secret 当文本字节，非 fromhex。"""
    return hmac.new(secret.encode("utf-8"), preimage.encode("utf-8"), hashlib.sha256).hexdigest()


def _flatten_options(options) -> dict | None:
    """card_desc/card_control 的 options（[{"0":"关"},{"1":"开"}]）拍平成 {"0":"关","1":"开"}。"""
    if not isinstance(options, list):
        return None
    flat: dict = {}
    for item in options:
        if isinstance(item, dict):
            flat.update({str(k): v for k, v in item.items()})
    return flat or None


def build_card_meta(smart_info: dict) -> dict:
    """复合 smartInfo.card_desc + card_control -> {stream_id: {name, unit, options, controllable}}。

    card_desc 给展示名(stream_text)/单位(unit)/枚举(options)；card_control 标记可控 + on/off 枚举。
    这是需求里的"复合"步：名称可直接套用，单位可能不准（用户可在选项里改）。
    """
    meta: dict[str, dict] = {}

    def _slot(sid):
        return meta.setdefault(
            str(sid), {"name": None, "unit": None, "options": None, "controllable": False}
        )

    for item in smart_info.get("card_desc") or []:
        sid = item.get("stream_id")
        if sid is None:
            continue
        slot = _slot(sid)
        if item.get("stream_text"):
            slot["name"] = item["stream_text"]
        if item.get("unit"):
            slot["unit"] = item["unit"]
        opts = _flatten_options(item.get("options"))
        if opts:
            slot["options"] = opts
    for item in smart_info.get("card_control") or []:
        sid = item.get("stream_id")
        if sid is None:
            continue
        slot = _slot(sid)
        slot["controllable"] = True
        opts = _flatten_options(item.get("options"))
        if opts and not slot["options"]:
            slot["options"] = opts
    return meta


def parse_device_list(resp: dict, requester_device_id: str | None = None) -> list[dict]:
    """把 getAllDevices 响应拍平成设备列表（供 HA 选设备绑定 / 轮询用）。

    每项:
        feed_id        真正的设备选择子（getDeviceSnapshot body 的 feed_id；getAllDevices 的 feedId）
        device_id      请求方手机 uuid（= ep.cipher.aid，对所有设备恒定；旧 getDeviceSnapshot 的 query device_id）
        hw_device_id   设备硬件短 id（如 EC0BAE3A8374，仅参考）
        name/room/category/sku/product_id
        streams        快照里有哪些流（如 Voltage/Electric/Power/CurrentPowerSum）
        snapshot       getAllDevices 内联的实时值（彩虹轮询可直接读，免再发 getDeviceSnapshot）
        card_meta      复合 card_desc+card_control 出的 {stream_id:{name,unit,options,controllable}}
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
                "card_meta": build_card_meta(si),
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
        profile: dict | None = None,
        android_id: str | None = None,
        ep_hdid: str = "",
        ep: dict | None = None,
        sign_secret: str,
        body_hdid: str | None = None,
        pin: str,
        jmafinger: str,
        tgt: str,
        ep_ts: int = 0,
        ep_ridx: int = -1,
    ) -> None:
        """设备档两种给法（二选一）:
            profile  明文设备档 dict（推荐，可读易改）+ ep_hdid（ep 信封 hdid token）
            ep       抓包的密文 ciphertype:5 信封 dict（旧格式，自动解出 profile）
        android_id 给了则自动算 aid=uuid=md5(AndroidId)，覆盖 profile 里的 aid/uuid（可不在 profile 里写）。
        body_hdid 不给则按 base64(sha256(eid)) 自动派生。
        """
        self._session = session
        if profile is not None:
            prof = dict(profile)
        elif ep is not None:
            prof = profile_from_ep(ep)
            ep_hdid = ep.get("hdid", ep_hdid)
            ep_ts = ep.get("ts", ep_ts)
            ep_ridx = ep.get("ridx", ep_ridx)
        else:
            raise ValueError("JdColorClient 需要 profile(明文设备档) 或 ep(密文信封)")
        if android_id:
            prof["aid"] = prof["uuid"] = aid_from_android_id(android_id)
        prof.setdefault("uuid", prof.get("aid"))
        prof.setdefault("appid", APPID)
        self.profile = prof
        self.ep_hdid = ep_hdid
        self.ep_ts = ep_ts
        self.ep_ridx = ep_ridx
        self.sign_secret = sign_secret
        self.body_hdid = body_hdid or hdid_from_eid(prof["eid"])
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

        profile = self.profile
        # ep 不进 sign：刷新 ts 只为过新鲜度校验；由明文设备档现造，与抓包线格式一致
        ts = t if refresh_ep_ts else self.ep_ts
        ep = ep_from_profile(profile, self.ep_hdid, ts=ts, ridx=self.ep_ridx)

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
        return parse_device_list(resp, requester_device_id=self.profile.get("uuid"))


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
    syn_prof["uuid"] = syn_prof["aid"]      # 真实里 uuid == aid（设备 uuid）
    syn_prof["appid"] = APPID
    syn_ep = ep_from_profile(syn_prof, "EPHDID", ts=1)   # 等价密文信封（cipher 排除 uuid/appid）
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
    # query 里的 ep 能 decode 回设备档（明文档现造 -> 解出 == 原档）
    q_ep = json.loads(q["ep"][0])
    check("query.ep 解回设备档", profile_from_ep(q_ep).get("eid") == syn_prof["eid"])

    # 3b) 明文 profile 路径 == 密文 ep 路径（同一设备档：sign/url/data 逐字节一致）
    client_prof = JdColorClient(None, profile=syn_prof, ep_hdid="EPHDID", ep_ts=1,
                                sign_secret="k" * 32, body_hdid="BODYHDID",
                                pin="pin", jmafinger="jma", tgt="TGT")
    r_prof = client_prof.build_request("jdsmart.house.getAllDevices", {"houseId": "1388207"},
                                       t=123, refresh_ep_ts=False)
    r_ep = client.build_request("jdsmart.house.getAllDevices", {"houseId": "1388207"},
                                t=123, refresh_ep_ts=False)
    check("明文 profile 路径 == 密文 ep 路径（sign/url/data 一致）",
          r_prof["sign"] == r_ep["sign"] and r_prof["url"] == r_ep["url"]
          and r_prof["data"] == r_ep["data"])
    check("body_hdid 缺省自动派生 = base64(sha256(eid))",
          JdColorClient(None, profile=syn_prof, ep_hdid="X", sign_secret="k" * 32,
                        pin="p", jmafinger="j", tgt="t").body_hdid == hdid_from_eid(syn_prof["eid"]))

    # 3c) android_id -> aid=uuid=md5(AndroidId)，覆盖 profile（profile 里可不写 aid/uuid）
    import hashlib as _hl
    aid_expect = _hl.md5("9774d56d682e549c".encode()).hexdigest()
    prof_no_aid = {k: k.upper() for k in DEVICE_KEYS if k not in ("aid", "uuid")}
    c_aid = JdColorClient(None, profile=prof_no_aid, android_id="9774d56d682e549c", ep_hdid="X",
                          sign_secret="k" * 32, pin="p", jmafinger="j", tgt="t")
    check("android_id -> aid=uuid=md5(AndroidId)（profile 可省 aid/uuid）",
          aid_from_android_id("9774d56d682e549c") == aid_expect
          and c_aid.profile["aid"] == aid_expect and c_aid.profile["uuid"] == aid_expect)

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
                                   "snapshot": {"Voltage": "235899", "Power": "1", "Electric": "82"},
                                   "card_desc": [
                                       {"stream_id": "TemperatureSet", "unit": "℃", "stream_text": "温度设置"},
                                       {"stream_id": "Mode", "stream_text": "当前模式",
                                        "options": [{"0": "自动"}, {"1": "制冷"}]}],
                                   "card_control": [
                                       {"stream_id": "Power", "options": [{"0": "关"}, {"1": "开"}]}]}},
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
    cm = d0.get("card_meta", {})
    check("card_meta 复合：名称/单位/枚举/可控",
          cm.get("TemperatureSet", {}).get("unit") == "℃"
          and cm.get("TemperatureSet", {}).get("name") == "温度设置"
          and cm.get("Mode", {}).get("options") == {"0": "自动", "1": "制冷"}
          and cm.get("Power", {}).get("controllable") is True
          and cm.get("Power", {}).get("options") == {"0": "关", "1": "开"})

    print("\ncolor_api self-test", "PASS" if ok else "FAIL")
    return ok


if __name__ == "__main__":
    import sys

    # 直接跑：`python custom_components/jd_smart/color_api.py`（脚本目录在 sys.path，codec 走 fallback import）
    sys.exit(0 if selftest() else 1)
