"""小京鱼 API 客户端：负责 HmacSHA1 签名并调用 getDeviceSnapshot_v1。

签名算法（已逆向并验证）：
    Authorization: smart <seg1>:::<seg2>:::<ts>
    seg2 = Base64( HmacSHA1( key, device_md + "postjson_body" + body + ts + seg1 + device_md ) )
    device_md = md5("Android"+app_version+hard_platform+plat_version+":"+DAY_OF_YEAR)
    body = {"json":{"feed_id":<int>,"version":"2.0","digest":""}}   # 紧凑、键序固定
签名只覆盖 body（不含 query），所以 device_id 只放 query、feed_id 进 body。
device_md 末尾含"当年第几天"，每天滚动一次，必须实时算（见 _device_md）——
这就是"tgt 没变插件也会失效"的真正原因。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
from datetime import datetime, timedelta, timezone

try:                                                          # 包内（HA 运行时）
    from .const import (
        API_BASE, CONTROL_PATH, GW_API_BASE, GW_DETAILS_PATH,
        GW_DEVICES_PATH, GW_HOUSES_PATH, SNAPSHOT_PATH,
    )
except ImportError:                                            # 直接 `python api.py` 跑自检
    from const import (                                        # 脚本目录已在 sys.path
        API_BASE, CONTROL_PATH, GW_API_BASE, GW_DETAILS_PATH,
        GW_DEVICES_PATH, GW_HOUSES_PATH, SNAPSHOT_PATH,
    )

_LOGGER = logging.getLogger(__name__)

TAG = "postjson_body"  # postJson 请求的标记；其它请求类型可能不同


def parse_snapshot(raw: dict) -> dict:
    """把 getDeviceSnapshot 响应规整成好用的结构。

    原始响应形如 {"status":0,"error":null,"result":"<内层 JSON 字符串>"}，
    内层 result 解析后含 streams:[{stream_id,current_value},...]。
    """
    inner: dict = {}
    res = raw.get("result") if isinstance(raw, dict) else None
    if isinstance(res, str):
        try:
            inner = json.loads(res)
        except ValueError:
            inner = {}
    elif isinstance(res, dict):
        inner = res
    streams: dict = {}
    for item in inner.get("streams", []) or []:
        sid = item.get("stream_id")
        if sid is not None:
            streams[sid] = item.get("current_value")
    return {
        "ok": isinstance(raw, dict) and raw.get("status") == 0 and not raw.get("error"),
        "api_status": raw.get("status") if isinstance(raw, dict) else None,
        "error": raw.get("error") if isinstance(raw, dict) else None,
        "device_status": inner.get("status"),
        "digest": inner.get("digest"),
        "control_ret": inner.get("control_ret"),  # controlDevice 响应：'done' 表示已下发
        "from_device_success": inner.get("fromDeviceSuccess"),
        "streams": streams,
        "raw": raw,
    }


# ====================== gw.smart.jd.com 轻量发现解析 —— 纯函数 ======================
def parse_houses_gw(raw: dict) -> list[dict]:
    """gw getHousesAndRooms → [{house_id, house_name, rooms}]。

    响应 result 是**数组**：每项含 house_id/house_name/rooms[{room_id,room_name}]。
    rooms 拍平成 {room_name: room_id} 备用——设备列表里部分设备只带 room_name 不带 room_id，
    回头用它补 room_id（getDeviceDetails 物模型请求要 roomId）。「默认房间」room_id 可能为 null。
    """
    result = raw.get("result") if isinstance(raw, dict) else None
    if isinstance(result, str):  # 稳妥：个别接口 result 可能是字符串
        try:
            result = json.loads(result)
        except ValueError:
            result = None
    houses: list[dict] = []
    for h in result or []:
        if not isinstance(h, dict):
            continue
        hid = h.get("house_id")
        if hid is None:
            continue
        rooms: dict = {}
        for r in h.get("rooms") or []:
            if isinstance(r, dict) and r.get("room_name"):
                rooms[r["room_name"]] = r.get("room_id")
        houses.append({
            "house_id": str(hid),
            "house_name": h.get("house_name") or str(hid),
            "rooms": rooms,
        })
    return houses


def parse_devices_gw(raw: dict, *, house_id=None, room_map: dict | None = None,
                     requester_device_id: str | None = None) -> list[dict]:
    """gw getDevicesAndCategory → 拍平设备列表（结构与 color_api.parse_device_list 对齐）。

    响应 result 是 **JSON 字符串**（需二次解析），内层 platform_list[].cards[] 是设备卡片。
    卡片的 card_desc/card_control/snapshot 字段形状与彩虹 smartInfo 同源，故直接复用 build_card_meta。
    部分卡片不带 room_id（如「默认房间」），用 house 的 room_map 按 room_name 回填，供 getDeviceDetails。
    """
    try:
        from .color_api import build_card_meta  # 与彩虹同源的卡片复合（纯函数，无 aiohttp）
    except ImportError:
        from color_api import build_card_meta

    res = raw.get("result") if isinstance(raw, dict) else None
    if isinstance(res, str):
        try:
            res = json.loads(res)
        except ValueError:
            res = {}
    if not isinstance(res, dict):
        res = {}
    room_map = room_map or {}
    out: list[dict] = []
    for plat in res.get("platform_list") or []:
        for card in plat.get("cards") or []:
            if not isinstance(card, dict):
                continue
            feed_id = card.get("feed_id")
            if feed_id is None:
                continue
            room_name = card.get("room_name")
            room_id = card.get("room_id")
            if room_id is None and room_name in room_map:
                room_id = room_map.get(room_name)
            snap = card.get("snapshot") or {}
            out.append({
                "feed_id": feed_id,
                "device_id": requester_device_id,
                "hw_device_id": card.get("device_id"),
                "name": card.get("card_name") or card.get("cname")
                        or (str(feed_id) if feed_id is not None else ""),
                "room": room_name,
                "room_id": room_id,
                "house_id": str(house_id) if house_id is not None else None,
                "category": card.get("category_name") or card.get("cname"),
                "sku": card.get("sku"),
                "product_id": card.get("product_id"),
                "streams": list(snap.keys()),
                "snapshot": snap,
                "card_meta": build_card_meta(card),
            })
    return out


# ====================== 设备物模型（getDeviceDetails）解析 —— 纯函数 ======================
def _num(value):
    """能转数字就转（int/float），否则原样返回。"""
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return value
    try:
        f = float(str(value).strip())
        return int(f) if f.is_integer() else f
    except (TypeError, ValueError):
        return value


def parse_value_des(value_des) -> dict | None:
    """getDeviceDetails 的 value_des（'[{"0":"关"},{"1":"开"}]'）拍平成 {"0":"关","1":"开"}。"""
    if not value_des:
        return None
    arr = value_des
    if isinstance(arr, str):
        try:
            arr = json.loads(arr)
        except ValueError:
            return None
    if not isinstance(arr, list):
        return None
    flat: dict = {}
    for item in arr:
        if isinstance(item, dict):
            flat.update({str(k): v for k, v in item.items()})
    return flat or None


def _details_streams(raw) -> list:
    """从 getDeviceDetails 响应里取 streams 列表。

    彩虹 `jdsmart.device.getDeviceDetails` 实测：streams 在 `result.smartDetailInfo.streams`。
    其余位置（result.streams/streamList/data、顶层数组）一并兼容兜底；取不到返回 []（上层回退 card_meta）。
    """
    if isinstance(raw, list):
        return raw
    if not isinstance(raw, dict):
        return []
    res = raw.get("result", raw)
    if isinstance(res, str):
        try:
            res = json.loads(res)
        except ValueError:
            return []
    if isinstance(res, dict):
        sdi = res.get("smartDetailInfo")
        if isinstance(sdi, dict) and isinstance(sdi.get("streams"), list):
            return sdi["streams"]
        streams = res.get("streams") or res.get("streamList") or res.get("data")
        return streams if isinstance(streams, list) else []
    if isinstance(res, list):
        return res
    return []


def parse_stream_model(raw) -> dict:
    """getDeviceDetails → {stream_id: {name,ptype,is_enum,options,min,max,step,unit,current,stream_type}}。

    设备「可控流物模型」的权威来源（比 card_meta 完整）。options 由 value_des 解析。
    **stream_type 是可控性的权威标志**（实证 jd_smart_traffic.db）：0=可控、1=只读传感器
    （如 Voltage/Electric，即便带 min/max 也不可写）；缺省(None)表示该来源未给（card_meta 降级）。
    """
    model: dict = {}
    for s in _details_streams(raw):
        if not isinstance(s, dict):
            continue
        sid = s.get("stream_id")
        if not sid:
            continue
        model[str(sid)] = {
            "name": s.get("stream_name") or str(sid),
            "ptype": s.get("ptype"),
            "is_enum": s.get("is_enum"),
            "options": parse_value_des(s.get("value_des")),
            "min": _num(s.get("min_value")),
            "max": _num(s.get("max_value")),
            "step": _num(s.get("step")),
            "unit": s.get("units") or None,
            "current": s.get("current_value"),
            "stream_type": s.get("stream_type"),  # 0=可控 / 1=只读；None=未知
        }
    return model


def control_kind(m: dict) -> str | None:
    """按物模型把一条流归类成可控实体类型：'switch'|'select'|'number'；None=只读，不建可控实体。

    可控性以 **stream_type** 为准（getDeviceDetails 实证）：
    - stream_type==1 → 只读传感器，恒 None（即便有 min/max，如 Voltage/Electric，不误判成可写 number）；
    - stream_type==0 → 可控，再按形状细分控件类型；形状不足时 number 兜底（自由写入）；
    - stream_type 缺省(None，card_meta 降级或老响应) → 退回按形状判定（options/min-max），保持原行为。

    控件细分：{0,1} 两档枚举→switch；其它多档枚举→select（码值可非连续，如 Mode 0/4）；
    非枚举数值（is_enum=-1 或 ptype 数值）带 min/max→number。
    """
    st = m.get("stream_type")
    if st == 1:
        return None  # 只读传感器：绝不建可控实体
    opts = m.get("options")
    if opts:
        if len(opts) == 2 and set(opts) <= {"0", "1"}:
            return "switch"
        return "select"
    if m.get("min") is not None and m.get("max") is not None:
        if m.get("is_enum") == -1 or m.get("ptype") in ("int", "float", "double", "number"):
            return "number"
    if st == 0:
        return "number"  # 明确可控但缺枚举/范围信息 → 数值自由写入兜底
    return None


def model_from_card_meta(dev: dict) -> dict:
    """getDeviceDetails 拿不到时的降级物模型：用发现阶段的 card_meta（仅可控流）。

    card_meta 缺 min/max/step，故只能派生 switch/select（数值流没范围，不建 number）。
    """
    model: dict = {}
    for sid, cm in (dev.get("card_meta") or {}).items():
        if not cm.get("controllable"):
            continue
        model[str(sid)] = {
            "name": cm.get("name") or str(sid),
            "ptype": None,
            "is_enum": None,
            "options": cm.get("options") or None,
            "min": None,
            "max": None,
            "step": None,
            "unit": cm.get("unit") or None,
            "current": None,
            "stream_type": 0,  # card_meta 只收 controllable 流，故均可控
        }
    return model


class JdSmartError(Exception):
    """任何调用/网络/HTTP 错误。"""


class JdSmartClient:
    """无状态客户端（除凭据外）。所有凭据都可在运行时更新（tgt/key 会过期或轮换）。"""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        *,
        seg1: str,
        key: str,
        tgt: str,
        hard_platform: str,
        app_version: str,
        plat_version: str,
        channel: str,
        plat: str,
    ) -> None:
        self._session = session
        self.seg1 = seg1
        self.key = key
        self.tgt = tgt
        self.hard_platform = hard_platform
        self.app_version = app_version
        self.plat_version = plat_version
        self.channel = channel
        self.plat = plat

    @staticmethod
    def now_ts() -> str:
        """形如 2026-06-14T20:59:57.403Z（毫秒）。

        实测京东这套发的是“北京时间(UTC+8)墙上时钟 + Z 后缀”（Z 名不副实，服务端也按此校验；
        发真 UTC 会比服务器慢 8 小时，被判 token invalid）。固定 +8 偏移免依赖系统 tzdata，
        与 _device_md() 取“当年第几天”的处理对齐。
        """
        n = datetime.now(timezone(timedelta(hours=8)))
        return n.strftime("%Y-%m-%dT%H:%M:%S.") + f"{n.microsecond // 1000:03d}Z"

    @staticmethod
    def build_body(feed_id) -> str:
        return json.dumps(
            {"json": {"feed_id": int(feed_id), "version": "2.0", "digest": ""}},
            separators=(",", ":"),
            ensure_ascii=False,
        )

    @staticmethod
    def _coerce_value(v):
        """current_value 归一：bool/数字按数字；纯数字字符串转数字；其余原样（匹配 App 裸数字形态）。"""
        if isinstance(v, bool):
            return int(v)
        if isinstance(v, (int, float)):
            return v
        s = str(v).strip()
        try:
            f = float(s)
            return int(f) if f.is_integer() else f
        except ValueError:
            return s

    @classmethod
    def build_control_body(cls, feed_id, commands) -> str:
        """controlDevice_v1 的 body：外层 {"json":"<内层字符串>"}，内层键序固定 feed_id→command→version。

        commands: [{"stream_id": str, "current_value": int|str}, ...]
        内层 JSON 再字符串化一次是 App 的真实形态（与快照的 json=对象不同）；签名按整串字节算，
        改成对象就会签名作废。feed_id 用 int 保大整数精度（JS 会丢，Python 任意精度）。
        """
        cmd = [
            {"stream_id": str(c["stream_id"]),
             "current_value": cls._coerce_value(c["current_value"])}
            for c in commands
        ]
        inner = json.dumps(
            {"feed_id": int(feed_id), "command": cmd, "version": "2.0"},
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return json.dumps({"json": inner}, separators=(",", ":"), ensure_ascii=False)

    def _device_md(self) -> str:
        """设备指纹，每天滚动一次（"tgt 没变插件也失效"的真凶）。

        逆向自 RestClient.getAuthorization：
            c10 = md5("Android" + app_version + deviceModel + Build.VERSION.RELEASE
                      + ":" + Calendar.get(DAY_OF_YEAR))
        末尾 DAY_OF_YEAR(当年第几天)每天 +1，所以 device_md 每天都变——必须实时算，
        不能写死。其余三段(app_version/hard_platform/plat_version)和 query 参数同源。
        用 Asia/Shanghai 取"今天第几天"，对齐 App(设备本地时区)与京东服务端。
        """
        # UTC+8(中国标准时，无夏令时，等价 Asia/Shanghai)；固定偏移免依赖系统 IANA 时区库
        doy = datetime.now(timezone(timedelta(hours=8))).timetuple().tm_yday
        raw = f"Android{self.app_version}{self.hard_platform}{self.plat_version}:{doy}"
        return hashlib.md5(raw.encode()).hexdigest()

    def _sign(self, body: str, ts: str) -> str:
        device_md = self._device_md()
        msg = device_md + TAG + body + ts + self.seg1 + device_md
        mac = hmac.new(self.key.encode(), msg.encode(), hashlib.sha1).digest()
        return base64.b64encode(mac).decode()

    def authorization(self, body: str, ts: str) -> str:
        return f"smart {self.seg1}:::{self._sign(body, ts)}:::{ts}"

    def _common_params(self, device_id: str) -> dict:
        return {
            "hard_platform": self.hard_platform,
            "app_version": self.app_version,
            "device_id": device_id,
            "plat_version": self.plat_version,
            "channel": self.channel,
            "plat": self.plat,
        }

    def _headers(self, body: str, ts: str) -> dict:
        return {
            "app_identity": "WL",
            "authorization": self.authorization(body, ts),
            "tgt": self.tgt,
            "content-type": "application/json; charset=utf-8",
            "user-agent": "okhttp/4.10.0",
        }

    async def _post(self, path: str, device_id: str, body: str, *, base: str | None = None) -> dict:
        """统一发包：同一套签名，发送被签名的原始字节（不能让框架重新序列化）。

        getDeviceSnapshot / controlDevice（api.smart）与 getHousesAndRooms /
        getDevicesAndCategory（gw.smart）共用——同一套 postjson_body 签名，只差 base/path 与 body。
        base 缺省 api.smart；gw 接口传 GW_API_BASE。
        """
        import aiohttp  # 惰性导入：离线只用签名/解析/自检时零三方依赖

        ts = self.now_ts()
        url = (base or API_BASE) + path
        try:
            async with self._session.post(
                url,
                params=self._common_params(device_id),
                data=body.encode(),
                headers=self._headers(body, ts),
                timeout=aiohttp.ClientTimeout(total=20),
            ) as resp:
                text = await resp.text()
                if resp.status != 200:
                    raise JdSmartError(f"HTTP {resp.status}: {text[:300]}")
        except aiohttp.ClientError as err:
            raise JdSmartError(str(err)) from err
        try:
            return json.loads(text)
        except ValueError:
            return {"raw": text}

    async def get_device_snapshot(self, device_id: str, feed_id) -> dict:
        # 走 **gw 统一网关**（与发现/物模型同一个 tgt）。实测：api.smart.jd.com 那套 integration/v1
        # 用小京鱼 tgt 恒 -4「登录已过期」（它要另一 App 的登录态/pin）；gw.smart.jd.com 转发**同一**
        # integration/v1 接口，当前 tgt 即 status=0。故 snapshot/control 一并改走 GW_API_BASE。
        return await self._post(SNAPSHOT_PATH, device_id, self.build_body(feed_id), base=GW_API_BASE)

    # ---- gw.smart.jd.com 轻量发现（不走彩虹；同一套签名，仅换 base/path/body）----
    async def get_houses_and_rooms(self, device_id: str, body: dict | None = None) -> dict:
        """家庭+房间。body 缺省 {}（列该账号全部家庭）。解析见 parse_houses_gw。"""
        payload = json.dumps(body or {}, separators=(",", ":"), ensure_ascii=False)
        return await self._post(GW_HOUSES_PATH, device_id, payload, base=GW_API_BASE)

    async def get_devices_and_category(self, device_id: str, house_id) -> dict:
        """某家庭的设备+类目。body {"houseId":"<str>"}。解析见 parse_devices_gw。"""
        payload = json.dumps({"houseId": str(house_id)}, separators=(",", ":"), ensure_ascii=False)
        return await self._post(GW_DEVICES_PATH, device_id, payload, base=GW_API_BASE)

    @staticmethod
    def build_device_details_body(feed_id, house_id) -> str:
        """gw getDeviceDetails 的 body（复刻 App）。

        外层 `device_id` = feed_id 的**字符串**（精确，真正的设备选择子）；`json_data.feed_id` 是
        数字——App 用 JS 发会丢精度（…755→…800），这里发**精确 int**（Python 任意精度），服务端按
        外层精确字符串选设备，更稳。只需 feed_id + houseId，**不需要 roomId**（默认房间设备也能拿全模型）。
        """
        return json.dumps(
            {"device_id": str(feed_id), "is_weilian": 1, "skill_id": "",
             "json_data": {"version": "2.0", "feed_id": int(feed_id), "houseId": str(house_id)}},
            separators=(",", ":"), ensure_ascii=False,
        )

    async def get_device_details(self, device_id: str, feed_id, house_id) -> dict:
        """设备完整物模型（**gw，不走彩虹**）。响应 result 为 JSON 字符串，streams 在
        `result.streams`（含 is_enum/value_des/min/max/step/stream_type）→ parse_stream_model 直接解析。
        device_id=请求方（query，UUID 即可）；feed_id/house_id 进 body。"""
        return await self._post(
            GW_DETAILS_PATH, device_id, self.build_device_details_body(feed_id, house_id),
            base=GW_API_BASE,
        )

    # 注：设备物模型(getDeviceDetails)是**彩虹网关** functionId jdsmart.device.getDeviceDetails，
    # 不在本(smart api)客户端，见 color_api.JdColorClient.get_device_details。

    async def control_device(self, device_id: str, feed_id, commands) -> dict:
        """下发控制。commands=[{stream_id,current_value},...]。

        走 **gw 统一网关**（base=GW_API_BASE，与 snapshot 同因：api.smart 域 -4，gw 转发同接口 status=0）。
        响应结构与快照一致（{status,error,result:"<内层>"}，内层含 control_ret + 全量最新 streams），
        故可直接 parse_snapshot 解析并乐观刷新。
        """
        return await self._post(CONTROL_PATH, device_id, self.build_control_body(feed_id, commands),
                                base=GW_API_BASE)


# ====================== 离线自检（不联网、不需 aiohttp、不需真实凭据）======================
def selftest() -> bool:
    ok = True

    def check(name, cond):
        nonlocal ok
        ok = ok and bool(cond)
        print(f"  [{'ok' if cond else 'FAIL'}] {name}")

    # 1) 控制 body 与抓包逐字节一致（最关键：签名按整串字节算，差一个字节签名就废）
    captured = ('{"json":"{\\"feed_id\\":576841753861489755,'
                '\\"command\\":[{\\"stream_id\\":\\"Vertical\\",\\"current_value\\":1}],'
                '\\"version\\":\\"2.0\\"}"}')
    built = JdSmartClient.build_control_body(
        576841753861489755, [{"stream_id": "Vertical", "current_value": 1}]
    )
    check("build_control_body 与抓包逐字节一致", built == captured)
    # 大整数不能退化成 5.768e17 / 丢末位（Python int 任意精度；这里确认数字串原样保留）
    check("feed_id 大整数不丢精度", "576841753861489755" in built and "e+" not in built.lower())
    check("current_value 字符串自动转裸数字",
          JdSmartClient.build_control_body(1, [{"stream_id": "Wind", "current_value": "10"}])
          == '{"json":"{\\"feed_id\\":1,\\"command\\":[{\\"stream_id\\":\\"Wind\\",\\"current_value\\":10}],\\"version\\":\\"2.0\\"}"}')

    # 2) 控制响应可被 parse_snapshot 复用解析（含 control_ret + 全量 streams）
    resp = {"status": 0, "error": None,
            "result": ('{"control_ret":"done","digest":"-1686130459","streams":['
                       '{"current_value":"1","stream_id":"Power"},'
                       '{"current_value":"1","stream_id":"Vertical"}]}')}
    parsed = parse_snapshot(resp)
    check("控制响应 ok + control_ret + streams 解析",
          parsed["ok"] and parsed["control_ret"] == "done"
          and parsed["streams"].get("Vertical") == "1")

    # 3) 物模型解析 + 归类（用户提供的 getDeviceDetails streams 子集）
    streams = [
        {"stream_id": "Horizontal", "stream_name": "左右摆头", "is_enum": 1,
         "value_des": '[{"0":"关"},{"1":"开"}]', "ptype": "int", "min_value": 0, "max_value": 1},
        {"stream_id": "Mode", "stream_name": "模式", "is_enum": 1,
         "value_des": '[{"0":"标准模式"},{"4":"婴儿风"}]', "ptype": "int"},
        {"stream_id": "Wind", "stream_name": "风速", "is_enum": 1,
         "value_des": '[{"0":"1档"},{"1":"2档"},{"2":"3档"}]', "ptype": "int"},
        {"stream_id": "TimingSetHour", "stream_name": "定时设置时", "is_enum": -1,
         "value_des": "", "ptype": "int", "min_value": 0, "max_value": 24, "step": "1"},
    ]
    # 实测响应里 streams 在 result.smartDetailInfo.streams（彩虹 jdsmart.device.getDeviceDetails）
    model = parse_stream_model({"code": "0", "result": {"smartDetailInfo": {"streams": streams}}})
    check("从 result.smartDetailInfo.streams 取流", set(model) >= {"Horizontal", "Mode", "Wind", "TimingSetHour"})
    check("value_des 解析枚举", model["Horizontal"]["options"] == {"0": "关", "1": "开"})
    check("Horizontal(0/1 两档) → switch", control_kind(model["Horizontal"]) == "switch")
    check("Mode(0/4 两档非 0/1) → select", control_kind(model["Mode"]) == "select")
    check("Wind(多档) → select", control_kind(model["Wind"]) == "select")
    check("TimingSetHour(数值带范围) → number", control_kind(model["TimingSetHour"]) == "number")
    check("number 范围/步长解析", model["TimingSetHour"]["max"] == 24
          and model["TimingSetHour"]["step"] == 1)
    check("名称取 stream_name", model["Mode"]["name"] == "模式")

    # 3b) stream_type 权威可控标志（真实插座 getDeviceDetails，实证自 jd_smart_traffic.db）
    socket = [
        {"stream_id": "Power", "is_enum": 1, "value_des": '[{"0":"关"},{"1":"开"}]',
         "min_value": 0, "max_value": 1, "ptype": "int", "stream_type": 0},
        {"stream_id": "Voltage", "is_enum": -1, "value_des": "", "min_value": 0,
         "max_value": 240, "ptype": "float", "units": "伏", "stream_type": 1},
        {"stream_id": "Electric", "is_enum": -1, "value_des": "", "min_value": 0,
         "max_value": 20, "ptype": "float", "units": "安", "stream_type": 1},
        {"stream_id": "CurrentPowerSum", "is_enum": -1, "value_des": "", "min_value": 0,
         "max_value": 65535, "ptype": "int", "stream_type": 1},
    ]
    sm = parse_stream_model({"result": {"smartDetailInfo": {"streams": socket}}})
    check("stream_type 已解析", sm["Power"]["stream_type"] == 0 and sm["Voltage"]["stream_type"] == 1)
    check("Power(type0,枚举) → switch", control_kind(sm["Power"]) == "switch")
    check("Voltage(type1,有 min/max) → None（只读，不误判 number）", control_kind(sm["Voltage"]) is None)
    check("Electric(type1) → None", control_kind(sm["Electric"]) is None)
    check("CurrentPowerSum(type1) → None", control_kind(sm["CurrentPowerSum"]) is None)
    check("type0 但无枚举/范围 → number 兜底",
          control_kind({"stream_type": 0, "options": None, "min": None, "max": None}) == "number")
    check("type0 多档枚举（value_des 空，options 由 card_desc 补）→ select",
          control_kind({"stream_type": 0, "options": {"0": "标准模式", "4": "婴儿风"}}) == "select")

    # 4) card_meta 降级物模型（缺 min/max → 只出 switch/select）
    dev = {"card_meta": {
        "Power": {"name": "开关", "controllable": True, "options": {"0": "关", "1": "开"}},
        "Voltage": {"name": "电压", "controllable": False},  # 不可控，应排除
    }}
    cm_model = model_from_card_meta(dev)
    check("card_meta 降级仅含可控流",
          set(cm_model) == {"Power"} and control_kind(cm_model["Power"]) == "switch")

    # 5) gw 轻量发现解析（结构取自真实抓包：result 数组 / result 字符串、card 同 smartInfo）
    houses = parse_houses_gw({"status": 0, "error": None, "result": [
        {"house_id": 1388207, "house_name": "我的家", "rooms": [
            {"room_id": 3875794, "room_name": "客厅"},
            {"room_id": None, "room_name": "默认房间"}]}]})
    check("gw 家庭解析 house_id/house_name",
          len(houses) == 1 and houses[0]["house_id"] == "1388207"
          and houses[0]["house_name"] == "我的家")
    check("gw 房间拍平 room_name->room_id（默认房间 None）",
          houses[0]["rooms"] == {"客厅": 3875794, "默认房间": None})

    devices_inner = (
        '{"platform_list":[{"cards":['
        '{"category_name":"电风扇","device_id":"34EAE780ABA0","feed_id":576841753861489755,'
        '"room_name":"默认房间","product_id":177800004,"card_name":"卧室电风扇",'
        '"card_desc":[{"stream_id":"Mode","options":[{"0":"普通模式"},{"1":"智能模式"}],"stream_text":"当前模式"}],'
        '"snapshot":{"Wind":"7","Mode":"0","Power":"0"},'
        '"card_control":[{"stream_id":"Power","options":[{"0":"关"},{"1":"开"}]}]},'
        '{"room_id":3875794,"category_name":"插座","device_id":"EC0BAE3A8374",'
        '"feed_id":563221780494556020,"room_name":"客厅","card_name":"北卧空调","card_desc":[],'
        '"snapshot":{"Voltage":"231536","Power":"1"},'
        '"card_control":[{"stream_id":"Power","options":[{"0":"关"},{"1":"开"}]}]}]}]}')
    devs = parse_devices_gw({"status": 0, "error": None, "result": devices_inner},
                            house_id="1388207", room_map=houses[0]["rooms"],
                            requester_device_id="PHONEDID")
    check("gw 设备解析出 2 台（result 字符串二次解析）", len(devs) == 2)
    fan = next((d for d in devs if str(d["feed_id"]) == "576841753861489755"), {})
    check("gw 风扇 feed_id 大整数不丢精度 + name/hw_device_id/house_id",
          fan.get("feed_id") == 576841753861489755 and fan.get("name") == "卧室电风扇"
          and fan.get("hw_device_id") == "34EAE780ABA0" and fan.get("house_id") == "1388207"
          and fan.get("device_id") == "PHONEDID")
    check("gw 风扇 room_id 由 room_map 回填（默认房间→None）",
          fan.get("room") == "默认房间" and fan.get("room_id") is None)
    check("gw 风扇 streams 来自 snapshot", set(fan.get("streams", [])) == {"Wind", "Mode", "Power"})
    check("gw 风扇 card_meta：Power 可控 + Mode 枚举名",
          fan.get("card_meta", {}).get("Power", {}).get("controllable") is True
          and fan.get("card_meta", {}).get("Mode", {}).get("options", {}).get("0") == "普通模式")
    socket = next((d for d in devs if str(d["feed_id"]) == "563221780494556020"), {})
    check("gw 插座 room_id 直接带出（不靠回填）",
          socket.get("room_id") == 3875794 and socket.get("room") == "客厅")

    # 6) gw getDeviceDetails（完整物模型，不走彩虹）：body 复刻 + result.streams 解析
    body = JdSmartClient.build_device_details_body(576841753861489755, "1388207")
    check("gw details body：外层 device_id=精确字符串 feed_id + json_data.feed_id=精确裸数字",
          '"device_id":"576841753861489755"' in body
          and '"feed_id":576841753861489755' in body and "e+" not in body.lower())
    check("gw details body：带 houseId、不带 roomId",
          '"houseId":"1388207"' in body and "roomId" not in body
          and '"version":"2.0"' in body and '"is_weilian":1' in body)
    # parse_stream_model 直接吃 gw 响应（streams 在 result.streams，非 smartDetailInfo）
    gw_detail = {"status": 0, "result": '{"streams":[' + ','.join([
        '{"stream_id":"Power","stream_name":"开关","is_enum":1,"min_value":0,"max_value":1,'
        '"ptype":"int","stream_type":0,"value_des":"[{\\"0\\":\\"关\\"},{\\"1\\":\\"开\\"}]"}',
        '{"stream_id":"Wind","stream_name":"风速","is_enum":1,"min_value":0,"max_value":33,'
        '"ptype":"int","stream_type":0,"value_des":"[{\\"0\\":\\"1档\\"},{\\"7\\":\\"6档\\"}]"}',
        '{"stream_id":"TimingSetHour","stream_name":"定时设置时","is_enum":-1,"min_value":0,'
        '"max_value":24,"step":"1","ptype":"int","stream_type":0,"value_des":""}',
    ]) + ']}'}
    gm = parse_stream_model(gw_detail)
    check("gw getDeviceDetails → result.streams 解析出全模型",
          set(gm) == {"Power", "Wind", "TimingSetHour"})
    check("gw 风扇 Power→switch / Wind→select / TimingSetHour→number",
          control_kind(gm["Power"]) == "switch" and control_kind(gm["Wind"]) == "select"
          and control_kind(gm["TimingSetHour"]) == "number" and gm["TimingSetHour"]["max"] == 24)

    print("\napi self-test", "PASS" if ok else "FAIL")
    return ok


if __name__ == "__main__":
    import sys

    sys.exit(0 if selftest() else 1)
