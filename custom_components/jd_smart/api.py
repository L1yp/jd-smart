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

try:
    from .const import API_BASE, CONTROL_PATH, DETAILS_PATH, SNAPSHOT_PATH  # 包内（HA 运行时）
except ImportError:                                                          # 直接 `python api.py` 跑自检
    from const import API_BASE, CONTROL_PATH, DETAILS_PATH, SNAPSHOT_PATH    # 脚本目录已在 sys.path

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

    响应外壳结构待与抓包对齐：兼容 result 为 JSON 字符串/对象、streams 在 result.streams/streamList/data
    或直接是顶层数组。取不到就返回 []（让上层回退 card_meta）。
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
        streams = res.get("streams") or res.get("streamList") or res.get("data")
        return streams if isinstance(streams, list) else []
    if isinstance(res, list):
        return res
    return []


def parse_stream_model(raw) -> dict:
    """getDeviceDetails → {stream_id: {name,ptype,is_enum,options,min,max,step,unit,current}}。

    设备「可控流物模型」的权威来源（比 card_meta 完整）。options 由 value_des 解析。
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
        }
    return model


def control_kind(m: dict) -> str | None:
    """按物模型把一条流归类成可控实体类型：'switch'|'select'|'number'；None=不作可控实体。

    - 枚举且恰好 {0,1} 两档 → switch（on/off）
    - 其它多档枚举 → select（按 value_des 标签；码值可非连续，如 Mode 0/4）
    - 非枚举数值（is_enum=-1 或 ptype int/float）且有 min/max → number
    """
    opts = m.get("options")
    if opts:
        if len(opts) == 2 and set(opts) <= {"0", "1"}:
            return "switch"
        return "select"
    if m.get("min") is not None and m.get("max") is not None:
        if m.get("is_enum") == -1 or m.get("ptype") in ("int", "float", "double", "number"):
            return "number"
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
    def build_details_body(feed_id) -> str:
        """getDeviceDetails_v1 的 body。

        【待对齐抓包】按 getDeviceSnapshot 同构推测（json 为对象、去掉 digest）；
        若你的 getDeviceDetails 抓包不同，把这里改成抓包里的真实 body 即可（签名逻辑不变）。
        """
        return json.dumps(
            {"json": {"feed_id": int(feed_id), "version": "2.0"}},
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

    async def _post(self, path: str, device_id: str, body: str) -> dict:
        """统一发包：同一套签名，发送被签名的原始字节（不能让框架重新序列化）。

        getDeviceSnapshot / getDeviceDetails / controlDevice 共用——同主机、同 path 前缀、
        同 postjson_body 签名，只差 path 与 body。
        """
        import aiohttp  # 惰性导入：离线只用签名/解析/自检时零三方依赖

        ts = self.now_ts()
        url = API_BASE + path
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
        return await self._post(SNAPSHOT_PATH, device_id, self.build_body(feed_id))

    async def get_device_details(self, device_id: str, feed_id) -> dict:
        """拉设备可控流物模型（getDeviceDetails_v1）。请求形态见 build_details_body 的【待对齐】注释。"""
        return await self._post(DETAILS_PATH, device_id, self.build_details_body(feed_id))

    async def control_device(self, device_id: str, feed_id, commands) -> dict:
        """下发控制。commands=[{stream_id,current_value},...]。

        响应结构与快照一致（{status,error,result:"<内层>"}，内层含 control_ret + 全量最新 streams），
        故可直接 parse_snapshot 解析并乐观刷新。
        """
        return await self._post(CONTROL_PATH, device_id, self.build_control_body(feed_id, commands))


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
    model = parse_stream_model({"result": {"streams": streams}})
    check("value_des 解析枚举", model["Horizontal"]["options"] == {"0": "关", "1": "开"})
    check("Horizontal(0/1 两档) → switch", control_kind(model["Horizontal"]) == "switch")
    check("Mode(0/4 两档非 0/1) → select", control_kind(model["Mode"]) == "select")
    check("Wind(多档) → select", control_kind(model["Wind"]) == "select")
    check("TimingSetHour(数值带范围) → number", control_kind(model["TimingSetHour"]) == "number")
    check("number 范围/步长解析", model["TimingSetHour"]["max"] == 24
          and model["TimingSetHour"]["step"] == 1)
    check("名称取 stream_name", model["Mode"]["name"] == "模式")

    # 4) card_meta 降级物模型（缺 min/max → 只出 switch/select）
    dev = {"card_meta": {
        "Power": {"name": "开关", "controllable": True, "options": {"0": "关", "1": "开"}},
        "Voltage": {"name": "电压", "controllable": False},  # 不可控，应排除
    }}
    cm_model = model_from_card_meta(dev)
    check("card_meta 降级仅含可控流",
          set(cm_model) == {"Power"} and control_kind(cm_model["Power"]) == "switch")

    print("\napi self-test", "PASS" if ok else "FAIL")
    return ok


if __name__ == "__main__":
    import sys

    sys.exit(0 if selftest() else 1)
