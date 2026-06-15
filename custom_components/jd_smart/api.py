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

import aiohttp

from .const import API_BASE, SNAPSHOT_PATH

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
        "from_device_success": inner.get("fromDeviceSuccess"),
        "streams": streams,
        "raw": raw,
    }


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
        """形如 2026-06-14T12:59:57.403Z（UTC，毫秒）。"""
        n = datetime.now(timezone.utc)
        return n.strftime("%Y-%m-%dT%H:%M:%S.") + f"{n.microsecond // 1000:03d}Z"

    @staticmethod
    def build_body(feed_id) -> str:
        return json.dumps(
            {"json": {"feed_id": int(feed_id), "version": "2.0", "digest": ""}},
            separators=(",", ":"),
            ensure_ascii=False,
        )

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

    async def get_device_snapshot(self, device_id: str, feed_id) -> dict:
        ts = self.now_ts()
        body = self.build_body(feed_id)
        params = {
            "hard_platform": self.hard_platform,
            "app_version": self.app_version,
            "device_id": device_id,
            "plat_version": self.plat_version,
            "channel": self.channel,
            "plat": self.plat,
        }
        headers = {
            "app_identity": "WL",
            "authorization": self.authorization(body, ts),
            "tgt": self.tgt,
            "content-type": "application/json; charset=utf-8",
            "user-agent": "okhttp/4.10.0",
        }
        url = API_BASE + SNAPSHOT_PATH
        try:
            async with self._session.post(
                url,
                params=params,
                data=body.encode(),  # 必须发送被签名的那串字节，不能让框架重新序列化
                headers=headers,
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
