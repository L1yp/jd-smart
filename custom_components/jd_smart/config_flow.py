"""Config & options flow for JD Smart（彩虹自动发现版）。

ConfigFlow（首次安装）:
    user    凭据（彩虹 color_* + 旧接口 seg1/key + 共用 tgt）
    device  设备档（android_id 必填、机型描述、eid 可选）；提交时解析 eid（填了用填的，
            否则查磁盘缓存，再否则 ds.json 现铸并缓存）
    houses  彩虹 getHouses → 多选家庭
    devices 选中家庭 getAllDevices → 多选设备 → 缓存进 entry.options → 建条目

OptionsFlow（菜单）:
    creds       更新 tgt / 轮询间隔 / device_id 覆盖
    rediscover  重新发现家庭→设备并更新缓存
    streams     选设备 → 逐流改 名称/单位/启用（card_meta 预填）
    manual      兜底：手填 名称|feed_id（device_id 自动 md5(android_id)）
"""
from __future__ import annotations

import hashlib
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .color_api import JdColorClient, JdColorError, parse_device_list
from .const import (
    COLOR_PROFILE_FIXED,
    CONF_ANDROID_ID,
    CONF_APP_VERSION,
    CONF_AREA,
    CONF_CHANNEL,
    CONF_COLOR_JMAFINGER,
    CONF_COLOR_PIN,
    CONF_COLOR_SIGN_SECRET,
    CONF_D_BRAND,
    CONF_D_MODEL,
    CONF_DEVICE_ID_OVERRIDE,
    CONF_DEVICES,
    CONF_EID,
    CONF_HARD_PLATFORM,
    CONF_HOUSES,
    CONF_KEY,
    CONF_NETWORK_TYPE,
    CONF_OS_VERSION,
    CONF_PLAT,
    CONF_PLAT_VERSION,
    CONF_SCAN_INTERVAL,
    CONF_SCREEN,
    CONF_SEG1,
    CONF_STREAM_OVERRIDES,
    CONF_TGT,
    DEFAULT_APP_VERSION,
    DEFAULT_AREA,
    DEFAULT_CHANNEL,
    DEFAULT_D_BRAND,
    DEFAULT_D_MODEL,
    DEFAULT_HARD_PLATFORM,
    DEFAULT_NETWORK_TYPE,
    DEFAULT_OS_VERSION,
    DEFAULT_PLAT,
    DEFAULT_PLAT_VERSION,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_SCREEN,
    DOMAIN,
)
from .device_finger import EidFetchError, async_fetch_eid
from .eid_cache import async_get_cached_eid, async_save_eid

# ── 凭据表单（步 user）─────────────────────────────────────────────────────
ACCOUNT_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_COLOR_SIGN_SECRET): str,
        vol.Required(CONF_COLOR_PIN): str,
        vol.Required(CONF_COLOR_JMAFINGER): str,
        vol.Required(CONF_TGT): str,
        vol.Required(CONF_SEG1): str,
        vol.Required(CONF_KEY): str,
        vol.Required(CONF_HARD_PLATFORM, default=DEFAULT_HARD_PLATFORM): str,
        vol.Required(CONF_APP_VERSION, default=DEFAULT_APP_VERSION): str,
        vol.Required(CONF_PLAT_VERSION, default=DEFAULT_PLAT_VERSION): str,
        vol.Required(CONF_CHANNEL, default=DEFAULT_CHANNEL): str,
        vol.Required(CONF_PLAT, default=DEFAULT_PLAT): str,
    }
)


def _device_schema(d: dict) -> vol.Schema:
    """步 device 表单；默认值取已填值或示例常量。"""
    return vol.Schema(
        {
            vol.Required(CONF_ANDROID_ID, default=d.get(CONF_ANDROID_ID, "")): str,
            vol.Required(CONF_D_BRAND, default=d.get(CONF_D_BRAND, DEFAULT_D_BRAND)): str,
            vol.Required(CONF_D_MODEL, default=d.get(CONF_D_MODEL, DEFAULT_D_MODEL)): str,
            vol.Required(CONF_OS_VERSION, default=d.get(CONF_OS_VERSION, DEFAULT_OS_VERSION)): str,
            vol.Required(CONF_SCREEN, default=d.get(CONF_SCREEN, DEFAULT_SCREEN)): str,
            vol.Required(CONF_AREA, default=d.get(CONF_AREA, DEFAULT_AREA)): str,
            vol.Required(CONF_NETWORK_TYPE, default=d.get(CONF_NETWORK_TYPE, DEFAULT_NETWORK_TYPE)): str,
            vol.Optional(CONF_EID, default=d.get(CONF_EID, "")): str,
        }
    )


# ── 共享纯函数 ─────────────────────────────────────────────────────────────
def _assemble_profile(data: dict, eid: str) -> dict:
    """从 entry data + eid 拼出彩虹 color_profile（固定常量 + 设备描述 + eid）。"""
    prof = dict(COLOR_PROFILE_FIXED)
    prof.update(
        {
            "eid": eid,
            "d_brand": data.get(CONF_D_BRAND) or DEFAULT_D_BRAND,
            "d_model": data.get(CONF_D_MODEL) or DEFAULT_D_MODEL,
            "osVersion": data.get(CONF_OS_VERSION) or DEFAULT_OS_VERSION,
            "screen": data.get(CONF_SCREEN) or DEFAULT_SCREEN,
            "area": data.get(CONF_AREA) or DEFAULT_AREA,
            "networkType": data.get(CONF_NETWORK_TYPE) or DEFAULT_NETWORK_TYPE,
        }
    )
    return prof


def _build_color_client(hass, data: dict, eid: str) -> JdColorClient:
    """彩虹发现客户端（aiohttp 走 HA 共享 session）。"""
    return JdColorClient(
        async_get_clientsession(hass),
        profile=_assemble_profile(data, eid),
        android_id=data[CONF_ANDROID_ID],
        ep_hdid="",
        sign_secret=data[CONF_COLOR_SIGN_SECRET],
        pin=data[CONF_COLOR_PIN],
        jmafinger=data[CONF_COLOR_JMAFINGER],
        tgt=data[CONF_TGT],
    )


def _device_id_for(data: dict, options: dict | None = None) -> str:
    """getDeviceSnapshot 的 device_id：优先 options 覆盖，否则 md5(android_id)。"""
    override = ((options or {}).get(CONF_DEVICE_ID_OVERRIDE) or "").strip()
    if override:
        return override
    return hashlib.md5(data[CONF_ANDROID_ID].encode("utf-8")).hexdigest()


def _parse_houses(resp: dict) -> list[dict]:
    """getHouses → [{house_id, house_name}]。"""
    result = (resp or {}).get("result") or {}
    houses = []
    for h in result.get("houseList") or []:
        hid = h.get("houseId")
        if hid is None:
            continue
        houses.append({"house_id": str(hid), "house_name": h.get("houseName") or str(hid)})
    return houses


def _dedupe_by_feed(devices: list[dict]) -> list[dict]:
    seen: set = set()
    out = []
    for d in devices:
        fid = str(d.get("feed_id"))
        if fid in seen:
            continue
        seen.add(fid)
        out.append(d)
    return out


def _device_label(dev: dict) -> str:
    room = dev.get("room") or "—"
    return f"{room} / {dev.get('name') or dev.get('feed_id')}"


def _device_cache_entry(d: dict, device_id: str) -> dict:
    """发现结果 → 持久化进 options 的精简结构（含 card_meta 供传感器复合）。"""
    return {
        "feed_id": d["feed_id"],
        "device_id": device_id,
        "name": d.get("name"),
        "room": d.get("room"),
        "category": d.get("category"),
        "streams": d.get("streams") or [],
        "card_meta": d.get("card_meta") or {},
    }


async def _async_resolve_eid(hass, data: dict) -> tuple[str | None, str | None]:
    """解析 eid：填了用填的；否则查缓存；再否则 ds.json 现铸并写缓存。返回 (eid, error)。"""
    eid = (data.get(CONF_EID) or "").strip()
    if eid:
        return eid, None
    android_id = data[CONF_ANDROID_ID]
    cached = await async_get_cached_eid(hass, android_id)
    if cached:
        return cached, None
    try:
        eid, t = await async_fetch_eid(async_get_clientsession(hass))
    except EidFetchError as err:
        return None, str(err)
    await async_save_eid(hass, android_id, eid, t)
    return eid, None


async def _async_fetch_houses(hass, data: dict) -> list[dict]:
    client = _build_color_client(hass, data, data[CONF_EID])
    return _parse_houses(await client.get_houses())


async def _async_fetch_devices(hass, data: dict, house_ids: list[str]) -> list[dict]:
    client = _build_color_client(hass, data, data[CONF_EID])
    did = _device_id_for(data)
    out: list[dict] = []
    for hid in house_ids:
        try:
            resp = await client.get_all_devices(hid)
        except JdColorError:
            continue
        out.extend(parse_device_list(resp, requester_device_id=did))
    return _dedupe_by_feed(out)


def _houses_select(houses: list[dict], default: list[str]) -> vol.Schema:
    options = [selector.SelectOptionDict(value=h["house_id"], label=h["house_name"]) for h in houses]
    return vol.Schema(
        {
            vol.Required("houses", default=default): selector.SelectSelector(
                selector.SelectSelectorConfig(options=options, multiple=True)
            )
        }
    )


def _devices_select(devices: list[dict], default: list[str]) -> vol.Schema:
    options = [
        selector.SelectOptionDict(value=str(d["feed_id"]), label=_device_label(d)) for d in devices
    ]
    return vol.Schema(
        {
            vol.Required("devices", default=default): selector.SelectSelector(
                selector.SelectSelectorConfig(options=options, multiple=True)
            )
        }
    )


def _parse_manual_devices(text: str | None, device_id: str) -> list[dict]:
    """兜底手填：每行 `名称|feed_id`（名称可省）；device_id 统一用传入值。"""
    import re

    out = []
    for line in re.split(r"[\n;]+", str(text or "")):
        line = line.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) == 2:
            name, feed_id = parts
        elif len(parts) == 1:
            feed_id = parts[0]
            name = feed_id
        else:
            continue
        if feed_id:
            out.append({"feed_id": feed_id, "device_id": device_id, "name": name,
                        "room": None, "category": None, "streams": [], "card_meta": {}})
    return out


# ── ConfigFlow ─────────────────────────────────────────────────────────────
class JdSmartConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """首次安装：凭据 → 设备(eid) → 选家庭 → 选设备。"""

    VERSION = 1

    def __init__(self) -> None:
        self._data: dict = {}
        self._houses: list[dict] = []
        self._selected_house_ids: list[str] = []
        self._all_devices: list[dict] = []

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        if user_input is not None:
            self._data.update(user_input)
            return await self.async_step_device()
        return self.async_show_form(step_id="user", data_schema=ACCOUNT_SCHEMA)

    async def async_step_device(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        errors: dict[str, str] = {}
        placeholders = {"detail": ""}
        if user_input is not None:
            self._data.update(user_input)
            await self.async_set_unique_id(self._data[CONF_ANDROID_ID])
            self._abort_if_unique_id_configured()
            eid, err = await _async_resolve_eid(self.hass, self._data)
            if err:
                errors["base"] = "eid_fetch_failed"
                placeholders["detail"] = err
            else:
                self._data[CONF_EID] = eid
                return await self.async_step_houses()
        return self.async_show_form(
            step_id="device",
            data_schema=_device_schema(self._data),
            errors=errors,
            description_placeholders=placeholders,
        )

    async def async_step_houses(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        if not self._houses:
            try:
                self._houses = await _async_fetch_houses(self.hass, self._data)
            except Exception:  # noqa: BLE001  网络/风控/签名失败统一中止
                return self.async_abort(reason="cannot_connect")
            if not self._houses:
                return self.async_abort(reason="no_houses")
        if user_input is not None:
            self._selected_house_ids = user_input["houses"]
            return await self.async_step_devices()
        default = [h["house_id"] for h in self._houses]
        return self.async_show_form(step_id="houses", data_schema=_houses_select(self._houses, default))

    async def async_step_devices(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        if not self._all_devices:
            try:
                self._all_devices = await _async_fetch_devices(
                    self.hass, self._data, self._selected_house_ids
                )
            except Exception:  # noqa: BLE001
                return self.async_abort(reason="cannot_connect")
            if not self._all_devices:
                return self.async_abort(reason="no_devices")
        if user_input is not None:
            selected = set(user_input["devices"])
            did = _device_id_for(self._data)
            cache = [
                _device_cache_entry(d, did)
                for d in self._all_devices
                if str(d["feed_id"]) in selected
            ]
            houses = [h for h in self._houses if h["house_id"] in self._selected_house_ids]
            options = {
                CONF_DEVICES: cache,
                CONF_HOUSES: houses,
                CONF_SCAN_INTERVAL: DEFAULT_SCAN_INTERVAL,
            }
            return self.async_create_entry(
                title="小京鱼 JD Smart", data=self._data, options=options
            )
        default = [str(d["feed_id"]) for d in self._all_devices]
        return self.async_show_form(
            step_id="devices", data_schema=_devices_select(self._all_devices, default)
        )

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> "JdSmartOptionsFlow":
        return JdSmartOptionsFlow(config_entry)


# ── OptionsFlow ────────────────────────────────────────────────────────────
class JdSmartOptionsFlow(config_entries.OptionsFlow):
    """更新凭据/间隔、重选设备、编辑流单位、兜底手填。"""

    def __init__(self, entry: config_entries.ConfigEntry) -> None:
        self._entry = entry
        self._houses: list[dict] = []
        self._selected_house_ids: list[str] = []
        self._all_devices: list[dict] = []
        self._edit_feed: str | None = None

    def _merged_options(self, **updates) -> dict:
        opts = dict(self._entry.options)
        opts.update(updates)
        return opts

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        return self.async_show_menu(
            step_id="init",
            menu_options=["creds", "rediscover", "streams", "manual"],
        )

    # --- 更新凭据/间隔 ---
    async def async_step_creds(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(title="", data=self._merged_options(**user_input))
        o = self._entry.options
        schema = vol.Schema(
            {
                vol.Optional(
                    CONF_TGT, default=o.get(CONF_TGT, self._entry.data.get(CONF_TGT, ""))
                ): str,
                vol.Optional(
                    CONF_SCAN_INTERVAL, default=o.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
                ): int,
                vol.Optional(CONF_DEVICE_ID_OVERRIDE, default=o.get(CONF_DEVICE_ID_OVERRIDE, "")): str,
            }
        )
        return self.async_show_form(step_id="creds", data_schema=schema)

    # --- 重选设备（houses → devices）---
    async def async_step_rediscover(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        if not self._houses:
            try:
                self._houses = await _async_fetch_houses(self.hass, self._entry.data)
            except Exception:  # noqa: BLE001
                return self.async_abort(reason="cannot_connect")
            if not self._houses:
                return self.async_abort(reason="no_houses")
        if user_input is not None:
            self._selected_house_ids = user_input["houses"]
            return await self.async_step_redevices()
        prev = [h["house_id"] for h in (self._entry.options.get(CONF_HOUSES) or [])]
        default = prev or [h["house_id"] for h in self._houses]
        return self.async_show_form(
            step_id="rediscover", data_schema=_houses_select(self._houses, default)
        )

    async def async_step_redevices(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        if not self._all_devices:
            try:
                self._all_devices = await _async_fetch_devices(
                    self.hass, self._entry.data, self._selected_house_ids
                )
            except Exception:  # noqa: BLE001
                return self.async_abort(reason="cannot_connect")
            if not self._all_devices:
                return self.async_abort(reason="no_devices")
        if user_input is not None:
            selected = set(user_input["devices"])
            did = _device_id_for(self._entry.data, self._entry.options)
            cache = [
                _device_cache_entry(d, did)
                for d in self._all_devices
                if str(d["feed_id"]) in selected
            ]
            houses = [h for h in self._houses if h["house_id"] in self._selected_house_ids]
            return self.async_create_entry(
                title="", data=self._merged_options(**{CONF_DEVICES: cache, CONF_HOUSES: houses})
            )
        prev = [str(d["feed_id"]) for d in (self._entry.options.get(CONF_DEVICES) or [])]
        default = prev or [str(d["feed_id"]) for d in self._all_devices]
        return self.async_show_form(
            step_id="redevices", data_schema=_devices_select(self._all_devices, default)
        )

    # --- 编辑流/单位 ---
    async def async_step_streams(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        devices = self._entry.options.get(CONF_DEVICES) or []
        if not devices:
            return self.async_abort(reason="no_devices")
        if user_input is not None:
            self._edit_feed = user_input["device"]
            return await self.async_step_edit_device()
        options = [
            selector.SelectOptionDict(value=str(d["feed_id"]), label=d.get("name") or str(d["feed_id"]))
            for d in devices
        ]
        schema = vol.Schema(
            {
                vol.Required("device"): selector.SelectSelector(
                    selector.SelectSelectorConfig(options=options)
                )
            }
        )
        return self.async_show_form(step_id="streams", data_schema=schema)

    async def async_step_edit_device(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        devices = self._entry.options.get(CONF_DEVICES) or []
        dev = next((d for d in devices if str(d["feed_id"]) == str(self._edit_feed)), None)
        if dev is None:
            return self.async_abort(reason="no_devices")
        streams = dev.get("streams") or []
        card_meta = dev.get("card_meta") or {}
        all_ov = dict(self._entry.options.get(CONF_STREAM_OVERRIDES) or {})
        cur = all_ov.get(str(self._edit_feed), {})

        if user_input is not None:
            ov = {}
            for sid in streams:
                ov[sid] = {
                    "name": (user_input.get(f"name__{sid}") or "").strip(),
                    "unit": (user_input.get(f"unit__{sid}") or "").strip(),
                    "enabled": bool(user_input.get(f"enabled__{sid}", True)),
                }
            all_ov[str(self._edit_feed)] = ov
            return self.async_create_entry(
                title="", data=self._merged_options(**{CONF_STREAM_OVERRIDES: all_ov})
            )

        fields: dict = {}
        for sid in streams:
            cm = card_meta.get(sid, {})
            c = cur.get(sid, {})
            name_def = c.get("name") or cm.get("name") or ""
            unit_def = c.get("unit") if c.get("unit") is not None else (cm.get("unit") or "")
            en_def = c.get("enabled", True)
            fields[vol.Optional(f"name__{sid}", default=name_def)] = str
            fields[vol.Optional(f"unit__{sid}", default=unit_def)] = str
            fields[vol.Optional(f"enabled__{sid}", default=en_def)] = bool
        return self.async_show_form(
            step_id="edit_device",
            data_schema=vol.Schema(fields),
            description_placeholders={"device": dev.get("name") or str(self._edit_feed)},
        )

    # --- 兜底手填 ---
    async def async_step_manual(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        if user_input is not None:
            did = _device_id_for(self._entry.data, self._entry.options)
            cache = _parse_manual_devices(user_input.get("manual", ""), did)
            return self.async_create_entry(title="", data=self._merged_options(**{CONF_DEVICES: cache}))
        existing = self._entry.options.get(CONF_DEVICES) or []
        lines = "\n".join(
            f"{d.get('name') or ''}|{d.get('feed_id')}" for d in existing if d.get("feed_id")
        )
        schema = vol.Schema(
            {
                vol.Optional("manual", default=lines): selector.TextSelector(
                    selector.TextSelectorConfig(multiline=True)
                )
            }
        )
        return self.async_show_form(step_id="manual", data_schema=schema)
