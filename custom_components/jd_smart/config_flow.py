"""Config & options flow for JD Smart（彩虹自动发现版）。

ConfigFlow（首次安装，支持多账号）:
    user    账号 3 必填项（tgt / jmafinger / color_pin）+ 设备身份（device_id 或 android_id
            二选一，首选 device_id）；其余 App/设备级常量用默认值自动补。提交时以 color_pin 作
            unique_id（同一台手机可加多个京东账号；重复账号会中止），并解析 eid（填了用填的，
            否则查磁盘缓存，再否则 ds.json 现铸并缓存）
    houses  彩虹 getHouses → 多选家庭
    devices 选中家庭 getAllDevices → 多选设备 → 缓存进 entry.options → 建条目

OptionsFlow（菜单）:
    credentials 只更新这 4 项（tgt 会过期，最常用）
    rediscover  重新发现家庭→设备并更新缓存
    streams     选设备 → 逐流改 名称/单位/启用（card_meta 预填）
    settings    高级：全部参数（seg1/key/机型/eid/间隔…；旧条目补齐也在此）
    manual      兜底：手填 名称|feed_id（device_id 取设备身份：直填值或 md5(android_id)）
"""
from __future__ import annotations

import hashlib
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import JdSmartClient, JdSmartError, parse_devices_gw, parse_houses_gw
from .color_api import JdColorClient
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
    CONF_DEVICE_ID,
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
    DEFAULT_COLOR_SIGN_SECRET,
    DEFAULT_D_BRAND,
    DEFAULT_D_MODEL,
    DEFAULT_HARD_PLATFORM,
    DEFAULT_KEY,
    DEFAULT_NETWORK_TYPE,
    DEFAULT_OS_VERSION,
    DEFAULT_PLAT,
    DEFAULT_PLAT_VERSION,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_SCREEN,
    DEFAULT_SEG1,
    DOMAIN,
)
from .device_finger import EidFetchError, async_fetch_eid
from .eid_cache import async_get_cached_eid, async_save_eid

# ── 账号必填 4 项（步 user / 选项 credentials）──────────────────────────────
# 每个账号不同的就这 4 项；其余 seg1/key/color_sign_secret/机型/设备档 都是 App/设备级
# 常量，对所有账号一致，用默认值自动补（高级设置里仍可改）。这样首次安装只填 4 项。
ADVANCED_DEFAULTS = {
    CONF_COLOR_SIGN_SECRET: DEFAULT_COLOR_SIGN_SECRET,
    CONF_SEG1: DEFAULT_SEG1,
    CONF_KEY: DEFAULT_KEY,
    CONF_HARD_PLATFORM: DEFAULT_HARD_PLATFORM,
    CONF_APP_VERSION: DEFAULT_APP_VERSION,
    CONF_PLAT_VERSION: DEFAULT_PLAT_VERSION,
    CONF_CHANNEL: DEFAULT_CHANNEL,
    CONF_PLAT: DEFAULT_PLAT,
    CONF_D_BRAND: DEFAULT_D_BRAND,
    CONF_D_MODEL: DEFAULT_D_MODEL,
    CONF_OS_VERSION: DEFAULT_OS_VERSION,
    CONF_SCREEN: DEFAULT_SCREEN,
    CONF_AREA: DEFAULT_AREA,
    CONF_NETWORK_TYPE: DEFAULT_NETWORK_TYPE,
}


def _with_defaults(data: dict) -> dict:
    """把 4 必填项之外的 App/设备级常量用默认值补齐（仅补缺失/空值），返回新 dict。
    下游 _build_color_client / JdSmartClient 仍能拿到完整字段，无需在表单里手抄常量。"""
    out = dict(data)
    for k, dv in ADVANCED_DEFAULTS.items():
        if not out.get(k):
            out[k] = dv
    return out


def _credentials_schema(cfg: dict | None = None) -> vol.Schema:
    """gw 发现只需 tgt + 设备身份（device_id 或 android_id 二选一，首选 device_id）。
    首次安装步 user / 选项 credentials 共用。pin/jmafinger 为**可选增强**——填了才走彩虹
    getDeviceDetails 拿完整物模型（风扇档位/模式等），不填只生成开关(Power)+传感器。"""
    cfg = cfg or {}
    return vol.Schema(
        {
            vol.Required(CONF_TGT, default=cfg.get(CONF_TGT, "")): str,
            vol.Optional(CONF_DEVICE_ID, default=cfg.get(CONF_DEVICE_ID, "")): str,
            vol.Optional(CONF_ANDROID_ID, default=cfg.get(CONF_ANDROID_ID, "")): str,
            vol.Optional(CONF_COLOR_PIN, default=cfg.get(CONF_COLOR_PIN, "")): str,
            vol.Optional(CONF_COLOR_JMAFINGER, default=cfg.get(CONF_COLOR_JMAFINGER, "")): str,
        }
    )


def _settings_schema(cfg: dict) -> vol.Schema:
    """选项里「凭据与设备信息」一站式编辑（旧条目补齐 / 随时修改）。默认值取 merged 配置。
    设备身份 android_id / device_id 二选一（首选 device_id）；device_id 预填会把旧 device_id_override 带出来。"""
    return vol.Schema(
        {
            vol.Required(CONF_TGT, default=cfg.get(CONF_TGT, "")): str,
            vol.Optional(CONF_COLOR_PIN, default=cfg.get(CONF_COLOR_PIN, "")): str,
            vol.Optional(CONF_COLOR_JMAFINGER, default=cfg.get(CONF_COLOR_JMAFINGER, "")): str,
            vol.Required(CONF_COLOR_SIGN_SECRET,
                         default=cfg.get(CONF_COLOR_SIGN_SECRET) or DEFAULT_COLOR_SIGN_SECRET): str,
            vol.Required(CONF_SEG1, default=cfg.get(CONF_SEG1) or DEFAULT_SEG1): str,
            vol.Required(CONF_KEY, default=cfg.get(CONF_KEY) or DEFAULT_KEY): str,
            vol.Optional(CONF_ANDROID_ID, default=cfg.get(CONF_ANDROID_ID, "")): str,
            vol.Optional(CONF_DEVICE_ID,
                         default=cfg.get(CONF_DEVICE_ID) or cfg.get(CONF_DEVICE_ID_OVERRIDE) or ""): str,
            vol.Required(CONF_D_BRAND, default=cfg.get(CONF_D_BRAND, DEFAULT_D_BRAND)): str,
            vol.Required(CONF_D_MODEL, default=cfg.get(CONF_D_MODEL, DEFAULT_D_MODEL)): str,
            vol.Required(CONF_OS_VERSION, default=cfg.get(CONF_OS_VERSION, DEFAULT_OS_VERSION)): str,
            vol.Required(CONF_SCREEN, default=cfg.get(CONF_SCREEN, DEFAULT_SCREEN)): str,
            vol.Required(CONF_AREA, default=cfg.get(CONF_AREA, DEFAULT_AREA)): str,
            vol.Required(CONF_NETWORK_TYPE, default=cfg.get(CONF_NETWORK_TYPE, DEFAULT_NETWORK_TYPE)): str,
            vol.Optional(CONF_EID, default=cfg.get(CONF_EID, "")): str,
            vol.Required(CONF_HARD_PLATFORM, default=cfg.get(CONF_HARD_PLATFORM, DEFAULT_HARD_PLATFORM)): str,
            vol.Required(CONF_APP_VERSION, default=cfg.get(CONF_APP_VERSION, DEFAULT_APP_VERSION)): str,
            vol.Required(CONF_PLAT_VERSION, default=cfg.get(CONF_PLAT_VERSION, DEFAULT_PLAT_VERSION)): str,
            vol.Required(CONF_CHANNEL, default=cfg.get(CONF_CHANNEL, DEFAULT_CHANNEL)): str,
            vol.Required(CONF_PLAT, default=cfg.get(CONF_PLAT, DEFAULT_PLAT)): str,
            vol.Optional(CONF_SCAN_INTERVAL, default=cfg.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)): int,
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
    """彩虹发现客户端（aiohttp 走 HA 共享 session）。

    aid=uuid=device_id（= 用户直填的 device_id 或 md5(android_id)），直接注入 profile，
    故不再依赖 android_id 原值——读不到 android_id 的机型只填 device_id 也能签名。
    """
    prof = _assemble_profile(data, eid)
    prof["aid"] = prof["uuid"] = _device_id_for(data)
    return JdColorClient(
        async_get_clientsession(hass),
        profile=prof,
        android_id=None,  # aid/uuid 已按 device_id 注入 profile
        ep_hdid="",
        sign_secret=data.get(CONF_COLOR_SIGN_SECRET) or DEFAULT_COLOR_SIGN_SECRET,
        pin=data.get(CONF_COLOR_PIN) or "",
        jmafinger=data.get(CONF_COLOR_JMAFINGER) or "",
        tgt=data[CONF_TGT],
    )


def _build_smart_client(hass, cfg: dict) -> JdSmartClient:
    """gw/api.smart 客户端：发现(gw)、快照/控制(api.smart)同一套 HmacSHA1 签名。

    只需 tgt + App 档（缺省自动补）+ device_id（仅 query、不签名）——**不碰彩虹**。
    """
    c = _with_defaults(cfg)
    return JdSmartClient(
        async_get_clientsession(hass),
        seg1=c[CONF_SEG1],
        key=c[CONF_KEY],
        tgt=c[CONF_TGT],
        hard_platform=c[CONF_HARD_PLATFORM],
        app_version=c[CONF_APP_VERSION],
        plat_version=c[CONF_PLAT_VERSION],
        channel=c[CONF_CHANNEL],
        plat=c[CONF_PLAT],
    )


def _device_id_for(data: dict, options: dict | None = None) -> str:
    """设备 device_id（= 彩虹 aid/uuid = md5(android_id)，同一个值）。

    优先级：直填 device_id > device_id_override(旧字段) > md5(android_id)。
    部分机型读不到 android_id，用户直接填 device_id 即可；都没填返回空串。
    options 给了则其非空值覆盖 data（兼容把覆盖项放 options 的老条目）。
    """
    src = dict(data)
    if options:
        for k, v in options.items():
            if v not in (None, ""):
                src[k] = v
    explicit = (src.get(CONF_DEVICE_ID) or src.get(CONF_DEVICE_ID_OVERRIDE) or "").strip()
    if explicit:
        return explicit
    aid = (src.get(CONF_ANDROID_ID) or "").strip()
    return hashlib.md5(aid.encode("utf-8")).hexdigest() if aid else ""


def _has_identity(data: dict, options: dict | None = None) -> bool:
    """是否具备设备身份（android_id 或 device_id 任一）。无则无法签名/发现。"""
    return bool(_device_id_for(data, options))


async def _async_fetch_houses_gw(hass, cfg: dict) -> list[dict]:
    """gw 发现家庭+房间（不走彩虹）。业务失败（tgt 过期等 status≠0）抛 JdSmartError。"""
    client = _build_smart_client(hass, cfg)
    raw = await client.get_houses_and_rooms(_device_id_for(cfg))
    if isinstance(raw, dict) and raw.get("status") not in (0, None):
        # gw 对过期 tgt 返回 HTTP 200 + status:-4；不抛就会被当成"没有家庭"，误导用户
        raise JdSmartError(f"status={raw.get('status')} error={raw.get('error')}")
    return parse_houses_gw(raw)


async def _async_fetch_devices_gw(hass, cfg: dict, houses: list[dict],
                                  house_ids: list[str], device_id: str) -> list[dict]:
    """gw 发现所选家庭的设备（不走彩虹）。用 house 的 rooms 表给设备回填 room_id。"""
    client = _build_smart_client(hass, cfg)
    room_maps = {h["house_id"]: (h.get("rooms") or {}) for h in houses}
    out: list[dict] = []
    for hid in house_ids:
        try:
            raw = await client.get_devices_and_category(device_id, hid)
        except JdSmartError:
            continue  # 单个家庭失败不拖垮其它家庭
        out.extend(parse_devices_gw(raw, house_id=hid, room_map=room_maps.get(hid),
                                    requester_device_id=device_id))
    return _dedupe_by_feed(out)


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


def _stream_reference_rows(streams: list[str], card_meta: dict) -> str:
    """编辑表单顶部「原始参数」参考表的数据行（markdown）。

    每行 `| 参数ID | 原名称 | 原单位 | 可选值 |`，表头放在翻译文案里（便于本地化），
    这里只产数据行（每行前置换行，紧接翻译里的表头分隔行）。让用户对照着改名/改单位。
    """
    def _esc(x) -> str:
        return str(x).replace("|", "\\|").replace("\n", " ")

    rows: list[str] = []
    for sid in streams:
        cm = card_meta.get(sid) or {}
        name = cm.get("name") or "—"
        unit = cm.get("unit") or "—"
        opts = cm.get("options")
        if isinstance(opts, dict) and opts:
            opt_text = ", ".join(f"{k}={v}" for k, v in opts.items())
        else:
            opt_text = "—"
        rows.append(f"\n| `{_esc(sid)}` | {_esc(name)} | {_esc(unit)} | {_esc(opt_text)} |")
    return "".join(rows)


def _device_cache_entry(d: dict, device_id: str) -> dict:
    """发现结果 → 持久化进 options 的精简结构（含 card_meta 供传感器复合）。

    house_id/room_id/hw_device_id 供 getDeviceDetails 物模型请求复刻 App body（缺则收不到物模型，
    只剩 Power 开关）；老缓存无这些字段时需「重新发现」补全。
    """
    return {
        "feed_id": d["feed_id"],
        "device_id": device_id,
        "hw_device_id": d.get("hw_device_id"),
        "house_id": d.get("house_id"),
        "room_id": d.get("room_id"),
        "name": d.get("name"),
        "room": d.get("room"),
        "category": d.get("category"),
        "streams": d.get("streams") or [],
        "card_meta": d.get("card_meta") or {},
    }


async def _async_resolve_eid(hass, data: dict) -> tuple[str | None, str | None]:
    """解析 eid：填了用填的；否则查缓存；再否则 ds.json 现铸并写缓存。返回 (eid, error)。

    缓存键用设备身份：有 android_id 用 android_id（与旧缓存兼容），否则用 device_id。
    eid 本身与身份无关（async_fetch_eid 不吃 android_id），键只为复用/去重。
    """
    eid = (data.get(CONF_EID) or "").strip()
    if eid:
        return eid, None
    key = (data.get(CONF_ANDROID_ID) or "").strip() or _device_id_for(data)
    cached = await async_get_cached_eid(hass, key)
    if cached:
        return cached, None
    try:
        eid, t = await async_fetch_eid(async_get_clientsession(hass))
    except EidFetchError as err:
        return None, str(err)
    await async_save_eid(hass, key, eid, t)
    return eid, None


def merged_config(entry) -> dict:
    """entry.data 叠加 entry.options（非空覆盖）。让选项里补填的 凭据/设备档/eid 生效，旧条目也能用。"""
    cfg = dict(entry.data)
    for k, v in (entry.options or {}).items():
        if v not in (None, ""):
            cfg[k] = v
    return cfg


def _clamp_default(default: list[str] | None, valid: list[str]) -> list[str]:
    """把默认多选值夹紧到当前合法选项：换账号后失效的旧默认（如旧家庭/设备 id）丢弃，
    全丢光了就回退「全选当前结果」。避免 SelectSelector 因默认值不在 options 里而校验失败。"""
    kept = [d for d in (default or []) if d in valid]
    return kept or list(valid)


def _houses_select(houses: list[dict], default: list[str]) -> vol.Schema:
    options = [selector.SelectOptionDict(value=h["house_id"], label=h["house_name"]) for h in houses]
    default = _clamp_default(default, [h["house_id"] for h in houses])
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
    default = _clamp_default(default, [str(d["feed_id"]) for d in devices])
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
    """首次安装：tgt + 设备身份 → gw 发现家庭 → 选设备。

    发现走 gw.smart.jd.com 轻量接口（只需 tgt + App 档 + device_id，**不碰彩虹**）。
    多账号 unique_id：填了 pin 用 pin（与旧条目兼容）；否则用账号家庭 id（不同账号家庭不同）。
    """

    VERSION = 1

    def __init__(self) -> None:
        self._data: dict = {}
        self._houses: list[dict] = []
        self._selected_house_ids: list[str] = []
        self._all_devices: list[dict] = []

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        errors: dict[str, str] = {}
        placeholders = {"detail": ""}
        if user_input is not None:
            self._data = _with_defaults(user_input)  # tgt+身份 + 自动补齐常量默认值
            if not _has_identity(self._data):
                errors["base"] = "need_identity"  # device_id / android_id 至少给一个
            else:
                pin = (self._data.get(CONF_COLOR_PIN) or "").strip()
                if pin:  # 填了 pin：发现前就能拦重复账号（与旧条目 unique_id 一致）
                    await self.async_set_unique_id(pin)
                    self._abort_if_unique_id_configured()
                try:
                    self._houses = await _async_fetch_houses_gw(self.hass, self._data)
                except JdSmartError as err:
                    errors["base"] = "cannot_connect"  # tgt 过期会落这里，detail 给出 status/error
                    placeholders["detail"] = str(err)
                else:
                    if not self._houses:
                        errors["base"] = "no_houses"
                    else:
                        if not pin:  # 没 pin：用家庭 id 作 unique_id 拦重复账号
                            uid = "gwhouse_" + "_".join(sorted(h["house_id"] for h in self._houses))
                            await self.async_set_unique_id(uid)
                            self._abort_if_unique_id_configured()
                        return await self.async_step_houses()
        return self.async_show_form(
            step_id="user",
            data_schema=_credentials_schema(self._data),
            errors=errors,
            description_placeholders=placeholders,
        )

    async def async_step_houses(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        # 家庭已在 user 步用 gw 拉好
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
                self._all_devices = await _async_fetch_devices_gw(
                    self.hass, self._data, self._houses,
                    self._selected_house_ids, _device_id_for(self._data),
                )
            except JdSmartError:
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
            houses = [
                {"house_id": h["house_id"], "house_name": h["house_name"]}
                for h in self._houses if h["house_id"] in self._selected_house_ids
            ]
            options = {
                CONF_DEVICES: cache,
                CONF_HOUSES: houses,
                CONF_SCAN_INTERVAL: DEFAULT_SCAN_INTERVAL,
            }
            # 标题：有 pin 用 pin，否则用 device_id 前 8 位，便于区分多账号
            tag = ((self._data.get(CONF_COLOR_PIN) or "").strip() or did[:8])
            title = f"小京鱼 {tag}".strip()
            return self.async_create_entry(title=title, data=self._data, options=options)
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
            menu_options=["credentials", "rediscover", "streams", "settings", "manual"],
        )

    # --- 只更新账号必填项 + 设备身份（tgt 会过期，最常用）---
    async def async_step_credentials(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            # 设备身份二选一校验：结合已存值，device_id 或 android_id 至少有一个
            merged = {**merged_config(self._entry), **user_input}
            if not _has_identity(merged):
                errors["base"] = "need_identity"
            else:
                return self.async_create_entry(title="", data=self._merged_options(**user_input))
        cfg = merged_config(self._entry)
        return self.async_show_form(
            step_id="credentials", data_schema=_credentials_schema(cfg), errors=errors
        )

    # --- 凭据与设备信息（一站式编辑；旧条目在此补齐 color 凭据/android_id/eid）---
    async def async_step_settings(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(title="", data=self._merged_options(**user_input))
        cfg = merged_config(self._entry)
        return self.async_show_form(
            step_id="settings", data_schema=_settings_schema(cfg)
        )

    # --- 重选设备（gw 发现：houses → devices）---
    async def async_step_rediscover(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        cfg = merged_config(self._entry)
        # 旧条目可能没填 tgt / 设备身份：先去「更新凭据」或「高级设置」补齐
        if not _has_identity(cfg) or not cfg.get(CONF_TGT):
            return self.async_abort(reason="missing_device_config")
        if not self._houses:
            try:
                self._houses = await _async_fetch_houses_gw(self.hass, cfg)
            except JdSmartError:
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
        cfg = merged_config(self._entry)
        if not self._all_devices:
            try:
                self._all_devices = await _async_fetch_devices_gw(
                    self.hass, cfg, self._houses, self._selected_house_ids,
                    _device_id_for(cfg, self._entry.options),
                )
            except JdSmartError:
                return self.async_abort(reason="cannot_connect")
            if not self._all_devices:
                return self.async_abort(reason="no_devices")
        if user_input is not None:
            selected = set(user_input["devices"])
            did = _device_id_for(cfg, self._entry.options)
            cache = [
                _device_cache_entry(d, did)
                for d in self._all_devices
                if str(d["feed_id"]) in selected
            ]
            houses = [
                {"house_id": h["house_id"], "house_name": h["house_name"]}
                for h in self._houses if h["house_id"] in self._selected_house_ids
            ]
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
            description_placeholders={
                "device": dev.get("name") or str(self._edit_feed),
                "reference": _stream_reference_rows(streams, card_meta),
            },
        )

    # --- 兜底手填 ---
    async def async_step_manual(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        if user_input is not None:
            did = _device_id_for(merged_config(self._entry), self._entry.options)
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
