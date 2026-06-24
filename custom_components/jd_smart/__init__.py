"""JD Smart (小京鱼) integration."""
from __future__ import annotations

import hashlib
import logging
import re

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall, SupportsResponse
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import JdSmartClient, JdSmartError, parse_snapshot
from .const import (
    ATTR_DEVICE_ID,
    ATTR_FEED_ID,
    CONF_ANDROID_ID,
    CONF_APP_VERSION,
    CONF_CHANNEL,
    CONF_DEVICE_ID_OVERRIDE,
    CONF_DEVICES,
    CONF_HARD_PLATFORM,
    CONF_KEY,
    CONF_PLAT,
    CONF_PLAT_VERSION,
    CONF_SCAN_INTERVAL,
    CONF_SEG1,
    CONF_STREAM_OVERRIDES,
    CONF_TGT,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    PLATFORMS,
    SERVICE_GET_SNAPSHOT,
)
from .coordinator import JdSmartCoordinator

_LOGGER = logging.getLogger(__name__)


def _load_devices(entry: ConfigEntry) -> list[dict]:
    """读 entry.options 里的设备：新版是结构化 list[dict]（含 card_meta），旧版兼容文本。

    统一 device_id：options 覆盖 > 缓存值 > md5(android_id)。运行时轮询只需 device_id+feed_id。
    """
    raw = entry.options.get(CONF_DEVICES)
    devices = [dict(d) for d in raw] if isinstance(raw, list) else parse_devices(raw)
    android_id = entry.data.get(CONF_ANDROID_ID)
    override = (entry.options.get(CONF_DEVICE_ID_OVERRIDE) or "").strip()
    default_did = hashlib.md5(android_id.encode("utf-8")).hexdigest() if android_id else None
    for d in devices:
        d["device_id"] = override or d.get("device_id") or default_did
    return devices


def parse_devices(text: str | None) -> list[dict]:
    """旧版文本格式兼容：每行 '名称|device_id|feed_id'（名称可省略）；也支持用 ; 分隔。"""
    devices: list[dict] = []
    if not text:
        return devices
    for line in re.split(r"[\n;]+", str(text)):
        line = line.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) == 3:
            name, device_id, feed_id = parts
        elif len(parts) == 2:
            device_id, feed_id = parts
            name = device_id
        else:
            continue
        if device_id and feed_id:
            devices.append({"name": name, "device_id": device_id, "feed_id": feed_id})
    return devices


def _client_from_entry(hass: HomeAssistant, entry: ConfigEntry) -> JdSmartClient:
    data = entry.data
    tgt = entry.options.get(CONF_TGT) or data[CONF_TGT]  # 选项里的 tgt 优先（可热更新）
    return JdSmartClient(
        async_get_clientsession(hass),
        seg1=data[CONF_SEG1],
        key=data[CONF_KEY],
        tgt=tgt,
        hard_platform=data[CONF_HARD_PLATFORM],
        app_version=data[CONF_APP_VERSION],
        plat_version=data[CONF_PLAT_VERSION],
        channel=data[CONF_CHANNEL],
        plat=data[CONF_PLAT],
    )


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    client = _client_from_entry(hass, entry)
    devices = _load_devices(entry)
    scan = entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
    overrides = entry.options.get(CONF_STREAM_OVERRIDES, {}) or {}

    coordinator = JdSmartCoordinator(hass, client, devices, scan, stream_overrides=overrides)
    if devices:
        await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    _async_register_services(hass)
    entry.async_on_unload(entry.add_update_listener(_async_reload_entry))
    return True


async def _async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        hass.data[DOMAIN].pop(entry.entry_id, None)
        if not hass.data[DOMAIN]:
            hass.services.async_remove(DOMAIN, SERVICE_GET_SNAPSHOT)
    return unloaded


def _async_register_services(hass: HomeAssistant) -> None:
    if hass.services.has_service(DOMAIN, SERVICE_GET_SNAPSHOT):
        return

    async def _handle_get_snapshot(call: ServiceCall) -> dict:
        device_id = call.data[ATTR_DEVICE_ID]
        feed_id = call.data[ATTR_FEED_ID]
        store = hass.data.get(DOMAIN, {})
        if not store:
            raise HomeAssistantError("jd_smart 尚未配置")
        coordinator: JdSmartCoordinator = next(iter(store.values()))
        try:
            data = await coordinator.client.get_device_snapshot(device_id, feed_id)
        except JdSmartError as err:
            raise HomeAssistantError(f"查询失败: {err}") from err
        parsed = parse_snapshot(data)
        return {
            "device_id": device_id,
            "feed_id": feed_id,
            "ok": parsed["ok"],
            "streams": parsed["streams"],
            "snapshot": data,
        }

    hass.services.async_register(
        DOMAIN,
        SERVICE_GET_SNAPSHOT,
        _handle_get_snapshot,
        schema=vol.Schema(
            {
                vol.Required(ATTR_DEVICE_ID): cv.string,
                vol.Required(ATTR_FEED_ID): cv.string,
            }
        ),
        supports_response=SupportsResponse.ONLY,
    )
