"""eid 磁盘缓存 —— 按 android_id 把设备指纹 eid 落到 HA `.storage/jd_smart_eid`。

eid 一旦铸出（ds.json）即长期有效，没必要每次配置都重铸。配置流程先查缓存，命中即复用；
未命中才走 `device_finger.async_fetch_eid` 并写回。键用 android_id（同一台设备复装也能复用）。
"""
from __future__ import annotations

from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

from .const import DOMAIN

_STORAGE_KEY = f"{DOMAIN}_eid"
_STORAGE_VERSION = 1


def _store(hass: HomeAssistant) -> Store:
    return Store(hass, _STORAGE_VERSION, _STORAGE_KEY)


async def async_get_cached_eid(hass: HomeAssistant, android_id: str) -> str | None:
    """返回 android_id 对应的已缓存 eid；无则 None。"""
    data = await _store(hass).async_load() or {}
    entry = data.get(android_id)
    if isinstance(entry, dict):
        return entry.get("eid") or None
    return None


async def async_save_eid(hass: HomeAssistant, android_id: str, eid: str, time_ms: int) -> None:
    """写入/更新 android_id -> {eid, time}。"""
    store = _store(hass)
    data = await store.async_load() or {}
    data[android_id] = {"eid": eid, "time": time_ms}
    await store.async_save(data)
