"""开关量传感器：把 Power 等 stream 表示成 on/off。"""
from __future__ import annotations

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import JdSmartCoordinator
from .sensor import device_info, is_binary_stream, overrides_for, resolve_stream, stream_enabled

_OFF_VALUES = {"0", "", "false", "False", "off", "OFF", "no"}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: JdSmartCoordinator = hass.data[DOMAIN][entry.entry_id]
    known: set = set()

    @callback
    def _add() -> None:
        new: list[BinarySensorEntity] = []
        data = coordinator.data or {}
        for dev in coordinator.devices:
            snap = data.get(dev["feed_id"])
            if not snap:
                continue
            ov = overrides_for(coordinator, dev["feed_id"])
            for stream_id in snap.get("streams", {}):
                if not is_binary_stream(dev, stream_id):
                    continue
                if not stream_enabled(ov, stream_id):
                    continue
                key = (dev["feed_id"], stream_id)
                if key in known:
                    continue
                known.add(key)
                new.append(JdStreamBinarySensor(coordinator, entry, dev, stream_id))
        if new:
            async_add_entities(new)

    _add()
    entry.async_on_unload(coordinator.async_add_listener(_add))


class JdStreamBinarySensor(CoordinatorEntity[JdSmartCoordinator], BinarySensorEntity):
    _attr_device_class = BinarySensorDeviceClass.POWER

    def __init__(self, coordinator, entry, dev, stream_id) -> None:
        super().__init__(coordinator)
        self._dev = dev
        self._feed = dev["feed_id"]
        self._stream = stream_id
        base = dev.get("name") or f"JD {self._feed}"
        meta = resolve_stream(dev, stream_id, overrides_for(coordinator, self._feed))
        self._attr_name = f"{base} {meta['name']}"
        self._attr_unique_id = f"{entry.entry_id}_{self._feed}_{stream_id}"
        self._attr_device_info = device_info(dev)

    def _snap(self):
        return (self.coordinator.data or {}).get(self._feed)

    @property
    def is_on(self) -> bool | None:
        snap = self._snap()
        if not snap:
            return None
        value = snap.get("streams", {}).get(self._stream)
        if value is None:
            return None
        return str(value).strip() not in _OFF_VALUES

    @property
    def available(self) -> bool:
        snap = self._snap()
        return super().available and bool(snap) and self._stream in (snap.get("streams") or {})
