"""可控开关：把 {0:关,1:开} 两档可控流表示成 HA switch（写值走 controlDevice_v1）。"""
from __future__ import annotations

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .api import JdSmartError
from .const import DOMAIN
from .control import control_map, control_name, model_entry
from .coordinator import JdSmartCoordinator
from .sensor import device_info, overrides_for, stream_enabled

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
        new: list[SwitchEntity] = []
        for dev in coordinator.devices:
            ov = overrides_for(coordinator, dev["feed_id"])
            for sid, kind in control_map(coordinator, dev).items():
                if kind != "switch" or not stream_enabled(ov, sid):
                    continue
                key = (dev["feed_id"], sid)
                if key in known:
                    continue
                known.add(key)
                new.append(JdControlSwitch(coordinator, entry, dev, sid))
        if new:
            async_add_entities(new)

    _add()
    entry.async_on_unload(coordinator.async_add_listener(_add))


class JdControlSwitch(CoordinatorEntity[JdSmartCoordinator], SwitchEntity):
    def __init__(self, coordinator, entry, dev, stream_id) -> None:
        super().__init__(coordinator)
        self._dev = dev
        self._feed = dev["feed_id"]
        self._stream = stream_id
        model = model_entry(coordinator, dev, stream_id)
        base = dev.get("name") or f"JD {self._feed}"
        self._attr_name = f"{base} {control_name(coordinator, dev, stream_id, model)}"
        self._attr_unique_id = f"{entry.entry_id}_{self._feed}_{stream_id}"
        self._attr_device_info = device_info(dev)

    def _value(self):
        snap = (self.coordinator.data or {}).get(self._feed)
        return (snap or {}).get("streams", {}).get(self._stream)

    @property
    def is_on(self) -> bool | None:
        value = self._value()
        if value is None:
            return None
        return str(value).strip() not in _OFF_VALUES

    async def _write(self, value: int) -> None:
        try:
            await self.coordinator.async_control(
                self._dev, [{"stream_id": self._stream, "current_value": value}]
            )
        except JdSmartError as err:
            raise HomeAssistantError(f"控制失败: {err}") from err

    async def async_turn_on(self, **kwargs) -> None:
        await self._write(1)

    async def async_turn_off(self, **kwargs) -> None:
        await self._write(0)

    @property
    def available(self) -> bool:
        snap = (self.coordinator.data or {}).get(self._feed)
        return super().available and bool(snap) and self._stream in (snap.get("streams") or {})
