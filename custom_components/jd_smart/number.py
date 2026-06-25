"""可控数值：is_enum=-1 的数值流（如 TimingSetHour/Minute）表示成 HA number。

min/max/step 取自物模型（getDeviceDetails）；card_meta 降级模型没有范围，故只有 getDeviceDetails
能建 number（见 api.control_kind）。
"""
from __future__ import annotations

from homeassistant.components.number import NumberEntity, NumberMode
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .api import JdSmartError, _num
from .const import DOMAIN
from .control import control_map, control_name, model_entry
from .coordinator import JdSmartCoordinator
from .sensor import device_info, overrides_for, stream_enabled


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: JdSmartCoordinator = hass.data[DOMAIN][entry.entry_id]
    known: set = set()

    @callback
    def _add() -> None:
        new: list[NumberEntity] = []
        for dev in coordinator.devices:
            ov = overrides_for(coordinator, dev["feed_id"])
            for sid, kind in control_map(coordinator, dev).items():
                if kind != "number" or not stream_enabled(ov, sid):
                    continue
                key = (dev["feed_id"], sid)
                if key in known:
                    continue
                known.add(key)
                new.append(JdControlNumber(coordinator, entry, dev, sid))
        if new:
            async_add_entities(new)

    _add()
    entry.async_on_unload(coordinator.async_add_listener(_add))


class JdControlNumber(CoordinatorEntity[JdSmartCoordinator], NumberEntity):
    _attr_mode = NumberMode.BOX

    def __init__(self, coordinator, entry, dev, stream_id) -> None:
        super().__init__(coordinator)
        self._dev = dev
        self._feed = dev["feed_id"]
        self._stream = stream_id
        model = model_entry(coordinator, dev, stream_id)
        self._is_int = model.get("ptype") in ("int", None)  # 默认按整数发
        base = dev.get("name") or f"JD {self._feed}"
        self._attr_name = f"{base} {control_name(coordinator, dev, stream_id, model)}"
        self._attr_unique_id = f"{entry.entry_id}_{self._feed}_{stream_id}"
        self._attr_device_info = device_info(dev)
        if model.get("min") is not None:
            self._attr_native_min_value = model["min"]
        if model.get("max") is not None:
            self._attr_native_max_value = model["max"]
        self._attr_native_step = model.get("step") or 1
        if model.get("unit"):
            self._attr_native_unit_of_measurement = model["unit"]

    @property
    def native_value(self):
        snap = (self.coordinator.data or {}).get(self._feed)
        raw = (snap or {}).get("streams", {}).get(self._stream)
        val = _num(raw)
        return val if isinstance(val, (int, float)) else None

    async def async_set_native_value(self, value: float) -> None:
        # HA 给的是 float；整数流发整数（build_control_body 会把 2.0 归一成 2）
        out = int(value) if self._is_int and float(value).is_integer() else value
        try:
            await self.coordinator.async_control(
                self._dev, [{"stream_id": self._stream, "current_value": out}]
            )
        except JdSmartError as err:
            raise HomeAssistantError(f"控制失败: {err}") from err

    @property
    def available(self) -> bool:
        snap = (self.coordinator.data or {}).get(self._feed)
        return super().available and bool(snap) and self._stream in (snap.get("streams") or {})
