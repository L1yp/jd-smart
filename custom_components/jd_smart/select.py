"""可控多档枚举：Mode/Wind 等表示成 HA select。

按物模型 value_des 的中文档位（label）展示，写值时反查回码值（可非连续，如 Mode 0/4）。
"""
from __future__ import annotations

from homeassistant.components.select import SelectEntity
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


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: JdSmartCoordinator = hass.data[DOMAIN][entry.entry_id]
    known: set = set()

    @callback
    def _add() -> None:
        new: list[SelectEntity] = []
        for dev in coordinator.devices:
            ov = overrides_for(coordinator, dev["feed_id"])
            for sid, kind in control_map(coordinator, dev).items():
                if kind != "select" or not stream_enabled(ov, sid):
                    continue
                key = (dev["feed_id"], sid)
                if key in known:
                    continue
                known.add(key)
                new.append(JdControlSelect(coordinator, entry, dev, sid))
        if new:
            async_add_entities(new)

    _add()
    entry.async_on_unload(coordinator.async_add_listener(_add))


class JdControlSelect(CoordinatorEntity[JdSmartCoordinator], SelectEntity):
    def __init__(self, coordinator, entry, dev, stream_id) -> None:
        super().__init__(coordinator)
        self._dev = dev
        self._feed = dev["feed_id"]
        self._stream = stream_id
        model = model_entry(coordinator, dev, stream_id)
        self._code_to_label: dict = model.get("options") or {}  # {"0":"标准模式","4":"婴儿风"}
        # label 可能重名，取后者；写值时按 label 反查码值
        self._label_to_code = {v: k for k, v in self._code_to_label.items()}
        self._attr_options = list(self._code_to_label.values())
        base = dev.get("name") or f"JD {self._feed}"
        self._attr_name = f"{base} {control_name(coordinator, dev, stream_id, model)}"
        self._attr_unique_id = f"{entry.entry_id}_{self._feed}_{stream_id}"
        self._attr_device_info = device_info(dev)

    def _value(self):
        snap = (self.coordinator.data or {}).get(self._feed)
        return (snap or {}).get("streams", {}).get(self._stream)

    @property
    def current_option(self) -> str | None:
        value = self._value()
        if value is None:
            return None
        return self._code_to_label.get(str(value))

    async def async_select_option(self, option: str) -> None:
        code = self._label_to_code.get(option)
        if code is None:
            raise HomeAssistantError(f"未知档位: {option}")
        try:
            # current_value 传码值字符串，build_control_body 会归一成裸数字（"4"→4）
            await self.coordinator.async_control(
                self._dev, [{"stream_id": self._stream, "current_value": code}]
            )
        except JdSmartError as err:
            raise HomeAssistantError(f"控制失败: {err}") from err

    @property
    def available(self) -> bool:
        snap = (self.coordinator.data or {}).get(self._feed)
        return super().available and bool(snap) and self._stream in (snap.get("streams") or {})
