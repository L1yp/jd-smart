"""数值传感器：每个 stream 一个（开关量 Power 走 binary_sensor）。"""
from __future__ import annotations

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    UnitOfElectricCurrent,
    UnitOfElectricPotential,
    UnitOfEnergy,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import BINARY_STREAMS, DOMAIN
from .coordinator import JdSmartCoordinator

# 已知 stream 的单位/缩放（device_class, 单位, 缩放因子, state_class, 显示精度）。
# 原始值是放大整数：Voltage 毫伏→V(/1000)，Electric 毫安(mA)，CurrentPowerSum 耗电量(Wh，按需改)。
# 因子/单位若与你的设备不符，改这里即可。
SENSOR_META: dict[str, dict] = {
    "Voltage": {
        "device_class": SensorDeviceClass.VOLTAGE,
        "unit": UnitOfElectricPotential.VOLT,
        "factor": 0.001,
        "state_class": SensorStateClass.MEASUREMENT,
        "precision": 3,
    },
    "Electric": {
        "device_class": SensorDeviceClass.CURRENT,
        "unit": UnitOfElectricCurrent.MILLIAMPERE,
        "factor": 1,
        "state_class": SensorStateClass.MEASUREMENT,
    },
    "CurrentPowerSum": {
        "device_class": SensorDeviceClass.ENERGY,
        "unit": UnitOfEnergy.WATT_HOUR,
        "factor": 1,
        "state_class": SensorStateClass.TOTAL_INCREASING,
    },
}


def _num(value):
    """能转数字就转（int/float），否则原样返回字符串。"""
    if value is None:
        return None
    try:
        f = float(value)
        return int(f) if f.is_integer() else f
    except (TypeError, ValueError):
        return value


def device_info(dev: dict) -> DeviceInfo:
    return DeviceInfo(
        identifiers={(DOMAIN, str(dev["feed_id"]))},
        name=dev.get("name") or f"JD {dev['feed_id']}",
        manufacturer="JD Smart 小京鱼",
        model="getDeviceSnapshot_v1",
    )


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: JdSmartCoordinator = hass.data[DOMAIN][entry.entry_id]

    async_add_entities(
        JdStatusSensor(coordinator, entry, dev) for dev in coordinator.devices
    )

    known: set = set()

    @callback
    def _add_stream_sensors() -> None:
        new: list[SensorEntity] = []
        data = coordinator.data or {}
        for dev in coordinator.devices:
            snap = data.get(dev["feed_id"])
            if not snap:
                continue
            for stream_id in snap.get("streams", {}):
                if stream_id in BINARY_STREAMS:
                    continue  # 开关量交给 binary_sensor 平台
                key = (dev["feed_id"], stream_id)
                if key in known:
                    continue
                known.add(key)
                new.append(JdStreamSensor(coordinator, entry, dev, stream_id))
        if new:
            async_add_entities(new)

    _add_stream_sensors()
    entry.async_on_unload(coordinator.async_add_listener(_add_stream_sensors))


class JdStatusSensor(CoordinatorEntity[JdSmartCoordinator], SensorEntity):
    _attr_icon = "mdi:chip"

    def __init__(self, coordinator, entry, dev) -> None:
        super().__init__(coordinator)
        self._dev = dev
        self._feed = dev["feed_id"]
        self._attr_name = f"{dev.get('name') or self._feed} 状态"
        self._attr_unique_id = f"{entry.entry_id}_{self._feed}_status"
        self._attr_device_info = device_info(dev)

    def _snap(self):
        return (self.coordinator.data or {}).get(self._feed)

    @property
    def native_value(self):
        snap = self._snap()
        if not snap:
            return None
        return "online" if snap.get("ok") else "offline"

    @property
    def extra_state_attributes(self) -> dict:
        snap = self._snap()
        if not snap:
            return {"device_id": self._dev["device_id"], "feed_id": self._feed}
        return {
            "device_id": self._dev["device_id"],
            "feed_id": self._feed,
            "api_status": snap.get("api_status"),
            "error": snap.get("error"),
            "device_status": snap.get("device_status"),
            "from_device_success": snap.get("from_device_success"),
            "streams": snap.get("streams"),
        }


class JdStreamSensor(CoordinatorEntity[JdSmartCoordinator], SensorEntity):
    def __init__(self, coordinator, entry, dev, stream_id) -> None:
        super().__init__(coordinator)
        self._dev = dev
        self._feed = dev["feed_id"]
        self._stream = stream_id
        base = dev.get("name") or f"JD {self._feed}"
        self._attr_name = f"{base} {stream_id}"
        self._attr_unique_id = f"{entry.entry_id}_{self._feed}_{stream_id}"
        self._attr_device_info = device_info(dev)

        meta = SENSOR_META.get(stream_id, {})
        self._factor = meta.get("factor", 1)
        if meta.get("device_class"):
            self._attr_device_class = meta["device_class"]
        if meta.get("unit"):
            self._attr_native_unit_of_measurement = meta["unit"]
        if meta.get("state_class"):
            self._attr_state_class = meta["state_class"]
        if meta.get("precision") is not None:
            self._attr_suggested_display_precision = meta["precision"]

    def _snap(self):
        return (self.coordinator.data or {}).get(self._feed)

    @property
    def native_value(self):
        snap = self._snap()
        if not snap:
            return None
        val = _num(snap.get("streams", {}).get(self._stream))
        if self._factor != 1 and isinstance(val, (int, float)):
            return round(val * self._factor, 6)
        return val

    @property
    def available(self) -> bool:
        snap = self._snap()
        return super().available and bool(snap) and self._stream in (snap.get("streams") or {})
