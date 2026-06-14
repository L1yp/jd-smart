"""数值传感器：每个 stream 一个（开关量 Power 走 binary_sensor）。

另有两个“计算型”传感器，不是直接来自某个 stream：
- 实时功率（W）：Voltage × Electric（视在功率，设备未直接上报瓦特）；
- 今日用电量（kWh）：对 CurrentPowerSum 增量累加，本地零点清零。
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from homeassistant.components.sensor import (
    RestoreSensor,
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    UnitOfElectricCurrent,
    UnitOfElectricPotential,
    UnitOfEnergy,
    UnitOfPower,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.restore_state import ExtraStoredData
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import dt as dt_util

from .const import BINARY_STREAMS, DOMAIN
from .coordinator import JdSmartCoordinator

# ── 原始值 → 物理单位的缩放（设备相关，整个集成的“单一真相”）─────────────
# 当前取“解释 A”（已和小京鱼 App 实测约 19W 核对）：
#   Voltage  原始毫伏(mV)  → V    ×0.001
#   Electric 原始毫安(mA)  → A    ×0.001
#   CurrentPowerSum 原始 0.1Wh    → kWh  ×0.0001
# 若 App 实测功率/电量与显示差 10 倍，切到“解释 B”：电流当厘安(×0.01)、能量计数当 Wh，
# 即把下面改成 ELECTRIC_TO_AMP=0.01、ENERGY_RAW_TO_KWH=0.001（其余无需动）。
VOLTAGE_TO_VOLT = 0.001
ELECTRIC_TO_AMP = 0.001
ENERGY_RAW_TO_KWH = 0.0001

# 已知 stream 的单位/缩放（device_class, 单位, 缩放因子, state_class, 显示精度）。
SENSOR_META: dict[str, dict] = {
    "Voltage": {
        "device_class": SensorDeviceClass.VOLTAGE,
        "unit": UnitOfElectricPotential.VOLT,
        "factor": VOLTAGE_TO_VOLT,
        "state_class": SensorStateClass.MEASUREMENT,
        "precision": 3,
    },
    "Electric": {
        "device_class": SensorDeviceClass.CURRENT,
        "unit": UnitOfElectricCurrent.MILLIAMPERE,
        "factor": 1,  # 原始即毫安，按 mA 直接显示
        "state_class": SensorStateClass.MEASUREMENT,
    },
    "CurrentPowerSum": {
        # 累计总用电量。原始为 0.1Wh，换算到 kWh 显示（修正了原先按 Wh×1 偏大 10 倍的标定）。
        "device_class": SensorDeviceClass.ENERGY,
        "unit": UnitOfEnergy.KILO_WATT_HOUR,
        "factor": ENERGY_RAW_TO_KWH,
        "state_class": SensorStateClass.TOTAL_INCREASING,
        "precision": 3,
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
            feed = dev["feed_id"]
            streams = snap.get("streams", {})
            for stream_id in streams:
                if stream_id in BINARY_STREAMS:
                    continue  # 开关量交给 binary_sensor 平台
                key = (feed, stream_id)
                if key in known:
                    continue
                known.add(key)
                new.append(JdStreamSensor(coordinator, entry, dev, stream_id))
            # 计算型：实时功率（需要电压与电流两个 stream）
            pkey = (feed, "__power__")
            if pkey not in known and "Voltage" in streams and "Electric" in streams:
                known.add(pkey)
                new.append(JdPowerSensor(coordinator, entry, dev))
            # 计算型：今日用电量（需要累计电量 stream）
            dkey = (feed, "__daily__")
            if dkey not in known and "CurrentPowerSum" in streams:
                known.add(dkey)
                new.append(JdDailyEnergySensor(coordinator, entry, dev))
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


class JdPowerSensor(CoordinatorEntity[JdSmartCoordinator], SensorEntity):
    """实时功率（W）= 电压 × 电流。

    设备未直接上报瓦特，这里取 Voltage×Electric 的视在功率（VA）当作功率；
    对功率因数接近 1 的负载，与真实有功功率（W）相差很小。
    """

    _attr_device_class = SensorDeviceClass.POWER
    _attr_native_unit_of_measurement = UnitOfPower.WATT
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_suggested_display_precision = 1

    def __init__(self, coordinator, entry, dev) -> None:
        super().__init__(coordinator)
        self._dev = dev
        self._feed = dev["feed_id"]
        base = dev.get("name") or f"JD {self._feed}"
        self._attr_name = f"{base} 实时功率"
        self._attr_unique_id = f"{entry.entry_id}_{self._feed}_power"
        self._attr_device_info = device_info(dev)

    def _snap(self):
        return (self.coordinator.data or {}).get(self._feed)

    @property
    def native_value(self):
        snap = self._snap()
        if not snap:
            return None
        streams = snap.get("streams", {})
        v = _num(streams.get("Voltage"))
        i = _num(streams.get("Electric"))
        if not isinstance(v, (int, float)) or not isinstance(i, (int, float)):
            return None
        return round(v * VOLTAGE_TO_VOLT * i * ELECTRIC_TO_AMP, 2)

    @property
    def available(self) -> bool:
        snap = self._snap()
        if not (super().available and snap):
            return False
        streams = snap.get("streams") or {}
        return "Voltage" in streams and "Electric" in streams


@dataclass
class _DailyEnergyData(ExtraStoredData):
    """每日用电量传感器跨重启需要持久化的内部状态。"""

    day: str | None
    last_raw: float | None
    value: float

    def as_dict(self) -> dict:
        return {"day": self.day, "last_raw": self.last_raw, "value": self.value}


class JdDailyEnergySensor(CoordinatorEntity[JdSmartCoordinator], RestoreSensor):
    """今日用电量（kWh）：对 CurrentPowerSum 的增量累加，本地零点清零。

    - 用“增量累加”而非“当前-零点基准”，天然容忍设备计数被清零/回绕；
    - RestoreSensor 持久化当日累计，HA 重启不丢；
    - state_class=TOTAL_INCREASING：每天清零会被能量看板识别为新周期。
    """

    _attr_device_class = SensorDeviceClass.ENERGY
    _attr_native_unit_of_measurement = UnitOfEnergy.KILO_WATT_HOUR
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_suggested_display_precision = 3
    _attr_icon = "mdi:lightning-bolt"

    def __init__(self, coordinator, entry, dev) -> None:
        super().__init__(coordinator)
        self._dev = dev
        self._feed = dev["feed_id"]
        base = dev.get("name") or f"JD {self._feed}"
        self._attr_name = f"{base} 今日用电量"
        self._attr_unique_id = f"{entry.entry_id}_{self._feed}_daily_energy"
        self._attr_device_info = device_info(dev)
        self._day: date | None = None
        self._last_raw: float | None = None
        self._value: float = 0.0

    def _snap(self):
        return (self.coordinator.data or {}).get(self._feed)

    def _raw(self) -> float | None:
        snap = self._snap()
        if not snap:
            return None
        val = _num(snap.get("streams", {}).get("CurrentPowerSum"))
        return float(val) if isinstance(val, (int, float)) else None

    @callback
    def _recompute(self) -> None:
        raw = self._raw()
        today = dt_util.now().date()
        if self._day is None:
            self._day = today
        if today != self._day:
            # 跨天：清零，从当前读数重新起算（忽略零点前后一个轮询周期的零头）
            self._day = today
            self._value = 0.0
            self._last_raw = raw
            return
        if raw is None:
            return  # 本轮无有效读数，保留上次累计
        if self._last_raw is not None and raw >= self._last_raw:
            self._value = round(
                self._value + (raw - self._last_raw) * ENERGY_RAW_TO_KWH, 4
            )
        # raw < last_raw：设备计数被清零/回绕，本次增量跳过，仅更新基准
        self._last_raw = raw

    @property
    def native_value(self):
        return self._value

    @property
    def extra_state_attributes(self) -> dict:
        return {
            "day": self._day.isoformat() if self._day else None,
            "source_stream": "CurrentPowerSum",
            "source_raw": self._last_raw,
        }

    @property
    def extra_restore_state_data(self) -> _DailyEnergyData:
        return _DailyEnergyData(
            day=self._day.isoformat() if self._day else None,
            last_raw=self._last_raw,
            value=self._value,
        )

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        last = await self.async_get_last_extra_data()
        if last is not None:
            d = last.as_dict()
            try:
                self._value = float(d.get("value") or 0.0)
            except (TypeError, ValueError):
                self._value = 0.0
            lr = d.get("last_raw")
            self._last_raw = float(lr) if isinstance(lr, (int, float)) else None
            ds = d.get("day")
            try:
                self._day = date.fromisoformat(ds) if ds else None
            except (TypeError, ValueError):
                self._day = None
        self._recompute()
        self.async_write_ha_state()

    @callback
    def _handle_coordinator_update(self) -> None:
        self._recompute()
        self.async_write_ha_state()
