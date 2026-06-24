"""数值传感器。

设备实际只上报 4 个 stream：
- Voltage          电压，毫伏(mV) → V
- Electric         电流，毫安(mA) → A（这里按 mA 直接显示）
- Power            继电器开关量(on/off)，走 binary_sensor 平台
- CurrentPowerSum  **实时有功功率**，毫瓦(mW) → W（名字含“Sum”但其值会上下波动，
                   是瞬时功率而非累计电量；已与外部空调伴侣实测待机 <3W 对齐）

在此之上派生两个实体：
- 实时功率（W）：直接取 CurrentPowerSum（设备已算好功率因数的真有功功率）；
- 今日用电量（kWh）：对实时功率做梯形时间积分（设备无累计电量流），本地零点清零。
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

# ── 原始值 → 物理单位的缩放（设备统一用“毫”单位：mV / mA / mW）──────────────
# 实时功率：CurrentPowerSum=2960 → 2.96 W，与空调伴侣实测待机 <3W 吻合。
# 若空调开机后实时功率明显不是额定值（差 10 倍），改 POWER_RAW_TO_WATT 即可。
VOLTAGE_TO_VOLT = 0.001
ELECTRIC_TO_AMP = 0.001
POWER_RAW_TO_WATT = 0.001

# CurrentPowerSum 由专门的“实时功率”实体呈现，不再当普通 stream 数值传感器。
POWER_STREAM = "CurrentPowerSum"

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
}


def overrides_for(coordinator, feed) -> dict:
    """该设备的用户流覆盖：{stream_id: {name,unit,enabled}}。键按 str(feed_id) 存。"""
    return (getattr(coordinator, "stream_overrides", None) or {}).get(str(feed)) or {}


def stream_enabled(overrides: dict, stream_id: str) -> bool:
    ov = overrides.get(stream_id)
    return ov.get("enabled", True) if ov else True


def is_binary_stream(dev: dict, stream_id: str) -> bool:
    """开关量判定：静态 BINARY_STREAMS，或 card_control 可控且恰好两档(on/off)。"""
    if stream_id in BINARY_STREAMS:
        return True
    cm = (dev.get("card_meta") or {}).get(stream_id) or {}
    return bool(cm.get("controllable")) and len(cm.get("options") or {}) == 2


def resolve_stream(dev: dict, stream_id: str, overrides: dict) -> dict:
    """复合「用户覆盖 > card_meta > 内置 SENSOR_META」。

    - name：覆盖名 > card_desc.stream_text > stream_id（名称可套用）
    - unit：覆盖单位 > 内置单位 > card_desc.unit（单位可能不准，用户可改）
    - factor/state_class/precision：始终取内置（物理缩放，与单位绑定）
    - device_class：仅在内置已知且单位未被改动时保留（避免 HA 单位/类约束告警）
    - options：card_desc/card_control 的 {code: label}，有则当枚举按 label 显示
    """
    cm = (dev.get("card_meta") or {}).get(stream_id) or {}
    bi = SENSOR_META.get(stream_id, {})
    ov = overrides.get(stream_id) or None
    bi_unit = bi.get("unit")
    unit = ov["unit"] if (ov and ov.get("unit")) else (bi_unit or cm.get("unit"))
    device_class = bi.get("device_class") if (bi.get("device_class") and unit == bi_unit) else None
    return {
        "name": (ov.get("name") if ov else None) or cm.get("name") or stream_id,
        "enabled": ov.get("enabled", True) if ov else True,
        "unit": unit,
        "factor": bi.get("factor", 1),
        "device_class": device_class,
        "state_class": bi.get("state_class"),
        "precision": bi.get("precision"),
        "options": cm.get("options") or None,
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
            ov = overrides_for(coordinator, feed)
            for stream_id in streams:
                if is_binary_stream(dev, stream_id):
                    continue  # 开关量交给 binary_sensor 平台
                if stream_id == POWER_STREAM:
                    continue  # 实时功率由专门实体呈现
                if not stream_enabled(ov, stream_id):
                    continue  # 用户在选项里禁用了该流
                key = (feed, stream_id)
                if key in known:
                    continue
                known.add(key)
                new.append(JdStreamSensor(coordinator, entry, dev, stream_id))
            # 派生：实时功率（W）与今日用电量（kWh），都基于 CurrentPowerSum
            if POWER_STREAM in streams:
                pkey = (feed, "__power__")
                if pkey not in known:
                    known.add(pkey)
                    new.append(JdPowerSensor(coordinator, entry, dev))
                dkey = (feed, "__daily__")
                if dkey not in known:
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
        meta = resolve_stream(dev, stream_id, overrides_for(coordinator, self._feed))
        self._factor = meta["factor"]
        self._options = meta["options"]  # {code: label}；有则按枚举映射 label，不加单位/缩放
        self._attr_name = f"{base} {meta['name']}"
        self._attr_unique_id = f"{entry.entry_id}_{self._feed}_{stream_id}"
        self._attr_device_info = device_info(dev)
        if not self._options:
            if meta["unit"]:
                self._attr_native_unit_of_measurement = meta["unit"]
            if meta["device_class"]:
                self._attr_device_class = meta["device_class"]
            if meta["state_class"]:
                self._attr_state_class = meta["state_class"]
            if meta["precision"] is not None:
                self._attr_suggested_display_precision = meta["precision"]

    def _snap(self):
        return (self.coordinator.data or {}).get(self._feed)

    @property
    def native_value(self):
        snap = self._snap()
        if not snap:
            return None
        raw = snap.get("streams", {}).get(self._stream)
        if self._options:  # 枚举流：把码值映射成中文 label（如 Mode 1 -> 制冷）
            return self._options.get(str(raw), raw)
        val = _num(raw)
        if self._factor != 1 and isinstance(val, (int, float)):
            return round(val * self._factor, 6)
        return val

    @property
    def available(self) -> bool:
        snap = self._snap()
        return super().available and bool(snap) and self._stream in (snap.get("streams") or {})


class JdPowerSensor(CoordinatorEntity[JdSmartCoordinator], SensorEntity):
    """实时功率（W）：直接取 CurrentPowerSum（设备已算好功率因数的真有功功率）。"""

    _attr_device_class = SensorDeviceClass.POWER
    _attr_native_unit_of_measurement = UnitOfPower.WATT
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_suggested_display_precision = 2

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
        val = _num(snap.get("streams", {}).get(POWER_STREAM))
        if not isinstance(val, (int, float)):
            return None
        return round(val * POWER_RAW_TO_WATT, 3)

    @property
    def extra_state_attributes(self) -> dict:
        # 暴露设备原始值，便于核对换算：原始 2960 → 显示 2.96 W（÷1000，同电压毫伏）。
        snap = self._snap()
        raw = _num((snap or {}).get("streams", {}).get(POWER_STREAM)) if snap else None
        return {"raw": raw, "factor": POWER_RAW_TO_WATT, "source_stream": POWER_STREAM}

    @property
    def available(self) -> bool:
        snap = self._snap()
        return super().available and bool(snap) and POWER_STREAM in (snap.get("streams") or {})


@dataclass
class _DailyEnergyData(ExtraStoredData):
    """每日用电量传感器跨重启需要持久化的内部状态。"""

    day: str | None
    value: float

    def as_dict(self) -> dict:
        return {"day": self.day, "value": self.value}


class JdDailyEnergySensor(CoordinatorEntity[JdSmartCoordinator], RestoreSensor):
    """今日用电量（kWh）：对实时功率做梯形时间积分，本地零点清零。

    设备没有累计电量流，只能由功率随时间积分得到电量（∫P·dt）。
    - 梯形法：每次取上次与本次功率的均值乘以时间差累加；
    - 仅在两次读数间隔 ≤ 3×轮询周期时积分，超出（重启/断连）则跳过该段，避免凭空累加；
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
        self._value: float = 0.0
        self._last_t = None          # 上次积分点时间（datetime）
        self._last_p: float | None = None  # 上次功率（W）

    def _snap(self):
        return (self.coordinator.data or {}).get(self._feed)

    def _power_w(self) -> float | None:
        snap = self._snap()
        if not snap:
            return None
        val = _num(snap.get("streams", {}).get(POWER_STREAM))
        return val * POWER_RAW_TO_WATT if isinstance(val, (int, float)) else None

    def _gap_cap_hours(self) -> float:
        interval = self.coordinator.update_interval
        secs = interval.total_seconds() if interval else 60.0
        return max(secs, 60.0) * 3.0 / 3600.0

    @callback
    def _update_integral(self) -> None:
        now = dt_util.now()
        today = now.date()
        p = self._power_w()
        if self._day is None:
            self._day = today
        if today != self._day:
            # 跨天：清零，从当前点重新起算
            self._day = today
            self._value = 0.0
            self._last_t = now if p is not None else None
            self._last_p = p
            return
        if p is None:
            # 读数缺失：暂停积分，避免跨空洞累加
            self._last_t = None
            self._last_p = None
            return
        if self._last_t is not None and self._last_p is not None:
            dt_h = (now - self._last_t).total_seconds() / 3600.0
            if 0 < dt_h <= self._gap_cap_hours():
                # 梯形积分：平均功率(W) × 时间(h) = Wh，再 /1000 → kWh
                self._value = round(
                    self._value + (self._last_p + p) / 2.0 * dt_h / 1000.0, 5
                )
            # 间隔过大（重启/长断连）：跳过该段，仅重置基准
        self._last_t = now
        self._last_p = p

    @property
    def native_value(self):
        return self._value

    @property
    def extra_state_attributes(self) -> dict:
        return {
            "day": self._day.isoformat() if self._day else None,
            "source_stream": POWER_STREAM,
            "last_power_w": self._last_p,
        }

    @property
    def extra_restore_state_data(self) -> _DailyEnergyData:
        return _DailyEnergyData(
            day=self._day.isoformat() if self._day else None,
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
            ds = d.get("day")
            try:
                self._day = date.fromisoformat(ds) if ds else None
            except (TypeError, ValueError):
                self._day = None
        # 重启后不跨空洞积分：清空上次积分点，首个新读数仅作基准
        self._last_t = None
        self._last_p = None
        self._update_integral()
        self.async_write_ha_state()

    @callback
    def _handle_coordinator_update(self) -> None:
        self._update_integral()
        self.async_write_ha_state()
