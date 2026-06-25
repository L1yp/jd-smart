"""DataUpdateCoordinator：按间隔轮询已配置设备的快照。"""
from __future__ import annotations

import logging
from datetime import timedelta

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .api import (
    JdSmartClient,
    JdSmartError,
    model_from_card_meta,
    parse_snapshot,
    parse_stream_model,
)
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


class JdSmartCoordinator(DataUpdateCoordinator):
    """data: { feed_id: snapshot_dict | None }"""

    def __init__(
        self,
        hass: HomeAssistant,
        client: JdSmartClient,
        devices: list[dict],
        scan_interval: int,
        stream_overrides: dict | None = None,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=scan_interval),
        )
        self.client = client
        self.devices = devices
        # {feed_id(str): {stream_id: {name,unit,enabled}}}，sensor/binary_sensor 复合用户覆盖用
        self.stream_overrides = stream_overrides or {}
        # {feed_id: {stream_id: 物模型项}}，switch/select/number 建实体用；setup 阶段拉一次
        self.stream_models: dict = {}

    async def _async_update_data(self) -> dict:
        result: dict = {}
        for dev in self.devices:
            feed_id = dev["feed_id"]
            try:
                raw = await self.client.get_device_snapshot(dev["device_id"], feed_id)
                result[feed_id] = parse_snapshot(raw)
            except JdSmartError as err:
                # 单个设备失败不拖垮其它设备（tgt 过期会让所有都失败，日志可见）
                _LOGGER.warning("查询设备 %s 失败: %s", dev.get("name", feed_id), err)
                result[feed_id] = None
        return result

    async def async_fetch_models(self) -> None:
        """每台设备拉一次 getDeviceDetails 物模型；失败/为空回退 card_meta。setup 阶段调用一次。

        物模型是静态元数据（哪些流可控、枚举档位、数值范围），不随状态变，故只在 setup 拉一次，
        实时值仍走 _async_update_data 的快照轮询。
        """
        for dev in self.devices:
            feed_id = dev["feed_id"]
            model: dict = {}
            try:
                raw = await self.client.get_device_details(dev["device_id"], feed_id)
                model = parse_stream_model(raw)
            except JdSmartError as err:
                _LOGGER.warning("拉取设备 %s 物模型失败，回退 card_meta: %s",
                                dev.get("name", feed_id), err)
            if not model:
                model = model_from_card_meta(dev)
            if model:
                self.stream_models[feed_id] = model

    async def async_control(self, dev: dict, commands: list[dict]) -> dict:
        """下发控制并用响应里的全量 streams 乐观刷新（UI 秒变，不必等下一轮轮询）。

        controlDevice 响应结构同快照，含执行后的最新 streams；合并进当前数据后 set_updated_data。
        """
        raw = await self.client.control_device(dev["device_id"], dev["feed_id"], commands)
        parsed = parse_snapshot(raw)
        if parsed.get("ok") and parsed.get("streams"):
            data = dict(self.data or {})
            prev = data.get(dev["feed_id"]) or {}
            streams = dict(prev.get("streams") or {})
            streams.update(parsed["streams"])  # 响应若是子集也不丢其它流
            data[dev["feed_id"]] = {**parsed, "streams": streams}
            self.async_set_updated_data(data)
        return parsed
