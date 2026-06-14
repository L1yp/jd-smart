"""DataUpdateCoordinator：按间隔轮询已配置设备的快照。"""
from __future__ import annotations

import logging
from datetime import timedelta

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .api import JdSmartClient, JdSmartError, parse_snapshot
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
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=scan_interval),
        )
        self.client = client
        self.devices = devices

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
