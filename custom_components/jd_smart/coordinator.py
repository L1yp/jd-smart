"""DataUpdateCoordinator：按间隔轮询已配置设备的快照。"""
from __future__ import annotations

import json
import logging
from datetime import timedelta

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .api import (
    JdSmartClient,
    JdSmartError,
    control_kind,
    model_from_card_meta,
    parse_snapshot,
    parse_stream_model,
)
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


def _snippet(obj, limit: int = 400) -> str:
    """把原始响应安全截断成一行，便于排查日志（不刷屏）。"""
    try:
        s = obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False)
    except (TypeError, ValueError):
        s = str(obj)
    return s[:limit] + ("…" if len(s) > limit else "")


def _enrich_options_from_card_meta(model: dict, dev: dict) -> None:
    """getDeviceDetails 缺 value_des 时，用 card_desc/card_meta 的枚举标签补 options/单位。

    getDeviceDetails 给权威可控性(stream_type)+范围，但个别可控枚举流 value_des 为空；枚举的
    中文档位散在 getAllDevices 的 card_desc（已复合进 dev['card_meta']），补进来 type0 枚举才能成 select
    而非退化成裸 number。仅补缺失项，不覆盖 getDeviceDetails 已有的值。
    """
    cmeta = dev.get("card_meta") or {}
    for sid, entry in model.items():
        cm = cmeta.get(sid) or {}
        if not entry.get("options") and cm.get("options"):
            entry["options"] = cm["options"]
        if not entry.get("unit") and cm.get("unit"):
            entry["unit"] = cm["unit"]


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

    async def async_fetch_models(self, color_client=None) -> None:
        """每台设备拉一次物模型；失败/为空/无彩虹客户端则回退 card_meta。setup 阶段调用一次。

        物模型走**彩虹** getDeviceDetails（jdsmart.device.getDeviceDetails），是静态元数据
        （哪些流可控、枚举档位、数值范围），不随状态变，故只在 setup 拉一次；实时值仍走快照轮询。
        """
        from .color_api import JdColorError  # 局部导入：仅 setup 用到彩虹客户端

        for dev in self.devices:
            feed_id = dev["feed_id"]
            name = dev.get("name", feed_id)
            model: dict = {}
            source = "card_meta"
            if color_client is not None:
                try:
                    raw = await color_client.get_device_details(
                        feed_id,
                        house_id=dev.get("house_id"),
                        room_id=dev.get("room_id"),
                        device_id=dev.get("hw_device_id"),
                    )
                    model = parse_stream_model(raw)
                    if model:
                        source = "getDeviceDetails"
                        _enrich_options_from_card_meta(model, dev)
                    else:
                        # 关键盲点：接口有响应但解析不出 streams（路径不符/空/错误载荷）。
                        # 以前这里静默回退 card_meta，"只有 Power"无从排查——打出原始片段。
                        _LOGGER.warning(
                            "设备 %s(feed=%s) getDeviceDetails 未解析出物模型，回退 card_meta"
                            "（card_control 通常只标 Power 可控，故只会生成 Power 开关）。"
                            "用 jd_smart.get_device_model 服务看完整原始响应。响应片段: %s",
                            name, feed_id, _snippet(raw),
                        )
                except JdColorError as err:
                    _LOGGER.warning(
                        "拉取设备 %s(feed=%s) 物模型失败，回退 card_meta（只会有 Power）: %s",
                        name, feed_id, err,
                    )
            else:
                _LOGGER.info(
                    "设备 %s(feed=%s) 无彩虹客户端，用 card_meta 物模型（通常仅 Power 可控）",
                    name, feed_id,
                )
            if not model:
                model = model_from_card_meta(dev)
            if model:
                self.stream_models[feed_id] = model
                kinds = [control_kind(m) for m in model.values()]
                _LOGGER.info(
                    "设备 %s(feed=%s) 物模型来源=%s，可控实体 switch=%d/select=%d/number=%d（流总数=%d）",
                    name, feed_id, source,
                    kinds.count("switch"), kinds.count("select"), kinds.count("number"),
                    len(model),
                )
            else:
                _LOGGER.warning(
                    "设备 %s(feed=%s) 无任何物模型（getDeviceDetails 与 card_meta 均为空），不会生成可控实体",
                    name, feed_id,
                )

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
