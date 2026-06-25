"""可控实体共享助手：物模型读取、流归类、命名复合。

- switch / select / number 三个平台共用 control_map 决定建哪些可控实体；
- sensor / binary_sensor 也用 control_map 来「让位」——一条流一旦成为可控实体，
  就不再重复建只读 sensor/binary_sensor（避免同一条流出现两个实体）。

只依赖纯函数 api.control_kind，不在顶层 import HA / sensor，避免循环导入。
"""
from __future__ import annotations

from .api import control_kind


def device_model(coordinator, dev: dict) -> dict:
    """该设备的物模型 {stream_id: 物模型项}（getDeviceDetails 或 card_meta 降级）。"""
    return (getattr(coordinator, "stream_models", None) or {}).get(dev["feed_id"]) or {}


def model_entry(coordinator, dev: dict, stream_id: str) -> dict:
    return device_model(coordinator, dev).get(stream_id) or {}


def control_map(coordinator, dev: dict) -> dict:
    """{stream_id: 'switch'|'select'|'number'}：该设备应建成可控实体的流。"""
    out: dict = {}
    for sid, m in device_model(coordinator, dev).items():
        kind = control_kind(m)
        if kind:
            out[sid] = kind
    return out


def control_name(coordinator, dev: dict, stream_id: str, model: dict) -> str:
    """显示名：用户覆盖名 > 物模型 stream_name > stream_id。"""
    from .sensor import overrides_for  # 延迟导入避免循环（sensor 顶层 import 本模块）

    ov = (overrides_for(coordinator, dev["feed_id"]) or {}).get(stream_id) or {}
    return ov.get("name") or model.get("name") or stream_id
