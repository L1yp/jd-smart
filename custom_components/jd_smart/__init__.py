"""JD Smart (小京鱼) integration."""
from __future__ import annotations

import logging
import re

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall, SupportsResponse
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import JdSmartClient, JdSmartError, parse_snapshot
from .const import (
    ATTR_COMMAND,
    ATTR_DEVICE_ID,
    ATTR_FEED_ID,
    ATTR_STREAM_ID,
    ATTR_VALUE,
    CONF_APP_VERSION,
    CONF_CHANNEL,
    CONF_COLOR_SIGN_SECRET,
    CONF_DEVICES,
    CONF_HARD_PLATFORM,
    CONF_KEY,
    CONF_PLAT,
    CONF_PLAT_VERSION,
    CONF_SCAN_INTERVAL,
    CONF_SEG1,
    CONF_STREAM_OVERRIDES,
    CONF_TGT,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    PLATFORMS,
    SERVICE_CONTROL_DEVICE,
    SERVICE_GET_DEVICE_MODEL,
    SERVICE_GET_SNAPSHOT,
)
from .coordinator import JdSmartCoordinator

_LOGGER = logging.getLogger(__name__)


def _load_devices(entry: ConfigEntry) -> list[dict]:
    """读 entry.options 里的设备：新版是结构化 list[dict]（含 card_meta），旧版兼容文本。

    统一 device_id：直填 device_id / device_id_override / md5(android_id)（同一个值）> 缓存值。
    解析单一真源用 config_flow._device_id_for。运行时轮询只需 device_id+feed_id。
    """
    from .config_flow import _device_id_for  # 局部导入避免顶层依赖 config_flow

    raw = entry.options.get(CONF_DEVICES)
    devices = [dict(d) for d in raw] if isinstance(raw, list) else parse_devices(raw)
    resolved = _device_id_for(_merged(entry))
    for d in devices:
        d["device_id"] = resolved or d.get("device_id")
    # 启动即暴露运行时 device_id：状态/控制都靠它。若不像 md5(android_id)（32 位十六进制、
    # 无连字符），多半是误把 App 安装 UUID（gw 接口里那种 a95d…-…）填进了 device_id 字段。
    did = (devices[0].get("device_id") if devices else "") or ""
    _LOGGER.info("加载 %d 台设备，smart device_id=%s", len(devices), did or "(空)")
    if did and (len(did) != 32 or "-" in did):
        _LOGGER.warning(
            "device_id=%s 不像 md5(android_id)（应为 32 位十六进制、无连字符）。api.smart 的状态/控制"
            "需要这个值——别把 App 安装 UUID 填进 device_id 字段；留空改用 android_id，或填 md5(android_id)。",
            did,
        )
    return devices


def parse_devices(text: str | None) -> list[dict]:
    """旧版文本格式兼容：每行 '名称|device_id|feed_id'（名称可省略）；也支持用 ; 分隔。"""
    devices: list[dict] = []
    if not text:
        return devices
    for line in re.split(r"[\n;]+", str(text)):
        line = line.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) == 3:
            name, device_id, feed_id = parts
        elif len(parts) == 2:
            device_id, feed_id = parts
            name = device_id
        else:
            continue
        if device_id and feed_id:
            devices.append({"name": name, "device_id": device_id, "feed_id": feed_id})
    return devices


def _merged(entry: ConfigEntry) -> dict:
    """entry.data 叠加 entry.options（非空覆盖）。选项里补填/改的 凭据/设备档 才会在运行时生效。"""
    cfg = dict(entry.data)
    for k, v in (entry.options or {}).items():
        if v not in (None, ""):
            cfg[k] = v
    return cfg


def _client_from_entry(hass: HomeAssistant, entry: ConfigEntry) -> JdSmartClient:
    cfg = _merged(entry)  # 选项里改的 tgt/seg1/key/机型 等优先（可热更新）
    return JdSmartClient(
        async_get_clientsession(hass),
        seg1=cfg[CONF_SEG1],
        key=cfg[CONF_KEY],
        tgt=cfg[CONF_TGT],
        hard_platform=cfg[CONF_HARD_PLATFORM],
        app_version=cfg[CONF_APP_VERSION],
        plat_version=cfg[CONF_PLAT_VERSION],
        channel=cfg[CONF_CHANNEL],
        plat=cfg[CONF_PLAT],
    )


async def _async_fetch_models(hass: HomeAssistant, entry: ConfigEntry, coordinator) -> None:
    """用彩虹客户端拉各设备物模型（jdsmart.device.getDeviceDetails）。

    复用 config_flow 的彩虹客户端构建 + eid 解析；任何一步失败都静默跳过，
    实体退回 card_meta 派生（不阻断 setup）。物模型只在此拉一次（静态元数据）。
    """
    # 局部导入：避免 __init__ 顶层依赖 config_flow（HA 加载顺序更稳）
    from .config_flow import _async_resolve_eid, _build_color_client, _has_identity

    cfg = _merged(entry)
    if not cfg.get(CONF_COLOR_SIGN_SECRET) or not _has_identity(cfg):
        return  # 旧条目没填彩虹凭据/设备身份：跳过
    try:
        eid, err = await _async_resolve_eid(hass, cfg)
        if err or not eid:
            _LOGGER.debug("物模型抓取跳过：eid 解析失败 %s", err)
            return
        color_client = _build_color_client(hass, cfg, eid)
    except Exception as err:  # noqa: BLE001  发现链路任何异常都不应拖垮 setup
        _LOGGER.debug("物模型抓取跳过：彩虹客户端构建失败 %s", err)
        return
    await coordinator.async_fetch_models(color_client)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    client = _client_from_entry(hass, entry)
    devices = _load_devices(entry)
    scan = entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
    overrides = entry.options.get(CONF_STREAM_OVERRIDES, {}) or {}

    coordinator = JdSmartCoordinator(hass, client, devices, scan, stream_overrides=overrides)
    if devices:
        await coordinator.async_config_entry_first_refresh()
        # 拉各设备「可控流物模型」（彩虹 getDeviceDetails），供 switch/select/number 建实体；
        # 失败仅记日志、回退 card_meta，不阻断 setup。
        await _async_fetch_models(hass, entry, coordinator)

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    _async_register_services(hass)
    entry.async_on_unload(entry.add_update_listener(_async_reload_entry))
    return True


async def _async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        hass.data[DOMAIN].pop(entry.entry_id, None)
        if not hass.data[DOMAIN]:
            hass.services.async_remove(DOMAIN, SERVICE_GET_SNAPSHOT)
            hass.services.async_remove(DOMAIN, SERVICE_CONTROL_DEVICE)
            hass.services.async_remove(DOMAIN, SERVICE_GET_DEVICE_MODEL)
    return unloaded


def _find_device_by_feed(hass: HomeAssistant, feed_id) -> tuple:
    """按 feed_id 在所有配置条目里找 (coordinator, dev)。feed_id 按字符串比对（大整数/字符串都兼容）。"""
    target = str(feed_id)
    for coordinator in hass.data.get(DOMAIN, {}).values():
        for dev in getattr(coordinator, "devices", []):
            if str(dev.get("feed_id")) == target:
                return coordinator, dev
    return None, None


def _entry_for_coordinator(hass: HomeAssistant, coordinator) -> ConfigEntry | None:
    """反查 coordinator 所属的 ConfigEntry（按 entry_id 索引），以复用该账号凭据。"""
    for entry_id, coord in hass.data.get(DOMAIN, {}).items():
        if coord is coordinator:
            return hass.config_entries.async_get_entry(entry_id)
    return None


def _build_commands(data: dict) -> list[dict]:
    """控制服务两种入参：command 数组（原始）或 stream_id+value（单条）。"""
    raw = data.get(ATTR_COMMAND)
    if raw:
        cmds = []
        for c in raw:
            sid = c.get("stream_id") if isinstance(c, dict) else None
            if sid is None or "current_value" not in c:
                raise HomeAssistantError("command 每项需含 stream_id 和 current_value")
            cmds.append({"stream_id": sid, "current_value": c["current_value"]})
        return cmds
    sid = data.get(ATTR_STREAM_ID)
    if sid is not None and ATTR_VALUE in data:
        return [{"stream_id": sid, "current_value": data[ATTR_VALUE]}]
    raise HomeAssistantError("请提供 stream_id+value，或 command 数组")


def _async_register_services(hass: HomeAssistant) -> None:
    if hass.services.has_service(DOMAIN, SERVICE_GET_SNAPSHOT):
        return

    async def _handle_get_snapshot(call: ServiceCall) -> dict:
        device_id = call.data[ATTR_DEVICE_ID]
        feed_id = call.data[ATTR_FEED_ID]
        store = hass.data.get(DOMAIN, {})
        if not store:
            raise HomeAssistantError("jd_smart 尚未配置")
        # 多账号：优先用拥有该 feed_id 的账号客户端（tgt/签名才匹配）；
        # 没选过的设备退回任一账号兜底。
        coordinator, _dev = _find_device_by_feed(hass, feed_id)
        if coordinator is None:
            coordinator = next(iter(store.values()))
        try:
            data = await coordinator.client.get_device_snapshot(device_id, feed_id)
        except JdSmartError as err:
            raise HomeAssistantError(f"查询失败: {err}") from err
        parsed = parse_snapshot(data)
        return {
            "device_id": device_id,
            "feed_id": feed_id,
            "ok": parsed["ok"],
            "streams": parsed["streams"],
            "snapshot": data,
        }

    hass.services.async_register(
        DOMAIN,
        SERVICE_GET_SNAPSHOT,
        _handle_get_snapshot,
        schema=vol.Schema(
            {
                vol.Required(ATTR_DEVICE_ID): cv.string,
                vol.Required(ATTR_FEED_ID): cv.string,
            }
        ),
        supports_response=SupportsResponse.ONLY,
    )

    async def _handle_control_device(call: ServiceCall) -> dict:
        feed_id = call.data[ATTR_FEED_ID]
        coordinator, dev = _find_device_by_feed(hass, feed_id)
        if dev is None:
            raise HomeAssistantError(f"未找到 feed_id={feed_id} 的设备（先在集成里选好设备）")
        commands = _build_commands(call.data)
        try:
            parsed = await coordinator.async_control(dev, commands)
        except JdSmartError as err:
            raise HomeAssistantError(f"控制失败: {err}") from err
        return {
            "feed_id": feed_id,
            "ok": parsed["ok"],
            "control_ret": parsed.get("control_ret"),
            "streams": parsed["streams"],
            "result": parsed.get("raw"),
        }

    hass.services.async_register(
        DOMAIN,
        SERVICE_CONTROL_DEVICE,
        _handle_control_device,
        schema=vol.Schema(
            {
                vol.Required(ATTR_FEED_ID): cv.string,
                vol.Optional(ATTR_STREAM_ID): cv.string,
                vol.Optional(ATTR_VALUE): vol.Any(int, float, str),
                vol.Optional(ATTR_COMMAND): [dict],
            }
        ),
        supports_response=SupportsResponse.OPTIONAL,
    )

    async def _handle_get_device_model(call: ServiceCall) -> dict:
        """诊断：拉某设备的彩虹 getDeviceDetails 物模型，返回原始响应 + 解析 + 可控归类。

        排查"为什么只有 Power 开关"：若 control_map 为空/缺 Mode/Wind 等，多半是
        getDeviceDetails 没返回物模型（接口形态/凭据问题），运行时便静默回退了 card_meta。
        """
        from .api import control_kind, parse_stream_model
        from .color_api import JdColorError
        from .config_flow import _async_resolve_eid, _build_color_client, _has_identity

        feed_id = call.data[ATTR_FEED_ID]
        coordinator, dev = _find_device_by_feed(hass, feed_id)
        if dev is None:
            raise HomeAssistantError(f"未找到 feed_id={feed_id} 的设备（先在集成里选好设备）")
        entry = _entry_for_coordinator(hass, coordinator)
        if entry is None:
            raise HomeAssistantError("找不到该设备所属配置条目")
        cfg = _merged(entry)
        if not cfg.get(CONF_COLOR_SIGN_SECRET) or not _has_identity(cfg):
            raise HomeAssistantError("缺少彩虹凭据(color_sign_secret)或设备身份(device_id/android_id)，无法查询物模型")
        eid, err = await _async_resolve_eid(hass, cfg)
        if err or not eid:
            raise HomeAssistantError(f"eid 解析失败: {err}")
        color_client = _build_color_client(hass, cfg, eid)
        try:
            raw = await color_client.get_device_details(
                feed_id,
                house_id=dev.get("house_id"),
                room_id=dev.get("room_id"),
                device_id=dev.get("hw_device_id"),
            )
        except JdColorError as e:
            raise HomeAssistantError(f"getDeviceDetails 调用失败: {e}") from e
        model = parse_stream_model(raw)
        control_map = {sid: k for sid, m in model.items() if (k := control_kind(m))}
        return {
            "feed_id": feed_id,
            "name": dev.get("name"),
            "streams_parsed": len(model),
            "control_map": control_map,   # {stream_id: switch|select|number}
            "model": model,               # 解析后的物模型（含 options/min/max/unit）
            "raw": raw,                   # 原始响应，便于核对接口形态
        }

    hass.services.async_register(
        DOMAIN,
        SERVICE_GET_DEVICE_MODEL,
        _handle_get_device_model,
        schema=vol.Schema({vol.Required(ATTR_FEED_ID): cv.string}),
        supports_response=SupportsResponse.ONLY,
    )
