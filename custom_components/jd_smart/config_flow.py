"""Config & options flow for JD Smart."""
from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.helpers import selector

from .const import (
    CONF_APP_VERSION,
    CONF_CHANNEL,
    CONF_DEVICE_MD,
    CONF_DEVICES,
    CONF_HARD_PLATFORM,
    CONF_KEY,
    CONF_PLAT,
    CONF_PLAT_VERSION,
    CONF_SCAN_INTERVAL,
    CONF_SEG1,
    CONF_TGT,
    DEFAULT_APP_VERSION,
    DEFAULT_CHANNEL,
    DEFAULT_HARD_PLATFORM,
    DEFAULT_PLAT,
    DEFAULT_PLAT_VERSION,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
)

ACCOUNT_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_SEG1): str,
        vol.Required(CONF_KEY): str,
        vol.Required(CONF_DEVICE_MD): str,
        vol.Required(CONF_TGT): str,
        vol.Required(CONF_HARD_PLATFORM, default=DEFAULT_HARD_PLATFORM): str,
        vol.Required(CONF_APP_VERSION, default=DEFAULT_APP_VERSION): str,
        vol.Required(CONF_PLAT_VERSION, default=DEFAULT_PLAT_VERSION): str,
        vol.Required(CONF_CHANNEL, default=DEFAULT_CHANNEL): str,
        vol.Required(CONF_PLAT, default=DEFAULT_PLAT): str,
    }
)


class JdSmartConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """账号/签名常量的初始配置。"""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        if user_input is not None:
            await self.async_set_unique_id(user_input[CONF_SEG1])
            self._abort_if_unique_id_configured()
            return self.async_create_entry(title="小京鱼 JD Smart", data=user_input)
        return self.async_show_form(step_id="user", data_schema=ACCOUNT_SCHEMA)

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> "JdSmartOptionsFlow":
        return JdSmartOptionsFlow(config_entry)


class JdSmartOptionsFlow(config_entries.OptionsFlow):
    """更新 tgt（会过期）、轮询间隔、监控设备列表。"""

    def __init__(self, entry: config_entries.ConfigEntry) -> None:
        self._entry = entry

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)
        opts = self._entry.options
        schema = vol.Schema(
            {
                vol.Optional(
                    CONF_TGT,
                    default=opts.get(CONF_TGT, self._entry.data.get(CONF_TGT, "")),
                ): str,
                vol.Optional(
                    CONF_SCAN_INTERVAL,
                    default=opts.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
                ): int,
                vol.Optional(
                    CONF_DEVICES, default=opts.get(CONF_DEVICES, "")
                ): selector.TextSelector(
                    selector.TextSelectorConfig(multiline=True)
                ),
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema)
