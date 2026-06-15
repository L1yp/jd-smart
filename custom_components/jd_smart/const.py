"""Constants for the JD Smart (小京鱼) integration."""

DOMAIN = "jd_smart"
PLATFORMS = ["sensor", "binary_sensor"]
# 这些 stream_id 是开关量(on/off)，用 binary_sensor 表示；其余作数值 sensor。
BINARY_STREAMS = {"Power"}

# config entry (account / device fingerprint)
CONF_SEG1 = "seg1"
CONF_KEY = "key"
# device_md 不再手填：含 DAY_OF_YEAR 每天滚动，由 api 用 app_version/hard_platform/plat_version 实时算
CONF_TGT = "tgt"
CONF_HARD_PLATFORM = "hard_platform"
CONF_APP_VERSION = "app_version"
CONF_PLAT_VERSION = "plat_version"
CONF_CHANNEL = "channel"
CONF_PLAT = "plat"

# options
CONF_DEVICES = "devices"
CONF_SCAN_INTERVAL = "scan_interval"

DEFAULT_HARD_PLATFORM = "HWI-AL00"
DEFAULT_APP_VERSION = "1.17.0"
DEFAULT_PLAT_VERSION = "9"
DEFAULT_CHANNEL = "xjgw-android"
DEFAULT_PLAT = "Android"
DEFAULT_SCAN_INTERVAL = 60

API_BASE = "https://api.smart.jd.com"
SNAPSHOT_PATH = "/c/service/integration/v1/getDeviceSnapshot_v1"

SERVICE_GET_SNAPSHOT = "get_device_snapshot"
ATTR_DEVICE_ID = "device_id"
ATTR_FEED_ID = "feed_id"
