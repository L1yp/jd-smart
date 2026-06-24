"""Constants for the JD Smart (小京鱼) integration."""

DOMAIN = "jd_smart"
PLATFORMS = ["sensor", "binary_sensor"]
# 这些 stream_id 是开关量(on/off)，用 binary_sensor 表示；其余作数值 sensor。
# card_control 里的 on/off 二值枚举流会自动并入（见 binary_sensor），这里是静态兜底。
BINARY_STREAMS = {"Power"}

# ── config entry：账号 / 签名常量（旧 getDeviceSnapshot 轮询用）──────────────
CONF_SEG1 = "seg1"
CONF_KEY = "key"
# device_md 不再手填：含 DAY_OF_YEAR 每天滚动，由 api 用 app_version/hard_platform/plat_version 实时算
CONF_TGT = "tgt"
CONF_HARD_PLATFORM = "hard_platform"
CONF_APP_VERSION = "app_version"
CONF_PLAT_VERSION = "plat_version"
CONF_CHANNEL = "channel"
CONF_PLAT = "plat"

# ── config entry：彩虹网关凭据（getHouses/getAllDevices 发现用）──────────────
CONF_COLOR_SIGN_SECRET = "color_sign_secret"
CONF_COLOR_PIN = "color_pin"
CONF_COLOR_JMAFINGER = "color_jmafinger"

# ── config entry：设备身份/档位 ───────────────────────────────────────────
CONF_ANDROID_ID = "android_id"   # Settings.Secure.ANDROID_ID(16hex)；自动算 aid=uuid=md5、device_id
CONF_EID = "eid"                 # 设备指纹；留空则按 android_id 走 ds.json 自动铸并缓存
CONF_D_BRAND = "d_brand"
CONF_D_MODEL = "d_model"
CONF_OS_VERSION = "os_version"     # -> color_profile["osVersion"]
CONF_SCREEN = "screen"
CONF_AREA = "area"
CONF_NETWORK_TYPE = "network_type"  # -> color_profile["networkType"]

# ── options ───────────────────────────────────────────────────────────────
CONF_DEVICES = "devices"               # 结构化设备缓存：list[{feed_id,device_id,name,room,...,card_meta}]
CONF_HOUSES = "houses"                 # 家庭缓存：list[{house_id,house_name}]
CONF_STREAM_OVERRIDES = "stream_overrides"  # {feed_id: {stream_id: {name,unit,enabled}}}
CONF_DEVICE_ID_OVERRIDE = "device_id_override"  # 不填则 device_id = md5(android_id)
CONF_SCAN_INTERVAL = "scan_interval"

# ── 旧接口默认值（getDeviceSnapshot）────────────────────────────────────────
DEFAULT_HARD_PLATFORM = "HWI-AL00"
DEFAULT_APP_VERSION = "1.17.0"
DEFAULT_PLAT_VERSION = "9"
DEFAULT_CHANNEL = "xjgw-android"
DEFAULT_PLAT = "Android"
DEFAULT_SCAN_INTERVAL = 90

# App 全局固定值（所有账号/设备相同，照抄即可）——作为表单默认内置，免得每次手抄。
# 见 jd_smart_secrets.example.json 的"固定值"标注。
DEFAULT_SEG1 = "a188caaf009839ba200bb55bb8fa38407a595c2a"
DEFAULT_KEY = "e685c8d1daa7e4dec8821a3df41c0b34a56db779"
DEFAULT_COLOR_SIGN_SECRET = "6b086ed29b1a4483b4544143061b295d"

# ── 彩虹设备档：示例默认值（设备相关，用户按需改）+ 固定常量（所有设备相同）──────
DEFAULT_D_BRAND = "HUAWEI"
DEFAULT_D_MODEL = "HWI-AL00"
DEFAULT_OS_VERSION = "28"
DEFAULT_SCREEN = "1080*2160"
DEFAULT_AREA = "20_1720_22909_60380"
DEFAULT_NETWORK_TYPE = "wifi"
# 按 App 构建固定（appid 与 color_api.APPID 同源）；ext 是固定 prstate 标记
COLOR_PROFILE_FIXED = {
    "appid": "jdsmart-android",
    "build": "381",
    "client": "android",
    "clientVersion": "1.17.0",
    "ext": '{"prstate":"0"}',
    "partner": "xjgw-android",
}

# ── 旧 getDeviceSnapshot 接口 ──────────────────────────────────────────────
API_BASE = "https://api.smart.jd.com"
SNAPSHOT_PATH = "/c/service/integration/v1/getDeviceSnapshot_v1"

SERVICE_GET_SNAPSHOT = "get_device_snapshot"
ATTR_DEVICE_ID = "device_id"
ATTR_FEED_ID = "feed_id"
