"""Constants for the JD Smart (小京鱼) integration."""

DOMAIN = "jd_smart"
PLATFORMS = ["sensor", "binary_sensor", "switch", "select", "number"]
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
# 设备身份二选一：android_id 或 device_id（首选 device_id，部分机型读不到 android_id）。
# device_id == 彩虹 aid == uuid == md5(android_id)，是同一个值；填了 device_id 就不需要 android_id。
CONF_ANDROID_ID = "android_id"   # Settings.Secure.ANDROID_ID(16hex)；自动算 aid=uuid=md5=device_id
CONF_DEVICE_ID = "device_id"     # 直填设备 device_id(=md5(android_id))；与 android_id 二选一，优先用它
CONF_EID = "eid"                 # 设备指纹；留空则按身份(android_id/device_id)走 ds.json 自动铸并缓存
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
CONF_DEVICE_ID_OVERRIDE = "device_id_override"  # 旧字段：等价于 CONF_DEVICE_ID，仍兼容读取
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

# ── api.smart.jd.com 接口（同一套 HmacSHA1 签名，仅 path/body 不同）────────────
API_BASE = "https://api.smart.jd.com"
SNAPSHOT_PATH = "/c/service/integration/v1/getDeviceSnapshot_v1"
CONTROL_PATH = "/c/service/integration/v1/controlDevice_v1"
# 注：设备物模型走**彩虹网关** functionId jdsmart.device.getDeviceDetails（api.m.jd.com，
# 彩虹 HMAC-SHA256），不在本组 smart-api path 里，见 color_api.JdColorClient.get_device_details。

SERVICE_GET_SNAPSHOT = "get_device_snapshot"
SERVICE_CONTROL_DEVICE = "control_device"
# 诊断：拉取并返回某设备的彩虹 getDeviceDetails 物模型（原始响应 + 解析 + 可控归类），
# 用于排查"为什么只生成了 Power 开关"——card_meta 降级模型 card_control 只标了 Power 可控。
SERVICE_GET_DEVICE_MODEL = "get_device_model"
ATTR_DEVICE_ID = "device_id"
ATTR_FEED_ID = "feed_id"
ATTR_STREAM_ID = "stream_id"   # 控制服务：单条流写值（与 ATTR_VALUE 搭配）
ATTR_VALUE = "value"
ATTR_COMMAND = "command"       # 控制服务：原始命令数组 [{stream_id,current_value},...]
