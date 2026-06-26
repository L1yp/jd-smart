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

# ── gw 默认 App 档（进 device_md 签名 + query）────────────────────────────────
# 取用户实测通过 gw 发现的组合 HWI-AL00/7.3.0/9（device_id 不签名故不在此）。app_version 只要
# 与 query 自洽即可被 DEFAULT_KEY 验签——旧条目已把自己的版本存进 data，改这里只影响新装。
DEFAULT_HARD_PLATFORM = "HWI-AL00"
DEFAULT_APP_VERSION = "7.3.0"
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

# ── integration/v1 接口：状态快照 + 控制（同一套 HmacSHA1 签名，仅 path/body 不同）──────
# **改走 gw 统一网关**（实测 2026-06-26）：api.smart.jd.com 用小京鱼 tgt 调 integration/v1 恒
# -4「登录已过期」（它要另一 App 的登录态/pin，与发现/物模型用的 tgt 不是一套）；gw.smart.jd.com
# **转发同一** integration/v1 接口、当前 tgt 即 status=0。故 api.get_device_snapshot/control_device
# 显式 base=GW_API_BASE（见下）。API_BASE 仅留作 _post 的默认兜底，不再实际命中。
API_BASE = "https://api.smart.jd.com"  # 旧域，已不直接使用（snapshot/control 现走 GW_API_BASE）
SNAPSHOT_PATH = "/c/service/integration/v1/getDeviceSnapshot_v1"
CONTROL_PATH = "/c/service/integration/v1/controlDevice_v1"
# 注：设备完整物模型同样走 gw（getDeviceDetails，见 GW_DETAILS_PATH / api.get_device_details）；
# 彩虹版 getDeviceDetails 已退役。

# ── gw.smart.jd.com 轻量发现接口（与 getDeviceSnapshot 同一套 HmacSHA1 签名）────
# 只需 tgt + App 档 + device_id，**完全不碰彩虹**(eid/aid/ep/color_*)。用于发现家庭/设备，
# 替代彩虹 getHouses/getAllDevices。device_id 只放 query、不参与签名、服务端不严格校验。
GW_API_BASE = "https://gw.smart.jd.com"
GW_HOUSES_PATH = "/s/service/getHousesAndRooms"          # body {} → 家庭+房间
GW_DEVICES_PATH = "/c/service/devmanager/v2/getDevicesAndCategory"  # body {"houseId":"<str>"} → 设备+类目
# 完整物模型也走 gw（不再需要彩虹 getDeviceDetails / eid / color_*）：streams 在 result.streams，
# body 只需 feed_id + houseId（连 roomId 都不要）。见 api.JdSmartClient.get_device_details。
GW_DETAILS_PATH = "/c/service/devmanager/v1/getDeviceDetails"

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
