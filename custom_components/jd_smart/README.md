# JD Smart (小京鱼) — Home Assistant 自定义集成

通过逆向出的 `HmacSHA1` 签名，直接调用小京鱼云端 `getDeviceSnapshot_v1` 查询设备状态。

## 安装

把整个 `custom_components/jd_smart/` 目录拷到你的 HA 配置目录下：

```
<config>/custom_components/jd_smart/
```

重启 HA → 设置 → 设备与服务 → 添加集成 → 搜索 “JD Smart / 小京鱼”。

## 配置（初始）

填入从 App 抓到的常量（用本仓库的 frida_capture.js + host.py 抓 `sign` 表）：

| 字段 | 说明 | 是否常变 |
|---|---|---|
| `seg1` | 恒定标识，如 `a188caaf...` | 否 |
| `key` | HmacSHA1 密钥，如 `e685c8d1...` | 重新登录可能轮换 |
| `device_md` | 设备指纹 md5 = `md5("Android"+app_version+hard_platform+plat_version+":"+versionCode)` | 否 |
| `tgt` | 登录票据 `AAJq...` | **会过期/每次登录变** |
| `hard_platform` / `app_version` / `plat_version` / `channel` / `plat` | 设备指纹与 query 参数 | 否 |

## 用法

### 1) 服务（按需查询，最贴合“输入 device_id/feed_id”）

开发者工具 → 服务 → `jd_smart.get_device_snapshot`：

```yaml
service: jd_smart.get_device_snapshot
data:
  device_id: "0123456789abcdef0123456789abcdef"
  feed_id: "100000000000000000"
```

带返回值（response），直接在开发者工具里看到完整快照 JSON。

### 2) 传感器（自动轮询）

集成 → 配置（选项）里填 **设备列表**，每行一个：

```
客厅空调|0123456789abcdef0123456789abcdef|100000000000000000
卧室灯|<device_id>|<feed_id>
```

每个设备生成一个 sensor：state 为返回的状态码，完整快照在属性 `snapshot` 里（可用模板传感器二次提取你要的字段）。轮询间隔在选项里改（默认 60s）。

## 凭据过期怎么办

`tgt` 会过期、`key` 重新登录可能轮换。失效时（请求返回鉴权错误 / sensor 变 unavailable）：

1. 用 frida 重新抓一份当前的 `tgt`（必要时连 `key` 一起）；
2. 集成 → 配置（选项）→ 更新 `tgt`（无需删除重加）；`key` 变了则删除集成重新添加。

## 注意

- **时间戳时区**：本集成用 UTC 生成 `ts`。若服务器因时间戳拒绝（鉴权失败但 key 没问题），多半是 App 实际用的是本地时间贴 `Z`；改 `api.py` 的 `now_ts()` 即可。
- **签名只覆盖 body**（不含 query）：`device_id` 在 query、`feed_id` 在 body，两者都要填。
- `tag="postjson_body"` 是 postJson 类请求的标记；其它接口若是别的请求类型，签名 tag 可能不同（届时另抓）。
- 先用仓库根目录的 `query_device.py` 联网自测通过，再依赖本集成：
  ```
  python query_device.py --device-id <id> --feed-id <feed_id>
  ```

## 返回数据与传感器

响应形如：

```json
{"status":0,"error":null,"result":"{\"streams\":[{\"current_value\":\"234937\",\"stream_id\":\"Voltage\"}, ...]}"}
```

`result` 是被转义的内层 JSON 字符串，集成会自动解析。每个设备生成：

- `<名称> 状态`：online/offline，属性里带 `streams`（完整字典）、`device_status`、`error` 等；
- `<名称> <stream_id>`：每个数据流一个数值传感器（如 Voltage / Electric / Power / CurrentPowerSum），值取 `current_value`，能转数字就转。stream 动态出现，自动补建。
- `<名称> 实时功率`（W）：**计算型**，= 电压 × 电流（视在功率，设备未直接上报瓦特）。功率因数≈1 的负载与真实有功功率相差很小。需要设备同时上报 `Voltage` 与 `Electric` 才会生成。
- `<名称> 今日用电量`（kWh）：**计算型**，对 `CurrentPowerSum` 增量累加，本地零点清零，`state_class=TOTAL_INCREASING`（可直接进能量看板）。跨 HA 重启不丢；容忍设备计数被清零/回绕。需要设备上报 `CurrentPowerSum`。

### 单位/缩放（设备相关，集成内已集中标定）

原始值不带单位、且常是放大整数。缩放因子集中在 `sensor.py` 顶部三个常量，是整个集成的“单一真相”：

| 常量 | 含义 | 当前值（“解释 A”，已与小京鱼 App 实测 ≈19W 核对） |
|---|---|---|
| `VOLTAGE_TO_VOLT` | Voltage 原始 → V | `0.001`（毫伏） |
| `ELECTRIC_TO_AMP` | Electric 原始 → A | `0.001`（毫安） |
| `ENERGY_RAW_TO_KWH` | CurrentPowerSum 原始 → kWh | `0.0001`（0.1Wh） |

> 注：仅凭抓包数据，电流/能量的绝对刻度存在 **10 倍歧义**（两种解释功率因数都≈0.94，无法区分）。
> 若你的 App 实时功率/今日电量与显示差 10 倍，切到“解释 B”：把 `ELECTRIC_TO_AMP` 改 `0.01`、
> `ENERGY_RAW_TO_KWH` 改 `0.001` 即可（实时功率会变 ~190W、电量量级 ×10）。
> `Power` 是开关量（on/off），由 binary_sensor 平台呈现，不在此换算。
