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
| `tgt` | 登录票据 `AAJq...` | **会过期/每次登录变** |
| `hard_platform` / `app_version` / `plat_version` / `channel` / `plat` | device_md 输入 + query 参数 | 否（App 升级才变） |

> `device_md` **无需填写**：= `md5("Android"+app_version+hard_platform+plat_version+":"+当年第几天)`，
> 末尾 `DAY_OF_YEAR` **每天滚动一次**——这正是“tgt 没变插件也会失效”的根因。集成用上面三个设备参数按
> `Asia/Shanghai` 当天实时算，不再手填、不会每天过期。App 升级后只需更新 `app_version`/`plat_version`/`hard_platform`。

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

- **时间戳时区**：实测京东服务端按“北京时间(UTC+8)墙上时钟贴 `Z`”校验 `ts`，发**真 UTC** 会慢 8 小时被判 `token invalid`。集成 `now_ts()` 已用固定 UTC+8 偏移生成，无需改动；自测脚本 `query_device.py` 同理（已去掉旧的 `--local` 开关）。
- **device_md 每日滚动**：= `md5(...+":"+当年第几天)`，集成按 `Asia/Shanghai` 取“今天第几天”实时算（对齐 App 与京东服务端）。若设备/服务端不在东八区、午夜前后偶发鉴权失败，改 `api.py` `_device_md()` 里的时区即可。
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

设备实际只上报 4 个 stream：

| stream | 含义 | 单位（设备统一用“毫”） | 呈现实体 |
|---|---|---|---|
| `Voltage` | 电压 | 毫伏 mV → V | `<名称> Voltage` |
| `Electric` | 电流 | 毫安 mA（按 mA 直接显示） | `<名称> Electric` |
| `Power` | 继电器开关量 | on/off | binary_sensor `<名称> Power` |
| `CurrentPowerSum` | **实时有功功率**（名字含 Sum，但其值会上下波动，是瞬时功率不是累计电量） | 毫瓦 mW → W | 见下方“实时功率” |

每个设备生成：

- `<名称> 状态`：online/offline，属性里带 `streams`（完整字典）、`device_status`、`error` 等；
- `<名称> 实时功率`（W）：直接取 `CurrentPowerSum`（设备计量芯片已算好功率因数的**真有功功率**）。已与外部空调伴侣实测待机 <3W 对齐。
- `<名称> 今日用电量`（kWh）：设备**没有累计电量流**，由实时功率做**梯形时间积分**（∫P·dt）得到，本地零点清零，`state_class=TOTAL_INCREASING`（可直接进能量看板）。跨 HA 重启不丢；两次读数间隔过大（重启/断连）时跳过该段，不凭空累加。

### 单位/缩放（设备相关，集成内已集中标定）

设备各路数值统一是“毫”单位，缩放因子集中在 `sensor.py` 顶部，是整个集成的“单一真相”：

| 常量 | 含义 | 当前值 |
|---|---|---|
| `VOLTAGE_TO_VOLT` | Voltage 毫伏 → V | `0.001` |
| `ELECTRIC_TO_AMP` | Electric 毫安 → A（电流实体本身按 mA 显示，此常量备用） | `0.001` |
| `POWER_RAW_TO_WATT` | CurrentPowerSum 毫瓦 → W | `0.001` |

> **关于功率“真有功 vs 视在”**：`电压×电流`=视在功率(VA)，对空调待机这类开关电源(SMPS)负载功率因数极低(~0.15)，
> V×I 会比真功率高出数倍（如 235V×0.082A≈19VA，真功率仅≈3W）。所以**不要**用 V×I 当功率；
> 设备已直接给出真有功功率 `CurrentPowerSum`，本集成即取它。
>
> **校准**：若空调开机后实时功率明显不是额定值（差约 10 倍），改 `POWER_RAW_TO_WATT` 即可。
> 待机 2960(mW)→2.96W；开机时该值应接近空调实际功率（约几百~上千 W）。
