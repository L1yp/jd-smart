# 小京鱼（com.jd.smart）设备快照接口 · 逆向分析笔记

> 个人研究/自用记录。本文只描述协议与方法论，**不含任何真实密钥**（凭据放
> `jd_smart_secrets.json`，已 `.gitignore`）。文中所有 `<...>`、`a188ca…` 一类均为占位/示意。

目标接口：`getDeviceSnapshot_v1`（按 `device_id` + `feed_id` 拉设备实时快照，
如电流/电压/功率）。通过逆向出的 `HmacSHA1` 鉴权签名直接调云端，无需官方网关。

---

## 0. 速查（TL;DR）

```
POST https://api.smart.jd.com/c/service/integration/v1/getDeviceSnapshot_v1
     ?hard_platform=HWI-AL00&app_version=1.17.0&device_id=<32hex>
     &plat_version=9&channel=xjgw-android&plat=Android

Headers:
  app_identity : WL
  authorization: smart <seg1>:::<seg2>:::<ts>
  tgt          : <登录票据，会过期>
  content-type : application/json; charset=utf-8
  user-agent   : okhttp/4.10.0

Body（紧凑、键序固定，被签名的就是这串字节）:
  {"json":{"feed_id":<int>,"version":"2.0","digest":""}}

签名:
  device_md = md5("Android" + app_version + hard_platform + plat_version + ":" + DAY_OF_YEAR)
  message   = device_md + "postjson_body" + body + ts + seg1 + device_md
  seg2      = Base64( HmacSHA1(key, message) )          # 标准 base64，带 '=' 填充
  ts        = 北京时间(UTC+8)墙上时钟，格式 %Y-%m-%dT%H:%M:%S.mmmZ   # Z 名不副实！
```

**三个最容易踩的坑**（每一个都对应一次线上事故/commit）：

1. `device_md` 末尾的 `DAY_OF_YEAR`（当年第几天）**每天 +1** → 即使 `tgt` 没变，
   插件/脚本第二天也会签名失效。必须实时算，不能写死。
2. `ts` 发的是 **UTC+8 墙上时钟贴 `Z`**，不是真 UTC。发真 UTC 会比服务器慢 8 小时，
   被判 `token invalid`（401）。
3. 签名**只覆盖 body**（不含 query）：`device_id` 在 query、`feed_id` 在 body，两者都要给对。

---

## 1. 接口总览

### 1.1 请求

- **方法 / URL**：`POST https://api.smart.jd.com/c/service/integration/v1/getDeviceSnapshot_v1`
- **Query 参数**（设备指纹 + 定位，不参与签名）：

  | 参数 | 示例 | 含义 |
  |---|---|---|
  | `hard_platform` | `HWI-AL00` | 机型，= App `BaseInfo.getDeviceModel()` |
  | `app_version` | `1.17.0` | App 版本 |
  | `device_id` | `<32 位 hex>` | 目标设备 id（**只在 query**） |
  | `plat_version` | `9` | = `Build.VERSION.RELEASE` |
  | `channel` | `xjgw-android` | 渠道 |
  | `plat` | `Android` | 平台 |

- **Body**：`{"json":{"feed_id":<int>,"version":"2.0","digest":""}}`
  - 必须**紧凑**（无空格）、**键序固定**；`feed_id` 是整数（**只在 body**）。
  - 发出去的就是被签名的那串字节——**不能让 HTTP 框架重新序列化**（HA 集成里用
    `data=body.encode()` 而非 `json=`，正是这个原因）。

### 1.2 响应

成功（外层 `status:0`，`result` 是一层 JSON **字符串**，需再 parse）：

```json
{
  "status": 0,
  "error": null,
  "result": "{\"digest\":\"432848389\",\"fromDeviceSuccess\":false,\"status\":\"1\",\"streams\":[{\"current_value\":\"83\",\"stream_id\":\"Electric\"},{\"current_value\":\"236040\",\"stream_id\":\"Voltage\"},{\"current_value\":\"1\",\"stream_id\":\"Power\"},{\"current_value\":\"3170\",\"stream_id\":\"CurrentPowerSum\"}]}"
}
```

- 内层 `streams[].stream_id / current_value` 才是真正的设备数据点
  （`Electric` 电流、`Voltage` 电压、`Power` 开关、`CurrentPowerSum` 累计电量等）。

鉴权失败（HTTP 仍是 200，靠 body 里的 `status:100` + `error` 判断）：

```json
{ "result": {}, "error": { "errorInfo": "token invalid", "errorCode": "401" }, "status": 100 }
```

---

## 2. 鉴权头与签名算法（核心）

### 2.1 `Authorization` 结构

```
authorization: smart <seg1>:::<seg2>:::<ts>
                     └seg1┘   └seg2┘   └ ts ┘
```

- `seg1`：40 位 hex（解出 20 字节），恒定的账号/设备标识。
- `seg2`：base64 串（解出 20 字节），就是这次请求的签名。
- `ts`：时间戳（也单独参与 HMAC 原文）。
- 三段用 `:::` 分隔。`seg1`、`seg2` 都是 20 字节 → 一眼锁定 **SHA-1 家族**（HmacSHA1/SHA-1）。

### 2.2 `device_md`（设备指纹，每天滚动）

逆向自 `RestClient.getAuthorization`：

```
c10 = md5("Android" + app_version + deviceModel + Build.VERSION.RELEASE + ":" + Calendar.get(DAY_OF_YEAR))
```

对应到本仓库参数：

```
device_md = md5("Android" + app_version + hard_platform + plat_version + ":" + DAY_OF_YEAR)
          = md5("Android" + "1.17.0"    + "HWI-AL00"     + "9"          + ":" + 167)   # 示例：第167天
```

- 末尾 `DAY_OF_YEAR`（当年第几天）**每天 +1**，所以 `device_md` 每天都变。
- **这就是"tgt 没变，插件/脚本却第二天失效"的真正原因**——很多人误以为是票据过期。
- `DAY_OF_YEAR` 按 **UTC+8（Asia/Shanghai，中国标准时无夏令时）** 取，对齐 App（设备本地时区）
  与京东服务端。代码里用**固定 +8 偏移**算，免依赖宿主机时区 / 系统 IANA tzdata。

### 2.3 HMAC 原文与 `seg2`

```
TAG     = "postjson_body"                                   # postJson 类请求的标记
message = device_md + TAG + body + ts + seg1 + device_md    # device_md 首尾各拼一次
seg2    = Base64( HmacSHA1(key, message) )                  # 标准 base64，带 '=' 填充
```

- `key`：HmacSHA1 密钥，从 frida 抓 `Mac.init` 的 `key_txt` 得到；恒定（重新登录**可能**轮换）。
- `TAG` 与请求类型绑定：`postJson` 用 `postjson_body`；GET 等其它请求类型 tag 多半不同（届时另抓）。

### 2.4 `ts` 时间戳（UTC+8 贴 Z 的坑）

- 格式：`2026-06-16T20:59:57.403Z`（`%Y-%m-%dT%H:%M:%S.` + 毫秒 + `Z`）。
- **实测**：客户端和服务端都用 **北京时间(UTC+8) 的墙上时钟** 直接贴 `Z` 后缀——`Z` 名不副实。
- 发**真 UTC** 会比服务器慢 8 小时 → 被判 `token invalid`（401）。
- 修法：固定 +8 偏移生成（与 `device_md` 取 `DAY_OF_YEAR` 同套路），免依赖宿主机时区。

### 2.5 完整伪代码

```python
def authorization(body, ts, *, key, seg1, app_version, hard_platform, plat_version):
    doy       = day_of_year_in_utc8()                      # 当年第几天（UTC+8）
    device_md = md5(f"Android{app_version}{hard_platform}{plat_version}:{doy}")
    message   = device_md + "postjson_body" + body + ts + seg1 + device_md
    seg2      = base64(hmac_sha1(key, message))
    return f"smart {seg1}:::{seg2}:::{ts}"

ts   = utc8_wall_clock_with_Z()                            # 2026-06-16T20:59:57.403Z
body = '{"json":{"feed_id":%d,"version":"2.0","digest":""}}' % feed_id
```

> 离线一比一复现见 [`verify_sign.py`](../verify_sign.py)；联网自测见 [`query_device.py`](../query_device.py)。

---

## 3. 各字段来源与生命周期

| 字段 | 来源（怎么抓） | 是否常变 | 失效表现 |
|---|---|---|---|
| `seg1` | `Authorization` 头第一段 / hook | 否（账号设备级恒定） | — |
| `key` | frida `Mac.init` 的 `key_txt` | 重新登录**可能**轮换 | 签名整体对不上 |
| `tgt` | 请求头 `tgt` | **每次登录变 / 会过期** | `token invalid`（也可能是 ts 坑，先排时间戳） |
| `device_md` | **不用抓**，由设备三参 + 当天实时算 | **每天滚动** | 次日签名失效（最隐蔽） |
| `ts` | 本地生成（UTC+8 贴 Z） | 每次请求 | 真 UTC → `token invalid` |
| `body` | 本地按 `feed_id` 拼 | 每次请求 | 键序/空格不对 → 签名失效 |
| 设备五参 | App 抓一次 | App 升级才变 | `device_md` 随之变，需同步更新 |

`seg1` / `key` 一次抓到长期可用；`tgt` 要随登录刷新；`device_md` 永远实时算。

---

## 4. App 内部调用链（混淆类名）

```
RestClient.postJson                       (com.jd.smart.base.net.http.RestClient)  ← 签名在此
   └─> PostStringBuilder                  (混淆名 rc.e)
        └─> PostStringRequest             (混淆名 vc.g)
             └─> OkHttpRequest(...).a      (混淆名 vc.d)  @ OkHttpRequest.java:46  ← 把 authorization 头 add 进去
                  └─> okhttp3 RealInterceptorChain.proceed → 发出
```

要点：

- **App 代码命名空间是 `com.jd.smart`，不是启动包名 `com.jd.iots`**——crypto hook 的调用方过滤要按
  `com.jd.smart` 收窄，否则要么抓不到、要么被 TLS 噪声淹没。
- `vc.d` / `vc.g` / `rc.e` 是**当前 App 版本**的混淆名，**换版本会变**；变了用 auth-tracer 的调用栈重新认
  （见 §5.3、[`trace_d_init.js`](../trace_d_init.js)）。
- `device_md` 在更早某处被读出/算出，拼进 HMAC 原文首尾。

---

## 5. 逆向方法论与工具链

整条链路一句话：**hook OkHttp 拦截器抓明文请求 → 锁定签名是 20 字节 SHA-1 系 → hook crypto API 抓
算法/密钥/原文 → auth-tracer 定位拼装点 → 值溯源找 device_md/key 出处 → 离线复现验证**。

主机侧 [`host.py`](../host.py) 把 frida `send()` 的记录落到 SQLite（`http` 表 + `sign` 表），方便 SQL 回溯。

### 5.1 抓包：hook OkHttp，天然绕过 SSL pinning

脚本：[`frida_okhttp_capture.js`](../frida_okhttp_capture.js)（或合并版 [`frida_capture.js`](../frida_capture.js) Part 1）。

- hook `okhttp3.internal.http.RealInterceptorChain.proceed(Request)`，在 `proceed` 前后读
  `Request`/`Response` 对象。
- **在 TLS 之前、进程内读对象**，所以**不受 SSL pinning 影响**，也不用证书。
- `proceed` 每过一个拦截器触发一次 → 同一请求多行，**带 `authorization`/`tgt` 的那行**是加完鉴权头之后的。
- body 读取细节：`isOneShot` 的流式 body 跳过（读了会消费掉真正要发的内容）；响应用
  `peekBody` 读副本不消费原始流。
- okhttp 被混淆找不到默认类名时，脚本自动 `enumerateLoadedClasses` 列出疑似 `okhttp3/okio` 类供手填 `CONFIG`。

### 5.2 定位签名：20 字节 → SHA-1 家族 → hook crypto

脚本：[`frida_sign_capture.js`](../frida_sign_capture.js)（或合并版 Part 2）。

- **判型**：`seg1`(40hex) 和 `seg2`(base64) 都解出 **20 字节** ⇒ 头号嫌疑 `HmacSHA1` / `SHA-1`。
- hook 一切"能产出摘要/签名"的 API：`MessageDigest` / `Mac` / `Signature` / `Cipher` /
  `Base64` / `SecretKeySpec` / `IvParameterSpec`，每次调用打印 + `send` 结构化记录入 `sign` 表。
- **关键产物**：
  - `Mac.init` → 拿到 HMAC **key**（`key_txt`）；
  - `Mac.update`（按线程累积）→ 拼出 HMAC **原文**（看到 `device_md+tag+body+ts+seg1+device_md` 的结构）；
  - `Mac.doFinal` → 20 字节 → base64 即 **seg2**；
  - `MD.digest`（MD5）→ 看到 `device_md` 的算法与输入。
- **稳定性收窄**（直接决定会不会把 App 搞崩）：
  - 只 hook `SIGN_ALGS`（默认 sha1 系，子串小写匹配），用算法名先挡掉 TLS 的 SHA-256/AES；
  - 默认**不** hook `Cipher`/`Signature`（AES 在 TLS 里极热，hook 它最容易闪退；RSA/ECDSA 输出 >20B 基本不是目标）；
  - 调用栈过滤（`calledFromApp`，按 `com.jd.smart` 收窄）**只在算法命中后**才抓栈，不在热路径抓栈；
  - Base64 只看 ≤64B 的小输入（跳过图片/大 JSON）；
  - 仍闪退就把 `ARM_DELAY_MS` 设几千毫秒，延迟装签名 hook，错开启动检测/首页加载窗口。

### 5.3 auth-tracer：定位"拼签名的那一帧"，并判 Java/native

合并版 [`frida_capture.js`](../frida_capture.js) Part 3。

- hook `okhttp3.Request$Builder.header/addHeader` 与 `Headers$Builder.add/set/...`；
  当某次设的是 `authorization` 头（或值里带 `:::`）时，**dump 调用栈**。
- 栈里**紧贴 okhttp 之前的 App 帧 = 拼签名处**；顺着它就能找到算法/原文位置。
- 若那帧标 `(Native Method)` ⇒ 签名在 native，得转 native hook。**这是判 Java/native 最直接的证据**，
  与 crypto 算法过滤无关。
- 本项目据此定位到 `OkHttpRequest(vc.d).a @ OkHttpRequest.java:46`（见 §4），且签名在 Java 层。

### 5.4 值溯源：device_md / key 到底从哪来

脚本：[`frida_trace_secret_src.js`](../frida_trace_secret_src.js)（反查"已知值"出处）+ 合并版 Part 4 secret-finder。

- 已知某个值（如当前 `device_md`），但不知它从哪读/何时生成时，盯几类"值的出口"，命中目标值就打栈：
  1. `SharedPreferences` `getString/putString`——标准 prefs 存取；
  2. **`com.tencent.mmkv.MMKV` `decodeString/getString`**——京东系常用 MMKV，**标准 SP hook 抓不到它**；
  3. `org.json.JSONObject` `getString/optString`——从接口响应 JSON 解析出来的那一刻（最可能直指下发接口），
     命中时连整个 JSON 上下文一起 dump，看它和谁（如 `tgt`）一起下发。
- 操作：触发设备刷新看**读取点**；退出账号→重新登录看**下发/生成点**。
- 全没命中 ⇒ 值可能常驻内存（登录时算好放单例字段）或走别的存储，转静态 jadx 看 `OkHttpRequest(vc.d).a`。
- `device_md` 最终确认是**本地实时算**（md5(设备参数 + DAY_OF_YEAR)），不是服务端下发——所以不用抓、只能算。

### 5.5 落库 schema（`host.py`）

- `http` 表：`ts/method/url/host/path/has_auth/has_tgt/code/req_headers/req_body/resp_headers/resp_body`
  ——抓包全量，按 `has_auth`/`has_tgt`/`url` 建索引，方便筛"带鉴权头的设备请求"。
- `sign` 表：`kind/algorithm/input_hex/input_txt/out_hex/out_b64/key_hex/key_txt/iv_hex/matched/target/stack`
  ——每次 crypto 调用一条；`kind` 形如 `Mac.doFinal`/`MD.digest`/`*.Base64.*`/`Mac.init`/`SECRET@...`/`SRC@...`/`WUserSig.*`/`WJ.*`。
  把 `TARGETS` 填成要找的 `seg1`/`seg2`，命中即 `matched=1` 并带调用栈，直接 SQL 反查。

### 5.6 wjlogin 登录态读写 / A2(tgt) 刷新 / 落盘追踪（所有 frida_*.js 内置）

`tgt` / 登录票据由京东 wjlogin SDK 的 `jd.wjlogin_sdk.model.WUserSigInfo` 持有。**6 个 frida_*.js
全部内置** `installWjloginHook()`，开箱即抓登录态的**读**与**写**两个口子：

- `createUserInfoFromJSON(JSONObject)`：从 JSON 反序列化出 `WUserSigInfo` —— **读 / 初始化**
  （登录成功后、或进程启动从磁盘恢复登录态时）。入参 JSON = 即将载入内存的整份登录态，看它从哪来。
- `toJSONObject()`：把 `WUserSigInfo` 序列化成 JSON —— **写**（大概率落盘前）。返回的 JSON =
  即将持久化的整份登录态。

两者都 **dump 调用栈**（这是要点，所以专门 hook）：栈里紧贴 `jd.wjlogin_sdk` 之前的 App 帧 =
触发读/写的地方，顺它就看清「**更新机制**」——比如 token 刷新后是谁调用 `toJSONObject` 把新
`tgt`/`a2` 写回磁盘。同一调用栈只打印一次（去重降噪），但每次调用都入库。

此外（`installWjExtraHooks()`，同样 6 脚本内置）还钉了 **A2(tgt) 刷新链路 + 真正的落盘 I/O**：

- `jd.wjlogin_sdk.common.h.c.b()`：判断**是否该刷新 A2/tgt** 的谓词。看返回值（`true` = 这次会
  触发刷新）+ 触发栈，就知道刷新的**判定时机与原因**。
- `jd.wjlogin_sdk.common.h.c.refreshLoginStatus()`：刷新登录态的**动作**本身。
- `static jd.wjlogin_sdk.util.v.b(content, path)`：**保存数据文件**——登录态/`tgt` 序列化后落盘的
  底层。`path` 在内部经 **md5(hex)** 得真正文件名，脚本已替你算好（落 `target` 字段 = 实际文件名），
  可直接 `adb pull /data/data/<pkg>/…/<md5>` 取文件。
- `static jd.wjlogin_sdk.util.v.g(path)`：**读取数据文件**（与上对应的读侧）。

只 hook 校验过参数个数的重载（如只钉无参 `b()`、双参 `v.b`、单参 `v.g`），避免被同名短方法误伤。

- 落库：全部走 `sign` 表。`kind` 形如 `WUserSig.toJSONObject(写/落盘)` / `WJ.shouldRefreshA2` /
  `WJ.refreshLoginStatus` / `WJ.fileSave` / `WJ.fileRead`；内容/JSON 存 `input_txt`，文件 `path` 存
  `key_txt`、`md5(path)` 文件名存 `target`，调用栈存 `stack`。`host.py` 控制台另打 `[WJLOGIN] …` 便于扫。
- 时机：相关类（`WUserSigInfo`/`common.h.c`/`util.v`）`--spawn` 早期可能未加载，hook 自带**重试**
  （每 0.7s，最多 ~21–28s）直到加载或超时；想抓「进程启动从磁盘恢复」务必 `--spawn`（attach 会错过）。

> 登录态 JSON 含 `a2` / `tgt` 等敏感票据；`*.db` 已 `.gitignore`，勿外传截图/日志。

---

## 6. 离线复现与联网自测

```bash
# 1) 离线复现签名算法（不联网，纯算）——确认算法实现正确
python verify_sign.py            # 填好 key 后跑，打印 seg2 / Authorization

# 2) 自测 body 拼装格式（不联网，不碰真实密钥）
python query_device.py --selftest

# 3) 真正联网查询（需 jd_smart_secrets.json 里的真实凭据）
python query_device.py --device-id <32hex> --feed-id <feed_id>
```

- [`verify_sign.py`](../verify_sign.py)：一比一复现 `device_md → message → seg2`，对历史样本验签可传当天的 `device_md`。
- [`query_device.py`](../query_device.py)：仅标准库的独立查询器，`--selftest` 校验拼装，带 `--device-id/--feed-id` 真查。
- 凭据从同目录 `jd_smart_secrets.json` 覆盖进来（拷 `jd_smart_secrets.example.json` 改；该文件已 `.gitignore`）。

---

## 7. 常见失效与排查

按"最容易→最隐蔽"排：

1. **`token invalid` / 401，但 key 没动**：
   - **先怀疑 `ts` 时间戳时区**（发了真 UTC？应为 UTC+8 贴 Z）。`query_device.py`/HA 集成已修成固定 UTC+8。
   - 再怀疑 `tgt` 过期 → frida 重新抓一份当前 `tgt`。
   - `--selftest` 签名计算正常、但联网 401，且时间戳已确认 ⇒ 基本就是 `tgt`。
2. **昨天好的今天突然失效**：`device_md` 每日滚动（`DAY_OF_YEAR`）。确认在用**实时算**而非写死的旧值。
3. **签名整体对不上**：`key` 重新登录被轮换 → 重抓 `key`；或 `body` 键序/空格不对、`feed_id` 类型不对。
4. **App 升级后失效**：设备五参（尤其 `app_version`/`plat_version`/`hard_platform`）变了，`device_md` 随之变，
   同步更新；混淆类名（`vc.d` 等）也可能变，用 auth-tracer 重新认。
5. **HA 集成 sensor 变 unavailable**：多为 `tgt` 过期 → 集成"选项"里更新 `tgt`（无需删除重加）；`key` 变了则删集成重加。

> 时区相关的两处实时计算（`device_md` 的 `DAY_OF_YEAR`、`ts` 的墙上时钟）都改用**固定 UTC+8 偏移**，
> 免依赖系统 tzdata；若设备/服务端不在东八区、午夜前后偶发鉴权失败，改对应函数里的偏移即可。

---

## 8. 彩虹/色彩网关接口（api.m.jd.com）—— `jdsmart.house.getHouses` 获取家庭列表

> 与 §1–§7 的 `getDeviceSnapshot_v1`（`api.smart.jd.com`，HmacSHA1、20 字节）**是两套体系**。
> 这是京东 App 通用的「彩虹/色彩」统一网关：所有业务走同一个 `POST /api`，靠 query 的
> `functionId` 路由；请求被**客户端加密 + SHA-256 签名**。本节是该接口的拆解与逆向入口。

### 8.1 速查（TL;DR）

```
POST https://api.m.jd.com/api
  ?functionId=jdsmart.house.getHouses    # 业务方法名（网关路由键）
  &appid=jdsmart-android                 # 网关应用 id（决定 appSecret）
  &t=1781528966944                       # 请求时间戳 ms（参与 sign）
  &uuid=ef42e0843b69284185f99fbebfe11b41 # 设备 uuid（32hex=16B）
  &sign=52e5...4388                      # 64hex = 32B = SHA-256 家族（不是旧接口的 SHA-1！）
  &ep=<URL编码的加密信封>                 # 设备指纹（加密），见 §8.3
  &ef=1&bef=1                            # ep / body 是否加密的标志（1=已加密）

Headers: Authorization / tgt（同旧接口，登录票据）

Body（表单）: body=<URL编码的加密信封>
  解码后: {"hdid":"...","ts":...,"ridx":1,
          "cipher":{"body":"<真实请求体密文>"},
          "ciphertype":5,"version":"1.2.0","appname":"com.jd.iots"}
```

### 8.2 Query 参数逐个拆解

| 参数 | 示例 | 含义 / 来源 | 与 sign |
|---|---|---|---|
| `functionId` | `jdsmart.house.getHouses` | 业务方法名，网关据此路由 | 进原文 |
| `appid` | `jdsmart-android` | 网关应用标识，**决定服务端用哪个 appSecret 验签** | 间接（定 key） |
| `t` | `1781528966944` | 请求时刻 ms | 进原文 |
| `uuid` | `ef42…11b41` | 设备 uuid，32hex=16B（疑似 md5(androidId/安装 id)，装机后恒定） | 多半进 |
| `sign` | `52e5…4388`（64hex） | **请求签名**；32B ⇒ SHA-256 系（MD5 仅 16B，排除） | 它本身 |
| `ep` | 加密信封 | encrypt params：设备指纹（eid/brand/model/screen/area…），**每字段单独加密** | 可能 |
| `ef` | `1` | ep 加密标志（encrypt flag）。=0 则 ep 为明文 | 否 |
| `bef` | `1` | body 加密标志（body encrypt flag）。=0 则 body 为明文 | 否 |

要点：

- `sign` 是 **32 字节**（64 hex），直接排除 MD5（16B），锁定 **SHA-256 / HmacSHA256**——与旧接口
  的 20 字节 SHA-1 不是一回事，crypto hook 的 `SIGN_ALGS` 必须放宽到 `sha-256`。
- `t`（query）≠ 信封里的 `ts`：`t` 是请求时刻、进签名；`ts` 是加密信封生成时刻。实测
  `ep.ts`(…3056) 比 `body.ts`(…6987) 早 ~4 秒 ⇒ **ep 在会话里被缓存复用，body 每次新生成**。
- `ef`/`bef` 是给网关的「这俩字段已加密」开关；想拿明文请求**不是**把它改成 0（服务端未必认），
  而是去抓**加密前的明文**（§8.4）。

### 8.3 加密信封与 `ciphertype:5`（核心难点）

`ep`（query）和 `body`（表单）**共用同一个加密信封**，出自同一个 JD 客户端加密 SDK：

```json
{"hdid":"<设备硬件id,base64=32B>","ts":<ms>,"ridx":<会话内自增>,
 "cipher":{ ...被加密的字段... },
 "ciphertype":5,"version":"1.2.0","appname":"com.jd.iots"}
```

两个 scope 的差别只在 `cipher` 里装什么：

- **ep.cipher**：设备指纹，**逐字段加密**——`eid`（JD 设备指纹/LogoManager 下发）、`d_brand`、
  `d_model`、`screen`、`area`、`osVersion`、`networkType`、`client`、`partner`、`build`、
  `clientVersion`、`aid`、`ext`。
- **body.cipher**：只有一个 `body` 键 = **真实 getHouses 请求体整体加密**后的密文。

**`ciphertype:5` 实测结论**：**不是标准 base64，也不是 AES**。

- 拿语义已知字段反推：`client`（应=`android`/7B）、`networkType`（应=`wifi`/4B）按标准 base64
  解出来是 `61 6e 6e 73 0f 5f 64`、`77 6b f0 68`——长度对得上但内容是乱的；
- 各字段密文长度 2/3/6/7 字节都有，**没有 16 字节块填充** ⇒ 排除 AES（ECB/CBC 都要 16B 对齐）；
- ⇒ 是 JD 自有的「**逐字节变换 +（很可能自定义字母表的）base64**」。**离线无法解**，
  必须 live 抓加密函数的明文↔密文。

### 8.4 逆向入口：`frida_color_capture.js` + 两张新表

脚本 [`frida_color_capture.js`](../frida_color_capture.js)，配 `host.py` 落到**两张新表**（结构和旧接口
差太多，单独建，见 §5.5 旁注）：

- `color` 表：彩虹请求结构化（functionId/appid/t/uuid/sign/ef/bef/ep/各信封字段/body_cipher…），
  由 `http` 表中 `host=api.m.jd.com` 的行**自动解析回填**（`host.py: parse_color`）。
- `cipher` 表：信封拼装点调用栈（`kind=envelope`）+ 加密函数明文↔密文（`kind=encrypt`）。

两遍打法（沿用 §5「发现→钉死」）：

1. **第一遍（发现）**：`DISCOVER_ENC` 枚举 `com.jd*/com.jingdong*` 下名字含
   encrypt/cipher/sign/security/guard/Logo 的候选类；同时 envelope tracer hook
   `JSONObject.put("ciphertype", …)`，把**信封拼装那一帧的调用栈**打出来——紧贴 `org.json`
   之前的 App 帧就是加密模块。
2. **第二遍（钉死）**：把定位到的类全名填进脚本顶部 `ENCRYPT_CLASSES`，脚本自动 hook 其所有
   `String->String` 方法，抓**明文↔密文**（如 `enc("android") -> "YW5ucw9fZK=="`、
   `enc(真实 body JSON) -> body 密文`）。
3. **求 sign**：把本次 wire 的 `sign` 填进 `TARGETS`，跑起来，命中的那条
   `MD.digest(SHA-256)`/`Mac.doFinal(HmacSHA256)` 的 `input_txt` 就是 **sign 原文**（preimage）→
   反推 `functionId + body + t + … + appSecret` 的拼接公式。

> 注意：若彩虹 SDK 不走 okhttp3（自带 HttpURLConnection），`http` 表可能抓不到该请求；
> 但 `sign`/`cipher` 两个 hook 仍能拿到签名原文与明文，请求外形对照 jadx 即可。

### 8.5 实测：getHouses 的真正鉴权是 Cookie（JMA / 设备指纹）

抓 getHouses 时发现：除了 §8.2 的 `sign`/`ep`，它**真正认的是两个 Cookie**（设备级稳定值，非每请求签名）：

```
whwswswws = <jmafinger UUID>                          # JMA 软设备 id，一次生成、持久化
unionwsws = {"devicefinger":"eidA005...","jmafinger":"<同上 UUID>"}
                        └ eid，来自 com.jd.sec.LogoManager.getLogo()
```

- `devicefinger` = **eid**，JD 硬件指纹。`getLogo()` 内部 `BiometricManager.getCacheTokenByBizId(bizId, a.c(), a.b())`
  只是**读缓存**；真正生成在 `com.jd.sec` 的 **jdguard native**（`libjdguard.so` 一类）。
- eid 结构：`eid` + 版本头 + **状态位 `[8:10]`** + 载荷。代码里 `"41".equals(substring(8,10))` 命中就**重生成**——
  即 `41` = 残缺/降级态。所以抓的时候要抓一个**状态位 != 41 的“好 eid”**。
- `jmafinger` / `whwswswws` = 同一个 **UUID**，一次生成后持久化（京东系多在 MMKV）。

**战略：到此打住，别逆 native。** 这是 cookie 鉴权，eid/UUID 都是**设备级稳定值** ⇒ 正确打法是
**抓一次、替换重放**，不是复现算法（jdguard native 白盒 + 反调试，投入产出比极低且无必要）。

逆向入口 [`frida_jma_capture.js`](../frida_jma_capture.js)，只 hook **输出边界 + 拼装点**，落 `sign` 表（`kind=JMA.*`）：

1. `com.jd.sec.LogoManager.getLogo()` → eid（顺带打印状态位，判是否 `41`）；
2. `*BiometricManager.getCacheTokenByBizId(...)` → 确认“读缓存” + bizId 三参（类名自动发现）；
3. `org.json.JSONObject.put("devicefinger"/"jmafinger")` → `unionwsws` 拼装点 + 栈；
4. `okhttp3.Request$Builder.header("Cookie", …)` → cookie 落到请求那一刻 + 栈。

- **cookie 其实已被抓到**：`http` 表的 `req_headers` 本就含 `Cookie`，直接 SQL 取即可重放；本脚本补的是
  **生成 / 来源 / 刷新节奏**。
- 找 UUID 存哪：把抓到的 UUID 填进 [`frida_trace_secret_src.js`](../frida_trace_secret_src.js) 的 `TARGETS` 跑一遍，
  命中 MMKV/SP 的 `getString` 即存储点（见 §5.4）。

---

## 9. 安全与合规

- 仅限**个人研究 / 自用自己账号的设备**。不内置、不提交任何密钥。
- `jd_smart_secrets.json`、`*.db`（抓包库，含 token）已 `.gitignore`。
- `tgt` 是登录票据，**勿公开分享**；过期在集成选项里更新。
- 联网自测会把真实 `device_id`/`feed_id` 与实时数据打到终端，注意别外传截图/日志。

---

## 附录：仓库文件清单

| 文件 | 作用 |
|---|---|
| [`frida_capture.js`](../frida_capture.js) | **合并版** hook：okhttp 抓包 + crypto 签名 + auth-tracer + secret-finder（落 `http`/`sign` 表） |
| [`frida_okhttp_capture.js`](../frida_okhttp_capture.js) | 单独的 OkHttp 抓包 hook |
| [`frida_sign_capture.js`](../frida_sign_capture.js) | 单独的 crypto 签名 hook（MessageDigest/Mac/Signature/Cipher/Base64） |
| [`frida_color_capture.js`](../frida_color_capture.js) | **彩虹网关版**（api.m.jd.com）：okhttp 抓包 + SHA-256 sign + ep/body 加密信封追踪（落 `color`/`cipher` 表，见 §8） |
| [`frida_jma_capture.js`](../frida_jma_capture.js) | **JMA/设备指纹 cookie 版**（getHouses 真正鉴权）：LogoManager.getLogo(eid) + BiometricManager 缓存 + unionwsws/Cookie 拼装（落 `sign` 表 `kind=JMA.*`，见 §8.5） |
| [`frida_trace_secret_src.js`](../frida_trace_secret_src.js) | 反查已知值（device_md 等）出处：SharedPreferences / MMKV / JSONObject |
| [`trace_d_init.js`](../trace_d_init.js) | 一次性调试：dump `OkHttpRequest(vc.d)` 构造参数 + 调用栈 |
| [`host.py`](../host.py) | Frida 主机：加载 hook 脚本，把记录落 SQLite（`http` + `sign` 表；彩虹网关另落 `color` + `cipher` 表） |
| [`verify_sign.py`](../verify_sign.py) | 离线一比一复现/校验签名 |
| [`query_device.py`](../query_device.py) | 仅标准库的独立联网查询器（`--selftest` / `--device-id`+`--feed-id`） |
| [`jd_smart_secrets.example.json`](../jd_smart_secrets.example.json) | 凭据模板（真实值放 `jd_smart_secrets.json`，已忽略） |
| [`custom_components/jd_smart/`](../custom_components/jd_smart/) | Home Assistant 自定义集成（`api.py` 即签名+调用实现） |
