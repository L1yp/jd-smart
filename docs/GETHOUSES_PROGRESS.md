# getHouses 逆向进度归档（`jdsmart.house.getHouses`）

> 阶段性快照，配合 [`REVERSE_ENGINEERING.md`](REVERSE_ENGINEERING.md) §8（含 §8.5/§8.6/§8.7）阅读。
> 归档日期：2026-06-16。不含真实凭据/指纹值（实样在抓包库 `*.db`，已 `.gitignore`）。

## 1. 一句话结论

getHouses = **彩虹网关（api.m.jd.com）+ Cookie 设备指纹 + 每请求签名**。

设备指纹（cookie 的 `jmafinger` UUID、`eid`）与 `tgt` 都能**抓一次重放**（`tgt` 会过期需刷新）。
**replay 之所以失败，不是指纹变了，而是 query 的 `sign` 覆盖了 `t`（时间戳）= 防重放**（§8.7）：
旧 `t` + 旧 `sign` 必被判 invalid sign。所以**唯一硬骨头是「用新 `t` 重算 `sign`」**——
`ep`/`body` 的 `ciphertype:5` 已证实是**换表 base64**（[`color_codec.py`](../color_codec.py) 可离线 decode/encode），
**不再是障碍**。**本阶段：攻 `sign`。实测：`d.a`(HmacSHA256) 只在「检查更新」走、getHouses 不经它；getHouses 真签名器 = `SignRequestInterceptor.c` + native `NativeEncodeDataToServer(_gm)`（见 §7.2）。其下的 HMAC 原语已锁定 = `com.jd.smart.algorithm.NativeAlgorithmHelper`：算法 = **标准 HMAC-SHA256（key 当 32 字符 ASCII 文本，非 fromhex）**，**密钥固定**（内嵌 `libnativealgorithm.so`，经无参 `getSecretKey()` 取，由 1 参 `getHmacSha256Value(data)` 内部消费）。详见 §7.3。**

## 2. 请求结构（详见 §8.1/§8.2）

```
POST https://api.m.jd.com/api
  ?functionId=jdsmart.house.getHouses&appid=jdsmart-android&t=<ms>&uuid=<32hex>
  &sign=<64hex>&ep=<加密信封JSON>&ef=1&bef=1
Headers: Authorization / tgt
Cookie:  whwswswws=<UUID>; unionwsws={"devicefinger":"<eid>","jmafinger":"<UUID>"}
Body(form): body=<加密信封JSON>{cipher:{body:<真实请求体密文>}}
```

## 3. 各组件可重放性矩阵

| 组件 | 位置 | 来源 / 性质 | 抓一次重放？ | 依据 |
|---|---|---|---|---|
| `jmafinger` / `whwswswws` | Cookie | SP `jma_sp_file`/`jma_softfingerprint`，`UUID.randomUUID()` 一次后不变 | ✅ 是 | §8.5 源码 |
| `devicefinger`（eid） | Cookie `unionwsws` | native `LoadDoor.getLocalEid`→116+32→SP→读 SP，稳定 | ✅ 是（status≠41 的好 eid） | §8.6/§8.7 |
| `tgt` / `Authorization` | Header | wjlogin 登录票据 | ⚠️ 会过期，需刷新/重抓 | §5.6 |
| `uuid` | query | 设备 uuid（32hex），装机后恒定 | ✅ 是 | §8.2 |
| `t` | query | 请求时刻 ms，本地生成 | n/a（本地） | 进 sign |
| **`sign`** | query | 64hex=32B=**SHA-256 系**，**覆盖 `t`（防重放）** | ❌ **必须用新 t 重算** | **§8.7，本阶段** |
| `ep` | query | `ciphertype:5` = 换表 base64 的设备指纹（含 `ts`，自己填新值即可） | ✅ 可离线生成 | §8.3 / `color_codec.py` |
| `body.cipher.body` | body | `ciphertype:5` 换表 base64；真实体 `{"pageSize":100,"page":1}` | ✅ 可离线生成 | §8.3 / `color_codec.py` |

> **关键**：cookies/指纹稳定 ≠ 能直接重放整条请求。卡点是 `sign(t)` 的防重放（§8.7）。

## 4. 已确认的来源 / 存储

- **jmafinger UUID**：`getJMAFinger` → `getSharedPreferences("jma_sp_file",0).getString("jma_softfingerprint","")`；
  空则 `UUID.randomUUID()` 写回。**随机一次、持久不变** → 直接重放。
- **eid（devicefinger）**：`LogoManager.getLogo()`→`getCacheTokenByBizId`→`ff.a.l`→worker `e`（§8.6）；
  **源头是 native** `com.jdcn.risk.cpp.LoadDoor.getLocalEid(ctx)`（`libbiometric.so`，getEid 长度 148）→
  切 `116(eid)+32(tail)` → 落 SP 键 `c("lcJade")`/`c("field")` → 之后读 SP（§8.7）。所以稳定、可重放。
- **tgt**：wjlogin `WUserSigInfo`（读 `createUserInfoFromJSON`/写 `toJSONObject`；落盘 `util.v.b/g`，文件名=md5(path)）。§5.6。

## 5. `ep` / `body`（已解：换表 base64，可离线生成）

`ciphertype:5` = **自定义字母表的标准 Base64**（不是加密）。逆向自 App `decode()`，见 [`color_codec.py`](../color_codec.py)；
往返校验全过，**离线 decode/encode 即可，无需 hook**。

- `ep.cipher` 逐字段就是明文设备指纹：`client=android` / `networkType=wifi` / `d_brand` / `d_model` /
  `screen` / `osVersion` / `clientVersion` / `partner` / `build` / `ext={"prstate":"0"}` /
  `eid`(=cookie devicefinger) / `aid`(=query uuid)。
- `body.cipher.body` 明文 = **`{"pageSize":100,"page":1}`**（getHouses 就是分页）。

⇒ 自造请求时：`body = color_codec.encode(json_bytes)`；`ep` 同理（`ts` 填新值再 encode）。
（早期「必须 hook 加密」与「LoadDoor.enc/dec = ciphertype:5」的猜测均作废，见 §8.3。）

## 6. 工具与落表一览

| 脚本 | 抓什么 | 落表 |
|---|---|---|
| [`frida_capture.js`](../frida_capture.js) | okhttp + 旧接口 sign + auth-tracer + secret-finder | `http` / `sign` |
| [`frida_color_capture.js`](../frida_color_capture.js) | 彩虹网关 okhttp + SHA-256 sign + ep/body 加密信封 + **Part7 jdupgrade `d.a`** + **Part8 真签名器(`SignRequestInterceptor`/native `NativeEncodeDataToServer`)** | `http`→`color` / `sign`(含 `HMAC.*`/`SIGNI.*`/`NSIGN.*`) / `cipher` |
| [`frida_jma_capture.js`](../frida_jma_capture.js) | LogoManager.getLogo + BiometricManager + unionwsws/Cookie | `sign`（`JMA.*`） |
| [`frida_eid_capture.js`](../frida_eid_capture.js) | worker `e` 叶子 + getCacheTokenByBizId + 现造 | `sign`（`EID.*`） |
| [`frida_loaddoor_capture.js`](../frida_loaddoor_capture.js) | **native** `LoadDoor` enc/dec/getToken/checkSum/getEid + SP 键 + rpc 现解 | `sign`（`LD.*`） |
| [`frida_sign_pipeline_capture.js`](../frida_sign_pipeline_capture.js) | **签名流水线三层**：A `NativeAlgorithmHelper.getSecretKey()`/`getHmacSha256Value` 入出（真 HMAC 原语，§7.3）+ B `light_http` 贴 sign + C `manto` 下发；#N 串因果 | —（纯 console） |
| 全部 `frida_*.js` | wjlogin 登录态读写/刷新/落盘 | `sign`（`WUserSig.*`/`WJ.*`） |
| [`color_codec.py`](../color_codec.py) | `ciphertype:5` 离线 decode/encode（ep/body 自造） | —（纯算） |
| [`verify_color_sign.py`](../verify_color_sign.py) | 离线复现 `HmacSHA256(preimage, secret)→64hex`（核对 wire sign / 换新 t 重算） | —（纯算，密钥读 `jd_smart_secrets.json`） |

## 7. 下一阶段：分析 query `sign`（可能 HmacSHA256，**也可能 native**）

判型：`sign`=64hex=32B ⇒ **SHA-256 家族**。两种可能：**Java**（MessageDigest/Mac）或 **native**（`LoadDoor.getToken/checkSum`，§8.7）。

runbook：

1. **先确认变量**（连发两次 getHouses，diff 每字段）：
   ```sql
   SELECT id, t, sign, body_ts, ep_ts, body_cipher FROM color
   WHERE function_id='jdsmart.house.getHouses' ORDER BY id DESC LIMIT 2;
   ```
   cookies 在 `http.req_headers`。预期：变的是 `t`/`ts`/`sign`（+ 若 ep/body 含 ts 则其密文也变）。
2. **同时开两套抓 sign 原文**，看 wire sign 在哪命中：
   - Java 侧：`frida_color_capture.js`，把 wire `sign` 填进 `TARGETS` → 命中的 `MD.digest(SHA-256)`/`Mac.doFinal` 的
     `input_txt` = **preimage**；若 Mac，则同段 `Mac.init.key_txt` = **HMAC 密钥**。
   - native 侧：`frida_loaddoor_capture.js`（`LD.*`）→ 若 `getToken`/`checkSum` 的输出 == wire sign，则 **sign 在 native**，
     其入参就是被签名的料。
   两边一对就知道 **sign 在 Java 还是 native**，以及原文/密钥。
3. 重点确认：**`ep` 是否进 sign 原文**（决定 ep 能否单独重放）。
4. 离线复现：仿 [`verify_sign.py`](../verify_sign.py) 写 `verify_color_sign.py` 验证拼接公式。

### 7.1 sign 算法（源码已确认）+ hook：jdupgrade `c.a` / `d.a`

> **实测结论**：连发 getHouses 后 `HMAC.a` 的 `out_hex` **不命中** `color.sign` —— **getHouses 不走 `d.a`**，
> `d.a` 仅「检查更新」请求用。getHouses 的真签名器见 **§7.2**。本节作为「JD 签名套路样板」保留（值拼接 + 内嵌 secret + HMAC）。

源码（`com.jingdong.sdk.jdupgrade.inner.c.a(functionId, query, body)` 调 `utils.d.a(data, key)`）：

```
treeMap  = TreeMap(自定义比较器 b){ functionId, *query 非空值, body? }
body     = f.a(f.b(json.getBytes())) = modBase64(gzip(bodyJson))     # 有 body 才加这项
preimage = "&".join(treeMap 各 value，按 key 排序)                    # 只拼 value、不含 key、去尾随 &
sign     = HmacSHA256(preimage_utf8, key_utf8) 转 64hex              # = d.a(data, key) 的返回值
```

- **`d.a` 参数顺序**：`d.a(data, key)` ⇒ **arg0 = 被签数据(preimage)**、**arg1 = 密钥**。
- **key = 固定 secret**（`c.W()` 决定 prod/test 二选一），且是那串 **32 字符 hex 文本本身的 UTF-8 字节(32B)**，
  **不是** `fromhex` 后的 16B（这点最容易踩坑）。
- **被签的是谁**（回答「query 还是 body」）：**都不是二选一** —— `functionId` + **全部 query 值** + **body 值** 一起进
  treeMap，**只取各 value 拼接**（key 仅用于排序）。`t`/`uuid` 等就在 query 里，随之进 preimage。

**⚠ 这是 jdupgrade（升级 SDK）的签名器，签的是升级请求。** getHouses 走彩虹网关，其 body 是 `ciphertype:5` 信封
（≠ 这里的 gzip+modBase64）⇒ **getHouses 很可能是另一个并行签名器**（大概率共用 `d.a` 这个 HMAC 原语、可能换
appSecret）。**是否复用 `d.a` 用实测定**——hook 已并入 [`frida_color_capture.js`](../frida_color_capture.js) **Part 7**
（只挂 `a(byte[],byte[])`，`data→input_*`、`key→key_*`，落 `sign` 表 `kind=HMAC.a`），与 okhttp 同跑后：

```sql
SELECT s.id, s.out_hex, c.sign, c.function_id, c.t
  FROM sign s JOIN color c ON lower(s.out_hex)=lower(c.sign)
 WHERE s.kind='HMAC.a' ORDER BY s.id DESC;
```

- **命中** ⇒ getHouses 复用 `d.a`：该行 `input_txt` 就是 getHouses 的 **preimage**（直接读，**免逆比较器 b**），
  `key_txt` 是其密钥；照上面算法换新 `t` 重算即可 replay。
- **不命中**（`d.a` 只在升级时响、getHouses 不经它）⇒ 彩虹签名器在别处；但 JD 套路已知
  （value-only TreeMap 拼接 + 固定内嵌 secret + HmacSHA256→hex），按此去找彩虹那一份。

复现/核对：

- 跑：`python host.py -p <包名> -s frida_color_capture.js --spawn` → 触发 getHouses（或 App「检查更新」触发升级签名）。
- 离线核对：[`verify_color_sign.py`](../verify_color_sign.py) `--preimage "<input_txt>" --key-name prod --expect <wire sign>`
  （密钥放 `jd_smart_secrets.json` 的 `upgrade_secret_prod`/`_test`，已 `.gitignore`，不硬编码、不提交）。
- 现算（用 App 自带 d.a，免对齐 gzip 字节）：`frida -U -n <包名> -l frida_color_capture.js` REPL：
  `rpc.exports.dahmac('<新 t 的 preimage>', '<secret>')` → 输出 == 新 `t` 的 wire sign 即公式正确。
- `d` 懒加载：脚本自带 50×0.7s 重试；仍无则触发检查更新/改 attach；换版本类名变了改顶部 `UPGRADE_HMAC_CLASS`。

### 7.2 getHouses 真签名器：`SignRequestInterceptor` + native `NativeEncodeDataToServer`

实测 `d.a` 不参与 getHouses（§7.1）。真链路在 `com.jd.smart.networklib`，已并入 [`frida_color_capture.js`](../frida_color_capture.js) **Part 8**：

- **Java 拦截器** `com.jd.smart.networklib.interceptor.SignRequestInterceptor.c(String)` —— okhttp 拦截器里的算签助手；
  抓入参（可能是 preimage/URL）与出参（可能是 sign），落 `sign` 表 `kind=SIGNI.c`。
- **native** `<JNI类>.NativeEncodeDataToServer(String, long, String×5, int)` 及国密变体 `NativeEncodeDataToServer_gm`，
  返回 `byte[]`，落 `sign` 表 `kind=NSIGN.*`。8 个入参大概率含 functionId/时间戳(long)/uuid/body/appSecret/flags，抓一次即见映射。
  类名在脚本里**留空自动发现**（按方法名在 `com.jd*`/`com.jingdong*` 里找）；从 jadx 拿到全名填 `NATIVE_SIGN_CLASS` 更稳。

跑法照旧（`python host.py -p <包名> -s frida_color_capture.js --spawn` → 触发 getHouses），然后：

```sql
SELECT s.kind, s.out_hex, c.sign, c.t
  FROM sign s JOIN color c ON lower(s.out_hex)=lower(c.sign)
 WHERE s.kind LIKE 'NSIGN.%' OR s.kind LIKE 'SIGNI.%' ORDER BY s.id DESC;
```

- **命中** ⇒ 该方法输出即 wire sign：其 `input_txt`（native 的 8 个入参 / 拦截器入参）就是被签的料 → 反推拼接。
- **对不上 `c.sign` 但对得上 `c.body_cipher`/`ep`** ⇒ `NativeEncodeDataToServer` 是「整体加密 data 到服务端」（含 sign 之外的料），
  把 join 右边换成 `c.body_cipher` 再看，sign 可能是其输出的一段或另由 `SIGNI.c` 产出。
- native 多在首个请求随 `lib*.so` 初始化才加载；脚本对拦截器/native 各自重试（50×0.7s / 40×1s）。

### 7.3 sign 原语锁定：`NativeAlgorithmHelper`（标准 HMAC-SHA256 + 固定内嵌 secret）

§7.2 的真签名器（`SignRequestInterceptor.c` / native `NativeEncodeDataToServer`）底下的 **HMAC 原语**已定位到：

```java
public final class NativeAlgorithmHelper {            // System.loadLibrary("nativealgorithm")
    public static final native String getHmacSha256Value(String data);          // 1 参：key 内部取自 getSecretKey()
    public static final native String getHmacSha256Value(String key, String data); // 2 参：key 显式
    public static final native String getSecretKey();                            // 返回固定密钥本体
}
```

**① 算法 = 标准 HMAC-SHA256，key 当「32 字符 ASCII 文本」(32B)，非 `fromhex` 的 16B。**
此结论从抓包库里一条**完整三元组**（id 373–375，`stats-api` 分析子系统的 Java `Mac` 路径，与本原语同款约定）离线证死：

```python
import hmac, hashlib
data = 'stats-api&{"appKey":"8135aa32c53140dfb72110ded25d210e"}&381&1&1.17.0&HUAWEI&HWI-AL00&statsConfig&wifi&9&xjgw-android&1080*2160&2.1.9&1781573926594&ef42e0843b69284185f99fbebfe11b41'
key  = 'f947bd5915ce47738050241663f595d0'                # 32 字符
hmac.new(key.encode(),            data.encode(), hashlib.sha256).hexdigest()  # == 抓到的 out_hex 452cc519... ✓ 命中
hmac.new(bytes.fromhex(key),      data.encode(), hashlib.sha256).hexdigest()  # 9c1f50...  ✗ 不命中
```

**② 密钥是固定的（内嵌 so，非每请求传入）。** 判据：App 实际只命中 **1 参** `getHmacSha256Value(String data)`——
该重载**没有 key 形参**，key 只能来自 native 内部（`getSecretKey()` / 烤进 `libnativealgorithm.so`）；而 `getSecretKey()`
是**无参 getter**，返回单一定值。故 secret **不是每请求输入，而是按 App 构建固定**（同 jdupgrade 那个 prod/test 内嵌 secret 的套路）。
本次抓到的值 `6b086ed29b1a4483b4544143061b295d`（32 字符，与三套 Java HMAC 密钥 `121dce72…`/`f947bd59…`/`e45e21c9…` 都不同——
那三套是 stats-api/mpaas2 等**别的**子系统；getAllDevices/getHouses 走 native 这一套，绕开 `javax.crypto.Mac`，所以不出现在 `sign` 表的 `SecretKeySpec/Mac.*` 行里）。
> 待补：跨设备/重装后 `getSecretKey()` 是否仍 == `6b086ed2…`，需第二台机抓一次或反 `libnativealgorithm.so` 才能从「按构建固定」升级到「全局固定」。对**同机 replay** 已足够：secret 不变，每请求只 `t` 变 → 同 key 换新 `t` 重算 HMAC 即可。

**③ preimage 形状（getAllDevices 实样，18 段、`&` 连接、首尾都是同一 `uuid`）：**

```
uuid & appid(jdsmart-android) & 20_1720_22909_60380(疑似 build 组合) & body({"houseId":"1388207"}) & 381 &
client(android) & version(1.17.0) & brand(HUAWEI) & model(HWI-AL00) & eid & ext({"prstate":"0"}) &
functionId(jdsmart.house.getAllDevices) & network(wifi) & sdkInt(28) & appname(xjgw-android) & screen(1080*2160) & t(ms) & uuid
```

与 §7.1 的 JD 套路一致：**TreeMap 各 value 按序 `&` 拼、只拼 value**。

**④ Python 复现 / 核对**（用现成 [`verify_color_sign.py`](../verify_color_sign.py)，`--key` 直接给即 key-as-text）：

```bash
python verify_color_sign.py --preimage "<上面那串 data>" --key 6b086ed29b1a4483b4544143061b295d --expect <wire sign 或抓到的 sign>
```

本次该样本算得（**待与抓到的 `getHmacSha256Value` 返回值 / wire `sign` 比对收口**）：
- key-as-text(32B)：`91f2368a8abbc3ff37b2ae7fe0b86358be71fe010b61588f733fcff0dd2a595a` ← **首选**（与 ① 证明的约定一致）
- key-as-hex(16B) ：`247aadc258e5a348ad00d751f0794456a8dfc5fb8b62d0e2582fc09e7352705d`（旁证，native 若反常才用）

抓 (data→sign) 对照用 [`frida_sign_pipeline_capture.js`](../frida_sign_pipeline_capture.js)（A 层 `getSecretKey()`/`getHmacSha256Value` 入出 + B 贴 sign + C 下发，纯 console、#N 串因果）。
text 形命中 ⇒ 原语 + key 形态 + preimage 三者全收口，sign 即可离线现造。

## 8. 再之后：`ep` / `body` 的 `ciphertype:5`

优先验证 `LoadDoor.dec/enc` 是否即 `ciphertype:5`（§5 线索，`rpc.exports.dec` 直接解）；
否则 envelope tracer + `ENCRYPT_CLASSES` 抓明文↔密文（§8.4）。目标：能本地生成 `ep` 与 `body` 密文。
