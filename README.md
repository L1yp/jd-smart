# JD Smart (小京鱼) for Home Assistant

把京东「小京鱼」(`com.jd.smart` / `api.smart.jd.com`) 的设备状态接入 Home Assistant。
通过逆向出的 `HmacSHA1` 签名直接调用云端 `getDeviceSnapshot_v1`，无需官方网关。

> ⚠️ 个人研究/自用。需要你**自己设备账号**抓到的签名常量，不内置任何密钥。

## 仓库结构

```
custom_components/jd_smart/   # ★ Home Assistant 自定义集成（要安装的就是它）
frida_capture.js + host.py    # 抓包 + 抓签名工具（用来获取你自己的 seg1/key/tgt 等）
query_device.py               # 独立命令行查询器（联网自测用，仅标准库）
verify_sign.py                # 签名离线复现/校验
jd_smart_secrets.example.json # 凭据模板（真实值放 jd_smart_secrets.json，已 .gitignore）
docs/REVERSE_ENGINEERING.md   # 完整逆向分析笔记（协议/签名算法/方法论/排错）
```

> 📄 协议细节、签名算法、frida 抓取方法论与常见失效排查，见
> [docs/REVERSE_ENGINEERING.md](docs/REVERSE_ENGINEERING.md)。

## 1. 抓你自己的签名常量

用 Frida（需 root/可注入环境）：

```bash
python host.py -p <小京鱼包名> -s frida_capture.js --spawn
```

触发一次设备请求，从 `sign` 表 / 控制台拿到：

- `seg1`：`Authorization: smart <seg1>:::...` 的第一段（恒定）
- `key`：`Mac.init` 的 `key_txt`（HmacSHA1 密钥，恒定）
- `tgt`：请求头 `tgt`（登录票据，**会过期**）

> `device_md` 不用抓：= `md5("Android"+app_version+hard_platform+plat_version+":"+当年第几天)`，
> 末尾含 `DAY_OF_YEAR` **每天滚动一次**（这才是“tgt 没变插件也会失效”的根因）；集成与 `query_device.py` 都按 `Asia/Shanghai` 当天实时算，无需手填。

签名算法（已验证）：

```
device_md = md5("Android"+app_version+hard_platform+plat_version+":"+DAY_OF_YEAR)  # 每天变
seg2 = Base64( HmacSHA1( key, device_md + "postjson_body" + body + ts + seg1 + device_md ) )
```

## 2. 离线自测（可选）

把抓到的值填进 `jd_smart_secrets.json`（拷 `jd_smart_secrets.example.json` 改），然后：

```bash
python query_device.py --selftest                          # 校验签名算法
python query_device.py --device-id <id> --feed-id <feed>   # 真正查询
```

## 3. 安装集成

- **HACS**：把本仓库作为自定义仓库（类别 Integration）添加 → 安装 → 重启。
- **手动**：把 `custom_components/jd_smart/` 拷到 `<config>/custom_components/` → 重启。

设置 → 添加集成「小京鱼 JD Smart」→ 填上面的常量。详见
[custom_components/jd_smart/README.md](custom_components/jd_smart/README.md)。

## 安全

- 集成本体**不含任何密钥**，全部由你在配置界面填入。
- `jd_smart_secrets.json`、`*.db`（抓包数据，含你的 token）已被 `.gitignore`，不会进仓库。
- `tgt` 是登录票据，请勿公开分享；过期后在集成选项里更新。
