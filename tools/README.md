# 逆向算法工具台（离线 HTML）

`index.html` —— 纯前端、零依赖、可离线（直接双击用浏览器打开）。复刻
[`docs/REVERSE_ENGINEERING.md`](../docs/REVERSE_ENGINEERING.md) /
[`docs/GETHOUSES_PROGRESS.md`](../docs/GETHOUSES_PROGRESS.md) 里已验证的算法，供本地测试。
所有计算都在浏览器内本地完成，**输入不出本页**，工具本身**不内置任何真实密钥/设备指纹**。

> 加密原语（MD5 / SHA-1 / SHA-256 / HMAC）是纯 JS 自实现，不依赖 Web Crypto，
> 所以 `file://` 直接打开也能用，无需起服务器。

## 四个标签页

| 标签 | 对应算法 | 输入 → 输出 |
|---|---|---|
| **彩虹 Sign · HMAC-SHA256** | `api.m.jd.com` 网关 query `sign`（进度 §7.3）| secret + 18 键设备档/请求字段 → preimage（字母序拼）+ `sign`(64hex)。支持「从 ep 信封自动解析设备档」、`t` 一键取现在、与 wire sign 比对 |
| **ciphertype:5 编解码 / 信封** | 换表 base64（`color_codec.py`）+ ep/body 信封 | 解码 cipher→明文 / 编码明文→cipher；整段信封解析成字段表；明文字段反向封成 `ciphertype:5` 信封（含 URL 编码） |
| **旧接口 Sign · HmacSHA1** | `getDeviceSnapshot_v1`（`verify_sign.py` / `api.py`）| key+seg1+设备三参+feed_id → `device_md`(MD5,UTC+8 每日滚动) / message / `seg2`(Base64) / Authorization。`ts` 取 UTC+8 墙钟贴 Z |
| **哈希 / HMAC 实验台** | 通用原语 | MD5/SHA-1/SHA-256 实时哈希；HMAC-SHA1/SHA-256（key 文本或 hex，含 jdupgrade/彩虹通用验签）；Base64/Hex 互转 |

## 自检

`_test.js` 抽取 `index.html` 内的核心脚本块，对照标准向量、Node 内置 `crypto`、
`test.http` 实样与 Python 参考脚本逐字节核对：

```bash
node tools/_test.js     # 期望「全部通过 ✓ (47)」
```

## 典型用法：换新 `t` 重算彩虹 sign（getHouses 防重放）

1. 打开 `index.html` → **彩虹 Sign** 标签。
2. 把抓包 `?ep=` 的内容粘进「从 ep 信封自动解析设备档」→ 解析（自动填 14 项设备档）。
3. 填 `secret`（native `getSecretKey()` 的 32 字符）、`functionId`、`body`。
4. 点「现在」取最新 `t` → 计算 → 得到新的 `preimage` 与 `sign`，替换原请求即可。

> 仅供个人研究 / 自用自己账号设备。secret、`eid`、`tgt` 等敏感值勿外传、勿提交
>（`jd_smart_secrets.json`、`*.http`、`*.db` 已 `.gitignore`）。
