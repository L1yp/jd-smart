#!/usr/bin/env python3
"""
Frida 主机：加载 hook 脚本，把抓到的请求/响应落到 SQLite，方便后续 SQL 分析刷新请求。

用法:
    frida-ps -Uai                          # 先找到小京鱼 App 的包名
    python3 host.py -p <包名> --spawn      # 推荐 spawn：能抓到启动/登录阶段的请求
    python3 host.py -p <包名>              # attach 到已运行进程

依赖: pip install frida-tools
"""
import argparse
import json
import sqlite3
import sys
import threading
import time
from urllib.parse import urlparse, parse_qs, parse_qsl, unquote

import frida

DDL = """
CREATE TABLE IF NOT EXISTS http (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           INTEGER,
    captured_at  TEXT,
    method       TEXT,
    url          TEXT,
    host         TEXT,
    path         TEXT,
    has_auth     INTEGER,
    has_tgt      INTEGER,
    code         INTEGER,
    req_headers  TEXT,
    req_body     TEXT,
    resp_headers TEXT,
    resp_body    TEXT
);
CREATE INDEX IF NOT EXISTS idx_url  ON http(url);
CREATE INDEX IF NOT EXISTS idx_host ON http(host);
CREATE INDEX IF NOT EXISTS idx_auth ON http(has_auth);

CREATE TABLE IF NOT EXISTS sign (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    captured_at TEXT,
    kind        TEXT,    -- Mac.doFinal / MD.digest / Sig.sign / Cipher.doFinal / *.Base64.* / *.init / SecretKeySpec ...
    algorithm   TEXT,    -- HmacSHA1 / SHA-1 / AES/CBC/PKCS5Padding ...
    input_hex   TEXT,    -- 被签名/摘要的原文（hex）
    input_txt   TEXT,    -- 原文的可打印预览
    out_hex     TEXT,    -- 输出摘要/签名（hex）
    out_b64     TEXT,    -- 输出的 base64（Base64 事件这里存编码结果串）
    key_hex     TEXT,    -- HMAC/AES 密钥（hex）
    key_txt     TEXT,
    iv_hex      TEXT,
    matched     INTEGER, -- 是否命中 TARGETS
    target      TEXT,
    stack       TEXT     -- 调用栈（仅命中或开启 STACK_IN_DB 时有值）
);
CREATE INDEX IF NOT EXISTS idx_sign_kind  ON sign(kind);
CREATE INDEX IF NOT EXISTS idx_sign_alg   ON sign(algorithm);
CREATE INDEX IF NOT EXISTS idx_sign_b64   ON sign(out_b64);
CREATE INDEX IF NOT EXISTS idx_sign_match ON sign(matched);

-- 彩虹/色彩网关（api.m.jd.com）请求：结构与旧 smart 接口差异很大，单独建表。
-- 由 http 表里 host=api.m.jd.com 的行自动解析回填（见 parse_color），便于按 functionId/sign 回溯。
CREATE TABLE IF NOT EXISTS color (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    captured_at     TEXT,
    function_id     TEXT,    -- query functionId（网关路由，如 jdsmart.house.getHouses）
    appid           TEXT,    -- query appid（如 jdsmart-android）
    t               INTEGER, -- query t（请求时间戳 ms，参与 sign）
    uuid            TEXT,    -- query uuid（设备 uuid，32hex）
    sign            TEXT,    -- query sign（64hex = 32B = SHA-256 家族）
    ef              TEXT,    -- query ef（ep 是否加密标志，1=已加密）
    bef             TEXT,    -- query bef（body 是否加密标志，1=已加密）
    ep_ciphertype   INTEGER, -- ep 信封 ciphertype（如 5）
    ep_ridx         INTEGER, -- ep 信封 ridx
    ep_ts           INTEGER, -- ep 信封 ts（ep 多被缓存，常早于 body_ts 几秒）
    ep              TEXT,    -- ep 原始 JSON（加密的设备指纹信封）
    body_ciphertype INTEGER, -- body 信封 ciphertype
    body_ridx       INTEGER,
    body_ts         INTEGER, -- body 信封 ts（每请求新生成）
    hdid            TEXT,    -- 信封 hdid（设备硬件 id，base64 = 32B）
    version         TEXT,    -- 加密 SDK 版本（如 1.2.0）
    appname         TEXT,    -- 真实包名（com.jd.iots）
    body_cipher     TEXT,    -- body 里真正请求体的密文（cipher.body）
    body_plain      TEXT,    -- 【回填】真实请求体明文（先空，靠 cipher 表/人工回填）
    sign_input      TEXT,    -- 【回填】sign 原文 preimage（命中 sign 表后回填）
    has_auth        INTEGER,
    has_tgt         INTEGER,
    code            INTEGER,
    url             TEXT,
    resp_body       TEXT
);
CREATE INDEX IF NOT EXISTS idx_color_fid  ON color(function_id);
CREATE INDEX IF NOT EXISTS idx_color_sign ON color(sign);

-- 客户端加密 I/O：信封拼装点的调用栈 + 加密函数的 明文↔密文（来自 frida_color_capture.js）。
CREATE TABLE IF NOT EXISTS cipher (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    captured_at TEXT,
    kind        TEXT,   -- envelope（信封拼装点）/ encrypt（明文->密文）/ decrypt
    clazz       TEXT,   -- 加密类全名
    method      TEXT,   -- 方法名
    field       TEXT,   -- envelope 命中的 key（ciphertype/cipher）
    plain_txt   TEXT,   -- 明文（encrypt 的 String 入参，如 android/wifi/真实 body JSON）
    cipher_txt  TEXT,   -- 密文 / 信封 JSON
    stack       TEXT
);
CREATE INDEX IF NOT EXISTS idx_cipher_kind  ON cipher(kind);
CREATE INDEX IF NOT EXISTS idx_cipher_plain ON cipher(plain_txt);
CREATE INDEX IF NOT EXISTS idx_cipher_ct    ON cipher(cipher_txt);
"""


def _try_json(s):
    if not s:
        return None
    try:
        return json.loads(s)
    except Exception:
        return None


def parse_color(url, req_body):
    """把 api.m.jd.com 彩虹网关请求拆成结构化字段；非该网关返回 None。"""
    u = urlparse(url or "")
    if "api.m.jd.com" not in (u.netloc or ""):
        return None
    q = parse_qs(u.query, keep_blank_values=True)

    def g(k):
        v = q.get(k)
        return v[0] if v else None

    fid = g("functionId")
    if not fid:
        return None
    out = {
        "function_id": fid, "appid": g("appid"), "uuid": g("uuid"),
        "sign": g("sign"), "ef": g("ef"), "bef": g("bef"), "url": url,
    }
    try:
        out["t"] = int(g("t")) if g("t") else None
    except Exception:
        out["t"] = None

    # ep 信封（query 里 parse_qs 已 urldecode）
    out["ep"] = g("ep")
    ep = _try_json(out["ep"])
    if isinstance(ep, dict):
        out["ep_ciphertype"] = ep.get("ciphertype")
        out["ep_ridx"] = ep.get("ridx")
        out["ep_ts"] = ep.get("ts")
        out["hdid"] = ep.get("hdid")
        out["version"] = ep.get("version")
        out["appname"] = ep.get("appname")

    # body 信封：表单 `body=<urlencoded json>`（也兜底纯 json / 多字段 form）
    env = None
    if req_body:
        if req_body.startswith("body="):
            env = _try_json(unquote(req_body[len("body="):]))
        if env is None:
            env = _try_json(req_body)
        if env is None:
            form = dict(parse_qsl(req_body, keep_blank_values=True))
            if "body" in form:
                env = _try_json(form["body"])
    if isinstance(env, dict):
        out["body_ciphertype"] = env.get("ciphertype")
        out["body_ridx"] = env.get("ridx")
        out["body_ts"] = env.get("ts")
        out.setdefault("hdid", env.get("hdid"))
        out.setdefault("version", env.get("version"))
        out.setdefault("appname", env.get("appname"))
        cip = env.get("cipher")
        if isinstance(cip, dict):
            out["body_cipher"] = cip.get("body")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-p", "--package", required=True,
                    help="App 包名，用 frida-ps -Uai 查（小京鱼大概类似 com.jd.smart）")
    ap.add_argument("-s", "--script", default="frida_capture.js",
                    help="默认合并版（http+sign 双表）；彩虹网关 api.m.jd.com 用 frida_color_capture.js（多落 color+cipher 表）")
    ap.add_argument("-d", "--db", default="jd_smart_traffic.db")
    ap.add_argument("--spawn", action="store_true",
                    help="spawn 启动而非 attach，能抓到启动期的登录/换票请求")
    ap.add_argument("-H", "--host", default=None,
                    help="连接远程 frida-server，如 127.0.0.1:8899（配合 adb forward）。不填则走 USB")
    args = ap.parse_args()

    # check_same_thread=False: Frida 的 on_message 回调在后台线程触发，
    # 连接在主线程创建，必须放开同线程校验；db_lock 保证写入串行。
    con = sqlite3.connect(args.db, check_same_thread=False)
    con.executescript(DDL)
    con.commit()
    db_lock = threading.Lock()

    def insert(d):
        u = urlparse(d.get("url") or "")
        rh = d.get("req_headers") or {}
        lower = {k.lower(): v for k, v in rh.items()}
        with db_lock:
            con.execute(
                "INSERT INTO http(ts,captured_at,method,url,host,path,has_auth,has_tgt,"
                "code,req_headers,req_body,resp_headers,resp_body) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    d.get("ts"),
                    time.strftime("%Y-%m-%dT%H:%M:%S"),
                    d.get("method"),
                    d.get("url"),
                    u.netloc,
                    u.path,
                    1 if "authorization" in lower else 0,
                    1 if "tgt" in lower else 0,
                    d.get("code"),
                    json.dumps(rh, ensure_ascii=False),
                    d.get("req_body"),
                    json.dumps(d.get("resp_headers") or {}, ensure_ascii=False),
                    d.get("resp_body"),
                ),
            )
            con.commit()

    def insert_sign(d):
        with db_lock:
            con.execute(
                "INSERT INTO sign(captured_at,kind,algorithm,input_hex,input_txt,"
                "out_hex,out_b64,key_hex,key_txt,iv_hex,matched,target,stack) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    time.strftime("%Y-%m-%dT%H:%M:%S"),
                    d.get("kind"),
                    d.get("algorithm"),
                    d.get("input_hex"),
                    d.get("input_txt"),
                    d.get("out_hex"),
                    d.get("out_b64"),
                    d.get("key_hex"),
                    d.get("key_txt"),
                    d.get("iv_hex"),
                    1 if d.get("matched") else 0,
                    d.get("target"),
                    d.get("stack"),
                ),
            )
            con.commit()

    def insert_color(http_row):
        c = parse_color(http_row.get("url"), http_row.get("req_body"))
        if not c:
            return None
        rh = {k.lower(): v for k, v in (http_row.get("req_headers") or {}).items()}
        with db_lock:
            con.execute(
                "INSERT INTO color(captured_at,function_id,appid,t,uuid,sign,ef,bef,"
                "ep_ciphertype,ep_ridx,ep_ts,ep,body_ciphertype,body_ridx,body_ts,hdid,version,appname,"
                "body_cipher,has_auth,has_tgt,code,url,resp_body) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    time.strftime("%Y-%m-%dT%H:%M:%S"),
                    c.get("function_id"), c.get("appid"), c.get("t"), c.get("uuid"),
                    c.get("sign"), c.get("ef"), c.get("bef"),
                    c.get("ep_ciphertype"), c.get("ep_ridx"), c.get("ep_ts"), c.get("ep"),
                    c.get("body_ciphertype"), c.get("body_ridx"), c.get("body_ts"),
                    c.get("hdid"), c.get("version"), c.get("appname"), c.get("body_cipher"),
                    1 if "authorization" in rh else 0, 1 if "tgt" in rh else 0,
                    http_row.get("code"), c.get("url"), http_row.get("resp_body"),
                ),
            )
            con.commit()
        return c

    def insert_cipher(d):
        with db_lock:
            con.execute(
                "INSERT INTO cipher(captured_at,kind,clazz,method,field,plain_txt,cipher_txt,stack) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (
                    time.strftime("%Y-%m-%dT%H:%M:%S"),
                    d.get("kind"), d.get("clazz"), d.get("method"), d.get("field"),
                    d.get("plain_txt"), d.get("cipher_txt"), d.get("stack"),
                ),
            )
            con.commit()

    def on_message(message, data):
        if message.get("type") == "send":
            payload = message.get("payload") or {}
            kind = payload.get("type")
            if kind == "http":
                d = payload["data"]
                try:
                    insert(d)
                except Exception as e:
                    print("[db error]", e)
                    return
                rh = {k.lower(): v for k, v in (d.get("req_headers") or {}).items()}
                flag = ""
                if "authorization" in rh:
                    flag += " [AUTH]"
                if "tgt" in rh:
                    flag += " [TGT]"
                url = (d.get("url") or "")[:100]
                print(f'{d.get("code")} {d.get("method")} {url}{flag}')
                # 彩虹网关请求顺手解析进 color 表（结构差异大，单独存）
                try:
                    c = insert_color(d)
                    if c:
                        print(f'    [COLOR] functionId={c.get("function_id")} '
                              f'sign={(c.get("sign") or "")[:16]}.. ef={c.get("ef")} bef={c.get("bef")}')
                except Exception as e:
                    print("[db error/color]", e)
            elif kind == "cipher":
                d = payload.get("data") or {}
                try:
                    insert_cipher(d)
                except Exception as e:
                    print("[db error/cipher]", e)
                    return
                ck = d.get("kind")
                if ck == "encrypt":
                    p = (d.get("plain_txt") or "")[:48]
                    cc = (d.get("cipher_txt") or "")[:32]
                    print(f'    [CIPHER] {d.get("clazz")}.{d.get("method")} "{p}" -> {cc}..')
                elif ck == "envelope":
                    print('    [CIPHER] envelope 拼装点已记录（cipher 表，含调用栈）')
            elif kind == "sign":
                d = payload.get("data") or {}
                try:
                    insert_sign(d)
                except Exception as e:
                    print("[db error]", e)
            elif kind == "error":
                print("[script error]", payload.get("data"))
        elif message.get("type") == "log":
            # 脚本里的 console.log/warn/error 走这里（例如 frida_sign_capture.js）
            print(message.get("payload"))
        elif message.get("type") == "error":
            print("[frida error]", message.get("stack") or message.get("description"))

    if args.host:
        device = frida.get_device_manager().add_remote_device(args.host)
    else:
        device = frida.get_usb_device(timeout=10)
    with open(args.script, "r", encoding="utf-8") as f:
        src = f.read()

    if args.spawn:
        pid = device.spawn([args.package])
        session = device.attach(pid)
        script = session.create_script(src)
        script.on("message", on_message)
        script.load()
        device.resume(pid)
    else:
        session = device.attach(args.package)
        script = session.create_script(src)
        script.on("message", on_message)
        script.load()

    print(f"[*] 抓包中，写入 {args.db} ... Ctrl+C 结束")
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass
    print("\n[*] 已停止")


if __name__ == "__main__":
    main()