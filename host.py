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
from urllib.parse import urlparse

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
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-p", "--package", required=True,
                    help="App 包名，用 frida-ps -Uai 查（小京鱼大概类似 com.jd.smart）")
    ap.add_argument("-s", "--script", default="frida_capture.js",
                    help="默认合并版（http+sign 双表）；也可单独用 frida_okhttp_capture.js / frida_sign_capture.js")
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