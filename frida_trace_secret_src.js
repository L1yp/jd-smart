"use strict";
/*
 * frida_trace_secret_src.js —— 反查一个“已知值”（如 device_md）从哪来。
 *
 * 场景：你已经知道 device_md 的当前值，但不知道它从哪读出来 / 何时生成。
 * 已知签名链（由 auth-tracer 的调用栈定位）：
 *   RestClient.postJson -> PostStringBuilder(rc.e) -> PostStringRequest(vc.g)
 *   -> OkHttpRequest(vc.d).a  在 OkHttpRequest.java:46 把 authorization 头 add 进去。
 * device_md 在更早某处被读出来，拼进 HMAC 原文 (device_md + tag + body + ts + seg1 + device_md)。
 *
 * 本脚本盯几类“值的出口”，命中你的目标值就打调用栈，顺栈即到来源：
 *   1) SharedPreferences getString/putString —— 标准 prefs 存取（= 现有 secret-finder 覆盖的范围）
 *   2) MMKV decodeString/getString           —— 腾讯 MMKV（京东系 App 常用，标准 SP hook 抓不到它！）
 *   3) JSONObject getString/optString         —— 从某接口响应 JSON 里解析出来的那一刻（最可能直指下发接口），
 *                                               命中时连整个 JSON 上下文一起打印，看它和谁（如 tgt）一起下发。
 *
 * 用法:
 *   1) 把 TARGETS 填成你的 device_md（当前有效值）。勿提交真实值（已 .gitignore 的 secrets 不在此文件）。
 *   2) python host.py -p <启动包名> -s frida_trace_secret_src.js --spawn
 *   3) 触发一次设备刷新 -> 看“读取点”；【退出账号 -> 重新登录】-> 看“下发/生成点”。
 *
 * 命中记录也会 send 到 host.py 的 sign 表（kind 形如 'SRC@JSONObject.getString'）。
 */
var TARGETS = [
  // '在这里填你的 device_md（当前有效值）', 勿提交真实值
  "db60ac94429fe21148453f8adb2c6588",
];
var MAX_TXT = 1024; // value / JSON 上下文预览上限

function safe(fn, d) {
  try {
    return fn();
  } catch (e) {
    return d;
  }
}
function clip(s) {
  s = "" + s;
  return s.length > MAX_TXT
    ? s.slice(0, MAX_TXT) + "..(+" + (s.length - MAX_TXT) + ")"
    : s;
}
function hitOf(v) {
  if (v === null || v === undefined) return null;
  var s = "" + v;
  for (var i = 0; i < TARGETS.length; i++)
    if (TARGETS[i] && s.indexOf(TARGETS[i]) !== -1) return TARGETS[i];
  return null;
}

/* wjlogin 登录态(WUserSigInfo)读写追踪 —— 所有 frida_*.js 内置（见 REVERSE_ENGINEERING.md §5.6）
 * createUserInfoFromJSON(读/初始化) + toJSONObject(写/落盘)，两者 dump 调用栈看更新机制。落 sign 表(kind=WUserSig.*)。
 * 注意：放在 TARGETS 早退之前调用，所以即便没填 TARGETS 也照常抓登录态读写。 */
var WJ_DONE = false;
function installWjloginHook() {
  var CLS = "jd.wjlogin_sdk.model.WUserSigInfo";
  var Throwable = Java.use("java.lang.Throwable");
  var Log = Java.use("android.util.Log");
  function stk() { try { return Log.getStackTraceString(Throwable.$new()); } catch (e) { return "(no stack)"; } }
  function clip2(s, n) { s = "" + s; return s.length > n ? s.substring(0, n) + "..(+" + (s.length - n) + "B)" : s; }
  var seen = {};
  function dump(op, json) {
    var s = stk(), sig = s.split("\n").slice(0, 8).join("|"), first = !seen[sig];
    if (first) seen[sig] = 1;
    console.log("\n########## wjlogin " + op + " ##########");
    console.log(" json = " + (json == null ? "null" : clip2(json, 1400)));
    if (first) { console.log(s); console.log(" ↑ 紧贴 jd.wjlogin_sdk 之前的 App 帧 = 触发读/写处（更新机制看这里）"); }
    else console.log(" (调用栈同前次，省略)");
    console.log("############################################\n");
    try { send({ type: "sign", data: { kind: "WUserSig." + op, input_txt: json, stack: s, matched: 1 } }); } catch (e) {}
  }
  function doHook(W) {
    if (WJ_DONE) return; WJ_DONE = true;
    var m1 = W.createUserInfoFromJSON;
    if (m1 && m1.overloads) {
      m1.overloads.forEach(function (ov) {
        ov.implementation = function () {
          var json = null; try { if (arguments.length && arguments[0]) json = "" + arguments[0].toString(); } catch (e) {}
          var ret = ov.apply(this, arguments);
          dump("createUserInfoFromJSON(读/初始化)", json);
          return ret;
        };
      });
      console.log("[wjlogin] hooked " + CLS + ".createUserInfoFromJSON x" + m1.overloads.length);
    } else console.log("[wjlogin] 未找到 createUserInfoFromJSON 方法（版本差异？）");
    var m2 = W.toJSONObject;
    if (m2 && m2.overloads) {
      m2.overloads.forEach(function (ov) {
        ov.implementation = function () {
          var ret = ov.apply(this, arguments);
          var json = null; try { if (ret) json = "" + ret.toString(); } catch (e) {}
          dump("toJSONObject(写/落盘)", json);
          return ret;
        };
      });
      console.log("[wjlogin] hooked " + CLS + ".toJSONObject x" + m2.overloads.length);
    } else console.log("[wjlogin] 未找到 toJSONObject 方法（版本差异？）");
  }
  var tries = 0, MAX = 30;
  (function attempt() {
    if (WJ_DONE) return;
    var W = null; try { W = Java.use(CLS); } catch (e) { W = null; }
    if (W) { doHook(W); return; }
    if (++tries <= MAX) setTimeout(function () { Java.perform(attempt); }, 700);
    else console.log("[wjlogin] 放弃：" + CLS + " 一直未加载（该版本可能未集成 wjlogin / 改名）");
  })();
}

Java.perform(function () {
  try { installWjloginHook(); } catch (e) { console.log("[!] wjlogin hook 安装失败: " + e); }
  if (!TARGETS.length) {
    console.log("[trace-src] 先填 TARGETS（你的 device_md），否则没目标可追（但 wjlogin 登录态读写照常抓）。");
    return;
  }
  var Throwable = Java.use("java.lang.Throwable");
  var Log = Java.use("android.util.Log");
  function stack() {
    return safe(function () {
      return Log.getStackTraceString(Throwable.$new());
    }, "(no stack)");
  }

  function report(where, key, value, ctx) {
    var stk = stack();
    console.log("\n##### SRC 命中 @ " + where + "  key=" + key + " #####");
    console.log(" value = " + clip(value));
    if (ctx) console.log(" ctx   = " + clip(ctx));
    console.log(stk);
    console.log("################################################\n");
    try {
      send({
        type: "sign",
        data: {
          kind: "SRC@" + where,
          input_txt: "" + key,
          out_b64: "" + value,
          stack: stk,
          matched: 1,
        },
      });
    } catch (e) {}
  }

  // hook 一批“返回 String”的取值方法：返回值命中目标就打栈。
  // keyIdx: 哪个入参是“键名”（用于报告）；withCtx: 命中时是否把 this.toString() 一起 dump。
  function hookReturn(cls, names, keyIdx, withCtx) {
    var clazz = safe(function () {
      return Java.use(cls);
    }, null);
    if (!clazz) {
      console.log(
        "[trace-src] 跳过 " + cls + "（未解析，可能没用它或类名被改）",
      );
      return;
    }
    names.forEach(function (mn) {
      var m = clazz[mn];
      if (!m || !m.overloads) return;
      m.overloads.forEach(function (ov) {
        ov.implementation = function () {
          var self = this;
          var r = ov.apply(this, arguments);
          try {
            if (hitOf(r)) {
              var key =
                keyIdx != null && arguments.length > keyIdx
                  ? arguments[keyIdx]
                  : "?";
              var ctx = withCtx
                ? safe(function () {
                    return "" + self.toString();
                  }, null)
                : null;
              report(cls.split(".").pop() + "." + mn, key, r, ctx);
            }
          } catch (e) {}
          return r;
        };
      });
      console.log(
        "[trace-src] hooked " + cls + "." + mn + " x" + m.overloads.length,
      );
    });
  }

  // 1) 标准 SharedPreferences 读取点
  hookReturn("android.app.SharedPreferencesImpl", ["getString"], 0, false);
  // 标准 SharedPreferences 写入点（命中在入参 value 上）
  var Ed = safe(function () {
    return Java.use("android.app.SharedPreferencesImpl$EditorImpl");
  }, null);
  if (Ed && Ed.putString)
    Ed.putString.overloads.forEach(function (ov) {
      ov.implementation = function (k, v) {
        try {
          if (hitOf(v)) report("SP.putString", k, v, null);
        } catch (e) {}
        return ov.apply(this, arguments);
      };
    });

  // 2) MMKV（京东系常用；之前 secret-finder 只盯标准 SP，若值走 MMKV 就抓不到）
  hookReturn("com.tencent.mmkv.MMKV", ["decodeString", "getString"], 0, false);

  // 3) JSONObject：解析接口响应取出 device_md 的瞬间（最可能直指下发接口），带整个 JSON 上下文
  hookReturn("org.json.JSONObject", ["getString", "optString"], 0, true);

  console.log(
    "\n[trace-src] 就位。盯：" +
      JSON.stringify(
        TARGETS.map(function (t) {
          return (t || "").slice(0, 8) + "..";
        }),
      ),
  );
  console.log(
    "[trace-src] 触发设备刷新看读取点；退出账号 -> 重新登录 看下发/生成点。",
  );
  console.log(
    "[trace-src] 全都没命中 = 值可能常驻内存（登录时算好放单例字段）或被别的存储持有，转静态 jadx 看 OkHttpRequest(vc.d).a。\n",
  );
});
