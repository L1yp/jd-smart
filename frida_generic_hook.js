"use strict";

/*
 * frida_generic_hook.js —— 通用方法 hook：只改顶部 SIGNATURES 列表即可
 *
 * 你想 hook 哪个方法，就把它的「签名」写进【外置文件 hook_signatures.js】（不用动本文件），脚本会自动：
 *   1) 等类加载（晚加载自动重试） -> 解析重载 -> 安装 hook；
 *   2) 每次被调用时在 console 打印一行（类.方法(签名)、入参、返回、可选调用栈）；
 *   3) 把 函数 / 入参 / 出参 / 线程 / 栈 落进 SQLite 的 hook_log 表（配 host.py，type=hook）。
 *      参数/返回【完整记录、不截断】；前 20 个入参各占一列 arg0~arg19，更多入参收进 args 字段。
 *
 * 不需要懂 frida：你只动 hook_signatures.js 里的签名列表（必要时动本文件几个全局开关）。其它都是通用逻辑。
 *
 * ── 签名怎么写（SIGNATURES 里每一项）──────────────────────────────────────
 *   字符串形式（最常用）：
 *     'pkg.Clazz.method'                         hook 该方法的【全部重载】
 *     'pkg.Clazz.method(java.lang.String,int)'   只 hook【指定参数】的那个重载
 *     'pkg.Clazz.method()'                        只 hook【无参】重载
 *     'pkg.Clazz.$init'                           hook【构造函数】（全部重载）
 *     'pkg.Clazz.$init(android.content.Context)'  hook 指定参数的构造
 *     'pkg.Clazz.*'                               hook 该类【全部声明方法】（不含构造）
 *   对象形式（给单条加选项）：
 *     { sig: 'pkg.Clazz.method', stack: true, tag: 'login', stash: true }
 *       stack=true  -> 该条每次都抓调用栈（贵，按需开）
 *       tag='xxx'   -> 落库到 hook_log.tag，方便 SQL 过滤同一类调用
 *       stash=true  -> 命中时把 this/对象入参/对象返回 retain 进对象仓库，配 RPC 调方法/读写字段（见文末 RPC）
 *
 *   参数类型写法很宽松：全名 'java.lang.String' / 简名 'String' / 数组 'byte[]' 或 '[B'
 *   / 基本类型 'int','long','boolean' 都认。指定参数没匹配到时，默认兜底 hook 全部重载并告警
 *   （想严格匹配把 STRICT_OVERLOAD 设 true）。
 *
 * ── 用法 ────────────────────────────────────────────────────────────────
 *   改签名：编辑 hook_signatures.js（host.py 会自动注入，无需动本文件）。
 *   落库（推荐）:  python host.py -p <包名> -s frida_generic_hook.js --spawn
 *                  （默认读 hook_signatures.js；想换文件加 --sig-file 别的.js）
 *   仅看 console:  frida -U -f <包名> -l frida_generic_hook.js
 *                  （standalone 不走 host.py，用本文件 DEFAULT_SIGNATURES 兜底；要用外置列表请走 host.py）
 *
 *   不知道方法签名长啥样？REPL 里枚举一个类的全部方法/构造：
 *     rpc.exports.dump("com.jd.sec.LogoManager")
 *   看当前各签名命中次数：
 *     rpc.exports.list()
 *
 *   ── RPC：拿 hook 现场的活对象来调方法/读写字段（standalone REPL 里用）──────────
 *     目标签名加 {stash:true}（或 rpc.exports.arm('类.方法',{stash:true}) 现场补），触发一次后：
 *       rpc.exports.objs()                      看仓库里有哪些对象（#id 类）
 *       rpc.exports.fields(id)                  列出该对象全部字段名=值（含父类/私有）
 *       rpc.exports.get(id,'a.b.c')             读字段（可路径下钻；对象结果再入仓返回新 id）
 *       rpc.exports.call(id,'m',[args],types?)  调方法（args 里 {$id:n} 可传别的仓库对象）
 *       rpc.exports.set(id,'field',value)       写字段
 *     id 填类全名字符串 => 操作静态方法/字段；release(id)/clearobjs() 清仓。
 *
 *   ── 专用：调网银 SDK 的 p7Envelope（默认自动跑，host.py 下也能拿结果）─────────
 *     默认 AUTO_P7=true：启动 AUTO_P7_DELAY_MS 后自动调一次（等类/Application 就绪，晚加载自动重试），
 *       结果 send(type=hook) 落 host.py 的 hook_log 表（tag=p7）并打印一行 —— 走 host.py 无需手动调。
 *       不想自动跑就把 AUTO_P7 设 false。查结果：SELECT * FROM hook_log WHERE tag='p7' ORDER BY id DESC;
 *     手动/重调（standalone REPL）：
 *       rpc.exports.p7envelope()          CryptoUtils.newInstance(ctx).p7Envelope(静态字段 a, content.getBytes())
 *                                          ctx 现取、key=CryptoUtils.a、content 默认 com.jd.iots/CCO-RISK JSON
 *       rpc.exports.p7envelope('{...}')   自定义 content 文本（其余同上）；返回 {byteLen,hex,b64,txt}
 *
 *   触发后查库：
 *     SELECT captured_at,clazz,method,sig,arg0,arg1,arg2,ret_txt,ret_b64 FROM hook_log ORDER BY id DESC LIMIT 50;
 *     SELECT clazz,method,args,ret_txt FROM hook_log WHERE tag='login';   -- args = 全部入参完整 dump
 */

/* =======================================================================
 *  ★ 签名列表 —— 请改外置文件 hook_signatures.js，本文件不用动 ★
 *  host.py 加载时会把 hook_signatures.js 的内容注入到下面这行标记处
 *  （定义 EXTERNAL_SIGNATURES）。该标记行勿删。
 *  没有外置文件时（如 standalone 纯看 console），用 DEFAULT_SIGNATURES 兜底。
 * ======================================================================= */
//__EXTERNAL_SIGNATURES__

var DEFAULT_SIGNATURES = [
  // 仅在「没有 hook_signatures.js」时作兜底；正常改签名请去 hook_signatures.js
  "com.jd.sec.LogoManager.getLogo",
];
var SIGNATURES =
  typeof EXTERNAL_SIGNATURES !== "undefined" && EXTERNAL_SIGNATURES
    ? EXTERNAL_SIGNATURES
    : DEFAULT_SIGNATURES;

/* =======================================================================
 *  全局开关（一般不用动）
 * ======================================================================= */
var STACK = false; // 全局：每条都抓调用栈（很贵）。多数情况关，单条用 {stack:true} 精确开
var STRICT_OVERLOAD = false; // 指定参数没匹配到重载时：false=兜底 hook 全部重载并告警；true=跳过该条
var INSPECT_OBJECTS = true; // 非 String/byte[]/数值 的对象，是否 toString 取值（限长 OBJ_TXT_MAX）
var THREAD_NAME = true; // 记录调用线程名（每次一次 Java 调用，量极大可关）
var STASH_FROM_HOOK = false; // 全局：hook 命中时把 this/对象入参/对象返回 retain 进对象仓库（配 RPC）；也可单条 {stash:true} 精确开
var STASH_CAP = 200; // 对象仓库上限，超了自动丢最旧（防 retain 长跑泄漏）

// 默认 0 = 完整记录、不截断（便于离线测算法/还原）。某次值特别大想限长，把对应项改成 >0 的字节/字符数。
var MAX_HEX = 0; // byte[] 的 hex 上限（字节）；0=不截断
var MAX_TXT = 0; // 文本上限（字符）；0=不截断
var OBJ_TXT_MAX = 0; // 对象 toString 上限；0=不截断

var MAX_PER_SIG = 0; // 每个签名最多落库多少条（防刷屏/刷库），0=不限
var CONSOLE_MAX = 0; // console 打印行数上限，0=不限
var ARM_DELAY_MS = 0; // >0：延迟装 hook（避开启动期检测窗口，闪退就设 3000~5000）
var RETRY_MS = 700,
  RETRY_MAX = 60; // 类晚加载时的重试间隔/次数

var SKIP_METHODS = [
  "toString",
  "hashCode",
  "equals",
  "clone",
  "finalize",
  "getClass",
  "wait",
  "notify",
  "notifyAll",
]; // '*' 全方法模式下跳过这些

/* =======================================================================
 *  纯 JS 字节/类型工具（不回调被 hook 的 API，避免递归/副作用）
 * ======================================================================= */
var HEX = "0123456789abcdef";
var B64C = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function safe(fn, d) {
  try {
    return fn();
  } catch (e) {
    return d;
  }
}
function isBytes(x) {
  return (
    x !== null &&
    x !== undefined &&
    x.length !== undefined &&
    typeof x !== "string" &&
    typeof x !== "function"
  );
}
function clip(s, n) {
  if (s === null || s === undefined) return null;
  s = "" + s;
  return n > 0 && s.length > n
    ? s.substring(0, n) + "..(+" + (s.length - n) + ")"
    : s;
}
function toHex(b) {
  if (!isBytes(b)) return null;
  var n = b.length,
    m = MAX_HEX > 0 ? Math.min(n, MAX_HEX) : n,
    s = "";
  for (var i = 0; i < m; i++) {
    var v = b[i] & 0xff;
    s += HEX.charAt(v >> 4) + HEX.charAt(v & 0xf);
  }
  if (n > m) s += "..(+" + (n - m) + "B)";
  return s;
}
function toTxt(b) {
  if (!isBytes(b)) return null;
  var n = MAX_TXT > 0 ? Math.min(b.length, MAX_TXT) : b.length,
    s = "";
  for (var i = 0; i < n; i++) {
    var c = b[i] & 0xff;
    if (c >= 0x20 && c < 0x7f) s += String.fromCharCode(c);
    else if (c === 0x0a) s += "\\n";
    else if (c === 0x0d) s += "\\r";
    else if (c === 0x09) s += "\\t";
    else s += ".";
  }
  if (b.length > n) s += "..";
  return s;
}
function toB64(b) {
  if (!isBytes(b)) return null;
  var n = MAX_HEX > 0 ? Math.min(b.length, MAX_HEX) : b.length,
    s = "";
  for (var i = 0; i < n; i += 3) {
    var b0 = b[i] & 0xff,
      b1 = i + 1 < n ? b[i + 1] & 0xff : 0,
      b2 = i + 2 < n ? b[i + 2] & 0xff : 0;
    var t = (b0 << 16) | (b1 << 8) | b2;
    s += B64C.charAt((t >> 18) & 63) + B64C.charAt((t >> 12) & 63);
    s += i + 1 < n ? B64C.charAt((t >> 6) & 63) : "=";
    s += i + 2 < n ? B64C.charAt(t & 63) : "=";
  }
  if (b.length > n) s += "..(+" + (b.length - n) + "B)";
  return s;
}
/* JVM/类型名 -> 可读简名：'java.lang.String'->'String'，'[B'->'byte[]'，'int'->'int'，'[Ljava.lang.String;'->'String[]' */
function simpleType(jvm) {
  if (!jvm) return "?";
  jvm = "" + jvm;
  var arr = "";
  while (jvm.charAt(0) === "[") {
    arr += "[]";
    jvm = jvm.substring(1);
  }
  var map = {
    B: "byte",
    C: "char",
    I: "int",
    J: "long",
    S: "short",
    Z: "boolean",
    F: "float",
    D: "double",
    V: "void",
  };
  if (jvm.length === 1 && map[jvm]) return map[jvm] + arr;
  if (jvm.charAt(0) === "L" && jvm.charAt(jvm.length - 1) === ";")
    jvm = jvm.substring(1, jvm.length - 1);
  var dot = jvm.lastIndexOf(".");
  return (dot >= 0 ? jvm.substring(dot + 1) : jvm) + arr;
}

/* 把返回值格式化成 {type, txt, hex, b64}（byte[] 同时给 txt/hex/b64） */
function fmtVal(x) {
  if (x === null || x === undefined)
    return {
      type: x === null ? "null" : "void",
      txt: null,
      hex: null,
      b64: null,
    };
  var t = typeof x;
  if (t === "string")
    return { type: "String", txt: clip(x, MAX_TXT), hex: null, b64: null };
  if (t === "number" || t === "boolean")
    return { type: t, txt: "" + x, hex: null, b64: null };
  if (isBytes(x))
    return {
      type: "byte[" + x.length + "]",
      txt: toTxt(x),
      hex: toHex(x),
      b64: toB64(x),
    };
  if (INSPECT_OBJECTS) {
    var cn =
      safe(function () {
        return x.$className;
      }, null) ||
      safe(function () {
        return "" + x.getClass().getName();
      }, "obj");
    return {
      type: cn,
      txt: clip(
        safe(
          function () {
            return "" + x;
          },
          "<" + cn + ">",
        ),
        OBJ_TXT_MAX,
      ),
      hex: null,
      b64: null,
    };
  }
  return { type: "obj", txt: "<obj>", hex: null, b64: null };
}

/* 把单个参数格式化成「一列的完整值」（不截断）：
 *   String -> 原文；数值/布尔 -> 其字符串；byte[] -> 完整 hex（无损）；其它对象 -> toString；null/缺参 -> null */
function argStr(x) {
  if (x === null || x === undefined) return null;
  var t = typeof x;
  if (t === "string") return x;
  if (t === "number" || t === "boolean") return "" + x;
  if (isBytes(x)) return toHex(x);
  if (INSPECT_OBJECTS) {
    var cn =
      safe(function () {
        return x.$className;
      }, null) ||
      safe(function () {
        return "" + x.getClass().getName();
      }, "obj");
    return safe(
      function () {
        return "" + x;
      },
      "<" + cn + ">",
    );
  }
  return "<obj>";
}

/* =======================================================================
 *  解析签名字符串/对象 -> {sig, clazz, method, args, stack, tag}
 *    args: null=任意重载 / []=无参 / [类型...]=指定重载
 * ======================================================================= */
function parseSig(entry) {
  var sig,
    stack = false,
    tag = null,
    stash = false;
  if (typeof entry === "string") {
    sig = entry;
  } else {
    sig = entry.sig;
    stack = !!entry.stack;
    tag = entry.tag || null;
    stash = !!entry.stash;
  }
  var s = ("" + sig).trim();
  var args = null;
  var lp = s.indexOf("(");
  if (lp !== -1) {
    var rp = s.lastIndexOf(")");
    var inside = rp > lp ? s.substring(lp + 1, rp).trim() : "";
    args = inside.length
      ? inside.split(",").map(function (x) {
          return x.trim();
        })
      : [];
    s = s.substring(0, lp).trim();
  }
  var dot = s.lastIndexOf(".");
  return {
    sig: ("" + sig).trim(),
    clazz: dot >= 0 ? s.substring(0, dot) : s,
    method: dot >= 0 ? s.substring(dot + 1) : s,
    args: args,
    stack: stack,
    tag: tag,
    stash: stash,
    _done: false,
  };
}

/* =======================================================================
 *  运行时状态 / 输出
 * ======================================================================= */
var parsed = SIGNATURES.map(parseSig);
var sigCount = {}; // key=类#方法签名 -> 落库次数（也供 MAX_PER_SIG / list()）
var armTries = 0;
var consoleLines = 0;
var Throwable = null,
  Log = null,
  ThreadCls = null;

function clog(s) {
  if (CONSOLE_MAX === 0 || consoleLines < CONSOLE_MAX) {
    console.log(s);
    consoleLines++;
  }
}
function stk() {
  return safe(function () {
    return Log.getStackTraceString(Throwable.$new());
  }, "(no stack)");
}
function curThread() {
  return safe(function () {
    if (!ThreadCls) ThreadCls = Java.use("java.lang.Thread");
    return "" + ThreadCls.currentThread().getName();
  }, null);
}
function emit(rec) {
  try {
    send({ type: "hook", data: rec });
  } catch (e) {}
}

function buildSig(ov) {
  var ats = ov.argumentTypes || [],
    o = [];
  for (var i = 0; i < ats.length; i++) o.push(simpleType(ats[i].className));
  return "(" + o.join(",") + ")";
}

/* 反射该类的 native/static 标记：
 *   bySig : key = 方法名+签名（如 "calc(String,int)"）-> {native,static}，【按重载精确判定】
 *   byName: key = 方法名 -> {native,static}（同名重载 OR 聚合，作兜底 + 全方法模式取方法名用）
 *   合并 getMethods（含继承的 public）与 getDeclaredMethods（本类全部，含 private/native，后者覆盖前者） */
function classMeta(C) {
  var bySig = {},
    byName = {};
  var Modifier = safe(function () {
    return Java.use("java.lang.reflect.Modifier");
  }, null);
  function feed(list) {
    if (!list) return;
    for (var i = 0; i < list.length; i++) {
      (function (m) {
        var nm = safe(function () {
          return "" + m.getName();
        }, "?");
        var mods = safe(function () {
          return m.getModifiers();
        }, 0);
        var nat =
          Modifier &&
          safe(function () {
            return Modifier.isNative(mods);
          }, false);
        var sta =
          Modifier &&
          safe(function () {
            return Modifier.isStatic(mods);
          }, false);
        var pts =
            safe(function () {
              return m.getParameterTypes();
            }, []) || [],
          ps = [];
        for (var k = 0; k < pts.length; k++)
          ps.push(simpleType("" + pts[k].getName()));
        bySig[nm + "(" + ps.join(",") + ")"] = {
          native: !!nat,
          static: !!sta,
        };
        if (!byName[nm]) byName[nm] = { native: false, static: false };
        if (nat) byName[nm].native = true;
        if (sta) byName[nm].static = true;
      })(list[i]);
    }
  }
  feed(
    safe(function () {
      return C.class.getMethods();
    }, null),
  );
  feed(
    safe(function () {
      return C.class.getDeclaredMethods();
    }, null),
  );
  var ctors =
    safe(function () {
      return C.class.getDeclaredConstructors();
    }, []) || [];
  for (var j = 0; j < ctors.length; j++) {
    (function (ct) {
      var pts =
          safe(function () {
            return ct.getParameterTypes();
          }, []) || [],
        ps = [];
      for (var k = 0; k < pts.length; k++)
        ps.push(simpleType("" + pts[k].getName()));
      bySig["$init(" + ps.join(",") + ")"] = { native: false, static: false };
    })(ctors[j]);
  }
  byName["$init"] = { native: false, static: false };
  return { bySig: bySig, byName: byName };
}

/* 从一个方法的全部重载里挑出匹配 args 的那些（args=null 全要；按简名比较，宽松） */
function selectOverloads(fn, args) {
  if (args === null) return fn.overloads.slice();
  var want = args.map(function (a) {
    return simpleType(a);
  });
  var res = [];
  fn.overloads.forEach(function (ov) {
    var ats = ov.argumentTypes || [];
    if (ats.length !== want.length) return;
    var ok = true;
    for (var i = 0; i < ats.length; i++) {
      if (simpleType(ats[i].className) !== want[i]) {
        ok = false;
        break;
      }
    }
    if (ok) res.push(ov);
  });
  return res;
}

/* =======================================================================
 *  hook 安装 + 回调
 * ======================================================================= */
function hookOne(entry, ov, meta) {
  var sig = buildSig(ov);
  ov.implementation = function () {
    var ret,
      threw = null;
    try {
      ret = ov.apply(this, arguments);
    } catch (e) {
      threw = e;
    }
    try {
      handle(entry, sig, meta, this, arguments, ret, threw);
    } catch (_) {}
    if (threw) throw threw; // 不改变原行为：原方法抛异常照样抛出
    return ret;
  };
  return sig;
}

function handle(entry, sig, meta, self, jsArgs, ret, threw) {
  var name = entry.method;
  var info =
    (meta.bySig && meta.bySig[name + sig]) ||
    (meta.byName && meta.byName[name]) || { native: false, static: false };

  var key = entry.clazz + "#" + name + sig;
  var c = (sigCount[key] = (sigCount[key] || 0) + 1);
  if (MAX_PER_SIG > 0 && c > MAX_PER_SIG) {
    if (c === MAX_PER_SIG + 1)
      clog(
        "[HK] " +
          entry.clazz +
          "." +
          name +
          sig +
          " 已达 MAX_PER_SIG=" +
          MAX_PER_SIG +
          "，后续不再落库（调大 MAX_PER_SIG 或加参数过滤）",
      );
    return;
  }

  var rec = {
    clazz: entry.clazz,
    method: name,
    sig: sig,
    is_static: info.static ? 1 : 0,
    is_native: info.native ? 1 : 0,
    tag: entry.tag || null,
  };

  /* 入参：前 20 个各占一列 arg0..arg19；全部入参完整拼进 args（含第 21 个起的溢出），均不截断 */
  var vals = [];
  for (var i = 0; i < jsArgs.length; i++) {
    var s = argStr(jsArgs[i]);
    vals.push(s);
    if (i < 20) rec["arg" + i] = s;
  }
  rec.args = vals.length
    ? vals
        .map(function (s, k) {
          return "a" + k + "=" + (s === null ? "null" : s);
        })
        .join(" | ")
    : "()";

  /* 返回（或异常），不截断 */
  var rv = threw
    ? { type: "throw", txt: "" + threw, hex: null, b64: null }
    : fmtVal(ret);
  rec.ret_type = rv.type;
  rec.ret_txt = rv.txt;
  rec.ret_hex = rv.hex;
  rec.ret_b64 = rv.b64;

  rec.stack = entry.stack || STACK ? stk() : null;
  rec.thread = THREAD_NAME ? curThread() : null;

  /* 可选：把 this / 对象入参 / 对象返回 retain 进对象仓库，供 RPC 调方法/读写字段（主要配 standalone REPL）*/
  var stashStr = "";
  if (entry.stash || STASH_FROM_HOOK) {
    var ids = [];
    var sT = stashObj(self);
    if (sT) ids.push("this#" + sT.id);
    for (var q = 0; q < jsArgs.length; q++) {
      if (isJavaObj(jsArgs[q])) {
        var sA = stashObj(jsArgs[q]);
        if (sA) ids.push("arg" + q + "#" + sA.id);
      }
    }
    if (!threw && isJavaObj(ret)) {
      var sR = stashObj(ret);
      if (sR) ids.push("ret#" + sR.id);
    }
    if (ids.length)
      stashStr =
        "\n   stashed: " +
        ids.join(" ") +
        "   (rpc.exports.objs()/fields(id)/get(id,'f')/call(id,'m',[])/set(id,'f',v))";
  }

  /* console：完整打印，每个参数单独一行（不截断） */
  var line =
    "\n[HK]" +
    (entry.tag ? " #" + entry.tag : "") +
    " " +
    entry.clazz +
    "." +
    name +
    sig +
    (info.static ? " [static]" : "") +
    (info.native ? " [native]" : "") +
    "  #" +
    c;
  if (!vals.length) line += "\n   (无参)";
  for (var j = 0; j < vals.length; j++)
    line += "\n   arg" + j + " = " + (vals[j] === null ? "null" : vals[j]);
  line +=
    "\n   ret  = " +
    (rv.txt === null ? "null" : rv.txt) +
    (rv.hex ? "  hex=" + rv.hex : "") +
    (rv.b64 ? "  b64=" + rv.b64 : "") +
    "  (" +
    rv.type +
    ")";
  if (stashStr) line += stashStr;
  if (rec.stack) line += "\n" + rec.stack;
  clog(line);

  emit(rec);
}

/* 安装一条签名（类已加载时调用）；成功返回 true */
function hookEntry(entry) {
  var C = safe(function () {
    return Java.use(entry.clazz);
  }, null);
  if (!C) return false;
  var meta = classMeta(C);

  /* 全方法模式：pkg.Clazz.* */
  if (entry.method === "*") {
    var cnt = 0;
    Object.keys(meta.byName).forEach(function (name) {
      if (name === "$init" || SKIP_METHODS.indexOf(name) !== -1) return;
      var fn = safe(function () {
        return C[name];
      }, null);
      if (!fn || !fn.overloads) return;
      fn.overloads.forEach(function (ov) {
        try {
          hookOne(
            {
              clazz: entry.clazz,
              method: name,
              tag: entry.tag,
              stack: entry.stack,
              stash: entry.stash,
            },
            ov,
            meta,
          );
          cnt++;
        } catch (e) {}
      });
    });
    console.log(
      "[HK] hooked " +
        entry.clazz +
        ".*  -> " +
        cnt +
        " 个重载（全部声明方法）",
    );
    return true;
  }

  /* 普通方法 / 构造（$init） */
  var fn = safe(function () {
    return C[entry.method];
  }, null);
  if (!fn || !fn.overloads) {
    console.log(
      "[HK] 跳过：" +
        entry.clazz +
        "." +
        entry.method +
        " 不是可 hook 的方法/构造（无重载）",
    );
    return false;
  }
  var ovs = selectOverloads(fn, entry.args);
  if (!ovs.length) {
    if (entry.args !== null) {
      console.log(
        "[HK] 警告：" +
          entry.clazz +
          "." +
          entry.method +
          "(" +
          entry.args.join(",") +
          ") 没匹配到重载。该方法实有重载：",
      );
      fn.overloads.forEach(function (ov) {
        console.log("        " + entry.method + buildSig(ov));
      });
      if (STRICT_OVERLOAD) {
        console.log("        STRICT_OVERLOAD=true -> 跳过该条");
        return false;
      }
      console.log("        STRICT_OVERLOAD=false -> 兜底 hook 全部重载");
      ovs = fn.overloads.slice();
    } else {
      return false;
    }
  }
  var sigs = [];
  ovs.forEach(function (ov) {
    try {
      sigs.push(hookOne(entry, ov, meta));
    } catch (e) {
      console.log(
        "[HK] 安装失败 " + entry.clazz + "." + entry.method + ": " + e,
      );
    }
  });
  if (sigs.length)
    console.log(
      "[HK] hooked " +
        entry.clazz +
        "." +
        entry.method +
        "  " +
        sigs.join(" , ") +
        (entry.tag ? "   #" + entry.tag : "") +
        (entry.stack || STACK ? "   +stack" : ""),
    );
  return sigs.length > 0;
}

/* 逐条安装，类未加载的过会儿重试 */
function armAll() {
  parsed.forEach(function (e) {
    if (
      !e._done &&
      safe(function () {
        return hookEntry(e);
      }, false)
    )
      e._done = true;
  });
  var left = parsed.filter(function (e) {
    return !e._done;
  });
  if (left.length && armTries++ < RETRY_MAX) {
    setTimeout(function () {
      Java.perform(armAll);
    }, RETRY_MS);
    return;
  }
  if (left.length) {
    console.log(
      "[HK] 以下签名的类一直未加载（检查类名/包名；或被自定义 ClassLoader 延后加载，可调大 RETRY_MAX）：",
    );
    left.forEach(function (e) {
      console.log("     " + e.sig);
    });
  } else {
    console.log("[HK] 全部签名已就绪。");
  }
}

/* =======================================================================
 *  对象仓库 + RPC 工具：把 hook 现场 retain 的活对象拿来调方法 / 读写字段
 * ======================================================================= */
var OBJS = {}; // id -> { obj: Java.retain 的活对象, cls: 类名 }
var OBJ_SEQ = 0;
var OBJ_ORDER = []; // id 入仓顺序，超 STASH_CAP 丢最旧

function isJavaObj(x) {
  return (
    x !== null &&
    x !== undefined &&
    typeof x === "object" &&
    !isBytes(x) &&
    (x.$className !== undefined ||
      safe(function () {
        return !!x.getClass;
      }, false))
  );
}

/* retain 一个活对象进仓库，返回 {id, cls}；非 Java 对象返回 null */
function stashObj(x) {
  if (!isJavaObj(x)) return null;
  var r = safe(function () {
    return Java.retain(x);
  }, null);
  if (!r) return null;
  var id = ++OBJ_SEQ;
  var cls =
    safe(function () {
      return "" + x.getClass().getName();
    }, null) ||
    safe(function () {
      return "" + x.$className;
    }, "obj");
  OBJS[id] = { obj: r, cls: cls };
  OBJ_ORDER.push(id);
  while (OBJ_ORDER.length > STASH_CAP) delete OBJS[OBJ_ORDER.shift()]; // 丢最旧（retain 随之可回收）
  return { id: id, cls: cls };
}

/* target：数字/数字串 -> 仓库实例；类全名字符串 -> 静态(inst=null) */
function resolveTarget(target) {
  var n =
    typeof target === "number"
      ? target
      : /^\d+$/.test("" + target)
        ? parseInt(target, 10)
        : null;
  if (n !== null) {
    var e = OBJS[n];
    if (!e)
      throw "对象 id=" + n + " 不在仓库（先触发带 {stash:true} 的 hook，或看 objs()）";
    return {
      inst: e.obj,
      klass: safe(function () {
        return e.obj.getClass();
      }, null),
      cls: e.cls,
      isStatic: false,
    };
  }
  var C = Java.use("" + target); // 当类全名，操作静态
  return {
    inst: null,
    klass: C.class,
    cls: "" + target,
    isStatic: true,
    use: C,
  };
}

/* 沿类层级找字段（含父类、私有），setAccessible */
function findField(klass, name) {
  var k = klass;
  while (k) {
    var f = safe(function () {
      return k.getDeclaredField(name);
    }, null);
    if (f) {
      safe(function () {
        return f.setAccessible(true);
      });
      return f;
    }
    if (
      safe(function () {
        return "" + k.getName();
      }, "") === "java.lang.Object"
    )
      break;
    k = safe(function () {
      return k.getSuperclass();
    }, null);
  }
  return null;
}

/* 读字段值：基本类型用 getInt/getLong... 返回 JS 原始值；否则 f.get() 返回对象/String/byte[] */
function getFieldVal(f, inst) {
  var tn = safe(function () {
    return "" + f.getType().getName();
  }, "");
  var g = {
    int: "getInt",
    long: "getLong",
    short: "getShort",
    byte: "getByte",
    char: "getChar",
    boolean: "getBoolean",
    float: "getFloat",
    double: "getDouble",
  };
  if (g[tn])
    return safe(function () {
      return f[g[tn]](inst);
    });
  return safe(function () {
    return f.get(inst);
  });
}

/* 写字段值：基本类型用 setInt/setLong... 否则 set；value 支持 {$id:n} 引用仓库对象 */
function setFieldVal(f, inst, value) {
  var tn = safe(function () {
    return "" + f.getType().getName();
  }, "");
  var v = marshal(value);
  var st = {
    int: "setInt",
    long: "setLong",
    short: "setShort",
    byte: "setByte",
    char: "setChar",
    boolean: "setBoolean",
    float: "setFloat",
    double: "setDouble",
  };
  if (st[tn]) f[st[tn]](inst, v);
  else f.set(inst, v);
}

/* RPC 入参编组：{$id:n} -> 仓库对象；其它原样（基本类型/字符串/null） */
function marshal(a) {
  if (a !== null && typeof a === "object" && a.$id !== undefined) {
    var e = OBJS[a.$id];
    if (!e) throw "参数引用对象 id=" + a.$id + " 不在仓库";
    return e.obj;
  }
  return a;
}

/* RPC 返回值：原始值直返；byte[]->{hex,b64,txt}；Java 对象->入仓 {id,cls,repr} */
function rpcVal(x) {
  if (x === null || x === undefined) return null;
  var t = typeof x;
  if (t === "string" || t === "number" || t === "boolean") return x;
  if (isBytes(x))
    return { byteLen: x.length, hex: toHex(x), b64: toB64(x), txt: toTxt(x) };
  if (isJavaObj(x)) {
    var st = stashObj(x);
    return {
      id: st ? st.id : null,
      cls: st ? st.cls : null,
      repr: clip(
        safe(function () {
          return "" + x;
        }, "<obj>"),
        300,
      ),
    };
  }
  return "" + x;
}

/* =======================================================================
 *  专用调用：com.wangyin.platform.CryptoUtils.newInstance(ctx).p7Envelope(a, content)
 *    - context  ：现取 ActivityThread.currentApplication().getApplicationContext()
 *    - key      ：静态字段 CryptoUtils.a（用反射读，规避「字段/同名方法」歧义；含父类/私有）
 *    - content  ：指定 JSON 的 String.getBytes()（Java 平台默认字符集，安卓=UTF-8）
 *  返回 p7Envelope 的结果（byte[] -> {byteLen,hex,b64,txt}），便于离线复用。
 *  REPL：rpc.exports.p7envelope()                       // 用下方默认 content
 *        rpc.exports.p7envelope('{"appId":"..."}')      // 自定义 content 文本
 * ======================================================================= */
var CU_CLASS = "com.wangyin.platform.CryptoUtils";
var P7_CONTENT =
  '{"appId":"com.jd.iots","bizId":"CCO-RISK","deviceInfo":{"sdk_version":"8.1.0"}}';

/* 自动触发（让走 host.py 无 REPL 也能拿到结果，不必手动调 rpc.exports.p7envelope）：
 *   AUTO_P7=false 则只保留手动 RPC 入口。--spawn 冷启动建议 DELAY ≥ 5000 给 SDK 初始化时间。 */
var AUTO_P7 = true;
var AUTO_P7_DELAY_MS = 6000; // 首次尝试前延迟
var AUTO_P7_RETRY_MS = 1500, // 类/Application 未就绪时的重试间隔
  AUTO_P7_RETRY_MAX = 40; // 重试次数上限

function callP7Envelope(contentStr) {
  var res;
  Java.perform(function () {
    try {
      contentStr =
        contentStr === undefined || contentStr === null
          ? P7_CONTENT
          : "" + contentStr;

      var ctx = Java.use("android.app.ActivityThread")
        .currentApplication()
        .getApplicationContext();
      var C = safe(function () {
        return Java.use(CU_CLASS);
      }, null);
      if (!C) {
        res = "[p7] 类未加载: " + CU_CLASS + "（触发让其加载后再调）";
        console.log(res);
        return;
      }

      /* key = 静态字段 a（反射读，避开「字段 a / 方法 a」同名歧义；setAccessible 处理私有） */
      var keyField = findField(C.class, "a");
      if (!keyField) {
        res = "[p7] 找不到静态字段 " + CU_CLASS + ".a";
        console.log(res);
        return;
      }
      var key = getFieldVal(keyField, null);

      /* content = "...".getBytes()（用真 Java String 的默认字符集字节，忠实复刻 .getBytes()） */
      var content = Java.use("java.lang.String").$new(contentStr).getBytes();

      /* newInstance(ctx).p7Envelope(key, content)（重载由 Frida 按实参类型自动解析） */
      var inst = C.newInstance(ctx);
      var out = inst.p7Envelope(key, content);

      var kf = fmtVal(key),
        of = fmtVal(out);
      console.log(
        "\n[p7] " + CU_CLASS + ".newInstance(ctx).p7Envelope(a, content)",
      );
      console.log("   ctx     = " + ctx);
      console.log(
        "   key(a)  = " +
          (kf.txt === null ? "null" : kf.txt) +
          (kf.hex ? "  hex=" + kf.hex : "") +
          "  (" +
          kf.type +
          ")",
      );
      console.log("   content = " + contentStr);
      console.log(
        "   ret     = " +
          (of.txt === null ? "null" : of.txt) +
          (of.hex ? "  hex=" + of.hex : "") +
          (of.b64 ? "  b64=" + of.b64 : "") +
          "  (" +
          of.type +
          ")",
      );

      /* 落库：send(type=hook) -> host.py 写 hook_log 表 + 打印一行（tag=p7 便于过滤）。
         这样走 host.py（无 REPL）也能拿到结果，不必手动调。 */
      var a0 = argStr(key),
        a1 = contentStr;
      emit({
        clazz: CU_CLASS,
        method: "p7Envelope",
        sig: "(via newInstance(ctx))",
        is_static: 0,
        is_native: 0,
        tag: "p7",
        arg0: a0,
        arg1: a1,
        args: "a0(key)=" + (a0 === null ? "null" : a0) + " | a1(content)=" + a1,
        ret_type: of.type,
        ret_txt: of.txt,
        ret_hex: of.hex,
        ret_b64: of.b64,
        thread: THREAD_NAME ? curThread() : null,
        stack: null,
      });
      res = rpcVal(out);
    } catch (e) {
      res = "[p7] 调用失败: " + e + "\n" + (e.stack || "");
      console.log(res);
    }
  });
  return res;
}

/* 启动后自动调一次：等 CryptoUtils 类 + Application 都就绪再触发（晚加载自动重试） */
function autoP7() {
  var tries = 0;
  (function attempt() {
    var ready = false;
    Java.perform(function () {
      ready =
        !!safe(function () {
          return Java.use(CU_CLASS);
        }, null) &&
        !!safe(function () {
          return Java.use("android.app.ActivityThread").currentApplication();
        }, null);
    });
    if (ready) {
      console.log("[p7] 自动触发 p7Envelope（关：AUTO_P7=false；重调：rpc.exports.p7envelope()）");
      safe(function () {
        return callP7Envelope();
      });
      return;
    }
    if (++tries <= AUTO_P7_RETRY_MAX) setTimeout(attempt, AUTO_P7_RETRY_MS);
    else
      console.log(
        "[p7] 放弃自动触发：" +
          CU_CLASS +
          " / Application 一直未就绪（在 App 里操作让 SDK 加载，或 rpc.exports.p7envelope() 手动调）",
      );
  })();
}

/* =======================================================================
 *  RPC：辅助查方法签名 / 看命中计数 / 用 hook 现场暂存的活对象调方法读写字段
 * ======================================================================= */
rpc.exports = {
  /* 枚举一个类的全部构造/方法签名，方便你抄进 SIGNATURES */
  dump: function (cn) {
    var out = [];
    Java.perform(function () {
      var C = safe(function () {
        return Java.use(cn);
      }, null);
      if (!C) {
        out.push("[HK] 未加载: " + cn);
        return;
      }
      var Modifier = safe(function () {
        return Java.use("java.lang.reflect.Modifier");
      }, null);
      var ctors =
        safe(function () {
          return C.class.getDeclaredConstructors();
        }, []) || [];
      out.push("== " + cn + "  构造 " + ctors.length + " ==");
      for (var i = 0; i < ctors.length; i++) {
        (function (ct) {
          var pts =
              safe(function () {
                return ct.getParameterTypes();
              }, []) || [],
            ps = [];
          for (var k = 0; k < pts.length; k++)
            ps.push(simpleType("" + pts[k].getName()));
          out.push("   $init(" + ps.join(",") + ")");
        })(ctors[i]);
      }
      var ms =
        safe(function () {
          return C.class.getDeclaredMethods();
        }, []) || [];
      out.push("== " + cn + "  方法 " + ms.length + " ==");
      for (var j = 0; j < ms.length; j++) {
        (function (m) {
          var nm = safe(function () {
            return "" + m.getName();
          }, "?");
          var mods = safe(function () {
            return m.getModifiers();
          }, 0);
          var nat = Modifier
            ? safe(function () {
                return Modifier.isNative(mods);
              }, false)
            : false;
          var sta = Modifier
            ? safe(function () {
                return Modifier.isStatic(mods);
              }, false)
            : false;
          var ret = simpleType(
            safe(function () {
              return "" + m.getReturnType().getName();
            }, "?"),
          );
          var pts =
              safe(function () {
                return m.getParameterTypes();
              }, []) || [],
            ps = [];
          for (var k = 0; k < pts.length; k++)
            ps.push(simpleType("" + pts[k].getName()));
          out.push(
            "   " +
              (nat ? "[native] " : "         ") +
              (sta ? "static " : "") +
              ret +
              " " +
              nm +
              "(" +
              ps.join(",") +
              ")",
          );
        })(ms[j]);
      }
    });
    var s = out.join("\n");
    console.log(s);
    return s;
  },
  /* 看每个签名当前命中（落库）次数 */
  list: function () {
    var out = ["[HK] 落库计数（key=类#方法签名 -> 次数）："];
    var ks = Object.keys(sigCount);
    if (!ks.length) out.push("   (还没有命中，触发一下目标功能)");
    ks.forEach(function (k) {
      out.push("   " + k + " -> " + sigCount[k]);
    });
    var s = out.join("\n");
    console.log(s);
    return s;
  },

  /* ---- 对象仓库 / 调方法 / 读写字段（配 hook 的 {stash:true}，standalone REPL 里用）---- */
  /* 看仓库里有哪些活对象 */
  objs: function () {
    var out = ["[HK] 对象仓库（#id 类）："];
    var ks = Object.keys(OBJS);
    if (!ks.length)
      out.push(
        "   (空；给目标签名加 {stash:true} 触发，或 rpc.exports.arm('类.方法',{stash:true}))",
      );
    ks.forEach(function (k) {
      out.push("   #" + k + "  " + OBJS[k].cls);
    });
    var s = out.join("\n");
    console.log(s);
    return s;
  },
  /* 运行时现场装一条 hook（REPL 补 hook，不用改文件）；opts={stack,stash,tag} */
  arm: function (sig, opts) {
    opts = opts || {};
    var r = "";
    Java.perform(function () {
      var e = parseSig(sig);
      e.stack = !!opts.stack;
      e.stash = !!opts.stash;
      if (opts.tag) e.tag = opts.tag;
      var ok = safe(function () {
        return hookEntry(e);
      }, false);
      r = ok
        ? "[HK] armed " + sig + (opts.stash ? " (+stash)" : "")
        : "[HK] arm 失败：" + e.clazz + " 未加载？触发让类加载后再 arm";
    });
    console.log(r);
    return r;
  },
  /* 列出对象全部字段（含父类、私有）名=值 */
  fields: function (target) {
    var out = [];
    Java.perform(function () {
      var t = resolveTarget(target);
      out.push(
        "== " + t.cls + (t.isStatic ? " (static)" : " #" + target) + " 字段 ==",
      );
      var k = t.klass;
      while (k) {
        if (
          safe(function () {
            return "" + k.getName();
          }, "") === "java.lang.Object"
        )
          break;
        var fs =
          safe(function () {
            return k.getDeclaredFields();
          }, []) || [];
        for (var i = 0; i < fs.length; i++) {
          (function (f) {
            safe(function () {
              return f.setAccessible(true);
            });
            var nm = safe(function () {
              return "" + f.getName();
            }, "?");
            var tn = simpleType(
              safe(function () {
                return "" + f.getType().getName();
              }, "?"),
            );
            var v = getFieldVal(f, t.isStatic ? null : t.inst);
            var disp = isBytes(v)
              ? "byte[" + v.length + "] " + toHex(v)
              : isJavaObj(v)
                ? clip(
                    safe(function () {
                      return "" + v;
                    }, "<obj>"),
                    300,
                  )
                : v === null
                  ? "null"
                  : "" + v;
            out.push("   " + tn + " " + nm + " = " + disp);
          })(fs[i]);
        }
        k = safe(function () {
          return k.getSuperclass();
        }, null);
      }
    });
    var s = out.join("\n");
    console.log(s);
    return s;
  },
  /* 读字段（支持 a.b.c 路径下钻；对象结果入仓返回 {id,cls,repr}） */
  get: function (target, path) {
    var res;
    Java.perform(function () {
      var parts = ("" + path).split(".");
      var t = resolveTarget(target);
      var inst = t.inst,
        klass = t.klass,
        isStatic = t.isStatic;
      for (var i = 0; i < parts.length; i++) {
        var f = findField(klass, parts[i]);
        if (!f) {
          res = "字段不存在: " + parts[i];
          return;
        }
        var v = getFieldVal(f, isStatic ? null : inst);
        if (i === parts.length - 1) {
          res = rpcVal(v);
          return;
        }
        if (!isJavaObj(v)) {
          res = "路径中断（" + parts[i] + " 不是对象）";
          return;
        }
        inst = v;
        klass = safe(function () {
          return v.getClass();
        }, null);
        isStatic = false;
      }
    });
    console.log(JSON.stringify(res));
    return res;
  },
  /* 调方法：args=参数数组（{$id:n} 引用仓库对象）；types=可选重载参数类型数组 */
  call: function (target, method, args, types) {
    var res;
    Java.perform(function () {
      var t = resolveTarget(target);
      var recv = t.isStatic ? t.use : t.inst;
      var fn = recv[method];
      if (!fn) {
        res = "方法不存在: " + method;
        return;
      }
      var margs = (args || []).map(marshal);
      var r =
        types && types.length
          ? fn.overload.apply(fn, types).apply(recv, margs)
          : fn.apply(recv, margs);
      res = rpcVal(r);
    });
    console.log(JSON.stringify(res));
    return res;
  },
  /* 写字段：value 基本类型/字符串/null 或 {$id:n} 引用仓库对象 */
  set: function (target, field, value) {
    var res;
    Java.perform(function () {
      var t = resolveTarget(target);
      var f = findField(t.klass, field);
      if (!f) {
        res = "字段不存在: " + field;
        return;
      }
      try {
        setFieldVal(f, t.isStatic ? null : t.inst, value);
        res = "ok: 已写 " + field;
      } catch (e) {
        res = "写入失败: " + e;
      }
    });
    console.log(res);
    return res;
  },
  /* 释放一个 / 清空仓库 */
  release: function (id) {
    delete OBJS[id];
    return "released #" + id;
  },
  clearobjs: function () {
    OBJS = {};
    OBJ_ORDER = [];
    OBJ_SEQ = 0;
    return "对象仓库已清空";
  },

  /* 专用：调 CryptoUtils.newInstance(ctx).p7Envelope(静态字段 a, content.getBytes())
     content 省略=默认 JSON；返回 {byteLen,hex,b64,txt}（byte[]）或原始值，便于离线复用 */
  p7envelope: function (content) {
    return callP7Envelope(content);
  },
};

/* =======================================================================
 *  入口
 * ======================================================================= */
Java.perform(function () {
  Throwable = Java.use("java.lang.Throwable");
  Log = Java.use("android.util.Log");

  if (!parsed.length) {
    console.log("[HK] SIGNATURES 为空——请在脚本顶部填入要 hook 的方法签名。");
    return;
  }
  console.log(
    "[HK] frida_generic_hook 启动，待 hook 签名 " + parsed.length + " 条：",
  );
  parsed.forEach(function (e) {
    console.log(
      "     - " +
        e.sig +
        (e.tag ? "   #" + e.tag : "") +
        (e.stack ? "   +stack" : ""),
    );
  });

  if (ARM_DELAY_MS > 0) {
    console.log("[HK] " + ARM_DELAY_MS + "ms 后开始装 hook（错开启动窗口）");
    setTimeout(function () {
      Java.perform(armAll);
    }, ARM_DELAY_MS);
  } else armAll();

  if (AUTO_P7) {
    console.log(
      "[p7] " +
        AUTO_P7_DELAY_MS +
        "ms 后自动调 CryptoUtils.newInstance(ctx).p7Envelope(a, content)，结果落 hook_log(tag=p7)",
    );
    setTimeout(autoP7, AUTO_P7_DELAY_MS);
  }

  console.log(
    "\n[*] 通用 hook 已启动（落 host.py 的 hook_log 表，type=hook）。",
  );
  console.log(
    '[*] 改签名只动 hook_signatures.js（host.py 自动注入）。REPL 里 rpc.exports.dump("类全名") 查签名 / rpc.exports.list() 看计数。\n',
  );
});
