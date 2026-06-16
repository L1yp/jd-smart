'use strict';

/*
 * frida_cryptoutils_capture.js —— 普查 com.wangyin.platform.CryptoUtils 的「全部方法」
 *
 * 背景：sign 位置仍未钉死。com.wangyin.platform.CryptoUtils 是京东「网银在线」底层加密 SDK，
 *      很多方法是 native（实现在 .so 里），是 sign/加解密的头号嫌疑窝点。本脚本不猜方法名，
 *      而是反射枚举该类「声明的所有方法」逐个 hook，把 方法名 / 参数 / 返回值 落进独立的
 *      crypto_utils 表，让你一眼看清：谁、用什么入参、调了这个类的哪个方法、返回了什么。
 *
 * 落库（配 host.py）：send({type:'cu'}) -> crypto_utils 表（与 sign/color/cipher 表分开，互不污染）。
 *   一行 = 一个「方法+参数预览+返回预览」唯一指纹(fp)；count = 去重后累计调用次数。
 *
 * 用法：
 *   python host.py -p <包名> -s frida_cryptoutils_capture.js --spawn      # 落 crypto_utils 表（推荐）
 *   frida -U -f <包名> -l frida_cryptoutils_capture.js                     # 仅看 console（standalone）
 *
 *   触发一次目标请求（如 getHouses）后，SQL 看这个类干了啥：
 *     SELECT method,sig,is_native,count,args_txt,ret_txt FROM crypto_utils ORDER BY count DESC;
 *   只看返回 32B/64hex（SHA-256 家族 sign 形态）的：
 *     SELECT method,sig,args_txt,ret_hex,ret_b64 FROM crypto_utils
 *      WHERE length(ret_hex)>=64 OR length(ret_b64)>=40 ORDER BY count DESC;
 *
 * ★ 防卡死设计（这个类可能每请求被调几十次、入参是大 body，全量打印/落库必卡）★
 *   1) 截断   ：参数/返回的 hex、txt、b64 预览统一限长（MAX_HEX/MAX_TXT），大 body 不全量转换。
 *   2) 去重   ：相同 (方法+参数+返回) 指纹只落一次，之后只累加 count —— 表不膨胀、send 不刷屏。
 *   3) 节流   ：每个指纹前 SEND_FIRST 次必落，之后每 SEND_EVERY 次补发一次（带增量 count）。
 *   4) 静默   ：console 首现打印有总量上限 CONSOLE_MAX，超了转纯落库（命中 TARGETS 仍会打）。
 *   5) 轻实现 ：hook 体内只用纯 JS 字节工具，绝不回调 CryptoUtils 自身方法（防递归/副作用）。
 *   6) 默认不打调用栈（贵）；仅命中 TARGETS / FOCUS_METHODS 时才取栈。
 *   要精确抓某个方法的每一次完整 I/O（不截断/不去重/带栈），把方法名填进 FOCUS_METHODS。
 */

/* =======================================================================
 *  配置
 * ======================================================================= */
var TARGET_CLASS = 'com.wangyin.platform.CryptoUtils';
var ARM_DELAY_MS = 0;        // >0：延迟装 hook（避开启动期 TLS/检测窗口，闪退就设 3000~5000）

var MAX_HEX = 256;           // 普通模式：byte[] 预览 hex 上限（字节）。大 body 只看前 256B 足够辨形态
var MAX_TXT = 200;           // 普通模式：可打印文本预览上限（字符）
var INSPECT_OBJECTS = true;  // 非 String/byte[]/数值 的 Java 对象，是否 toString 取值（限长 OBJ_TXT_MAX）
var OBJ_TXT_MAX = 120;

var SKIP_METHODS = ['toString', 'hashCode', 'equals', 'clone', 'finalize', 'getClass', 'wait', 'notify', 'notifyAll'];
var ONLY_METHODS = [];       // 非空 = 只 hook 列出的方法名（其余跳过），临时聚焦某几个用
var FOCUS_METHODS = [];      // 全量模式方法名：不截断/不去重/每次落库/带栈（配合 TARGETS 精确抓 I/O）。例: ['NativeEncodeDataToServer']
var FOCUS_HEX = 8192, FOCUS_TXT = 4096;

var TARGETS = [];            // 想高亮的 wire 值（本次 sign / 某段密文等）；命中入参或返回即 [CU MATCH] 并打栈。勿提交真实值。

/* 去重 / 节流（核心防卡，按需调） */
var DEDUP = true;
var SEND_FIRST = 3;          // 每个唯一指纹前 N 次都落库（看清前几次形态）
var SEND_EVERY = 300;        // 之后每累计 N 次补发一次（带增量 count），让表里 count 逼近真实调用数
var SEEN_CAP = 5000;         // 指纹表上限，超过则整体清空一次（防长跑内存膨胀）
var CONSOLE_MAX = 300;       // console 首现打印总行数上限，超了转静默（只落库；命中仍打）
var STACK_IN_DB = false;     // 给每条落库都带栈（DB 变大；一般 false，命中/FOCUS 时无论如何带）

/* =======================================================================
 *  纯 JS 字节工具（不调用被 hook 的 API，避免递归/污染）
 * ======================================================================= */
var HEX = '0123456789abcdef';
var B64C = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function isBytes(x) { return x !== null && x !== undefined && x.length !== undefined && typeof x !== 'string' && typeof x !== 'function'; }
function safe(fn, dflt) { try { return fn(); } catch (e) { return dflt; } }
function clip(s, n) { if (s === null || s === undefined) return null; s = '' + s; return s.length > n ? s.substring(0, n) + '..(+' + (s.length - n) + ')' : s; }
function toHex(b, lim) {
    if (!isBytes(b)) return null; lim = lim || MAX_HEX;
    var n = b.length, m = Math.min(n, lim), s = '';
    for (var i = 0; i < m; i++) { var v = b[i] & 0xff; s += HEX.charAt(v >> 4) + HEX.charAt(v & 0xf); }
    if (n > m) s += '..(+' + (n - m) + 'B)';
    return s;
}
function toTxt(b, lim) {
    if (!isBytes(b)) return null; lim = lim || MAX_TXT;
    var n = Math.min(b.length, lim), s = '';
    for (var i = 0; i < n; i++) {
        var c = b[i] & 0xff;
        if (c >= 0x20 && c < 0x7f) s += String.fromCharCode(c);
        else if (c === 0x0a) s += '\\n'; else if (c === 0x0d) s += '\\r'; else if (c === 0x09) s += '\\t'; else s += '.';
    }
    if (b.length > n) s += '..';
    return s;
}
function toB64(b, lim) {
    if (!isBytes(b)) return null; lim = lim || MAX_HEX;
    var n = Math.min(b.length, lim), s = '';
    for (var i = 0; i < n; i += 3) {
        var b0 = b[i] & 0xff, b1 = (i + 1 < n) ? (b[i + 1] & 0xff) : 0, b2 = (i + 2 < n) ? (b[i + 2] & 0xff) : 0;
        var t = (b0 << 16) | (b1 << 8) | b2;
        s += B64C.charAt((t >> 18) & 63) + B64C.charAt((t >> 12) & 63);
        s += (i + 1 < n) ? B64C.charAt((t >> 6) & 63) : '=';
        s += (i + 2 < n) ? B64C.charAt(t & 63) : '=';
    }
    if (b.length > n) s += '..(+' + (b.length - n) + 'B)';
    return s;
}
function djb2(s) { var h = 5381; for (var i = 0; i < s.length; i++) h = (((h << 5) + h) ^ s.charCodeAt(i)) >>> 0; return ('00000000' + h.toString(16)).slice(-8); }
function simpleType(jvm) {
    if (!jvm) return '?'; jvm = '' + jvm;
    var arr = '';
    while (jvm.charAt(0) === '[') { arr += '[]'; jvm = jvm.substring(1); }
    var map = { 'B': 'byte', 'C': 'char', 'I': 'int', 'J': 'long', 'S': 'short', 'Z': 'boolean', 'F': 'float', 'D': 'double', 'V': 'void' };
    if (jvm.length === 1 && map[jvm]) return map[jvm] + arr;
    if (jvm.charAt(0) === 'L' && jvm.charAt(jvm.length - 1) === ';') jvm = jvm.substring(1, jvm.length - 1);
    var dot = jvm.lastIndexOf('.');
    var simple = dot >= 0 ? jvm.substring(dot + 1) : jvm;
    return simple + arr;
}

/* 把一个 hook 实参/返回值格式化成 {type, txt, hex, b64} */
function fmtVal(x, hexMax, txtMax) {
    if (x === null || x === undefined) return { type: x === null ? 'null' : 'void', txt: null, hex: null, b64: null };
    var t = typeof x;
    if (t === 'string') return { type: 'String', txt: clip(x, txtMax), hex: null, b64: null };
    if (t === 'number' || t === 'boolean') return { type: t, txt: '' + x, hex: null, b64: null };
    if (isBytes(x)) return { type: 'byte[' + x.length + ']', txt: toTxt(x, txtMax), hex: toHex(x, hexMax), b64: toB64(x, hexMax) };
    if (INSPECT_OBJECTS) {
        var cn = safe(function () { return x.$className; }, null) || safe(function () { return '' + x.getClass().getName(); }, 'obj');
        return { type: cn, txt: clip(safe(function () { return '' + x; }, '<' + cn + '>'), OBJ_TXT_MAX), hex: null, b64: null };
    }
    return { type: 'obj', txt: '<obj>', hex: null, b64: null };
}

/* =======================================================================
 *  去重 / 节流
 * ======================================================================= */
var seen = {}, seenN = 0;
function bump(fp) {
    var e = seen[fp];
    if (!e) {
        if (seenN >= SEEN_CAP) { seen = {}; seenN = 0; }   // 防膨胀：满了清空重来
        e = seen[fp] = { n: 0, sends: 0, lastSent: 0 }; seenN++;
    }
    e.n++;
    var r = { n: e.n, inc: 0, doSend: false, firstSeen: (e.n === 1) };
    if (e.sends < SEND_FIRST) { r.doSend = true; r.inc = 1; e.sends++; e.lastSent = e.n; }
    else if (e.n - e.lastSent >= SEND_EVERY) { r.doSend = true; r.inc = e.n - e.lastSent; e.sends++; e.lastSent = e.n; }
    return r;
}

/* =======================================================================
 *  命中 / 输出
 * ======================================================================= */
var consoleLines = 0;
function clog(s) { if (consoleLines < CONSOLE_MAX) { console.log(s); consoleLines++; } }
function matchAny(vals) {
    for (var i = 0; i < TARGETS.length; i++) {
        var tl = ('' + TARGETS[i]).toLowerCase();
        for (var j = 0; j < vals.length; j++) {
            var v = vals[j]; if (!v) continue; v = ('' + v).toLowerCase();
            if (v === tl || v.indexOf(tl) !== -1) return TARGETS[i];
        }
    }
    return null;
}
function emit(rec) { try { send({ type: 'cu', data: rec }); } catch (e) {} }

/* =======================================================================
 *  安装：枚举 -> 逐方法 hook
 * ======================================================================= */
var Throwable, Log, Modifier;
function stk() { return safe(function () { return Log.getStackTraceString(Throwable.$new()); }, '(no stack)'); }

function buildSig(ov) {
    var ats = ov.argumentTypes || [], o = [];
    for (var i = 0; i < ats.length; i++) o.push(simpleType(ats[i].className));
    return '(' + o.join(',') + ')';
}

function installOn(C) {
    Throwable = Java.use('java.lang.Throwable');
    Log = Java.use('android.util.Log');
    Modifier = safe(function () { return Java.use('java.lang.reflect.Modifier'); }, null);

    /* 1) 反射枚举该类声明的所有方法（含 native），打印一览 + 记 native 标记 */
    var methods = safe(function () { return C.class.getDeclaredMethods(); }, null);
    if (!methods) { console.log('[CU] 取不到 getDeclaredMethods，类可能异常'); return; }
    var nameMeta = {}, names = [], n = methods.length;
    console.log('\n[CU] ' + TARGET_CLASS + ' 已加载，声明方法 ' + n + ' 个：');
    for (var i = 0; i < n; i++) {
        var mm = methods[i];
        var mn = safe(function () { return '' + mm.getName(); }, '?');
        var mods = safe(function () { return mm.getModifiers(); }, 0);
        var isNat = Modifier ? safe(function () { return Modifier.isNative(mods); }, false) : false;
        var isStatic = Modifier ? safe(function () { return Modifier.isStatic(mods); }, false) : false;
        var ret = simpleType(safe(function () { return '' + mm.getReturnType().getName(); }, '?'));
        var pts = safe(function () { return mm.getParameterTypes(); }, []);
        var ps = []; for (var k = 0; k < pts.length; k++) ps.push(simpleType(safe(function () { return '' + pts[k].getName(); }, '?')));
        if (!nameMeta[mn]) { nameMeta[mn] = { native: false }; names.push(mn); }
        if (isNat) nameMeta[mn].native = true;
        console.log('  ' + (isNat ? '[native] ' : '         ') + (isStatic ? 'static ' : '') + ret + ' ' + mn + '(' + ps.join(', ') + ')');
    }

    /* 2) 逐方法 hook 全部重载 */
    var hookedM = 0, hookedOv = 0, skipped = 0;
    for (var a = 0; a < names.length; a++) {
        var name = names[a];
        if (SKIP_METHODS.indexOf(name) !== -1) { skipped++; continue; }
        if (ONLY_METHODS.length && ONLY_METHODS.indexOf(name) === -1) { skipped++; continue; }
        var isNative = nameMeta[name].native;
        var focus = (FOCUS_METHODS.indexOf(name) !== -1);
        var fn = safe(function () { return C[name]; }, null);
        if (!fn || !fn.overloads) { console.log('[CU][skip] ' + name + '（非方法/无重载）'); continue; }
        var ok = 0;
        fn.overloads.forEach(function (ov) {
            var sig = buildSig(ov);
            try {
                ov.implementation = makeImpl(ov, name, sig, isNative, focus);
                ok++; hookedOv++;
            } catch (e) { console.log('[CU][skip] ' + name + sig + ' : ' + e); }
        });
        if (ok) hookedM++;
    }
    console.log('\n[CU] 已 hook 方法 ' + hookedM + ' 个 / 重载 ' + hookedOv + ' 个（跳过 ' + skipped + '）。'
        + (FOCUS_METHODS.length ? ' FOCUS=' + JSON.stringify(FOCUS_METHODS) : '')
        + '\n[CU] 触发请求后看下方 [CU.call]；落 crypto_utils 表。命中高亮值填 TARGETS。\n');
}

function makeImpl(ov, methodName, sig, isNative, focus) {
    return function () {
        var ret = ov.apply(this, arguments);
        try { handle(methodName, sig, isNative, focus, arguments, ret); }
        catch (e) { clog('[CU.err] ' + methodName + sig + ': ' + e); }
        return ret;
    };
}

function handle(methodName, sig, isNative, focus, jsArgs, ret) {
    var hexMax = focus ? FOCUS_HEX : MAX_HEX, txtMax = focus ? FOCUS_TXT : MAX_TXT;

    /* 参数 */
    var txtParts = [], hexParts = [];
    for (var i = 0; i < jsArgs.length; i++) {
        var v = fmtVal(jsArgs[i], hexMax, txtMax);
        txtParts.push('a' + i + '=' + (v.txt === null ? 'null' : v.txt));
        if (v.hex) hexParts.push('a' + i + '=' + v.hex);
    }
    var args_txt = txtParts.length ? txtParts.join(' | ') : '()';
    var args_hex = hexParts.length ? hexParts.join(' | ') : null;

    /* 返回 */
    var rv = fmtVal(ret, hexMax, txtMax);

    /* 命中 + 指纹 */
    var matched = matchAny([args_txt, args_hex, rv.txt, rv.hex, rv.b64]);
    var baseFp = djb2(methodName + '|' + sig + '|' + (args_txt || '') + '|' + (args_hex || '') + '|' + rv.type + '|' + (rv.txt || '') + '|' + (rv.hex || ''));

    /* 节流（FOCUS 不去重：fp 加 nonce 使每次唯一、host 端落多行） */
    var inc = 1, doSend = true, firstSeen = true, fp = baseFp;
    if (!focus && DEDUP) {
        var b = bump(baseFp); inc = b.inc; doSend = b.doSend; firstSeen = b.firstSeen;
    } else if (focus) {
        fp = baseFp + ':' + (++focusNonce);
    }

    var takeStack = !!matched || focus || STACK_IN_DB;
    var stack = takeStack ? stk() : null;

    /* console：首现一行；命中详打 */
    if (matched) {
        console.log('\n===================== CU MATCH =====================');
        console.log(' method : ' + methodName + sig + (isNative ? '  [native]' : ''));
        console.log(' target : ' + matched);
        console.log(' args   : ' + clip(args_txt, 400));
        if (args_hex) console.log(' a.hex  : ' + clip(args_hex, 400));
        console.log(' ret    : ' + clip(rv.txt, 300) + (rv.hex ? '  hex=' + clip(rv.hex, 300) : ''));
        if (rv.b64) console.log(' ret.b64: ' + clip(rv.b64, 200));
        console.log(stack);
        console.log('===================================================\n');
    } else if (firstSeen) {
        clog('[CU.call] ' + methodName + sig + (isNative ? ' [native]' : '')
            + '\n   in : ' + clip(args_txt, 240)
            + '\n   out: ' + (rv.txt === null ? 'null' : clip(rv.txt, 200)) + (rv.hex ? '  hex=' + clip(rv.hex, 120) : '') + '  (' + rv.type + ')');
    }

    if (!doSend) return;
    emit({
        clazz: TARGET_CLASS, method: methodName, sig: sig, is_native: isNative ? 1 : 0,
        args_txt: args_txt, args_hex: args_hex,
        ret_type: rv.type, ret_txt: rv.txt, ret_hex: rv.hex, ret_b64: rv.b64,
        count: inc, fp: fp,
        matched: matched ? 1 : 0, target: matched, stack: stack
    });
}
var focusNonce = 0;

/* =======================================================================
 *  入口：等类加载（重试），再装 hook
 * ======================================================================= */
function arm() {
    var DONE = false, tries = 0, MAX = 60;
    (function attempt() {
        if (DONE) return;
        var C = safe(function () { return Java.use(TARGET_CLASS); }, null);
        if (C) { DONE = true; try { installOn(C); } catch (e) { console.log('[CU] 安装失败: ' + e + '\n' + (e.stack || '')); } return; }
        if (++tries <= MAX) setTimeout(function () { Java.perform(attempt); }, 700);
        else console.log('[CU] 放弃：' + TARGET_CLASS + ' 一直未加载（该版本未集成网银 SDK / 类名变了？用 frida-ps 确认包名，或 enumerateLoadedClasses 搜 wangyin）');
    })();
}

Java.perform(function () {
    console.log('[CU] frida_cryptoutils_capture 启动，目标类 ' + TARGET_CLASS);
    if (ARM_DELAY_MS > 0) { console.log('[CU] ' + ARM_DELAY_MS + 'ms 后装 hook（错开启动窗口）'); setTimeout(function () { Java.perform(arm); }, ARM_DELAY_MS); }
    else arm();
});

/* rpc：standalone 下手动重新枚举/确认类是否就绪
 *   frida -U -n <包名> -l frida_cryptoutils_capture.js  然后  rpc.exports.ready()
 */
rpc.exports = {
    ready: function () {
        var ok = false;
        Java.perform(function () { ok = !!safe(function () { return Java.use(TARGET_CLASS); }, null); });
        return ok;
    }
};
