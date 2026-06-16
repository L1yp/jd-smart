'use strict';

/*
 * frida_mobileconfig_sign_capture.js —— 钉死 com.jingdong.app.mall.bundle.mobileConfig.d.b 的 sign
 *
 * 目标（用户指定的两个静态方法，都叫 a，靠签名区分重载）：
 *   1) 拼接 sign 参数：  static  String d.b.a(String, String, String)
 *        把若干请求参数拼成「待签名预映像(preimage)」并返回。看清三段入参怎么拼、拼成啥。
 *   2) 计算 sign：      private static String d.b.a(byte[] data, byte[] key)
 *        对 (data, key) 做摘要/HMAC，返回最终 sign 字符串。
 *        ★ arg1=key 就是密钥：若为固定 secret，抓到即可离线复现（参考 verify_sign.py 套路）。★
 *
 * 典型数据流（hook 两个即可印证）：
 *   String preimage = a(p0, p1, p2);                 // 拼接
 *   String sign     = a(preimage.getBytes(), KEY);   // 计算（HMAC/摘要）
 *
 * 输出：仅打印到控制台（不落库、不依赖 host.py）。每条带「调用序号 #N」便于把
 *       「拼接 #k」与紧随其后的「计算 #k+1」对上号，并打调用栈看谁触发了签名。
 *
 * 用法（二选一）：
 *   frida -U -f <包名> -l frida_mobileconfig_sign_capture.js          # spawn，纯看 console（推荐）
 *   frida -U -n <进程名> -l frida_mobileconfig_sign_capture.js        # attach 到已运行进程
 *   python host.py -p <包名> -s frida_mobileconfig_sign_capture.js --spawn   # 也行，只是无 send，纯转发 console
 *
 *   触发一次会签名的请求后看 [MC.拼接] / [MC.计算]。standalone 下可 rpc.exports.ready() 查类是否就绪。
 *
 * ★ 注意：mobileConfig 是「bundle」（插件/动态加载）模块，很可能不在默认 ClassLoader。
 *   本脚本自动扫描全部 ClassLoader 找到能加载该类的那个，再在对应 ClassFactory 上 hook。★
 */

/* =======================================================================
 *  配置
 * ======================================================================= */
var TARGET_CLASS = 'com.jingdong.app.mall.bundle.mobileConfig.d.b';
var RETRY_MS = 700, RETRY_MAX = 80;   // 类晚加载（bundle）：每 700ms 重试，最多 ~56s

var KEY_MAX  = 256;    // key(byte[]) 预览上限（B）。密钥很短；超过 256B 基本就不是 key
var DATA_HEX = 512;    // data(byte[]) hex 预览上限（B）。preimage 可能较大，只看头部辨形态
var DATA_TXT = 1024;   // data(byte[]) 文本预览上限（字符）
var STR_MAX  = 2000;   // String 入参/返回的打印上限（字符）

var TARGETS = [];      // 可选：填本次 wire 上的真实 sign 值；命中入参/返回即标 [★命中] 高亮。勿提交真实值。

/* =======================================================================
 *  纯 JS 字节工具（不回调被 hook 的 API，避免递归/副作用）
 * ======================================================================= */
var HEX = '0123456789abcdef';
var B64C = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function safe(fn, d) { try { return fn(); } catch (e) { return d; } }
function isBytes(x) { return x !== null && x !== undefined && x.length !== undefined && typeof x !== 'string' && typeof x !== 'function'; }
function clip(s, n) { if (s === null || s === undefined) return null; s = '' + s; return s.length > n ? s.substring(0, n) + '..(+' + (s.length - n) + ')' : s; }
function toHex(b, lim) {
    if (!isBytes(b)) return null; lim = lim || DATA_HEX;
    var n = b.length, m = Math.min(n, lim), s = '';
    for (var i = 0; i < m; i++) { var v = b[i] & 0xff; s += HEX.charAt(v >> 4) + HEX.charAt(v & 0xf); }
    if (n > m) s += '..(+' + (n - m) + 'B)';
    return s;
}
function toTxt(b, lim) {
    if (!isBytes(b)) return null; lim = lim || DATA_TXT;
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
    if (!isBytes(b)) return null; lim = lim || KEY_MAX;
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

/* 把返回值/字符串归类，提示 sign 形态 */
function classify(s) {
    if (typeof s !== 'string') return '';
    if (/^[0-9a-fA-F]+$/.test(s)) {
        if (s.length === 64) return '  ← 64hex（SHA-256 / HmacSHA256 形态）';
        if (s.length === 40) return '  ← 40hex（SHA-1 形态）';
        if (s.length === 32) return '  ← 32hex（MD5 形态）';
        return '  ← ' + s.length + ' hex';
    }
    if (/^[A-Za-z0-9+/]+={0,2}$/.test(s) && s.length >= 16) return '  ← base64 形态（len=' + s.length + '）';
    return '  ← len=' + s.length;
}

/* TARGETS 命中检测 */
function matchAny(vals) {
    for (var i = 0; i < TARGETS.length; i++) {
        var tl = ('' + TARGETS[i]).toLowerCase(); if (!tl) continue;
        for (var j = 0; j < vals.length; j++) {
            var v = vals[j]; if (!v) continue; v = ('' + v).toLowerCase();
            if (v.indexOf(tl) !== -1) return TARGETS[i];
        }
    }
    return null;
}

/* =======================================================================
 *  调用栈
 * ======================================================================= */
var Throwable, Log;
function stk() { return safe(function () { return Log.getStackTraceString(Throwable.$new()); }, '(no stack)'); }

/* =======================================================================
 *  跨 ClassLoader 解析目标类（bundle 类不在默认 loader）
 * ======================================================================= */
function resolveClass(name) {
    var C = safe(function () { return Java.use(name); }, null);
    if (C) return { C: C, via: 'default ClassFactory' };
    var found = null;
    safe(function () {
        Java.enumerateClassLoaders({
            onMatch: function (loader) {
                if (found) return;
                var f = safe(function () { return Java.ClassFactory.get(loader); }, null);
                if (!f) return;
                var c = safe(function () { return f.use(name); }, null);
                if (c) found = { C: c, via: '' + loader };
            },
            onComplete: function () {}
        });
    }, null);
    return found;
}

/* =======================================================================
 *  安装：枚举 a 的全部重载，按签名 hook 我们要的两个
 * ======================================================================= */
function argTypes(ov) {
    var ats = ov.argumentTypes || [], o = [];
    for (var i = 0; i < ats.length; i++) o.push(ats[i].className);
    return o;
}
function sigStr(ats) {
    var o = [];
    for (var i = 0; i < ats.length; i++) o.push(ats[i] === '[B' ? 'byte[]' : ats[i].replace(/^java\.lang\./, ''));
    return '(' + o.join(', ') + ')';
}
function allStr(ats, t) { for (var i = 0; i < ats.length; i++) if (ats[i] !== t) return false; return ats.length > 0; }

function installOn(C, via) {
    var fn = C.a;
    if (!fn || !fn.overloads) { console.log('[MC] ' + TARGET_CLASS + ' 没有方法 a / 无重载，类名可能随版本变了'); return; }

    console.log('\n[MC] 命中类：' + TARGET_CLASS);
    console.log('[MC] 来自 ClassLoader：' + via);
    console.log('[MC] a() 的重载共 ' + fn.overloads.length + ' 个：');

    var hookedConcat = false, hookedCompute = false;
    fn.overloads.forEach(function (ov) {
        var ats = argTypes(ov), sig = sigStr(ats);
        if (ats.length === 3 && allStr(ats, 'java.lang.String')) {
            ov.implementation = makeConcatImpl(ov, sig);
            hookedConcat = true;
            console.log('   [hook 拼接] a' + sig);
        } else if (ats.length === 2 && allStr(ats, '[B')) {
            ov.implementation = makeComputeImpl(ov, sig);
            hookedCompute = true;
            console.log('   [hook 计算] a' + sig + '   ← arg1 = 密钥');
        } else {
            console.log('   [未hook   ] a' + sig);
        }
    });

    if (!hookedConcat) console.log('[MC][!] 未找到 a(String,String,String) 重载 —— 拼接方法签名可能变了，见上面重载清单');
    if (!hookedCompute) console.log('[MC][!] 未找到 a(byte[],byte[]) 重载 —— 计算方法签名可能变了，见上面重载清单');
    console.log('[MC] 安装完成。触发一次会签名的请求，看下方 [MC.拼接] / [MC.计算]。\n');
}

/* 拼接：a(String, String, String) -> String */
var CALL = 0;
function makeConcatImpl(ov, sig) {
    return function () {
        var ret = ov.apply(this, arguments);
        try {
            var id = ++CALL;
            var a0 = arguments[0], a1 = arguments[1], a2 = arguments[2];
            var matched = matchAny([a0, a1, a2, ret]);
            console.log('\n┌── [MC.拼接] #' + id + '  d.b.a' + sig + (matched ? '   [★命中 ' + matched + ']' : ''));
            console.log('│ a0 = ' + clip(a0, STR_MAX));
            console.log('│ a1 = ' + clip(a1, STR_MAX));
            console.log('│ a2 = ' + clip(a2, STR_MAX));
            console.log('│ ─▶ 返回(preimage?) = ' + clip(ret, STR_MAX) + classify('' + ret));
            console.log('│ ' + stk().split('\n').join('\n│ '));
            console.log('└' + new Array(60).join('─'));
        } catch (e) { console.log('[MC.拼接][err] ' + e); }
        return ret;
    };
}

/* 计算：a(byte[] data, byte[] key) -> String */
function makeComputeImpl(ov, sig) {
    return function () {
        var ret = ov.apply(this, arguments);
        try {
            var id = ++CALL;
            var data = arguments[0], key = arguments[1];
            var dLen = isBytes(data) ? data.length : '?', kLen = isBytes(key) ? key.length : '?';
            var matched = matchAny([toTxt(data, DATA_TXT), toHex(data, DATA_HEX), toTxt(key, KEY_MAX), toHex(key, KEY_MAX), ret]);
            console.log('\n╔══ [MC.计算] #' + id + '  d.b.a' + sig + (matched ? '   [★命中 ' + matched + ']' : ''));
            console.log('║ data  byte[' + dLen + ']');
            console.log('║   txt = ' + toTxt(data, DATA_TXT));
            console.log('║   hex = ' + toHex(data, DATA_HEX));
            console.log('║ key   byte[' + kLen + ']   ★密钥（固定即可离线复现）');
            console.log('║   txt = ' + toTxt(key, KEY_MAX));
            console.log('║   hex = ' + toHex(key, KEY_MAX));
            console.log('║   b64 = ' + toB64(key, KEY_MAX));
            console.log('║ ═▶ sign(返回) = ' + clip(ret, STR_MAX) + classify('' + ret));
            console.log('║ ' + stk().split('\n').join('\n║ '));
            console.log('╚' + new Array(60).join('═'));
        } catch (e) { console.log('[MC.计算][err] ' + e); }
        return ret;
    };
}

/* =======================================================================
 *  入口：等类加载（bundle 晚到），扫 ClassLoader 解析后装 hook
 * ======================================================================= */
var INSTALLED = false;
function arm() {
    Throwable = Java.use('java.lang.Throwable');
    Log = Java.use('android.util.Log');
    var tries = 0;
    (function attempt() {
        if (INSTALLED) return;
        var r = resolveClass(TARGET_CLASS);
        if (r && r.C) { INSTALLED = true; try { installOn(r.C, r.via); } catch (e) { console.log('[MC] 安装失败: ' + e + '\n' + (e.stack || '')); } return; }
        if (++tries <= RETRY_MAX) { setTimeout(function () { Java.perform(attempt); }, RETRY_MS); return; }
        console.log('[MC] 放弃：' + TARGET_CLASS + ' 一直未加载。可能：该 bundle 未进内存（先进对应业务页再跑）/ 类名随版本变了。');
        console.log('[MC] 自动枚举 *mobileConfig* 相关类供你核对类名：');
        safe(function () {
            Java.enumerateLoadedClassesSync().forEach(function (n) {
                if (n.indexOf('mobileConfig') !== -1 || n.indexOf('mobileconfig') !== -1) console.log('   ' + n);
            });
        }, null);
    })();
}

Java.perform(function () {
    console.log('[MC] frida_mobileconfig_sign_capture 启动，目标 ' + TARGET_CLASS);
    arm();
});

/* standalone：rpc.exports.ready() 查类是否已就绪可 hook */
rpc.exports = {
    ready: function () {
        var ok = false;
        Java.perform(function () { ok = !!(resolveClass(TARGET_CLASS) || {}).C; });
        return ok;
    }
};
