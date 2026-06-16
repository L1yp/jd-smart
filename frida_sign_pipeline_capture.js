'use strict';

/*
 * frida_sign_pipeline_capture.js —— 串起「签名流水线」三层，一条 console 流里看全
 *
 * 宿主 App：com.jd.smart（小京鱼）。三层目标（一次请求里大概率按此顺序触发，用 #N 序号对号入座）：
 *
 *  ── A. 算法层（native，.so 实现，但在 Java 边界即可拦到明文 in/out，无需逆 so）──
 *     com.jd.smart.algorithm.NativeAlgorithmHelper
 *       native String getSecretKey()                       ★ 返回密钥本体——固定即可离线复现
 *       native String getHmacSha256Value(String)           1 参：data，key 内部取自 getSecretKey()
 *       native String getHmacSha256Value(String, String)   2 参：(data, key) 显式传入
 *     这极可能就是 getHouses 那个 64hex sign 的「真·HMAC 原语」（memory 里 SignRequestInterceptor.c
 *     / NativeEncodeDataToServer 之下可能就是它）。抓到 getSecretKey() + 一对 (data→sign) 即可离线算。
 *
 *  ── B. http 工具层（把 sign 贴到参数表上）──
 *     static String com.jingdong.lib.light_http_toolkit.util.c.a(HashMap<String,String> params, String sign)
 *       参数2 = sign。dump 整张 params（被签/将发的字段）+ sign + 返回值，看 sign 如何并入请求。
 *
 *  ── C. manto 网络层（小程序请求派发；manto 是插件/动态加载，开小程序后才进内存）──
 *     private void com.jingdong.manto.network.common.a.b(
 *         boolean, String, String, JSONObject, JSONObject, String, IMantoServerRequester$CallBack)
 *       dump 全部 7 个入参（url/方法名/data/extra/sign?/回调），看一次小程序网络请求的完整下发面貌。
 *
 * 输出：仅 console（不落库、不依赖 host.py）。全局 #N 调用序号贯穿三层，便于把
 *       A(getSecretKey/HMAC) → B(贴 sign) → C(下发) 串成一次请求的因果链；每条带调用栈。
 *
 * 用法：
 *   frida -U -f com.jd.smart -l frida_sign_pipeline_capture.js          # spawn 纯看 console（推荐）
 *   frida -U -n <进程名>      -l frida_sign_pipeline_capture.js          # attach 到已运行进程
 *   python host.py -p com.jd.smart -s frida_sign_pipeline_capture.js --spawn   # 也行，无 send 纯转发 console
 *
 *   C(manto) 只有打开小程序才加载——脚本会持续重试装载；standalone 下 rpc.exports.ready() 看各层就绪情况。
 *
 * ★ 跨 ClassLoader：manto / light_http_toolkit 多为 bundle，不在默认 loader。脚本自动扫全部
 *   ClassLoader 找到能加载目标的那个，再在对应 ClassFactory 上 hook。★
 */

/* =======================================================================
 *  配置
 * ======================================================================= */
var CLS_ALG   = 'com.jd.smart.algorithm.NativeAlgorithmHelper';
var CLS_HTTP  = 'com.jingdong.lib.light_http_toolkit.util.c';
var CLS_MANTO = 'com.jingdong.manto.network.common.a';

var RETRY_MS = 1000, RETRY_MAX = 600;   // 最多重试 ~10min（manto 要开小程序才加载）
var HEARTBEAT_EVERY = 20;               // 每隔 N 轮，报一次还在等哪些类

var STR_MAX  = 2000;    // String / JSON / map 文本打印上限（字符）
var PROBE_SECRET_KEY = true;  // HMAC(1 参) 时若还没见过密钥，主动 getSecretKey() 取一次配对打印
var TARGETS = [];       // 可选：填本次 wire 上的真实 sign；命中入参/返回即标 [★命中]。勿提交真实值。

/* =======================================================================
 *  工具
 * ======================================================================= */
function safe(fn, d) { try { return fn(); } catch (e) { return d; } }
function clip(s, n) { if (s === null || s === undefined) return '' + s; s = '' + s; return s.length > n ? s.substring(0, n) + '..(+' + (s.length - n) + ')' : s; }

/* 返回值/字符串归类，提示 sign 形态 */
function classify(s) {
    if (typeof s !== 'string') return '';
    if (/^[0-9a-fA-F]+$/.test(s)) {
        if (s.length === 64) return '  ← 64hex（SHA-256 / HmacSHA256 形态）';
        if (s.length === 40) return '  ← 40hex（SHA-1 形态）';
        if (s.length === 32) return '  ← 32hex（MD5 形态）';
        return '  ← ' + s.length + ' hex';
    }
    if (/^[A-Za-z0-9+/]+={0,2}$/.test(s) && s.length >= 16) return '  ← base64 形态（len=' + s.length + '）';
    return '';
}

/* 任意值转可读字符串（String/数值/布尔/Java 对象 toString + 类名） */
function jval(x, max) {
    if (x === null || x === undefined) return '' + x;
    var t = typeof x;
    if (t === 'string') return clip(x, max);
    if (t === 'number' || t === 'boolean') return '' + x;
    var cn = safe(function () { return x.$className; }, null) || safe(function () { return '' + x.getClass().getName(); }, 'obj');
    var s = safe(function () { return '' + x; }, null);
    return s !== null ? clip(s, max) + '  «' + cn + '»' : '«' + cn + '»';
}

/* dump 一个 java.util.Map：逐键一行 */
function dumpMap(map, max) {
    var r = safe(function () {
        var ks = map.keySet().toArray(), out = [];
        for (var i = 0; i < ks.length; i++) out.push('      ' + ks[i] + ' = ' + clip('' + map.get(ks[i]), 400));
        return out.length ? out.join('\n') : '      (empty)';
    }, null);
    return r !== null ? r : '      ' + clip('' + map, max);
}

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

var Throwable, Log;
function stk() { return safe(function () { return Log.getStackTraceString(Throwable.$new()); }, '(no stack)'); }
function indent(s, pre) { return pre + ('' + s).split('\n').join('\n' + pre); }

/* 跨 ClassLoader 解析目标类（bundle 不在默认 loader） */
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

function argTypes(ov) { var a = ov.argumentTypes || [], o = []; for (var i = 0; i < a.length; i++) o.push(a[i].className); return o; }

var CALL = 0;          // 贯穿三层的全局调用序号
var SECRET = null;     // 最近一次 getSecretKey() 的返回，供 HMAC(1参) 配对显示
var probing = false;   // 主动探测 getSecretKey 时抑制其自身打印

/* =======================================================================
 *  A. 算法层 NativeAlgorithmHelper（native）
 * ======================================================================= */
function installAlg(C, via) {
    console.log('\n[ALG] 命中 ' + CLS_ALG + '  via ' + via);

    /* getSecretKey() */
    if (C.getSecretKey && C.getSecretKey.overloads) {
        C.getSecretKey.overloads.forEach(function (ov) {
            ov.implementation = function () {
                var ret = ov.apply(this, arguments);
                try {
                    SECRET = (ret === null || ret === undefined) ? null : '' + ret;
                    if (!probing) {
                        var id = ++CALL;
                        console.log('\n████ [ALG.secret] #' + id + '  getSecretKey() ★密钥');
                        console.log('  key = ' + clip(SECRET, STR_MAX) + (SECRET ? '   (len=' + SECRET.length + ')' : ''));
                        console.log(indent(stk(), '  | '));
                    }
                } catch (e) { console.log('[ALG.secret][err] ' + e); }
                return ret;
            };
        });
        console.log('[ALG] hooked getSecretKey x' + C.getSecretKey.overloads.length);
    } else console.log('[ALG][!] 无 getSecretKey（签名变体？）');

    /* getHmacSha256Value(String) / (String,String) */
    if (C.getHmacSha256Value && C.getHmacSha256Value.overloads) {
        C.getHmacSha256Value.overloads.forEach(function (ov) {
            var nArgs = (ov.argumentTypes || []).length;
            ov.implementation = function () {
                var ret = ov.apply(this, arguments);
                try {
                    var id = ++CALL;
                    var data = arguments[0];
                    var key;
                    if (nArgs >= 2) key = '' + arguments[1] + '   (显式传入 arg1)';
                    else {
                        if (PROBE_SECRET_KEY && SECRET === null) {
                            probing = true; SECRET = safe(function () { return '' + this.getSecretKey(); }.bind(this), null); probing = false;
                        }
                        key = (SECRET === null ? '未知（getSecretKey 尚未触发）' : SECRET + '   (取自 getSecretKey)');
                    }
                    var matched = matchAny([data, ret]);
                    console.log('\n▓▓▓▓ [ALG.hmac] #' + id + '  getHmacSha256Value(' + nArgs + ' 参)' + (matched ? '   [★命中 ' + matched + ']' : ''));
                    console.log('  data = ' + clip('' + data, STR_MAX));
                    console.log('  key  = ' + clip(key, STR_MAX));
                    console.log('  ─▶ sign = ' + clip('' + ret, STR_MAX) + classify('' + ret));
                    console.log(indent(stk(), '  | '));
                } catch (e) { console.log('[ALG.hmac][err] ' + e); }
                return ret;
            };
        });
        console.log('[ALG] hooked getHmacSha256Value x' + C.getHmacSha256Value.overloads.length);
    } else console.log('[ALG][!] 无 getHmacSha256Value（签名变体？）');
}

/* =======================================================================
 *  B. http 工具层 light_http_toolkit.util.c.a(HashMap, String=sign)
 * ======================================================================= */
function installHttp(C, via) {
    console.log('\n[HTTP] 命中 ' + CLS_HTTP + '  via ' + via);
    var fn = C.a;
    if (!fn || !fn.overloads) { console.log('[HTTP][!] 无方法 a / 无重载'); return; }
    var hooked = 0;
    fn.overloads.forEach(function (ov) {
        var ats = argTypes(ov);
        // a(Map-ish, String)：arg0 是 Map 家族、arg1 是 String
        if (ats.length === 2 && /Map$/.test(ats[0]) && ats[1] === 'java.lang.String') {
            ov.implementation = function () {
                var ret = ov.apply(this, arguments);
                try {
                    var id = ++CALL;
                    var params = arguments[0], sign = '' + arguments[1];
                    var matched = matchAny([sign, ret]);
                    console.log('\n▒▒▒▒ [HTTP.c.a] #' + id + '  贴 sign 到参数表' + (matched ? '   [★命中 ' + matched + ']' : ''));
                    console.log('  sign(arg1) = ' + clip(sign, STR_MAX) + classify(sign));
                    console.log('  params(arg0):\n' + dumpMap(params, STR_MAX));
                    console.log('  ─▶ 返回 = ' + jval(ret, STR_MAX));
                    console.log(indent(stk(), '  | '));
                } catch (e) { console.log('[HTTP.c.a][err] ' + e); }
                return ret;
            };
            hooked++;
            console.log('[HTTP] hooked a(' + ats.join(', ') + ')');
        }
    });
    if (!hooked) {
        console.log('[HTTP][!] 未匹配到 a(Map,String) 重载，现有重载：');
        fn.overloads.forEach(function (ov) { console.log('   a(' + argTypes(ov).join(', ') + ')'); });
    }
}

/* =======================================================================
 *  C. manto 网络层 manto.network.common.a.b(7 参)
 * ======================================================================= */
var MANTO_PARAMS = ['z(boolean)', 'str1', 'str2', 'json1', 'json2', 'str3', 'callback'];
function installManto(C, via) {
    console.log('\n[MANTO] 命中 ' + CLS_MANTO + '  via ' + via);
    var fn = C.b;
    if (!fn || !fn.overloads) { console.log('[MANTO][!] 无方法 b / 无重载'); return; }
    var hooked = 0;
    fn.overloads.forEach(function (ov) {
        var ats = argTypes(ov);
        if (ats.length === 7 && ats[0] === 'boolean') {
            ov.implementation = function () {
                try {
                    var id = ++CALL;
                    var vals = []; for (var i = 0; i < arguments.length; i++) vals.push('' + arguments[i]);
                    var matched = matchAny(vals);
                    console.log('\n░░░░ [MANTO.a.b] #' + id + '  小程序网络请求下发' + (matched ? '   [★命中 ' + matched + ']' : ''));
                    for (var k = 0; k < arguments.length; k++) {
                        var label = MANTO_PARAMS[k] || ('arg' + k);
                        console.log('  ' + (k) + ' ' + label + ' = ' + jval(arguments[k], STR_MAX));
                    }
                    console.log(indent(stk(), '  | '));
                } catch (e) { console.log('[MANTO.a.b][err] ' + e); }
                return ov.apply(this, arguments);   // void：照常放行
            };
            hooked++;
            console.log('[MANTO] hooked b(' + ats.join(', ') + ')');
        }
    });
    if (!hooked) {
        console.log('[MANTO][!] 未匹配到 7 参 b(...)，现有重载：');
        fn.overloads.forEach(function (ov) { console.log('   b(' + argTypes(ov).join(', ') + ')'); });
    }
}

/* =======================================================================
 *  装载：各目标独立重试（manto 晚到）
 * ======================================================================= */
var done = { alg: false, http: false, manto: false };
function tryHook(key, cls, installer) {
    if (done[key]) return;
    var r = resolveClass(cls);
    if (r && r.C) { done[key] = true; try { installer(r.C, r.via); } catch (e) { console.log('[' + key + '] 安装失败: ' + e + '\n' + (e.stack || '')); } }
}

function arm() {
    Throwable = Java.use('java.lang.Throwable');
    Log = Java.use('android.util.Log');
    var tries = 0;
    (function attempt() {
        tryHook('alg', CLS_ALG, installAlg);
        tryHook('http', CLS_HTTP, installHttp);
        tryHook('manto', CLS_MANTO, installManto);

        if (done.alg && done.http && done.manto) { console.log('\n[*] 三层全部就绪，触发请求/打开小程序看 #N 因果链。\n'); return; }
        if (++tries <= RETRY_MAX) {
            if (tries % HEARTBEAT_EVERY === 0) {
                var pend = [];
                if (!done.alg) pend.push('ALG'); if (!done.http) pend.push('HTTP'); if (!done.manto) pend.push('MANTO(开小程序才加载)');
                console.log('[*] 仍在等待：' + pend.join(', ') + '  （第 ' + tries + '/' + RETRY_MAX + ' 轮）');
            }
            setTimeout(function () { Java.perform(attempt); }, RETRY_MS);
            return;
        }
        var miss = [];
        if (!done.alg) miss.push(CLS_ALG);
        if (!done.http) miss.push(CLS_HTTP);
        if (!done.manto) miss.push(CLS_MANTO);
        console.log('[*] 放弃未命中：' + miss.join(' , ') + '。可能未进内存/类名随版本变。枚举相关类供核对：');
        safe(function () {
            Java.enumerateLoadedClassesSync().forEach(function (n) {
                if (n.indexOf('NativeAlgorithm') !== -1 || n.indexOf('light_http_toolkit') !== -1 || n.indexOf('manto.network') !== -1) console.log('   ' + n);
            });
        }, null);
    })();
}

Java.perform(function () {
    console.log('[*] frida_sign_pipeline_capture 启动 —— A.算法 / B.http贴sign / C.manto下发');
    console.log('[*] 宿主 com.jd.smart；A 多为启动期就绪，C 需打开小程序后才加载（会持续重试）。');
    arm();
});

/* standalone：rpc.exports.ready() 查各层就绪情况 */
rpc.exports = {
    ready: function () {
        var r = {};
        Java.perform(function () {
            r.alg = !!(resolveClass(CLS_ALG) || {}).C;
            r.http = !!(resolveClass(CLS_HTTP) || {}).C;
            r.manto = !!(resolveClass(CLS_MANTO) || {}).C;
        });
        return r;
    }
};
