'use strict';

/*
 * frida_color_capture.js —— 京东「彩虹/色彩」统一网关（api.m.jd.com）接口逆向
 * 目标接口示例：functionId=jdsmart.house.getHouses（获取家庭列表）
 *
 * 与旧接口 getDeviceSnapshot_v1（api.smart.jd.com，HmacSHA1，20 字节）是两套体系：
 *   - 走统一网关 POST api.m.jd.com/api，靠 query 的 functionId 路由
 *   - query.sign = 64 hex = 32 字节 => SHA-256 家族（不是旧接口的 20 字节 SHA-1）
 *   - query.ep 与 body 里真正的请求体都被 JD 客户端加密：
 *       信封 {hdid, ts, ridx, cipher:{...}, ciphertype:5, version:"1.2.0", appname}
 *       ciphertype:5 实测不是标准 base64/AES（语义已知字段解出来是 2~7 字节乱码，
 *       无 16 字节块填充）=> JD 自有「逐字节变换 + 自定义字母表 base64」，只能 live 抓。
 *
 * 本脚本干四件事，全部 send() 给 host.py 落库：
 *   1) OkHttp 抓包          → type:'http'   → http 表（host.py 自动把 api.m.jd.com 行解析进 color 表）
 *   2) sign 的 crypto       → type:'sign'   → sign 表（算法放宽到 SHA-256/MD5/HMAC）
 *   3) ep/body 加密信封追踪  → type:'cipher' → cipher 表（定位加密函数所在类）
 *   4) 加密函数明文↔密文     → type:'cipher' → cipher 表（钉死类后自动抓 I/O）
 *
 * 用法:
 *   python host.py -p <包名> -s frida_color_capture.js --spawn
 *
 * 方法论（沿用本仓库「发现→钉死」套路，见 docs/REVERSE_ENGINEERING.md §5）：
 *   第一遍：DISCOVER_ENC + envelope tracer 跑起来，看 console 把候选加密类列出来、
 *           并用 JSONObject.put 把「信封拼装那一帧」的调用栈打出来 → 定位到具体类。
 *   第二遍：把定位到的类全名填进 ENCRYPT_CLASSES，脚本自动 hook 其 String->String 方法，
 *           抓 明文↔密文（client=android、networkType=wifi、真实 body JSON 等）。
 *   求 sign：把本次 wire 的 sign 值填进 TARGETS，跑起来，命中的那条 MD.digest(SHA-256)
 *           的 input_txt 就是 sign 原文（preimage）→ 反推拼接公式。
 */

/* =======================================================================
 *  开关（这几个直接决定开销/稳定性，先看注释再改）
 * ======================================================================= */
var APP_PKGS = ['com.jd.', 'com.jingdong.']; // 调用方归属：彩虹 SDK 在 com.jingdong/com.jd（启动包名是 com.jd.iots）
var SIGN_ALGS = ['sha-256', 'sha256', 'hmacsha256', 'md5', 'sha-1', 'hmacsha1'];
//                ^ sign=32B=>SHA-256 系；保留 md5(uuid/设备指纹)/sha1(旧接口同跑)。设 [] = 不按算法过滤(开销大)。
var HOOK_CIPHER = false;      // 默认 false：ciphertype:5 非标准 AES（字段无 16B 块），且 AES 在 TLS 里极热易闪退。
var HOOK_BASE64 = true;       // ep 单字段密文的最后一步可能是 base64
var B64_MAX_INPUT = 256;      // ep 字段密文不长，放宽到 256B（旧脚本是 64B）
var ARM_DELAY_MS = 0;         // >0：延迟装 sign/加密 hook（闪退就设 4000 错开启动期 TLS/检测窗口）
var DISCOVER_ENC = true;      // 启动枚举一次候选加密/签名类（定位完可设 false 降噪）
var TRACE_ENVELOPE = true;    // hook JSONObject.put 追 ciphertype/cipher 信封拼装点（打栈定位加密类）
var ENVELOPE_STACK_MAX = 4;   // 信封拼装点最多打几次栈（避免刷屏）
var ENCRYPT_CLASSES = [];     // 【发现后填】定位到的加密类全名；脚本自动 hook 其 String->String 方法抓明文↔密文
                              //   例: ['com.jingdong.xxx.YyyEncrypt', 'com.jd.xxx.SecExc']
var TARGETS = [];             // 想高亮的 wire 值（如本次 sign / ep 某字段密文），命中 crypto/base64 输出即打栈。勿提交真实值。

/* Part 7 · sign 头号嫌疑：jdupgrade 的 HmacSHA256 工具 d.a(byte[],byte[])（静态分析锁定） */
var HOOK_UPGRADE_HMAC = true;                                       // 抓 d.a 的【两入参 + 输出 + 栈】，落 sign 表 kind=HMAC.a
var UPGRADE_HMAC_CLASS = 'com.jingdong.sdk.jdupgrade.inner.utils.d'; // 混淆类名，换 App 版本可能变；变了用栈/jadx 重认
var UPGRADE_HMAC_METHOD = 'a';                                       // a(byte[],byte[]) -> HMAC；只挂 (byte[],byte[]) 这一重载
var HMAC_DATA_ARG = 0, HMAC_KEY_ARG = 1;                            // 源码确认 d.a(data, key)：arg0=被签数据(preimage)、arg1=固定密钥(prod/test secret)

/* Part 8 · 彩虹/smart-home 真签名器（实测 getHouses 走这里；Part 7 的 d.a 只在「检查更新」时响） */
var HOOK_COLOR_SIGNER = true;                                       // 抓 SignRequestInterceptor.c + native NativeEncodeDataToServer(_gm)
var SIGN_INTERCEPTOR_CLASS = 'com.jd.smart.networklib.interceptor.SignRequestInterceptor';
var SIGN_INTERCEPTOR_METHOD = 'c';                                  // c(String)：签名拦截器里的算签助手
var NATIVE_SIGN_CLASS = '';                                         // 声明 NativeEncodeDataToServer 的 JNI 类全名；留空=自动发现（从 jadx 拿到可直接填，更稳）
var NATIVE_SIGN_METHODS = ['NativeEncodeDataToServer', 'NativeEncodeDataToServer_gm']; // _gm = 国密(SM)变体

var CONFIG = { chainClass: 'okhttp3.internal.http.RealInterceptorChain', requestClass: 'okhttp3.Request', bufferClass: 'okio.Buffer' };
var MAX_BODY = 512 * 1024;
var CALLER_SCAN = 8;          // 判归属时向下扫多少个「非加密库」发起帧
var MAX_HEX = 4096, MAX_TXT = 2048;
var LOG_UPDATE = true;        // 打印 update() 分段输入（不影响入库，原文始终累积）
var STACK_IN_DB = false;

/* =======================================================================
 *  通用工具
 * ======================================================================= */
var HEX = '0123456789abcdef';
var B64C = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function isBytes(x) { return x !== null && x !== undefined && x.length !== undefined && typeof x !== 'string'; }
function toHex(b) {
    if (!isBytes(b)) return 'null';
    var n = b.length, lim = Math.min(n, MAX_HEX), s = '';
    for (var i = 0; i < lim; i++) { var v = b[i] & 0xff; s += HEX.charAt(v >> 4) + HEX.charAt(v & 0xf); }
    if (n > lim) s += '..(+' + (n - lim) + 'B)';
    return s;
}
function toB64(b) {
    if (!isBytes(b)) return 'null';
    var n = b.length, s = '';
    for (var i = 0; i < n; i += 3) {
        var b0 = b[i] & 0xff, b1 = (i + 1 < n) ? (b[i + 1] & 0xff) : 0, b2 = (i + 2 < n) ? (b[i + 2] & 0xff) : 0;
        var t = (b0 << 16) | (b1 << 8) | b2;
        s += B64C.charAt((t >> 18) & 63) + B64C.charAt((t >> 12) & 63);
        s += (i + 1 < n) ? B64C.charAt((t >> 6) & 63) : '=';
        s += (i + 2 < n) ? B64C.charAt(t & 63) : '=';
    }
    return s;
}
function toTxt(b) {
    if (!isBytes(b)) return 'null';
    var n = Math.min(b.length, MAX_TXT), s = '';
    for (var i = 0; i < n; i++) {
        var c = b[i] & 0xff;
        if (c >= 0x20 && c < 0x7f) s += String.fromCharCode(c);
        else if (c === 0x0a) s += '\\n'; else if (c === 0x0d) s += '\\r'; else if (c === 0x09) s += '\\t'; else s += '.';
    }
    if (b.length > n) s += '..';
    return s;
}
function toAscii(b) { if (!isBytes(b)) return 'null'; var s = ''; for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i] & 0xff); return s; }
function hexN(b) { return isBytes(b) ? toHex(b) : null; }
function txtN(b) { return isBytes(b) ? toTxt(b) : null; }
function safe(fn, dflt) { try { return fn(); } catch (e) { return dflt; } }
function emit(rec) { try { send({ type: 'sign', data: rec }); } catch (e) {} }
function emitCipher(rec) { try { send({ type: 'cipher', data: rec }); } catch (e) {} }
function algAllowed(name) {
    if (!SIGN_ALGS.length) return true;
    if (!name) return false;
    var n = ('' + name).toLowerCase();
    for (var i = 0; i < SIGN_ALGS.length; i++) if (n.indexOf(SIGN_ALGS[i]) !== -1) return true;
    return false;
}

/* =======================================================================
 *  Part 1 · OkHttp 抓包（与 frida_capture.js 一致；天然绕过 SSL pinning）
 * ======================================================================= */
function headersToObj(headers) {
    var out = {};
    try { var n = headers.size(); for (var i = 0; i < n; i++) out[headers.name(i)] = headers.value(i); } catch (e) {}
    return out;
}
function readRequestBody(request, BufferCls) {
    try {
        var body = request.body();
        if (body === null) return null;
        try { if (body.isOneShot && body.isOneShot()) return '<<one-shot body, skipped>>'; } catch (e) {}
        var len = -1; try { len = body.contentLength(); } catch (e) {}
        if (len > MAX_BODY) return '<<req body too large: ' + len + '>>';
        if (!BufferCls) return '<<okio.Buffer not resolved>>';
        var buffer = BufferCls.$new();
        body.writeTo(buffer);
        var s = buffer.readUtf8(); buffer.clear();
        return s;
    } catch (e) { return '<<req body unreadable: ' + e + '>>'; }
}
function readResponseBody(response) {
    try { return response.peekBody(MAX_BODY).string(); } catch (e) { return '<<resp body unreadable: ' + e + '>>'; }
}
function discoverOkhttp() {
    console.log('[discover] enumerating okhttp3/okio classes...');
    Java.enumerateLoadedClasses({
        onMatch: function (name) { if (name.indexOf('okhttp') !== -1 || name.indexOf('okio') !== -1) console.log('  ' + name); },
        onComplete: function () { console.log('[discover] done. 若为空则 okhttp 被完全混淆，找有 proceed 的类填进 CONFIG。'); }
    });
}
function installOkHttp() {
    var Chain, Buffer = null;
    try { Chain = Java.use(CONFIG.chainClass); Java.use(CONFIG.requestClass); }
    catch (e) { console.log('[!] 找不到 ' + CONFIG.chainClass + ' : ' + e); discoverOkhttp(); return; }
    try { Buffer = Java.use(CONFIG.bufferClass); } catch (e) { console.log('[!] okio.Buffer 未解析，请求 body 读不到'); }
    var BufferRef = Buffer;
    try {
        Chain.proceed.overload(CONFIG.requestClass).implementation = function (request) {
            var response = this.proceed(request);
            try {
                send({ type: 'http', data: {
                    ts: Date.now(), method: request.method(), url: request.url().toString(),
                    req_headers: headersToObj(request.headers()), req_body: readRequestBody(request, BufferRef),
                    code: response.code(), resp_headers: headersToObj(response.headers()), resp_body: readResponseBody(response)
                } });
            } catch (e) { send({ type: 'error', data: '' + e }); }
            return response;
        };
        console.log('[+] OkHttp hook 已安装。带 authorization/tgt 的那行是加完鉴权头之后的。');
        console.log('    注意：若彩虹 SDK 不走 okhttp3（自带 HttpURLConnection），这里抓不到；');
        console.log('    届时靠 sign/cipher 两个 hook 仍能拿到签名原文与明文，请求外形看 jadx。');
    } catch (e) { console.log('[!] hook proceed(Request) 失败: ' + e); discoverOkhttp(); }
}

/* =======================================================================
 *  Part 2 · sign 的 crypto（SHA-256/MD5/HMAC；与旧脚本同套累积/过滤机制）
 * ======================================================================= */
function installSignHooks() {
    var Throwable = Java.use('java.lang.Throwable');
    var Log = Java.use('android.util.Log');
    function stack() { return safe(function () { return Log.getStackTraceString(Throwable.$new()); }, '(no stack)'); }
    function tid() { return Process.getCurrentThreadId(); }
    function calledFromApp() {
        if (!APP_PKGS.length) return true;
        var frames = safe(function () { return Throwable.$new().getStackTrace(); }, null);
        if (!frames) return true;
        var seen = 0;
        for (var i = 0; i < frames.length && seen < CALLER_SCAN; i++) {
            var cn = ''; try { cn = '' + frames[i].getClassName(); } catch (e) { continue; }
            if (cn.indexOf('java.security.') === 0 || cn.indexOf('javax.crypto.') === 0 || cn.indexOf('java.lang.') === 0 ||
                cn.indexOf('com.android.org.conscrypt') === 0 || cn.indexOf('org.conscrypt') === 0 ||
                cn.indexOf('sun.security') === 0 || cn.indexOf('dalvik.') === 0) continue;
            seen++;
            for (var j = 0; j < APP_PKGS.length; j++) if (cn.indexOf(APP_PKGS[j]) === 0) return true;
        }
        return false;
    }
    function matchOf(oh, ob) {
        for (var i = 0; i < TARGETS.length; i++) { var t = TARGETS[i]; if ((oh && oh.toLowerCase() === t.toLowerCase()) || ob === t) return t; }
        return null;
    }
    function logOut(kind, algorithm, out, input) {
        if (!calledFromApp()) return;
        var oh = toHex(out), ob = toB64(out), ih = hexN(input), it = txtN(input);
        console.log('[' + kind + ' alg=' + algorithm + '] out.hex=' + oh);
        if (it !== null) console.log('    input "' + it + '"');
        var hit = matchOf(oh, ob);
        var stk = (hit || STACK_IN_DB) ? stack() : null;
        if (hit) {
            console.log('\n========================= MATCH (sign?) =========================');
            console.log(' where  : ' + kind + ' alg=' + algorithm + '\n target : ' + hit);
            console.log(' out.hex: ' + oh);
            if (it !== null) console.log(' INPUT  : "' + it + '"\n          hex=' + ih);
            console.log(stk); console.log('================================================================\n');
        }
        emit({ kind: kind, algorithm: algorithm, input_hex: ih, input_txt: it, out_hex: oh, out_b64: ob, matched: !!hit, target: hit, stack: stk });
    }
    function b64hit(kind, resultStr, input) {
        if (!calledFromApp()) return;
        var ih = hexN(input), it = txtN(input);
        var hit = (TARGETS.indexOf(resultStr) >= 0) ? resultStr : null;
        var stk = (hit || STACK_IN_DB) ? stack() : null;
        if (hit) {
            console.log('\n===== BASE64 MATCH @ ' + kind + ' =====\n result : ' + resultStr + '\n raw.hex: ' + ih + '\n raw.txt: "' + it + '"');
            console.log(stk); console.log('=====================================\n');
        }
        emit({ kind: kind, algorithm: null, input_hex: ih, input_txt: it, out_hex: null, out_b64: resultStr, matched: !!hit, target: hit, stack: stk });
    }

    var accMac = {}, accMd = {};
    function accAppend(store, t, bytes) { if (!isBytes(bytes)) return; var a = store[t] || (store[t] = []); for (var i = 0; i < bytes.length; i++) a.push(bytes[i] & 0xff); }
    function accGet(store, t) { var a = store[t]; return (a && a.length) ? a : null; }
    function accClear(store, t) { delete store[t]; }
    function updBytes(a) {
        if (!isBytes(a[0])) return null;
        if (a.length >= 3 && typeof a[1] === 'number' && typeof a[2] === 'number') {
            var off = a[1], len = a[2], out = []; for (var i = 0; i < len; i++) out.push(a[0][off + i] & 0xff); return out;
        }
        return a[0];
    }
    function hookAll(cls, method, cb) {
        var clazz = safe(function () { return Java.use(cls); }, null);
        if (!clazz) { console.log('[skip] ' + cls + ' (类不存在)'); return; }
        var m = clazz[method];
        if (!m || !m.overloads) { console.log('[skip] ' + cls + '.' + method + ' (方法不存在)'); return; }
        m.overloads.forEach(function (ov) {
            ov.implementation = function () { var ret = ov.apply(this, arguments); try { cb(this, arguments, ret); } catch (e) { console.log('[hookerr] ' + cls + '.' + method + ': ' + e); } return ret; };
        });
        console.log('[hooked] ' + cls + '.' + method + ' x' + m.overloads.length);
    }
    function alg(self) { return safe(function () { return self.getAlgorithm(); }, '?'); }

    /* MessageDigest（SHA-256 / MD5 / SHA-1）—— sign 头号嫌疑（32B=SHA-256） */
    hookAll('java.security.MessageDigest', 'getInstance', function (s, a) { if (algAllowed(a[0])) console.log('[MessageDigest.getInstance] ' + a[0]); });
    hookAll('java.security.MessageDigest', 'reset', function () { accClear(accMd, tid()); });
    hookAll('java.security.MessageDigest', 'update', function (s, a) {
        if (!algAllowed(alg(s))) return; var b = updBytes(a); if (!b) return; accAppend(accMd, tid(), b);
        if (LOG_UPDATE && calledFromApp()) console.log('[MD.update] alg=' + alg(s) + ' "' + toTxt(b) + '"');
    });
    hookAll('java.security.MessageDigest', 'digest', function (s, a, ret) {
        var al = alg(s); if (!algAllowed(al)) return; var t = tid();
        if (typeof ret === 'number') { accClear(accMd, t); return; }
        if (isBytes(a[0])) accAppend(accMd, t, a[0]);
        var input = accGet(accMd, t); accClear(accMd, t); logOut('MD.digest', al, ret, input);
    });

    /* Mac（HmacSHA256 / HmacSHA1） */
    hookAll('javax.crypto.Mac', 'getInstance', function (s, a) { if (algAllowed(a[0])) console.log('[Mac.getInstance] ' + a[0]); });
    hookAll('javax.crypto.Mac', 'init', function (s, a) {
        var al = alg(s); if (!algAllowed(al)) return; accClear(accMac, tid());
        var enc = safe(function () { return a[0].getEncoded(); }, null);
        if (calledFromApp()) { console.log('\n[Mac.init] alg=' + al + ' key.hex=' + toHex(enc) + ' key.txt="' + toTxt(enc) + '"'); emit({ kind: 'Mac.init', algorithm: al, key_hex: hexN(enc), key_txt: txtN(enc) }); }
    });
    hookAll('javax.crypto.Mac', 'update', function (s, a) {
        if (!algAllowed(alg(s))) return; var b = updBytes(a); if (!b) return; accAppend(accMac, tid(), b);
        if (LOG_UPDATE && calledFromApp()) console.log('[Mac.update] "' + toTxt(b) + '"');
    });
    hookAll('javax.crypto.Mac', 'doFinal', function (s, a, ret) {
        var al = alg(s); if (!algAllowed(al)) return; var t = tid();
        if (ret === undefined || ret === null) { var inp = accGet(accMac, t); accClear(accMac, t); logOut('Mac.doFinal', al, a[0], inp); return; }
        if (isBytes(a[0])) accAppend(accMac, t, a[0]);
        var input = accGet(accMac, t); accClear(accMac, t); logOut('Mac.doFinal', al, ret, input);
    });

    /* Cipher（默认关；ciphertype:5 非标准 AES，留作万一对照） */
    if (HOOK_CIPHER) {
        hookAll('javax.crypto.Cipher', 'getInstance', function (s, a) { console.log('[Cipher.getInstance] ' + a[0]); });
        hookAll('javax.crypto.Cipher', 'init', function (s, a) {
            var al = alg(s), enc = safe(function () { return a[1].getEncoded(); }, null), iv = safe(function () { return a[2].getIV(); }, null);
            if (calledFromApp()) { console.log('\n[Cipher.init] alg=' + al + ' opmode=' + a[0] + ' key.hex=' + toHex(enc) + (iv ? ' iv.hex=' + toHex(iv) : '')); emit({ kind: 'Cipher.init', algorithm: al, key_hex: hexN(enc), key_txt: txtN(enc), iv_hex: hexN(iv) }); }
        });
        hookAll('javax.crypto.Cipher', 'doFinal', function (s, a, ret) {
            if (typeof ret === 'number') return; logOut('Cipher.doFinal', alg(s), ret, isBytes(a[0]) ? a[0] : null);
        });
    }

    /* Base64 编码（小输入；ep 单字段密文的可能最后一步） */
    if (HOOK_BASE64) {
        hookAll('android.util.Base64', 'encodeToString', function (s, a, ret) { if (isBytes(a[0]) && a[0].length > B64_MAX_INPUT) return; b64hit('android.Base64.encodeToString', ret, a[0]); });
        hookAll('android.util.Base64', 'encode', function (s, a, ret) { if (isBytes(a[0]) && a[0].length > B64_MAX_INPUT) return; b64hit('android.Base64.encode', toAscii(ret), a[0]); });
        hookAll('java.util.Base64$Encoder', 'encodeToString', function (s, a, ret) { if (isBytes(a[0]) && a[0].length > B64_MAX_INPUT) return; b64hit('java.Base64.encodeToString', ret, a[0]); });
        hookAll('java.util.Base64$Encoder', 'encode', function (s, a, ret) { if (isBytes(a[0]) && a[0].length > B64_MAX_INPUT) return; b64hit('java.Base64.encode', toAscii(ret), a[0]); });
    }

    /* SecretKeySpec（HMAC/AES 密钥来源） */
    var SKS = safe(function () { return Java.use('javax.crypto.spec.SecretKeySpec'); }, null);
    if (SKS) SKS.$init.overloads.forEach(function (ov) {
        ov.implementation = function () {
            var r = ov.apply(this, arguments);
            try { var kb = arguments[0], a = '' + arguments[arguments.length - 1];
                if (isBytes(kb) && algAllowed(a) && calledFromApp()) { console.log('[SecretKeySpec] alg=' + a + ' key.hex=' + toHex(kb) + ' key.txt="' + toTxt(kb) + '"'); emit({ kind: 'SecretKeySpec', algorithm: a, key_hex: toHex(kb), key_txt: toTxt(kb) }); }
            } catch (e) {}
            return r;
        };
    });

    console.log('[*] sign hook 已就位（落 sign 表）。algs=' + JSON.stringify(SIGN_ALGS) + ' pkgs=' + JSON.stringify(APP_PKGS));
}

/* =======================================================================
 *  Part 3 · 加密信封追踪：定位「拼 {ciphertype,cipher,...} 的那一帧」= 加密类
 *  hook org.json.JSONObject.put，当 key 命中 ciphertype/cipher 时 dump 栈。
 *  栈里紧贴 org.json 之前的 App 帧 = 加密模块；顺它进 jadx 看 String->String 加密方法。
 * ======================================================================= */
function installEnvelopeTracer() {
    if (!TRACE_ENVELOPE) return;
    var JO = safe(function () { return Java.use('org.json.JSONObject'); }, null);
    if (!JO || !JO.put) { console.log('[env] org.json.JSONObject.put 未解析，跳过信封追踪'); return; }
    var Throwable = Java.use('java.lang.Throwable');
    var Log = Java.use('android.util.Log');
    function stk() { return safe(function () { return Log.getStackTraceString(Throwable.$new()); }, '(no stack)'); }
    var WATCH = { 'ciphertype': 1, 'cipher': 1 };
    var dumped = 0, seenStacks = {};
    JO.put.overloads.forEach(function (ov) {
        ov.implementation = function () {
            var ret = ov.apply(this, arguments);
            try {
                var k = '' + arguments[0];
                if (WATCH[k] && k === 'ciphertype' && dumped < ENVELOPE_STACK_MAX) {
                    var self = this, full = safe(function () { return '' + self.toString(); }, '?');
                    var s = stk();
                    // 调用栈去重：同一处只打一次
                    var sig = s.split('\n').slice(0, 6).join('|');
                    if (!seenStacks[sig]) {
                        seenStacks[sig] = 1; dumped++;
                        console.log('\n===== 加密信封拼装 @ JSONObject.put("ciphertype", ' + arguments[1] + ') =====');
                        console.log(' envelope = ' + (full.length > 400 ? full.substring(0, 400) + '..' : full));
                        console.log(s);
                        console.log(' ↑ 紧贴 org.json 之前的 App 帧 = 加密信封拼装处；把那个类全名填进 ENCRYPT_CLASSES 再跑一遍。');
                        console.log('=========================================================================\n');
                        emitCipher({ kind: 'envelope', field: k, cipher_txt: full, stack: s });
                    }
                }
            } catch (e) {}
            return ret;
        };
    });
    console.log('[env] envelope tracer 已就位（盯 JSONObject.put ciphertype，最多打 ' + ENVELOPE_STACK_MAX + ' 处栈）');
}

/* =======================================================================
 *  Part 4 · 加密函数 I/O：钉死类后自动抓 明文↔密文
 *  把 Part3 定位到的类填进 ENCRYPT_CLASSES，这里自动 hook 其全部声明方法，
 *  凡「有 String 入参 且 返回 String」的调用，记录 明文(入)↔密文(出)。
 * ======================================================================= */
function installEncryptHooks() {
    if (!ENCRYPT_CLASSES.length) { console.log('[enc] ENCRYPT_CLASSES 为空：先看 envelope/discover 输出定位加密类，再填它跑第二遍'); return; }
    ENCRYPT_CLASSES.forEach(function (cn) {
        var C = safe(function () { return Java.use(cn); }, null);
        if (!C) { console.log('[enc] 跳过（类不存在）: ' + cn); return; }
        var methods = safe(function () { return C.class.getDeclaredMethods(); }, null);
        if (!methods) { console.log('[enc] 取方法失败: ' + cn); return; }
        var done = {}, cnt = 0;
        for (var i = 0; i < methods.length; i++) {
            var mn = '' + methods[i].getName();
            if (done[mn]) continue; done[mn] = 1;
            var fn = C[mn]; if (!fn || !fn.overloads) continue;
            (function (mname) {
                fn.overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        var ret = ov.apply(this, arguments);
                        try {
                            var sArgs = [];
                            for (var j = 0; j < arguments.length; j++) if (typeof arguments[j] === 'string') sArgs.push(arguments[j]);
                            if (typeof ret === 'string' && ret.length && sArgs.length) {
                                var plain = sArgs.join(' | ');
                                console.log('[enc] ' + cn + '.' + mname + '("' + plain + '") -> ' + ret);
                                emitCipher({ kind: 'encrypt', clazz: cn, method: mname, plain_txt: plain, cipher_txt: '' + ret });
                            }
                        } catch (e) {}
                        return ret;
                    };
                });
            })(mn);
            cnt++;
        }
        console.log('[enc] hooked ' + cn + '  方法数~' + cnt + '（String->String 自动记录明文↔密文）');
    });
}

/* =======================================================================
 *  Part 5 · 候选加密/签名类枚举（一次性，名字包含关键词且属 com.jd/com.jingdong）
 * ======================================================================= */
function discoverEnc() {
    if (!DISCOVER_ENC) return;
    var pats = ['encrypt', 'Encrypt', 'cipher', 'Cipher', 'jdmobilesign', 'JDMobileSign', 'MobileSign',
        'colorsign', 'ColorSign', 'jdguard', 'JDGuard', 'Security', 'security', 'SecExc', 'sec.Logo', 'Logo', 'aes', 'Aes', 'sign', 'Sign'];
    console.log('[discover] 枚举候选加密/签名类（com.jd/com.jingdong 下，名字含: encrypt/cipher/sign/security/guard/Logo...）...');
    var seen = {}, n = 0;
    Java.enumerateLoadedClasses({
        onMatch: function (name) {
            if (name.indexOf('com.jd') === -1 && name.indexOf('com.jingdong') === -1) return;
            for (var i = 0; i < pats.length; i++) {
                if (name.indexOf(pats[i]) !== -1) { if (!seen[name]) { seen[name] = 1; n++; console.log('  ' + name); } break; }
            }
        },
        onComplete: function () { console.log('[discover] done. 命中 ' + n + ' 个。把疑似类填进 ENCRYPT_CLASSES 跑第二遍。'); }
    });
}

/* =======================================================================
 *  Part 6 · wjlogin 登录态(WUserSigInfo)读写追踪 —— 所有 frida_*.js 内置（见 §5.6）
 *  createUserInfoFromJSON(读/初始化) + toJSONObject(写/落盘)，两者 dump 调用栈看更新机制。
 * ======================================================================= */
/* =======================================================================
 *  wjlogin 补充 hook：A2(tgt) 刷新判定/动作 + 登录态文件读写 —— 所有 frida_*.js 内置（见 §5.6）
 *    jd.wjlogin_sdk.common.h.c.b()                  判断是否该刷新 A2(tgt) —— 看返回值 + 触发栈
 *    jd.wjlogin_sdk.common.h.c.refreshLoginStatus() 刷新登录态动作
 *    static jd.wjlogin_sdk.util.v.b(content, path)  保存数据文件（实际文件名 = md5hex(path)）
 *    static jd.wjlogin_sdk.util.v.g(path)           读取数据文件
 *  均 dump 调用栈；落 host.py sign 表(kind=WJ.*)。类晚加载自动重试，与 WUserSigInfo hook 互不影响。
 * ======================================================================= */
function installWjExtraHooks() {
    var WJX = { refresh: false, file: false };
    var Throwable = Java.use('java.lang.Throwable');
    var Log = Java.use('android.util.Log');
    function stk() { try { return Log.getStackTraceString(Throwable.$new()); } catch (e) { return '(no stack)'; } }
    function clip(s, n) { if (s == null) return 'null'; s = '' + s; return s.length > n ? s.substring(0, n) + '..(+' + (s.length - n) + 'B)' : s; }
    function md5hex(s) {
        try {
            var MD = Java.use('java.security.MessageDigest').getInstance('MD5');
            var JS = Java.use('java.lang.String');
            var d = MD.digest(JS.$new('' + s).getBytes('UTF-8'));
            var h = ''; for (var i = 0; i < d.length; i++) { var v = d[i] & 0xff; h += (v < 16 ? '0' : '') + v.toString(16); }
            return h;
        } catch (e) { return '(md5? ' + e + ')'; }
    }
    var seen = {};
    function emit(kind, title, info, opts) {
        var s = stk(), sig = kind + '|' + s.split('\n').slice(0, 8).join('|'), first = !seen[sig];
        if (first) seen[sig] = 1;
        console.log('\n########## ' + title + '  [' + kind + '] ##########');
        console.log(info);
        if (first) { console.log(s); console.log(' ↑ 紧贴 jd.wjlogin_sdk 之前的 App 帧 = 触发处（更新机制看这里）'); }
        else console.log(' (调用栈同前次，省略)');
        console.log('############################################\n');
        var rec = { kind: kind, stack: s, matched: 1 };
        if (opts) for (var kk in opts) rec[kk] = opts[kk];
        try { send({ type: 'sign', data: rec }); } catch (e) {}
    }
    function hookRefresh(C) {
        var b = C.b;
        if (b && b.overloads) b.overloads.forEach(function (ov) {
            if (!ov.argumentTypes || ov.argumentTypes.length !== 0) return; // 只要无参 b()
            ov.implementation = function () {
                var r = ov.apply(this, arguments);
                emit('WJ.shouldRefreshA2', '是否该刷新A2 · h.c.b()', ' result = ' + r, { out_b64: '' + r });
                return r;
            };
        });
        var rf = C.refreshLoginStatus;
        if (rf && rf.overloads) rf.overloads.forEach(function (ov) {
            ov.implementation = function () {
                emit('WJ.refreshLoginStatus', '刷新登录态 · refreshLoginStatus()', ' (进入) args=' + arguments.length, null);
                return ov.apply(this, arguments);
            };
        });
        console.log('[wjlogin+] hooked common.h.c.b()/refreshLoginStatus');
    }
    function hookFile(V) {
        var b = V.b; // static b(String content, String path)
        if (b && b.overloads) b.overloads.forEach(function (ov) {
            if (!ov.argumentTypes || ov.argumentTypes.length !== 2) return;
            ov.implementation = function (content, path) {
                var p = '' + path, md = md5hex(p);
                emit('WJ.fileSave', '保存数据文件 · v.b(content,path)',
                    ' path = ' + p + '\n file = ' + md + '  (=md5hex(path))\n content = ' + clip(content, 1400),
                    { input_txt: (content == null ? null : '' + content), key_txt: p, target: md });
                return ov.apply(this, arguments);
            };
        });
        var g = V.g; // static g(String path) -> content
        if (g && g.overloads) g.overloads.forEach(function (ov) {
            if (!ov.argumentTypes || ov.argumentTypes.length !== 1) return;
            ov.implementation = function (path) {
                var r = ov.apply(this, arguments);
                var p = '' + path, md = md5hex(p);
                emit('WJ.fileRead', '读取数据文件 · v.g(path)',
                    ' path = ' + p + '\n file = ' + md + '  (=md5hex(path))\n content = ' + clip(r, 1400),
                    { input_txt: (r == null ? null : '' + r), key_txt: p, target: md });
                return r;
            };
        });
        console.log('[wjlogin+] hooked util.v.b(save)/v.g(read)');
    }
    var specs = [
        { cls: 'jd.wjlogin_sdk.common.h.c', key: 'refresh', fn: hookRefresh },
        { cls: 'jd.wjlogin_sdk.util.v', key: 'file', fn: hookFile }
    ];
    var tries = 0, MAX = 40;
    (function attempt() {
        var pending = 0;
        specs.forEach(function (sp) {
            if (WJX[sp.key]) return;
            var C = null; try { C = Java.use(sp.cls); } catch (e) { C = null; }
            if (C) { try { sp.fn(C); } catch (e) { console.log('[wjlogin+] 安装 ' + sp.cls + ' 失败: ' + e); } WJX[sp.key] = true; }
            else pending++;
        });
        if (pending && ++tries <= MAX) setTimeout(function () { Java.perform(attempt); }, 700);
        else if (pending) specs.forEach(function (sp) { if (!WJX[sp.key]) console.log('[wjlogin+] 放弃：' + sp.cls + ' 未加载（版本可能改名/未集成）'); });
    })();
}
Java.perform(function () { try { installWjExtraHooks(); } catch (e) { console.log('[!] wjlogin+ hook 安装失败: ' + e); } });

var WJ_DONE = false;
function installWjloginHook() {
    var CLS = 'jd.wjlogin_sdk.model.WUserSigInfo';
    var Throwable = Java.use('java.lang.Throwable');
    var Log = Java.use('android.util.Log');
    function stk() { try { return Log.getStackTraceString(Throwable.$new()); } catch (e) { return '(no stack)'; } }
    function clip(s, n) { s = '' + s; return s.length > n ? s.substring(0, n) + '..(+' + (s.length - n) + 'B)' : s; }
    var seen = {};
    function dump(op, json) {
        var s = stk(), sig = s.split('\n').slice(0, 8).join('|'), first = !seen[sig];
        if (first) seen[sig] = 1;
        console.log('\n########## wjlogin ' + op + ' ##########');
        console.log(' json = ' + (json == null ? 'null' : clip(json, 1400)));
        if (first) { console.log(s); console.log(' ↑ 紧贴 jd.wjlogin_sdk 之前的 App 帧 = 触发读/写处（更新机制看这里）'); }
        else console.log(' (调用栈同前次，省略)');
        console.log('############################################\n');
        try { send({ type: 'sign', data: { kind: 'WUserSig.' + op, input_txt: json, stack: s, matched: 1 } }); } catch (e) {}
    }
    function doHook(W) {
        if (WJ_DONE) return; WJ_DONE = true;
        var m1 = W.createUserInfoFromJSON;
        if (m1 && m1.overloads) {
            m1.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var json = null; try { if (arguments.length && arguments[0]) json = '' + arguments[0].toString(); } catch (e) {}
                    var ret = ov.apply(this, arguments);
                    dump('createUserInfoFromJSON(读/初始化)', json);
                    return ret;
                };
            });
            console.log('[wjlogin] hooked ' + CLS + '.createUserInfoFromJSON x' + m1.overloads.length);
        } else console.log('[wjlogin] 未找到 createUserInfoFromJSON 方法（版本差异？）');
        var m2 = W.toJSONObject;
        if (m2 && m2.overloads) {
            m2.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var ret = ov.apply(this, arguments);
                    var json = null; try { if (ret) json = '' + ret.toString(); } catch (e) {}
                    dump('toJSONObject(写/落盘)', json);
                    return ret;
                };
            });
            console.log('[wjlogin] hooked ' + CLS + '.toJSONObject x' + m2.overloads.length);
        } else console.log('[wjlogin] 未找到 toJSONObject 方法（版本差异？）');
    }
    var tries = 0, MAX = 30;
    (function attempt() {
        if (WJ_DONE) return;
        var W = null; try { W = Java.use(CLS); } catch (e) { W = null; }
        if (W) { doHook(W); return; }
        if (++tries <= MAX) setTimeout(function () { Java.perform(attempt); }, 700);
        else console.log('[wjlogin] 放弃：' + CLS + ' 一直未加载（该版本可能未集成 wjlogin / 改名）');
    })();
}

/* =======================================================================
 *  Part 7 · jdupgrade HMAC：com.jingdong.sdk.jdupgrade.inner.utils.d.a(byte[] data, byte[] key)
 *  源码已确认（签名器 c.a(functionId, query, body)）：sign = HmacSHA256(data, key) 转十六进制(64hex)。
 *    - arg0 = data = preimage：TreeMap(自定义比较器 b){functionId + query(map) + body} 的【各 value】
 *             按 key 排序后用 '&' 拼接（只拼 value、不含 key、去尾随 &）；body = modBase64(gzip(bodyJson))。
 *    - arg1 = key  = 固定 secret：c.W() 决定 prod/test 二选一，是 32 字符 hex 串的 UTF-8 字节(32B)，非解码后 16B。
 *  本 hook 只挂 (byte[],byte[]) 重载，抓 data/key/sign/栈，落 sign 表(kind=HMAC.a；data→input_*、key→key_*)。
 *
 *  ⚠ 此 c.a 属 jdupgrade（升级 SDK），签的是【升级请求】。getHouses(彩虹网关) 是否复用 d.a 要实测：
 *    其 body 这里是 gzip+modBase64，而 getHouses 的 body 是 ciphertype:5 信封 —— 编码不同，
 *    很可能是【并行的另一个签名器】（共用 d.a 这个 HMAC 原语，可能用不同 appSecret）。命中即复用：
 *    SELECT s.id, s.out_hex, c.sign, c.function_id, c.t
 *      FROM sign s JOIN color c ON lower(s.out_hex)=lower(c.sign)
 *     WHERE s.kind='HMAC.a' ORDER BY s.id DESC;
 *  命中 ⇒ 该次 d.a 的 input_txt 即 getHouses 的 preimage（直接读，免逆 比较器 b），key_txt = 其密钥。
 * ======================================================================= */
var UPG_DONE = false;
function installUpgradeHmacHook() {
    if (!HOOK_UPGRADE_HMAC) { console.log('[hmac] HOOK_UPGRADE_HMAC=false，跳过 jdupgrade d.a'); return; }
    var Throwable = Java.use('java.lang.Throwable');
    var Log = Java.use('android.util.Log');
    function stk() { return safe(function () { return Log.getStackTraceString(Throwable.$new()); }, '(no stack)'); }
    function classNames(ov) { var ats = ov.argumentTypes || [], o = []; for (var i = 0; i < ats.length; i++) o.push(ats[i].className); return o; }
    function report(sig, args, ret) {
        // 源码确认 d.a(data, key)：data=preimage、key=固定 secret。arg 顺序可经 HMAC_DATA_ARG/HMAC_KEY_ARG 调。
        var data = args[HMAC_DATA_ARG], key = args[HMAC_KEY_ARG];
        var dHex = hexN(data), dTxt = txtN(data), kHex = hexN(key), kTxt = txtN(key);
        // 返回多为 64hex 字符串（HMAC 后转十六进制）；兜底 byte[]。统一把十六进制结果落 out_hex，便于 join color.sign。
        var outHex = null, outB64 = null, outShow;
        if (isBytes(ret)) { outHex = toHex(ret); outB64 = toB64(ret); outShow = 'hex=' + outHex + ' (' + ret.length + 'B)'; }
        else if (typeof ret === 'string' && /^[0-9a-fA-F]+$/.test(ret) && ret.length % 2 === 0) { outHex = ret.toLowerCase(); outShow = 'hex=' + outHex + ' (' + (ret.length / 2) + 'B)'; }
        else if (typeof ret === 'string') { outB64 = ret; outShow = 'str="' + ret + '"'; }
        else { outShow = 'str="' + ret + '"'; }
        var hit = null;
        for (var i = 0; i < TARGETS.length; i++) {
            var t = ('' + TARGETS[i]).toLowerCase();
            if ((outHex && outHex === t) || (outB64 && ('' + outB64).toLowerCase() === t)) { hit = TARGETS[i]; break; }
        }
        var s = stk();
        console.log('\n[HMAC d.a]  data[' + (isBytes(data) ? data.length : '?') + 'B]  key[' + (isBytes(key) ? key.length : '?') + 'B]');
        console.log('   data.txt="' + dTxt + '"');
        console.log('   key.txt ="' + kTxt + '"   (固定 secret，prod/test 二选一)');
        console.log('   sign     ' + outShow);
        if (hit) {
            console.log('\n===================== MATCH: d.a 输出 == TARGETS(wire sign) =====================');
            console.log(' ⇒ d.a 即此 sign。preimage = data.txt（上）；key = key.txt。target=' + hit);
            console.log(s);
            console.log('================================================================================\n');
        }
        emit({
            kind: 'HMAC.a', algorithm: 'HmacSHA256',
            input_hex: dHex, input_txt: dTxt,
            key_hex: kHex, key_txt: kTxt,
            out_hex: outHex, out_b64: outB64,
            matched: hit ? 1 : 0, target: hit, stack: s
        });
    }
    var tries = 0, MAX = 50;
    (function attempt() {
        if (UPG_DONE) return;
        var D = safe(function () { return Java.use(UPGRADE_HMAC_CLASS); }, null);
        if (!D) {
            if (++tries <= MAX) { setTimeout(function () { Java.perform(attempt); }, 700); return; }
            console.log('[hmac] 放弃：' + UPGRADE_HMAC_CLASS + ' 未加载（jdupgrade SDK 未初始化/换版本改名）。可触发一次「检查更新」或改 attach 再试。');
            return;
        }
        var m = D[UPGRADE_HMAC_METHOD];
        if (!m || !m.overloads) { console.log('[hmac] ' + UPGRADE_HMAC_CLASS + '.' + UPGRADE_HMAC_METHOD + ' 不存在/非方法。'); UPG_DONE = true; return; }
        var n = 0;
        m.overloads.forEach(function (ov) {
            var cn = classNames(ov);
            if (cn.length === 2 && cn[0] === '[B' && cn[1] === '[B') {
                ov.implementation = function () {
                    var ret = ov.apply(this, arguments);
                    try { report(cn.join(','), arguments, ret); } catch (e) { console.log('[hmac.err] ' + e); }
                    return ret;
                };
                n++;
                console.log('[hmac] hooked ' + UPGRADE_HMAC_CLASS + '.' + UPGRADE_HMAC_METHOD + '(byte[],byte[])');
            }
        });
        if (!n) {
            console.log('[hmac] 未找到 ' + UPGRADE_HMAC_METHOD + '(byte[],byte[]) 重载。现有 ' + UPGRADE_HMAC_METHOD + ' 重载签名：');
            m.overloads.forEach(function (ov) { console.log('   ' + UPGRADE_HMAC_METHOD + '(' + classNames(ov).join(', ') + ')'); });
            console.log('[hmac] 若签名不符：改 UPGRADE_HMAC_METHOD，或在此放宽过滤（如含 byte[] 的 2 参重载）。');
        } else {
            console.log('[hmac] 提示：d.a 内部 HmacSHA256 的 key 会被既有 [Mac.init]/[SecretKeySpec] 同时打出 → 哪个 arg == 该 key，另一个就是 preimage。');
        }
        UPG_DONE = true;
    })();
    console.log('[hmac] jdupgrade HMAC hook 安装中（盯 ' + UPGRADE_HMAC_CLASS + '.a(byte[],byte[])，落 sign 表 kind=HMAC.a）');
}

/* rpc：用 App 自带的 d.a(data, key) 现场算 HMAC —— 验证「换新 t 的新 preimage ⇒ 新 sign」（免对齐 gzip 字节）。
 * 仅 frida CLI REPL 用：frida -U -n <包名> -l frida_color_capture.js，然后（顺序 = d.a：先 data 后 key）：
 *   rpc.exports.dahmac('<新 t 的 preimage 文本>', '<32 字符 secret 文本>')   // 输出 == 新 t 的 wire sign 即公式正确
 * 入参约定：以 'hex:' 开头按十六进制，否则按 UTF-8 文本。 */
function toJavaBytes(s) {
    s = '' + s;
    if (s.indexOf('hex:') === 0) {
        var h = s.substring(4).replace(/[^0-9a-fA-F]/g, ''), arr = [];
        for (var i = 0; i + 1 < h.length; i += 2) { var v = parseInt(h.substr(i, 2), 16); arr.push(v > 127 ? v - 256 : v); }
        return Java.array('byte', arr);
    }
    return Java.use('java.lang.String').$new(s).getBytes('UTF-8');
}
rpc.exports = {
    dahmac: function (s0, s1) {
        var out = null;
        Java.perform(function () {
            try {
                var D = Java.use(UPGRADE_HMAC_CLASS);
                var r = D.a(toJavaBytes(s0), toJavaBytes(s1));
                out = isBytes(r) ? toHex(r) : ('' + r);
                console.log('[rpc] d.a(' + s0 + ', ' + s1 + ') -> ' + out);
            } catch (e) { console.log('[rpc] d.a 失败: ' + e); out = 'ERR:' + e; }
        });
        return out;
    }
};

/* =======================================================================
 *  Part 8 · 彩虹/smart-home 真签名器（实测：getHouses 走这里，jdupgrade d.a 只在「检查更新」时响）
 *   8a) Java 拦截器  com.jd.smart.networklib.interceptor.SignRequestInterceptor.c(String)
 *   8b) native       <JNI类>.NativeEncodeDataToServer(String,long,String×5,int) / _gm（国密变体）
 *  抓【入参 / 输出 / 调用栈】，落 sign 表（kind=SIGNI.c / NSIGN.*）。native 类名留空则自动发现。
 *  与 okhttp 同跑后对 wire sign（若输出是 body/ep 料则改对 c.body_cipher）：
 *    SELECT s.kind,s.out_hex,c.sign,c.t FROM sign s JOIN color c ON lower(s.out_hex)=lower(c.sign)
 *     WHERE s.kind LIKE 'NSIGN.%' OR s.kind LIKE 'SIGNI.%' ORDER BY s.id DESC;
 * ======================================================================= */
var SIGNI_DONE = false, NSIGN_DONE = false;
function installColorSignerHook() {
    if (!HOOK_COLOR_SIGNER) { console.log('[csign] HOOK_COLOR_SIGNER=false，跳过彩虹签名器'); return; }
    var Throwable = Java.use('java.lang.Throwable');
    var Log = Java.use('android.util.Log');
    function stk() { return safe(function () { return Log.getStackTraceString(Throwable.$new()); }, '(no stack)'); }
    function clip(s, n) { s = '' + s; return s.length > n ? s.substring(0, n) + '..(+' + (s.length - n) + 'B)' : s; }
    var seen = {};
    function once(k) { if (seen[k]) return false; seen[k] = 1; return true; }
    function isHexStr(s) { return typeof s === 'string' && s.length >= 32 && s.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(s); }

    /* 8a · Java 拦截器 c(String)：抓 入参(可能是 preimage/URL) 与 输出(可能是 sign) */
    function hookInterceptorOn(C) {
        var m = C[SIGN_INTERCEPTOR_METHOD];
        if (!m || !m.overloads) { console.log('[csign] ' + SIGN_INTERCEPTOR_CLASS + '.' + SIGN_INTERCEPTOR_METHOD + ' 无此方法（版本改名？）'); return; }
        m.overloads.forEach(function (ov) {
            ov.implementation = function () {
                var ret = ov.apply(this, arguments);
                try {
                    var inp = arguments.length ? ('' + arguments[0]) : '';
                    var out = (ret === null || ret === undefined) ? ('' + ret) : ('' + ret);
                    var s = stk();
                    console.log('\n[SIGNI ' + SIGN_INTERCEPTOR_METHOD + '] in ="' + clip(inp, 320) + '"');
                    console.log('          out="' + clip(out, 200) + '"');
                    if (once('signi')) console.log(s);
                    var outHex = isHexStr(out) ? out.toLowerCase() : null;
                    emit({ kind: 'SIGNI.' + SIGN_INTERCEPTOR_METHOD, algorithm: null, input_txt: inp, out_hex: outHex, out_b64: (outHex ? null : out), stack: s, matched: 1 });
                } catch (e) { console.log('[csign.err/intc] ' + e); }
                return ret;
            };
        });
        console.log('[csign] hooked ' + SIGN_INTERCEPTOR_CLASS + '.' + SIGN_INTERCEPTOR_METHOD + ' x' + m.overloads.length);
    }

    /* 8b · native NativeEncodeDataToServer / _gm：抓 8 个入参 + 输出 byte[] */
    function fmtArg(x) {
        if (x === null || x === undefined) return 'null';
        if (typeof x === 'string') return '"' + clip(x, 220) + '"';
        if (typeof x === 'number' || typeof x === 'boolean') return '' + x;
        if (isBytes(x)) return '[' + x.length + 'B]"' + toTxt(x) + '"';
        return safe(function () { return '' + x; }, '<obj>');
    }
    function hookNativeOn(C) {
        NATIVE_SIGN_METHODS.forEach(function (mn) {
            var m = C[mn];
            if (!m || !m.overloads) { console.log('[csign] (native) ' + NATIVE_SIGN_CLASS + '.' + mn + ' 不存在'); return; }
            m.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var ret = ov.apply(this, arguments);
                    try {
                        var args = [];
                        for (var i = 0; i < arguments.length; i++) args.push(fmtArg(arguments[i]));
                        var outHex = isBytes(ret) ? toHex(ret) : null, outB64 = isBytes(ret) ? toB64(ret) : null;
                        var s = stk();
                        console.log('\n[NSIGN ' + mn + '] args=( ' + args.join(' , ') + ' )');
                        console.log('   out[' + (isBytes(ret) ? ret.length : '?') + 'B] hex=' + outHex);
                        if (once('nsign:' + mn)) console.log(s);
                        emit({ kind: 'NSIGN.' + mn, algorithm: null, input_txt: args.join(' | '), out_hex: outHex, out_b64: outB64, stack: s, matched: 1 });
                    } catch (e) { console.log('[csign.err/native] ' + e); }
                    return ret;
                };
            });
            console.log('[csign] hooked native ' + NATIVE_SIGN_CLASS + '.' + mn + ' x' + m.overloads.length);
        });
    }
    function discoverNativeSync() {
        var name = NATIVE_SIGN_METHODS[0];
        var list = safe(function () { return Java.enumerateLoadedClassesSync(); }, []);
        for (var i = 0; i < list.length; i++) {
            var cn = list[i];
            if (cn.indexOf('com.jd') !== 0 && cn.indexOf('com.jingdong') !== 0) continue;
            if (!/[Ss]ign|[Jj]ni|[Nn]ative|[Ss]ecurit|networklib|[Ee]ncode/.test(cn)) continue;
            var C = safe(function () { return Java.use(cn); }, null);
            if (C && C[name] && C[name].overloads) return { C: C, cn: cn };
        }
        return null;
    }

    (function attemptInterceptor(tries) {
        if (SIGNI_DONE) return;
        var C = safe(function () { return Java.use(SIGN_INTERCEPTOR_CLASS); }, null);
        if (C) { hookInterceptorOn(C); SIGNI_DONE = true; return; }
        if (tries < 50) setTimeout(function () { Java.perform(function () { attemptInterceptor(tries + 1); }); }, 700);
        else console.log('[csign] 放弃拦截器：' + SIGN_INTERCEPTOR_CLASS + ' 未加载（换版本改名？用 auth-tracer 的栈重认）');
    })(0);

    (function attemptNative(tries) {
        if (NSIGN_DONE) return;
        var C = null, cn = NATIVE_SIGN_CLASS;
        if (cn) C = safe(function () { return Java.use(cn); }, null);
        else { var h = discoverNativeSync(); if (h) { C = h.C; cn = h.cn; NATIVE_SIGN_CLASS = cn; console.log('[csign] 自动发现 native 类: ' + cn); } }
        if (C) { hookNativeOn(C); NSIGN_DONE = true; return; }
        if (tries < 40) setTimeout(function () { Java.perform(function () { attemptNative(tries + 1); }); }, 1000);
        else console.log('[csign] 放弃 native：未发现声明 ' + NATIVE_SIGN_METHODS[0] + ' 的类；把全名填进 NATIVE_SIGN_CLASS 再跑。');
    })(0);

    console.log('[csign] 彩虹真签名器 hook 安装中（SIGNI.' + SIGN_INTERCEPTOR_METHOD + ' + NSIGN.NativeEncodeDataToServer[_gm]，落 sign 表）');
}

/* =======================================================================
 *  入口
 * ======================================================================= */
Java.perform(function () {
    try { installOkHttp(); } catch (e) { console.log('[!] okhttp hook 安装失败: ' + e); }
    try { installEnvelopeTracer(); } catch (e) { console.log('[!] envelope tracer 安装失败: ' + e); }
    try { installWjloginHook(); } catch (e) { console.log('[!] wjlogin hook 安装失败: ' + e); }
    function armRest() {
        Java.perform(function () {
            try { installSignHooks(); } catch (e) { console.log('[!] sign hook 安装失败: ' + e); }
            try { installUpgradeHmacHook(); } catch (e) { console.log('[!] jdupgrade HMAC(d.a) hook 安装失败: ' + e); }
            try { installColorSignerHook(); } catch (e) { console.log('[!] 彩虹真签名器 hook 安装失败: ' + e); }
            try { installEncryptHooks(); } catch (e) { console.log('[!] encrypt hook 安装失败: ' + e); }
            try { discoverEnc(); } catch (e) { console.log('[!] discoverEnc 失败: ' + e); }
        });
    }
    if (ARM_DELAY_MS > 0) { console.log('[*] sign/加密 hook 将在 ' + ARM_DELAY_MS + 'ms 后安装（错开启动窗口）'); setTimeout(armRest, ARM_DELAY_MS); }
    else armRest();
    console.log('\n[*] 彩虹网关抓包 + sign + 加密信封 + jdupgrade d.a + 真签名器(SignRequestInterceptor/native) 已启动。');
    console.log('[*] 触发一次 getHouses 后，SQL 对一下「签名器输出」与 wire sign：');
    console.log("    SELECT s.kind,s.out_hex,c.sign,c.t FROM sign s JOIN color c ON lower(s.out_hex)=lower(c.sign)");
    console.log("      WHERE s.kind='HMAC.a' OR s.kind LIKE 'NSIGN.%' OR s.kind LIKE 'SIGNI.%' ORDER BY s.id DESC;\n");
});
