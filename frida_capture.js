'use strict';

/*
 * frida_capture.js —— 合并版：一个脚本同时抓两类数据，配合 host.py 落到同一个 SQLite。
 *   1) OkHttp 请求/响应      → send {type:'http'} → host.py 写 http 表
 *   2) 签名/摘要 crypto 调用  → send {type:'sign'} → host.py 写 sign 表
 *
 * 用法:
 *   python host.py -p <包名> -s frida_capture.js --spawn
 *
 * 性能/稳定性（重要）：加密 hook 会被“算法名 + 调用方包名”双重收窄，避免拖垮启动期的 TLS。
 *   - 只 hook SIGN_ALGS 里的算法（默认 SHA-1 系列，因为目标值是 20 字节）
 *   - 默认不 hook Cipher/Signature（AES 在 TLS 里极热，hook 它最容易把 App 搞崩）
 *   - 调用栈过滤（calledFromApp）只在算法命中后才做，不在热路径上抓栈
 *   若加了加密 hook 就闪退，先试把 ARM_DELAY_MS 设成几千毫秒（错开启动检测/加载窗口）。
 */

/* =======================================================================
 *  Part 1 · OkHttp 抓包
 * ======================================================================= */
var CONFIG = {
    chainClass:   'okhttp3.internal.http.RealInterceptorChain',
    requestClass: 'okhttp3.Request',
    bufferClass:  'okio.Buffer'
};
var MAX_BODY = 512 * 1024;

function headersToObj(headers) {
    var out = {};
    try {
        var n = headers.size();
        for (var i = 0; i < n; i++) out[headers.name(i)] = headers.value(i);
    } catch (e) {}
    return out;
}

function readRequestBody(request, BufferCls) {
    try {
        var body = request.body();
        if (body === null) return null;
        try { if (body.isOneShot && body.isOneShot()) return '<<one-shot body, skipped>>'; } catch (e) {}
        var len = -1;
        try { len = body.contentLength(); } catch (e) {}
        if (len > MAX_BODY) return '<<req body too large: ' + len + '>>';
        if (!BufferCls) return '<<okio.Buffer not resolved>>';
        var buffer = BufferCls.$new();
        body.writeTo(buffer);
        var s = buffer.readUtf8();
        buffer.clear();
        return s;
    } catch (e) {
        return '<<req body unreadable: ' + e + '>>';
    }
}

function readResponseBody(response) {
    try {
        var peeked = response.peekBody(MAX_BODY);
        return peeked.string();
    } catch (e) {
        return '<<resp body unreadable: ' + e + '>>';
    }
}

function discover() {
    console.log('[discover] enumerating okhttp3/okio classes...');
    Java.enumerateLoadedClasses({
        onMatch: function (name) {
            if (name.indexOf('okhttp') !== -1 || name.indexOf('okio') !== -1) console.log('  ' + name);
        },
        onComplete: function () {
            console.log('[discover] done. 若上面为空说明 okhttp 被完全混淆，');
            console.log('           找一个有 newCall / proceed 方法的类名手动填进 CONFIG。');
        }
    });
}

function installOkHttp() {
    var Chain, Buffer = null;
    try {
        Chain = Java.use(CONFIG.chainClass);
        Java.use(CONFIG.requestClass);
    } catch (e) {
        console.log('[!] 找不到 ' + CONFIG.chainClass + ' / ' + CONFIG.requestClass + ' : ' + e);
        discover();
        return;
    }
    try { Buffer = Java.use(CONFIG.bufferClass); } catch (e) {
        console.log('[!] okio.Buffer 未解析，请求 body 将读不到（响应和头不受影响）');
    }

    var BufferRef = Buffer;
    var hooked = false;
    try {
        Chain.proceed.overload(CONFIG.requestClass).implementation = function (request) {
            var response = this.proceed(request);
            try {
                send({ type: 'http', data: {
                    ts: Date.now(),
                    method: request.method(),
                    url: request.url().toString(),
                    req_headers: headersToObj(request.headers()),
                    req_body: readRequestBody(request, BufferRef),
                    code: response.code(),
                    resp_headers: headersToObj(response.headers()),
                    resp_body: readResponseBody(response)
                } });
            } catch (e) {
                send({ type: 'error', data: '' + e });
            }
            return response;
        };
        hooked = true;
    } catch (e) {
        console.log('[!] hook proceed(Request) 失败，可能 Request 参数类型被混淆: ' + e);
        discover();
    }

    if (hooked) {
        console.log('[+] OkHttp hook 已安装。proceed 每过一个拦截器触发一次，');
        console.log('    带 authorization/tgt 的那行是加完鉴权头之后的。');
    }
}

/* =======================================================================
 *  Part 2 · 签名/摘要抓取（已收窄，避免拖垮启动）
 * ======================================================================= */
var TARGETS = [  // 想高亮命中的目标值（如 auth 的 seg1/seg2），按需填；留空只抓不高亮。勿提交真实值。
];

/* ---- 收窄开关：这几个直接决定开销/稳定性 ---- */
var SIGN_ALGS = ['hmacsha1', 'sha1', 'sha-1']; // 只 hook 这些算法（小写子串匹配）。目标 20 字节=SHA-1 系列。
                                               // 抓不到就加：'hmacsha256','sha-256'；设 [] = 不按算法过滤（开销大）。
var HOOK_CIPHER = false;       // 默认 false：AES 在 TLS 里极热，hook 它最容易闪退。确认要看加密再开。
var HOOK_SIGNATURE = false;    // 默认 false：RSA/ECDSA 输出 >20 字节，基本不是你的目标。
var HOOK_BASE64 = true;        // hook Base64 编码（seg2 的最后一步）
var B64_MAX_INPUT = 64;        // 只关心“小输入”的 base64（签名/摘要 ≤64B），跳过图片/JSON 大块
var ARM_DELAY_MS = 0;          // >0：延迟这么多毫秒再装签名 hook（错开启动检测/首页加载窗口）

var APP_PKGS = ['com.jd.smart']; // App 代码命名空间是 com.jd.smart（不是启动包名 com.jd.iots）！签名在 com.jd.smart.base.net.http.RestClient。抓不全再加 'com.jd.'。
var CALLER_SCAN = 6;            // 向下扫描多少个“非加密库”发起帧来判定归属
var DUMP_STACK_ALWAYS = false;  // true: 每次 doFinal/sign 都把调用栈打到 console
var STACK_IN_DB = false;        // true: 每条入库记录都带调用栈（命中时无论如何都带）
var LOG_UPDATE = true;          // 是否打印 update() 分段输入（不影响入库，原文始终累积）
var MAX_HEX = 4096, MAX_TXT = 2048;
// 追踪这些固定值（KEY / seg1）的来历：抓到谁读/写它们就打印调用栈。放空 [] = 关闭。
var WATCH_SECRETS = []; // 想追踪来历的固定值（key/seg1 等），按需填；留空=关闭。勿提交真实值。

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
        var b0 = b[i] & 0xff;
        var b1 = (i + 1 < n) ? (b[i + 1] & 0xff) : 0;
        var b2 = (i + 2 < n) ? (b[i + 2] & 0xff) : 0;
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
        else if (c === 0x0a) s += '\\n';
        else if (c === 0x0d) s += '\\r';
        else if (c === 0x09) s += '\\t';
        else s += '.';
    }
    if (b.length > n) s += '..';
    return s;
}
function toAscii(b) { if (!isBytes(b)) return 'null'; var s = ''; for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i] & 0xff); return s; }
function hexN(b) { return isBytes(b) ? toHex(b) : null; }
function txtN(b) { return isBytes(b) ? toTxt(b) : null; }
function safe(fn, dflt) { try { return fn(); } catch (e) { return dflt; } }
// 便宜的算法过滤：先用它挡掉 TLS 的 SHA-256/AES 等，再谈抓栈。
function algAllowed(name) {
    if (!SIGN_ALGS.length) return true;
    if (!name) return false;
    var n = ('' + name).toLowerCase();
    for (var i = 0; i < SIGN_ALGS.length; i++) if (n.indexOf(SIGN_ALGS[i]) !== -1) return true;
    return false;
}

function installSignHooks() {
    var Throwable = Java.use('java.lang.Throwable');
    var Log = Java.use('android.util.Log');
    function stack() { return safe(function () { return Log.getStackTraceString(Throwable.$new()); }, '(no stack)'); }
    function tid() { return Process.getCurrentThreadId(); }
    // 仅在“算法已命中”后才调用——扫描栈顶若干真正发起方帧，判断是不是 APP_PKGS 自己发起的。
    function calledFromApp() {
        if (!APP_PKGS.length) return true;
        var frames = safe(function () { return Throwable.$new().getStackTrace(); }, null);
        if (!frames) return true;
        var seen = 0;
        for (var i = 0; i < frames.length && seen < CALLER_SCAN; i++) {
            var cn = '';
            try { cn = '' + frames[i].getClassName(); } catch (e) { continue; }
            if (cn.indexOf('java.security.') === 0 || cn.indexOf('javax.crypto.') === 0 ||
                cn.indexOf('java.lang.') === 0 || cn.indexOf('com.android.org.conscrypt') === 0 ||
                cn.indexOf('org.conscrypt') === 0 || cn.indexOf('sun.security') === 0 ||
                cn.indexOf('dalvik.') === 0) continue;
            seen++;
            for (var j = 0; j < APP_PKGS.length; j++) if (cn.indexOf(APP_PKGS[j]) === 0) return true;
        }
        return false;
    }

    function emit(rec) { try { send({ type: 'sign', data: rec }); } catch (e) {} }
    function matchOf(oh, ob) {
        for (var i = 0; i < TARGETS.length; i++) {
            var t = TARGETS[i];
            if ((oh && oh.toLowerCase() === t.toLowerCase()) || ob === t) return t;
        }
        return null;
    }

    function logOut(kind, algorithm, out, input) {
        if (!calledFromApp()) return;          // 抓栈过滤放在算法过滤之后，热路径不抓栈
        var oh = toHex(out), ob = toB64(out), ih = hexN(input), it = txtN(input);
        console.log('[' + kind + ' alg=' + algorithm + '] out.hex=' + oh + ' out.b64=' + ob);
        if (it !== null) console.log('    input "' + it + '" hex=' + ih);
        var hit = matchOf(oh, ob);
        var stk = (hit || STACK_IN_DB || DUMP_STACK_ALWAYS) ? stack() : null;
        if (hit) {
            console.log('\n========================= MATCH =========================');
            console.log(' where  : ' + kind + ' alg=' + algorithm);
            console.log(' target : ' + hit);
            console.log(' out.hex: ' + oh + '\n out.b64: ' + ob);
            if (it !== null) console.log(' INPUT  : "' + it + '"\n          hex=' + ih);
            console.log(stk);
            console.log('=========================================================\n');
        } else if (DUMP_STACK_ALWAYS) { console.log(stk); }
        emit({ kind: kind, algorithm: algorithm, input_hex: ih, input_txt: it,
               out_hex: oh, out_b64: ob, matched: !!hit, target: hit, stack: (hit || STACK_IN_DB) ? stk : null });
    }

    function b64hit(kind, resultStr, input) {
        if (!calledFromApp()) return;
        var ih = hexN(input), it = txtN(input);
        console.log('[' + kind + '] "' + resultStr + '" <= hex=' + ih);
        var hit = (TARGETS.indexOf(resultStr) >= 0) ? resultStr : null;
        var stk = (hit || STACK_IN_DB) ? stack() : null;
        if (hit) {
            console.log('\n===== BASE64 MATCH @ ' + kind + ' =====');
            console.log(' seg2 = base64( 上面这 ' + (isBytes(input) ? input.length : '?') + ' 字节 )');
            console.log(' result : ' + resultStr + '\n raw.hex: ' + ih + '\n raw.txt: "' + it + '"');
            console.log(stk);
            console.log('=========================================\n');
        }
        emit({ kind: kind, algorithm: null, input_hex: ih, input_txt: it,
               out_hex: null, out_b64: resultStr, matched: !!hit, target: hit, stack: stk });
    }

    /* update() 输入累积：按线程归集 */
    var accMac = {}, accMd = {}, accSig = {};
    function accAppend(store, t, bytes) {
        if (!isBytes(bytes)) return;
        var a = store[t] || (store[t] = []);
        for (var i = 0; i < bytes.length; i++) a.push(bytes[i] & 0xff);
    }
    function accGet(store, t) { var a = store[t]; return (a && a.length) ? a : null; }
    function accClear(store, t) { delete store[t]; }
    function updBytes(a) {
        if (!isBytes(a[0])) return null;
        if (a.length >= 3 && typeof a[1] === 'number' && typeof a[2] === 'number') {
            var off = a[1], len = a[2], out = [];
            for (var i = 0; i < len; i++) out.push(a[0][off + i] & 0xff);
            return out;
        }
        return a[0];
    }

    function hookAll(cls, method, cb) {
        var clazz = safe(function () { return Java.use(cls); }, null);
        if (!clazz) { console.log('[skip] ' + cls + ' (类不存在)'); return; }
        var m = clazz[method];
        if (!m || !m.overloads) { console.log('[skip] ' + cls + '.' + method + ' (方法不存在)'); return; }
        m.overloads.forEach(function (ov) {
            ov.implementation = function () {
                var ret = ov.apply(this, arguments); // 先调原实现
                try { cb(this, arguments, ret); } catch (e) { console.log('[hookerr] ' + cls + '.' + method + ': ' + e); }
                return ret;
            };
        });
        console.log('[hooked] ' + cls + '.' + method + ' x' + m.overloads.length);
    }
    function alg(self) { return safe(function () { return self.getAlgorithm(); }, '?'); }

    /* ---- MessageDigest（仅 SIGN_ALGS 命中的算法） ---- */
    hookAll('java.security.MessageDigest', 'getInstance', function (s, a) { if (algAllowed(a[0])) console.log('[MessageDigest.getInstance] ' + a[0]); });
    hookAll('java.security.MessageDigest', 'reset', function () { accClear(accMd, tid()); });
    hookAll('java.security.MessageDigest', 'update', function (s, a) {
        if (!algAllowed(alg(s))) return;
        var b = updBytes(a); if (!b) return;
        accAppend(accMd, tid(), b);
        if (LOG_UPDATE && calledFromApp()) console.log('[MD.update] alg=' + alg(s) + ' "' + toTxt(b) + '" hex=' + toHex(b));
    });
    hookAll('java.security.MessageDigest', 'digest', function (s, a, ret) {
        var al = alg(s); if (!algAllowed(al)) return;
        var t = tid();
        if (typeof ret === 'number') { accClear(accMd, t); if (calledFromApp()) console.log('[MD.digest->buf] alg=' + al + ' len=' + ret); return; }
        if (isBytes(a[0])) accAppend(accMd, t, a[0]);
        var input = accGet(accMd, t); accClear(accMd, t);
        logOut('MD.digest', al, ret, input);
    });

    /* ---- Mac（HmacSHA1...）—— 头号嫌疑 ---- */
    hookAll('javax.crypto.Mac', 'getInstance', function (s, a) { if (algAllowed(a[0])) console.log('[Mac.getInstance] ' + a[0]); });
    hookAll('javax.crypto.Mac', 'init', function (s, a) {
        var al = alg(s); if (!algAllowed(al)) return;
        accClear(accMac, tid());
        var enc = safe(function () { return a[0].getEncoded(); }, null);
        if (calledFromApp()) {
            console.log('\n[Mac.init] alg=' + al + ' key.hex=' + toHex(enc) + ' key.txt="' + toTxt(enc) + '"');
            emit({ kind: 'Mac.init', algorithm: al, key_hex: hexN(enc), key_txt: txtN(enc) });
        }
    });
    hookAll('javax.crypto.Mac', 'update', function (s, a) {
        if (!algAllowed(alg(s))) return;
        var b = updBytes(a); if (!b) return;
        accAppend(accMac, tid(), b);
        if (LOG_UPDATE && calledFromApp()) console.log('[Mac.update] "' + toTxt(b) + '" hex=' + toHex(b));
    });
    hookAll('javax.crypto.Mac', 'doFinal', function (s, a, ret) {
        var al = alg(s); if (!algAllowed(al)) return;
        var t = tid();
        if (ret === undefined || ret === null) { var inp = accGet(accMac, t); accClear(accMac, t); logOut('Mac.doFinal', al, a[0], inp); return; }
        if (isBytes(a[0])) accAppend(accMac, t, a[0]);
        var input = accGet(accMac, t); accClear(accMac, t);
        logOut('Mac.doFinal', al, ret, input);
    });

    /* ---- Signature（默认关；输出 >20 字节，basically 不是目标） ---- */
    if (HOOK_SIGNATURE) {
        hookAll('java.security.Signature', 'getInstance', function (s, a) { console.log('[Signature.getInstance] ' + a[0]); });
        hookAll('java.security.Signature', 'update', function (s, a) {
            var b = updBytes(a); if (!b) return;
            accAppend(accSig, tid(), b);
            if (LOG_UPDATE && calledFromApp()) console.log('[Sig.update] "' + toTxt(b) + '" hex=' + toHex(b));
        });
        hookAll('java.security.Signature', 'sign', function (s, a, ret) {
            var t = tid(), input = accGet(accSig, t); accClear(accSig, t);
            if (typeof ret === 'number') { console.log('[Sig.sign->buf] alg=' + alg(s) + ' len=' + ret); return; }
            logOut('Sig.sign', alg(s), ret, input);
        });
    }

    /* ---- Cipher（默认关：AES 在 TLS 里极热，hook 它最易闪退） ---- */
    if (HOOK_CIPHER) {
        hookAll('javax.crypto.Cipher', 'getInstance', function (s, a) { console.log('[Cipher.getInstance] ' + a[0]); });
        hookAll('javax.crypto.Cipher', 'init', function (s, a) {
            var al = alg(s);
            var enc = safe(function () { return a[1].getEncoded(); }, null);
            var iv = safe(function () { return a[2].getIV(); }, null);
            if (calledFromApp()) {
                console.log('\n[Cipher.init] alg=' + al + ' opmode=' + a[0] +
                    ' key.hex=' + toHex(enc) + ' key.txt="' + toTxt(enc) + '"' + (iv ? ' iv.hex=' + toHex(iv) : ''));
                emit({ kind: 'Cipher.init', algorithm: al, key_hex: hexN(enc), key_txt: txtN(enc), iv_hex: hexN(iv) });
            }
        });
        hookAll('javax.crypto.Cipher', 'doFinal', function (s, a, ret) {
            if (typeof ret === 'number') { console.log('[Cipher.doFinal->buf] alg=' + alg(s) + ' len=' + ret); return; }
            logOut('Cipher.doFinal', alg(s), ret, isBytes(a[0]) ? a[0] : null);
        });
    }

    /* ---- Base64 编码（seg2 最后一步，只看小输入） ---- */
    if (HOOK_BASE64) {
        hookAll('android.util.Base64', 'encodeToString', function (s, a, ret) {
            if (isBytes(a[0]) && a[0].length > B64_MAX_INPUT) return;
            b64hit('android.Base64.encodeToString', ret, a[0]);
        });
        hookAll('android.util.Base64', 'encode', function (s, a, ret) {
            if (isBytes(a[0]) && a[0].length > B64_MAX_INPUT) return;
            b64hit('android.Base64.encode', toAscii(ret), a[0]);
        });
        hookAll('java.util.Base64$Encoder', 'encodeToString', function (s, a, ret) {
            if (isBytes(a[0]) && a[0].length > B64_MAX_INPUT) return;
            b64hit('java.Base64.encodeToString', ret, a[0]);
        });
        hookAll('java.util.Base64$Encoder', 'encode', function (s, a, ret) {
            if (isBytes(a[0]) && a[0].length > B64_MAX_INPUT) return;
            b64hit('java.Base64.encode', toAscii(ret), a[0]);
        });
    }

    /* ---- 密钥 / IV 来源 ---- */
    var SKS = safe(function () { return Java.use('javax.crypto.spec.SecretKeySpec'); }, null);
    if (SKS) SKS.$init.overloads.forEach(function (ov) {
        ov.implementation = function () {
            var r = ov.apply(this, arguments);
            try {
                var kb = arguments[0], a = '' + arguments[arguments.length - 1];
                if (isBytes(kb) && algAllowed(a) && calledFromApp()) {
                    console.log('[SecretKeySpec] alg=' + a + ' key.hex=' + toHex(kb) + ' key.txt="' + toTxt(kb) + '"');
                    emit({ kind: 'SecretKeySpec', algorithm: a, key_hex: toHex(kb), key_txt: toTxt(kb) });
                }
            } catch (e) {}
            return r;
        };
    });
    if (HOOK_CIPHER) {
        var IPS = safe(function () { return Java.use('javax.crypto.spec.IvParameterSpec'); }, null);
        if (IPS) IPS.$init.overloads.forEach(function (ov) {
            ov.implementation = function () {
                var r = ov.apply(this, arguments);
                try {
                    if (isBytes(arguments[0]) && calledFromApp()) {
                        console.log('[IvParameterSpec] iv.hex=' + toHex(arguments[0]));
                        emit({ kind: 'IvParameterSpec', iv_hex: toHex(arguments[0]) });
                    }
                } catch (e) {}
                return r;
            };
        });
    }

    console.log('[*] sign hook 已就位（落 sign 表）。algs=' + JSON.stringify(SIGN_ALGS) +
        ' cipher=' + HOOK_CIPHER + ' sig=' + HOOK_SIGNATURE + ' pkgs=' + JSON.stringify(APP_PKGS));
}

/* =======================================================================
 *  Part 3 · 鉴权头拼装点追踪
 *  在 authorization 头被塞进 okhttp 的那一刻打印调用栈：
 *    - 栈里紧贴 okhttp 之前的 App 帧 = 拼签名的地方（顺着它就能找到算法/原文）；
 *    - 若该帧标着 (Native Method) = 签名在 native，那才需要转 native hook。
 *  这一步与 crypto 算法过滤完全无关，是判 Java/native 最直接的证据。
 * ======================================================================= */
function installAuthTracer() {
    var Throwable = Java.use('java.lang.Throwable');
    var Log = Java.use('android.util.Log');
    function stk() { return safe(function () { return Log.getStackTraceString(Throwable.$new()); }, '(no stack)'); }
    function isAuth(name, value) {
        if (('' + name).toLowerCase() === 'authorization') return true;
        return ('' + value).indexOf(':::') !== -1; // 兜底：值里带 ::: 的也算
    }
    function trace(where, name, value) {
        var s = stk();
        console.log('\n========== AUTH HEADER SET @ ' + where + ' ==========');
        console.log(' ' + name + ' = ' + value);
        console.log(s);
        console.log(' ↑ 栈里紧贴 okhttp 之前的 App 帧 = 拼签名处；若有 (Native Method) 则签名在 native。');
        console.log('====================================================\n');
        try { send({ type: 'sign', data: { kind: 'AUTH-HEADER@' + where, input_txt: '' + name, out_b64: '' + value, stack: s, matched: 0 } }); } catch (e) {}
    }
    var targets = [['okhttp3.Request$Builder', ['header', 'addHeader']],
                   ['okhttp3.Headers$Builder', ['add', 'set', 'addLenient', 'addUnsafeNonAscii']]];
    targets.forEach(function (pair) {
        var cls = safe(function () { return Java.use(pair[0]); }, null);
        if (!cls) { console.log('[auth] 跳过 ' + pair[0] + '（未解析，可能被混淆）'); return; }
        pair[1].forEach(function (mname) {
            var m = cls[mname];
            if (!m || !m.overloads) return;
            m.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    try {
                        if (arguments.length >= 2 && isAuth(arguments[0], arguments[1]))
                            trace(pair[0].substring(pair[0].indexOf('.') + 1) + '.' + mname, arguments[0], arguments[1]);
                    } catch (e) {}
                    return ov.apply(this, arguments);
                };
            });
            console.log('[auth] hooked ' + pair[0] + '.' + mname + ' x' + m.overloads.length);
        });
    });
}

/* =======================================================================
 *  Part 4 · 固定密钥/标识来历追踪（找 KEY、seg1 从哪来）
 *  抓到谁把 WATCH_SECRETS 里的值写进/读出 SharedPreferences，并打印调用栈。
 *  - SP.putString 命中 = 谁存的（多半紧跟登录响应解析，顺栈即到下发它的接口）
 *  - SP.getString 命中 = 谁用的（每次签名前 RestClient 读它，能看到 prefs 键名）
 * ======================================================================= */
function installSecretFinder() {
    if (!WATCH_SECRETS.length) return;
    var Throwable = Java.use('java.lang.Throwable');
    var Log = Java.use('android.util.Log');
    function stk() { return safe(function () { return Log.getStackTraceString(Throwable.$new()); }, '(no stack)'); }
    function hitOf(v) {
        if (v === null || v === undefined) return null;
        var s = '' + v;
        for (var i = 0; i < WATCH_SECRETS.length; i++) if (s.indexOf(WATCH_SECRETS[i]) !== -1) return WATCH_SECRETS[i];
        return null;
    }
    function report(where, name, value) {
        var s = stk();
        console.log('\n##### SECRET 命中 @ ' + where + '  name=' + name + ' #####');
        console.log(' value = ' + value);
        console.log(s);
        console.log('################################################\n');
        try { send({ type: 'sign', data: { kind: 'SECRET@' + where, input_txt: '' + name, out_b64: '' + value, stack: s, matched: 1 } }); } catch (e) {}
    }
    var Ed = safe(function () { return Java.use('android.app.SharedPreferencesImpl$EditorImpl'); }, null);
    if (Ed && Ed.putString) Ed.putString.overloads.forEach(function (ov) {
        ov.implementation = function (k, v) { try { if (hitOf(v)) report('SP.putString', k, v); } catch (e) {} return ov.apply(this, arguments); };
    });
    var Sp = safe(function () { return Java.use('android.app.SharedPreferencesImpl'); }, null);
    if (Sp && Sp.getString) Sp.getString.overloads.forEach(function (ov) {
        ov.implementation = function () { var r = ov.apply(this, arguments); try { if (hitOf(r)) report('SP.getString', arguments[0], r); } catch (e) {} return r; };
    });
    console.log('[*] secret-finder 已就位，盯：' + JSON.stringify(WATCH_SECRETS));
}

/* =======================================================================
 *  入口
 * ======================================================================= */
Java.perform(function () {
    try { installOkHttp(); } catch (e) { console.log('[!] okhttp hook 安装失败: ' + e); }
    try { installAuthTracer(); } catch (e) { console.log('[!] auth-tracer 安装失败: ' + e); }
    try { installSecretFinder(); } catch (e) { console.log('[!] secret-finder 安装失败: ' + e); }
    if (ARM_DELAY_MS > 0) {
        console.log('[*] 签名 hook 将在 ' + ARM_DELAY_MS + 'ms 后安装（错开启动窗口）');
        setTimeout(function () { Java.perform(function () { try { installSignHooks(); } catch (e) { console.log('[!] sign hook 安装失败: ' + e); } }); }, ARM_DELAY_MS);
    } else {
        try { installSignHooks(); } catch (e) { console.log('[!] sign hook 安装失败: ' + e); }
    }
    console.log('\n[*] 抓包+签名+auth追踪 已启动。\n');
});
