'use strict';

/*
 * Hook OkHttp 的拦截器链，抓取每条请求/响应，send() 给 Python 主机落库。
 * 在 TLS 之前、进程内读对象，所以不受 SSL pinning 影响。
 *
 * 如果 App 对 okhttp 做了混淆，下面默认类名会找不到 —— 脚本会自动跑一次
 * 类枚举（discovery），把疑似的 okhttp3/okio 类名打到控制台，你照着改 CONFIG。
 */

var CONFIG = {
    chainClass:   'okhttp3.internal.http.RealInterceptorChain',
    requestClass: 'okhttp3.Request',
    bufferClass:  'okio.Buffer'
};

var MAX_BODY = 512 * 1024; // body 读取上限，避免 send 过大

function headersToObj(headers) {
    var out = {};
    try {
        var n = headers.size();
        for (var i = 0; i < n; i++) {
            out[headers.name(i)] = headers.value(i);
        }
    } catch (e) {}
    return out;
}

function readRequestBody(request, BufferCls) {
    try {
        var body = request.body();
        if (body === null) return null;
        // 跳过一次性/流式 body，读了会把真正要发出去的内容消费掉
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
        // peekBody 返回副本，不消费原始流，真正的响应不受影响
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
            if (name.indexOf('okhttp') !== -1 || name.indexOf('okio') !== -1) {
                console.log('  ' + name);
            }
        },
        onComplete: function () {
            console.log('[discover] done. 如果上面是空的，说明 okhttp 被完全混淆，');
            console.log('           找一个有 newCall / proceed 方法的类名手动填进 CONFIG。');
        }
    });
}

function installHook() {
    var Chain, Request, Buffer = null;
    try {
        Chain = Java.use(CONFIG.chainClass);
        Request = Java.use(CONFIG.requestClass); // 仅用于确认存在
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
            var response = this.proceed(request); // 调原始方法
            try {
                var entry = {
                    ts: Date.now(),
                    method: request.method(),
                    url: request.url().toString(),
                    req_headers: headersToObj(request.headers()),
                    req_body: readRequestBody(request, BufferRef),
                    code: response.code(),
                    resp_headers: headersToObj(response.headers()),
                    resp_body: readResponseBody(response)
                };
                send({ type: 'http', data: entry });
            } catch (e) {
                send({ type: 'error', data: '' + e });
            }
            return response; // 必须把原始响应还回去
        };
        hooked = true;
    } catch (e) {
        console.log('[!] hook proceed(Request) 失败，可能 Request 参数类型被混淆: ' + e);
        discover();
    }

    if (hooked) {
        console.log('[+] OkHttp hook 已安装。注意：proceed 每经过一个拦截器都会触发一次，');
        console.log('    所以同一请求会有多行 —— 带 authorization/tgt 的那一行就是加完鉴权头之后的。');
    }
}

/* wjlogin 登录态(WUserSigInfo)读写追踪 —— 所有 frida_*.js 内置（见 REVERSE_ENGINEERING.md §5.6）
 * createUserInfoFromJSON(读/初始化) + toJSONObject(写/落盘)，两者 dump 调用栈看更新机制。落 sign 表(kind=WUserSig.*)。 */
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

Java.perform(function () { installHook(); try { installWjloginHook(); } catch (e) { console.log('[!] wjlogin hook 安装失败: ' + e); } });
