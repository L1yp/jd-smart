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

Java.perform(installHook);
