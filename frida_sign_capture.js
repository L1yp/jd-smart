/*
 * frida_sign_capture.js
 * 目标：搞清楚 authorization 头里那段签名是怎么算出来的，并把每次 crypto 调用落库。
 *
 * 已知格式: <seg1>:::<seg2>:::<timestamp>
 *   seg1 = <40位hex>         (20 字节 → SHA-1 / HMAC-SHA1 的 hex)
 *   seg2 = <base64串>        (base64 解出 20 字节 → SHA-1 / HMAC-SHA1 的 base64)
 * 两段都是 20 字节 ⇒ 头号嫌疑是 HmacSHA1 / SHA-1。
 *
 * 策略：hook 所有“能产出摘要/签名”的常见 API（MessageDigest / Mac / Signature / Cipher /
 * Base64 / SecretKeySpec / IvParameterSpec），每次调用 console.log 打印，并 send 一条结构化记录。
 * 配合 host.py 时记录会写入 SQLite 的 sign 表；输出正好等于 TARGETS 时打 MATCH 横幅。
 *
 * 用法:
 *   python host.py -p <包名> -s frida_sign_capture.js     # 推荐：会落库（sign 表）
 *   frida -U -f <包名> -l frida_sign_capture.js           # 仅看 console（standalone 还会回显 send 原文）
 */
'use strict';

/* ===== 配置 ===== */
var TARGETS = [                                   // 盯着的目标值（会轮换；抓到新值替换这两行）
  // 按需填要高亮的目标值（seg1/seg2 等）；勿提交真实值。
];
var DUMP_STACK_ALWAYS = false; // true: 每次 doFinal/sign 都把调用栈打到 console（吵）
var STACK_IN_DB = false;       // true: 给每条入库记录都带上调用栈（DB 会变大；命中时无论如何都带）
var LOG_UPDATE = true;         // 是否打印 update() 的分段输入（不影响入库，原文始终会被累积）
var MAX_HEX = 4096;            // 输入 hex 预览上限（字节）
var MAX_TXT = 2048;            // 输入文本预览上限（字符）

/* ===== 纯 JS 字节工具（不调用被 hook 的 Base64，避免递归/污染） ===== */
var HEX = '0123456789abcdef';
function isBytes(x) { return x !== null && x !== undefined && x.length !== undefined && typeof x !== 'string'; }
function toHex(b) {
  if (!isBytes(b)) return 'null';
  var n = b.length, lim = Math.min(n, MAX_HEX), s = '';
  for (var i = 0; i < lim; i++) { var v = b[i] & 0xff; s += HEX.charAt(v >> 4) + HEX.charAt(v & 0xf); }
  if (n > lim) s += '..(+' + (n - lim) + 'B)';
  return s;
}
var B64C = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
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
function hexN(b) { return isBytes(b) ? toHex(b) : null; }   // 给入库用：空就是 SQL NULL，不是字符串 'null'
function txtN(b) { return isBytes(b) ? toTxt(b) : null; }
function safe(fn, dflt) { try { return fn(); } catch (e) { return dflt; } }

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

Java.perform(function () {
  try { installWjloginHook(); } catch (e) { console.log('[!] wjlogin hook 安装失败: ' + e); }
  var Throwable = Java.use('java.lang.Throwable');
  var Log = Java.use('android.util.Log');
  function stack() { return safe(function () { return Log.getStackTraceString(Throwable.$new()); }, '(no stack)'); }
  function tid() { return Process.getCurrentThreadId(); }

  function emit(rec) { try { send({ type: 'sign', data: rec }); } catch (e) {} }
  function matchOf(oh, ob) {
    for (var i = 0; i < TARGETS.length; i++) {
      var t = TARGETS[i];
      if ((oh && oh.toLowerCase() === t.toLowerCase()) || ob === t) return t;
    }
    return null;
  }

  /* 摘要/MAC/签名 类输出：打印 + 命中检查 + 入库 */
  function logOut(kind, algorithm, out, input) {
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
           out_hex: oh, out_b64: ob, matched: !!hit, target: hit, stack: hit ? stk : (STACK_IN_DB ? stk : null) });
  }

  /* Base64 编码结果（seg2 的最后一步）：打印 + 命中检查 + 入库 */
  function b64hit(kind, resultStr, input) {
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

  /* update() 输入累积：按线程归集（同线程上一个 Mac/MD/Sig 实例的调用是串行的） */
  var accMac = {}, accMd = {}, accSig = {};
  function accAppend(store, t, bytes) {
    if (!isBytes(bytes)) return;
    var a = store[t] || (store[t] = []);
    for (var i = 0; i < bytes.length; i++) a.push(bytes[i] & 0xff);
  }
  function accGet(store, t) { var a = store[t]; return (a && a.length) ? a : null; }
  function accClear(store, t) { delete store[t]; }
  function updBytes(a) { // 解析 update([B) 或 update([B,off,len)
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
        var ret = ov.apply(this, arguments); // 从 JS 调重载 = 调原实现，不递归
        try { cb(this, arguments, ret); } catch (e) { console.log('[hookerr] ' + cls + '.' + method + ': ' + e); }
        return ret;
      };
    });
    console.log('[hooked] ' + cls + '.' + method + ' x' + m.overloads.length);
  }
  function alg(self) { return safe(function () { return self.getAlgorithm(); }, '?'); }

  /* ---------------- MessageDigest（SHA-1/MD5/SHA-256...） ---------------- */
  hookAll('java.security.MessageDigest', 'getInstance', function (s, a) { console.log('[MessageDigest.getInstance] ' + a[0]); });
  hookAll('java.security.MessageDigest', 'reset', function () { accClear(accMd, tid()); });
  hookAll('java.security.MessageDigest', 'update', function (s, a) {
    var b = updBytes(a); if (!b) return;
    accAppend(accMd, tid(), b);
    if (LOG_UPDATE) console.log('[MD.update] alg=' + alg(s) + ' "' + toTxt(b) + '" hex=' + toHex(b));
  });
  hookAll('java.security.MessageDigest', 'digest', function (s, a, ret) {
    var t = tid();
    if (typeof ret === 'number') { accClear(accMd, t); console.log('[MD.digest->buf] alg=' + alg(s) + ' len=' + ret); return; }
    if (isBytes(a[0])) accAppend(accMd, t, a[0]);             // digest(data) 一次性
    var input = accGet(accMd, t); accClear(accMd, t);
    logOut('MD.digest', alg(s), ret, input);
  });

  /* ---------------- Mac（HmacSHA1/256...）—— 头号嫌疑 ---------------- */
  hookAll('javax.crypto.Mac', 'getInstance', function (s, a) { console.log('[Mac.getInstance] ' + a[0]); });
  hookAll('javax.crypto.Mac', 'init', function (s, a) {
    accClear(accMac, tid());
    var al = alg(s), enc = safe(function () { return a[0].getEncoded(); }, null);
    console.log('\n[Mac.init] alg=' + al + ' key.hex=' + toHex(enc) + ' key.txt="' + toTxt(enc) + '"');
    emit({ kind: 'Mac.init', algorithm: al, key_hex: hexN(enc), key_txt: txtN(enc) });
  });
  hookAll('javax.crypto.Mac', 'update', function (s, a) {
    var b = updBytes(a); if (!b) return;
    accAppend(accMac, tid(), b);
    if (LOG_UPDATE) console.log('[Mac.update] "' + toTxt(b) + '" hex=' + toHex(b));
  });
  hookAll('javax.crypto.Mac', 'doFinal', function (s, a, ret) {
    var t = tid();
    if (ret === undefined || ret === null) {                 // doFinal(output, offset)：结果写进 a[0]
      var inp = accGet(accMac, t); accClear(accMac, t);
      logOut('Mac.doFinal', alg(s), a[0], inp);
      return;
    }
    if (isBytes(a[0])) accAppend(accMac, t, a[0]);           // doFinal(data) 一次性
    var input = accGet(accMac, t); accClear(accMac, t);
    logOut('Mac.doFinal', alg(s), ret, input);
  });

  /* ---------------- Signature（RSA/ECDSA，输出一般 >20 字节，兜底） ---------------- */
  hookAll('java.security.Signature', 'getInstance', function (s, a) { console.log('[Signature.getInstance] ' + a[0]); });
  hookAll('java.security.Signature', 'update', function (s, a) {
    var b = updBytes(a); if (!b) return;
    accAppend(accSig, tid(), b);
    if (LOG_UPDATE) console.log('[Sig.update] "' + toTxt(b) + '" hex=' + toHex(b));
  });
  hookAll('java.security.Signature', 'sign', function (s, a, ret) {
    var t = tid(), input = accGet(accSig, t); accClear(accSig, t);
    if (typeof ret === 'number') { console.log('[Sig.sign->buf] alg=' + alg(s) + ' len=' + ret); return; }
    logOut('Sig.sign', alg(s), ret, input);
  });

  /* ---------------- Cipher（AES 等，万一“签名”其实是加密结果） ---------------- */
  hookAll('javax.crypto.Cipher', 'getInstance', function (s, a) { console.log('[Cipher.getInstance] ' + a[0]); });
  hookAll('javax.crypto.Cipher', 'init', function (s, a) {
    var al = alg(s);
    var enc = safe(function () { return a[1].getEncoded(); }, null);
    var iv = safe(function () { return a[2].getIV(); }, null);
    console.log('\n[Cipher.init] alg=' + al + ' opmode=' + a[0] +
      ' key.hex=' + toHex(enc) + ' key.txt="' + toTxt(enc) + '"' + (iv ? ' iv.hex=' + toHex(iv) : ''));
    emit({ kind: 'Cipher.init', algorithm: al, key_hex: hexN(enc), key_txt: txtN(enc), iv_hex: hexN(iv) });
  });
  hookAll('javax.crypto.Cipher', 'doFinal', function (s, a, ret) {
    if (typeof ret === 'number') { console.log('[Cipher.doFinal->buf] alg=' + alg(s) + ' len=' + ret); return; }
    logOut('Cipher.doFinal', alg(s), ret, isBytes(a[0]) ? a[0] : null);
  });

  /* ---------------- Base64 编码（seg2 的最后一步，直接对照命中） ---------------- */
  hookAll('android.util.Base64', 'encodeToString', function (s, a, ret) { b64hit('android.Base64.encodeToString', ret, a[0]); });
  hookAll('android.util.Base64', 'encode', function (s, a, ret) { b64hit('android.Base64.encode', toAscii(ret), a[0]); });
  hookAll('java.util.Base64$Encoder', 'encodeToString', function (s, a, ret) { b64hit('java.Base64.encodeToString', ret, a[0]); });
  hookAll('java.util.Base64$Encoder', 'encode', function (s, a, ret) { b64hit('java.Base64.encode', toAscii(ret), a[0]); });

  /* ---------------- 密钥 / IV 来源 ---------------- */
  (function () {
    var SKS = safe(function () { return Java.use('javax.crypto.spec.SecretKeySpec'); }, null);
    if (SKS) SKS.$init.overloads.forEach(function (ov) {
      ov.implementation = function () {
        var r = ov.apply(this, arguments);
        try {
          var kb = arguments[0], a = '' + arguments[arguments.length - 1];
          if (isBytes(kb)) {
            console.log('[SecretKeySpec] alg=' + a + ' key.hex=' + toHex(kb) + ' key.txt="' + toTxt(kb) + '"');
            emit({ kind: 'SecretKeySpec', algorithm: a, key_hex: toHex(kb), key_txt: toTxt(kb) });
          }
        } catch (e) {}
        return r;
      };
    });
    var IPS = safe(function () { return Java.use('javax.crypto.spec.IvParameterSpec'); }, null);
    if (IPS) IPS.$init.overloads.forEach(function (ov) {
      ov.implementation = function () {
        var r = ov.apply(this, arguments);
        try {
          if (isBytes(arguments[0])) {
            console.log('[IvParameterSpec] iv.hex=' + toHex(arguments[0]));
            emit({ kind: 'IvParameterSpec', iv_hex: toHex(arguments[0]) });
          }
        } catch (e) {}
        return r;
      };
    });
  })();

  console.log('\n[*] sign-capture 已就位（结果会 send 到 host.py 落入 sign 表）。');
  console.log('[*] TARGETS = ' + JSON.stringify(TARGETS));
  console.log('[*] 触发请求后看 console 的 MATCH 横幅，或 SQL 查 sign 表。\n');
});
