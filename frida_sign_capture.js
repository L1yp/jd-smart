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

Java.perform(function () {
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
