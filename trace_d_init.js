'use strict';
// 一次性调试片段：hook OkHttpRequest(vc.d) 构造，dump 各参数(含 headers map2) + 调用栈。
// vc.d 是【当前 App 版本】的混淆类名，换版本可能变；变了用 auth-tracer 的栈重新认。
// 跑法：python host.py -p <启动包名> -s trace_d_init.js --spawn
//      （spawn 若报找不到 vc.d，改 attach：先打开 App 进设备页，再去掉 --spawn 跑）
/* wjlogin 登录态(WUserSigInfo)读写追踪 —— 所有 frida_*.js 内置（见 REVERSE_ENGINEERING.md §5.6）
 * createUserInfoFromJSON(读/初始化) + toJSONObject(写/落盘)，两者 dump 调用栈看更新机制。
 * 放在 vc.d 早退之前调用，所以即便找不到 vc.d 也照常抓登录态读写。 */
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
  function safe(fn, d) { try { return fn(); } catch (e) { return d; } }
  var Log = Java.use('android.util.Log');
  var Throwable = Java.use('java.lang.Throwable');
  var MapEntry = Java.use('java.util.Map$Entry');

  function stack() { return safe(function () { return Log.getStackTraceString(Throwable.$new()); }, '(no stack)'); }
  function isMap(a) { return safe(function () { return a && typeof a !== 'string' && !!a.entrySet; }, false); }
  function dumpMap(m) {
    return safe(function () {
      var out = [], it = m.entrySet().iterator();
      while (it.hasNext()) { var e = Java.cast(it.next(), MapEntry); out.push(e.getKey() + '=' + e.getValue()); }
      return '{' + out.join('  |  ') + '}';
    }, '<map err>');
  }
  function hasSig(m) {  // header map 里有没有签名特征(:::)
    return safe(function () {
      var it = m.values().iterator();
      while (it.hasNext()) if (('' + it.next()).indexOf(':::') !== -1) return true;
      return false;
    }, false);
  }
  function dumpArg(a) {
    if (a === null || a === undefined) return 'null';
    if (typeof a === 'string') return '"' + a + '"';
    if (isMap(a)) return dumpMap(a);
    return safe(function () { return '' + a; }, '<obj>');
  }

  var D = safe(function () { return Java.use('vc.d'); }, null);
  if (!D) {
    console.log('[!] 找不到 vc.d 类。① spawn 太早、类还没加载 -> 改 attach（先手动打开 App 进设备页，再去掉 --spawn 跑）；② 换了 App 版本、混淆名变了 -> 用 auth-tracer 的栈重新认 OkHttpRequest 的混淆名。');
    return;
  }
  D.$init.overloads.forEach(function (ov) {
    ov.implementation = function () {
      var ret = ov.apply(this, arguments);
      try {
        // 只在某个参数是“含签名的 header map”时打印，避免被其它请求刷屏
        var interesting = false;
        for (var i = 0; i < arguments.length; i++) if (isMap(arguments[i]) && hasSig(arguments[i])) { interesting = true; break; }
        if (interesting) {
          console.log('\n========== vc.d.<init> (OkHttpRequest) ==========');
          for (var j = 0; j < arguments.length; j++) console.log(' arg' + j + ' = ' + dumpArg(arguments[j]));
          console.log(stack());
          console.log('=================================================\n');
        }
      } catch (e) { console.log('[hookerr] ' + e); }
      return ret;
    };
  });
  console.log('[*] hooked vc.d.<init> x' + D.$init.overloads.length + '，触发一次设备请求看 header map 全貌。');
});
