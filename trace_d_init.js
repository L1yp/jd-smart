'use strict';
// 一次性调试片段：hook OkHttpRequest(vc.d) 构造，dump 各参数(含 headers map2) + 调用栈。
// vc.d 是【当前 App 版本】的混淆类名，换版本可能变；变了用 auth-tracer 的栈重新认。
// 跑法：python host.py -p <启动包名> -s trace_d_init.js --spawn
//      （spawn 若报找不到 vc.d，改 attach：先打开 App 进设备页，再去掉 --spawn 跑）
Java.perform(function () {
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
