'use strict';

/*
 * frida_loaddoor_capture.js —— libbiometric.so（com.jdcn.risk.cpp.LoadDoor）native 面板抓取
 *
 * 这套 JD 风控的“总开关”都在 libbiometric.so，经 LoadDoor 的一组 private static native 暴露：
 *   enc(String) / dec(String)        字符串加/解密  <== 极可能就是 §8.3 的 ciphertype:5
 *   getToken(Object)                 token 料        <== sign 候选
 *   checkSum(Object)                 校验和          <== sign 候选
 *   getEid(Object)                   148 字符 = 116(eid) + 32(tail)  -> getLocalEid 切片落 SP
 *   getFingerprint/getModel(Object)、checkFingers(String,String)、getDecStr(double[],int)、checkAntiFile()
 *
 * eid 已锤死：native getEid -> 116+32 -> 落 SharedPreferences(键经 c() 混淆: lcJade=eid, field=tail) -> 读 SP。稳定。
 * replay 报 invalid sign 的真因：query 的 sign 覆盖 t（时间戳）=防重放；旧 t+sign 必被拒，要用【新 t 重算 sign】。
 * => 本脚本把 native 的 enc/dec/getToken/checkSum 的【明文↔密文 / 输入↔输出】直接抓出来，
 *    顺带验证 ciphertype:5 是不是 enc()，并给出 sign 的料从哪来。
 *
 * 落 host.py sign 表（kind=LD.*）。还暴露 rpc：可拿 App 自己的 native 现场 加/解密 任意串。
 *
 * 用法:
 *   python host.py -p <包名> -s frida_loaddoor_capture.js --spawn
 *   # 或 frida -U -n <包名> -l frida_loaddoor_capture.js 后在 REPL：
 *   #   rpc.exports.dec("<ep 里某字段密文>")      // 用 App native 解密
 *   #   rpc.exports.enc("android")               // 看 ciphertype:5 是不是 enc()
 *   #   rpc.exports.geteid()  rpc.exports.gettoken()
 */

var LD_CLASS = 'com.jdcn.risk.cpp.LoadDoor';
var STACK_FOR = ['enc', 'dec', 'getToken', 'checkSum'];   // 这几个打调用栈（看谁在用 -> 关联 sign/ep 拼装）
var RETRY_MS = 700, RETRY_MAX = 50;
var MAXP = 220;

function safe(fn, d) { try { return fn(); } catch (e) { return d; } }
function emit(rec) { try { send({ type: 'sign', data: rec }); } catch (e) {} }
function clip(s, n) { s = '' + s; return s.length > n ? s.substring(0, n) + '..(+' + (s.length - n) + 'B)' : s; }
function eidStatus(s) { return (typeof s === 'string' && s.indexOf('eid') === 0 && s.length >= 10) ? s.substring(8, 10) : null; }

/* rpc：用 App 自己的 native 现场加/解密、取 eid/token（不重写算法） */
function callNative(name, useCtx, arg) {
    var r = null;
    Java.perform(function () {
        try {
            var LD = Java.use(LD_CLASS);
            if (useCtx) {
                var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
                r = '' + LD[name](ctx);
            } else {
                r = '' + LD[name](arg);
            }
            console.log('[rpc] ' + name + '(' + (useCtx ? 'ctx' : JSON.stringify(arg)) + ') -> ' + r);
        } catch (e) { console.log('[rpc] ' + name + ' 失败: ' + e); }
    });
    return r;
}
rpc.exports = {
    enc: function (s) { return callNative('enc', false, '' + s); },
    dec: function (s) { return callNative('dec', false, '' + s); },
    geteid: function () { return callNative('getEid', true); },
    gettoken: function () { return callNative('getToken', true); },
    fingerprint: function () { return callNative('getFingerprint', true); },
    model: function () { return callNative('getModel', true); },
    checksum: function () { return callNative('checkSum', true); }
};

Java.perform(function () {
    var Throwable = Java.use('java.lang.Throwable');
    var Log = Java.use('android.util.Log');
    function stk() { return safe(function () { return Log.getStackTraceString(Throwable.$new()); }, '(no stack)'); }
    var seen = {};
    function once(k) { if (seen[k]) return false; seen[k] = 1; return true; }

    function argPrev(a) {
        var out = [];
        for (var i = 0; i < a.length; i++) {
            var x = a[i];
            if (x === null || x === undefined) out.push('null');
            else if (typeof x === 'string') out.push(JSON.stringify(clip(x, MAXP)));
            else if (typeof x === 'number' || typeof x === 'boolean') out.push('' + x);
            else if (x.length !== undefined && typeof x !== 'string') out.push('[' + x.length + ']');   // 数组(double[])
            else out.push('<' + safe(function () { return '' + x.getClass().getName(); }, typeof x) + '>'); // Context 等
        }
        return out;
    }

    function hookLD(LD, name) {
        var m = LD[name];
        if (!m || !m.overloads) { return false; }
        var wantStack = STACK_FOR.indexOf(name) !== -1;
        m.overloads.forEach(function (ov) {
            ov.implementation = function () {
                var ret = ov.apply(this, arguments);
                try {
                    var args = argPrev(arguments);
                    var rs = (ret === null || ret === undefined) ? ('' + ret) : ('' + ret);
                    var st = eidStatus(rs);
                    var s = wantStack ? stk() : null;
                    console.log('\n[ld] ' + name + '(' + args.join(', ') + ')\n     -> ' + clip(rs, 200) +
                        (st ? '  [eid status=' + st + ']' : '') + (typeof ret === 'string' ? '  (len=' + rs.length + ')' : ''));
                    if (s && once('ldstk:' + name)) console.log(s);
                    emit({
                        kind: 'LD.' + name, input_txt: args.join(' | '),
                        out_b64: (typeof ret === 'string' ? rs : null), stack: s, matched: 1
                    });
                } catch (e) {}
                return ret;
            };
        });
        console.log('[ld] hooked ' + LD_CLASS + '.' + name + ' x' + m.overloads.length);
        return true;
    }

    /* SP 抓取：揭示 c("lcJade")/c("field") 的真实键名 + 存的 116/32 片 */
    function hookSP() {
        function interesting(v) {
            if (typeof v !== 'string') return null;
            if (v.indexOf('eid') === 0 && v.length === 116) return 'eid(116)';
            if (v.length === 32) return 'tail(32)';
            if (v.length === 148 && v.indexOf('eid') === 0) return 'localEid(148)';
            return null;
        }
        var Ed = safe(function () { return Java.use('android.app.SharedPreferencesImpl$EditorImpl'); }, null);
        if (Ed && Ed.putString) Ed.putString.overloads.forEach(function (ov) {
            ov.implementation = function (k, v) {
                try {
                    var tag = interesting(v);
                    if (tag && once('sp:put:' + k)) {
                        console.log('[ld.sp] putString  key="' + k + '"  <= ' + tag + '  ' + clip(v, 60));
                        emit({ kind: 'LD.spKey.put', input_txt: 'key=' + k + ' (' + tag + ')', out_b64: '' + v, matched: 1 });
                    }
                } catch (e) {}
                return ov.apply(this, arguments);
            };
        });
        var Sp = safe(function () { return Java.use('android.app.SharedPreferencesImpl'); }, null);
        if (Sp && Sp.getString) Sp.getString.overloads.forEach(function (ov) {
            ov.implementation = function () {
                var r = ov.apply(this, arguments);
                try {
                    var tag = interesting(r);
                    if (tag && once('sp:get:' + arguments[0])) {
                        console.log('[ld.sp] getString  key="' + arguments[0] + '"  => ' + tag);
                        emit({ kind: 'LD.spKey.get', input_txt: 'key=' + arguments[0] + ' (' + tag + ')', out_b64: '' + r, matched: 1 });
                    }
                } catch (e) {}
                return r;
            };
        });
        console.log('[ld] hooked SharedPreferences put/getString（揪 lcJade/field 真实键名）');
    }

    var NATIVES = ['enc', 'dec', 'getToken', 'checkSum', 'getEid', 'getFingerprint', 'getModel', 'checkFingers', 'getDecStr', 'checkAntiFile'];
    try { hookSP(); } catch (e) { console.log('[ld] SP hook 失败: ' + e); }

    var tries = 0;
    (function attempt() {
        var LD = safe(function () { return Java.use(LD_CLASS); }, null);
        if (!LD) {
            if (++tries <= RETRY_MAX) { setTimeout(function () { Java.perform(attempt); }, RETRY_MS); return; }
            console.log('[ld] 放弃：' + LD_CLASS + ' 一直未加载（libbiometric 未初始化？换版本类名可能变）');
            return;
        }
        var ok = 0;
        NATIVES.forEach(function (n) { if (safe(function () { return hookLD(LD, n); }, false)) ok++; });
        console.log('[ld] LoadDoor 就位，hook 到 ' + ok + '/' + NATIVES.length + ' 个 native（含 enc/dec）。');
        console.log('[ld] REPL 可：rpc.exports.dec("<密文>") / rpc.exports.enc("android") / geteid() / gettoken()');
    })();

    console.log('\n[*] LoadDoor/libbiometric native 抓取已启动（落 sign 表 kind=LD.*）。');
    console.log('[*] 触发一次 getHouses，重点看 LD.enc / LD.dec / LD.getToken / LD.checkSum 的输入输出。\n');
});
