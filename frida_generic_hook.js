'use strict';

/*
 * frida_generic_hook.js —— 通用方法 hook：只改顶部 SIGNATURES 列表即可
 *
 * 你想 hook 哪个方法，就把它的「签名」写进下面的 SIGNATURES 数组，脚本会自动：
 *   1) 等类加载（晚加载自动重试） -> 解析重载 -> 安装 hook；
 *   2) 每次被调用时在 console 打印一行（类.方法(签名)、入参、返回、可选调用栈）；
 *   3) 把 函数 / 入参 / 出参 / 线程 / 栈 落进 SQLite 的 hook_log 表（配 host.py，type=hook）。
 *
 * 不需要懂 frida：你只动 SIGNATURES（必要时动几个全局开关）。其它都是通用逻辑。
 *
 * ── 签名怎么写（SIGNATURES 里每一项）──────────────────────────────────────
 *   字符串形式（最常用）：
 *     'pkg.Clazz.method'                         hook 该方法的【全部重载】
 *     'pkg.Clazz.method(java.lang.String,int)'   只 hook【指定参数】的那个重载
 *     'pkg.Clazz.method()'                        只 hook【无参】重载
 *     'pkg.Clazz.$init'                           hook【构造函数】（全部重载）
 *     'pkg.Clazz.$init(android.content.Context)'  hook 指定参数的构造
 *     'pkg.Clazz.*'                               hook 该类【全部声明方法】（不含构造）
 *   对象形式（给单条加选项）：
 *     { sig: 'pkg.Clazz.method', stack: true, tag: 'login' }
 *       stack=true  -> 该条每次都抓调用栈（贵，按需开）
 *       tag='xxx'   -> 落库到 hook_log.tag，方便 SQL 过滤同一类调用
 *
 *   参数类型写法很宽松：全名 'java.lang.String' / 简名 'String' / 数组 'byte[]' 或 '[B'
 *   / 基本类型 'int','long','boolean' 都认。指定参数没匹配到时，默认兜底 hook 全部重载并告警
 *   （想严格匹配把 STRICT_OVERLOAD 设 true）。
 *
 * ── 用法 ────────────────────────────────────────────────────────────────
 *   落库（推荐）:  python host.py -p <包名> -s frida_generic_hook.js --spawn
 *   仅看 console:  frida -U -f <包名> -l frida_generic_hook.js
 *
 *   不知道方法签名长啥样？REPL 里枚举一个类的全部方法/构造：
 *     rpc.exports.dump("com.jd.sec.LogoManager")
 *   看当前各签名命中次数：
 *     rpc.exports.list()
 *
 *   触发后查库：
 *     SELECT captured_at,clazz,method,sig,args_txt,ret_txt,ret_b64 FROM hook_log ORDER BY id DESC LIMIT 50;
 *     SELECT * FROM hook_log WHERE tag='login';
 */

/* =======================================================================
 *  ★ 你要改的就是这里 ★
 * ======================================================================= */
var SIGNATURES = [
    // —— 把下面换成你要 hook 的方法即可（删掉示例、按需增删行）——
    'com.jd.sec.LogoManager.getLogo',                       // 示例：无参方法，hook 全部重载
    // 'com.foo.Bar.calc(java.lang.String,byte[])',         // 示例：指定参数重载
    // 'com.foo.Crypto.*',                                  // 示例：某类全部方法
    // { sig: 'com.foo.Net.send', stack: true, tag: 'net' },// 示例：带调用栈 + 打标签
];

/* =======================================================================
 *  全局开关（一般不用动）
 * ======================================================================= */
var STACK = false;            // 全局：每条都抓调用栈（很贵）。多数情况关，单条用 {stack:true} 精确开
var STRICT_OVERLOAD = false;  // 指定参数没匹配到重载时：false=兜底 hook 全部重载并告警；true=跳过该条
var INSPECT_OBJECTS = true;   // 非 String/byte[]/数值 的对象，是否 toString 取值（限长 OBJ_TXT_MAX）
var THREAD_NAME = true;       // 记录调用线程名（每次一次 Java 调用，量极大可关）

var MAX_HEX = 512;            // byte[] 预览 hex 上限（字节）
var MAX_TXT = 400;            // 文本预览上限（字符）
var OBJ_TXT_MAX = 160;        // 对象 toString 预览上限

var MAX_PER_SIG = 0;          // 每个签名最多落库多少条（防刷屏/刷库），0=不限
var CONSOLE_MAX = 0;          // console 打印行数上限，0=不限
var ARM_DELAY_MS = 0;         // >0：延迟装 hook（避开启动期检测窗口，闪退就设 3000~5000）
var RETRY_MS = 700, RETRY_MAX = 60;  // 类晚加载时的重试间隔/次数

var SKIP_METHODS = ['toString', 'hashCode', 'equals', 'clone', 'finalize',
    'getClass', 'wait', 'notify', 'notifyAll'];   // '*' 全方法模式下跳过这些

/* =======================================================================
 *  纯 JS 字节/类型工具（不回调被 hook 的 API，避免递归/副作用）
 * ======================================================================= */
var HEX = '0123456789abcdef';
var B64C = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function safe(fn, d) { try { return fn(); } catch (e) { return d; } }
function isBytes(x) { return x !== null && x !== undefined && x.length !== undefined && typeof x !== 'string' && typeof x !== 'function'; }
function clip(s, n) { if (s === null || s === undefined) return null; s = '' + s; return s.length > n ? s.substring(0, n) + '..(+' + (s.length - n) + ')' : s; }
function toHex(b, lim) {
    if (!isBytes(b)) return null; lim = lim || MAX_HEX;
    var n = b.length, m = Math.min(n, lim), s = '';
    for (var i = 0; i < m; i++) { var v = b[i] & 0xff; s += HEX.charAt(v >> 4) + HEX.charAt(v & 0xf); }
    if (n > m) s += '..(+' + (n - m) + 'B)';
    return s;
}
function toTxt(b, lim) {
    if (!isBytes(b)) return null; lim = lim || MAX_TXT;
    var n = Math.min(b.length, lim), s = '';
    for (var i = 0; i < n; i++) {
        var c = b[i] & 0xff;
        if (c >= 0x20 && c < 0x7f) s += String.fromCharCode(c);
        else if (c === 0x0a) s += '\\n'; else if (c === 0x0d) s += '\\r'; else if (c === 0x09) s += '\\t'; else s += '.';
    }
    if (b.length > n) s += '..';
    return s;
}
function toB64(b, lim) {
    if (!isBytes(b)) return null; lim = lim || MAX_HEX;
    var n = Math.min(b.length, lim), s = '';
    for (var i = 0; i < n; i += 3) {
        var b0 = b[i] & 0xff, b1 = (i + 1 < n) ? (b[i + 1] & 0xff) : 0, b2 = (i + 2 < n) ? (b[i + 2] & 0xff) : 0;
        var t = (b0 << 16) | (b1 << 8) | b2;
        s += B64C.charAt((t >> 18) & 63) + B64C.charAt((t >> 12) & 63);
        s += (i + 1 < n) ? B64C.charAt((t >> 6) & 63) : '=';
        s += (i + 2 < n) ? B64C.charAt(t & 63) : '=';
    }
    if (b.length > n) s += '..(+' + (b.length - n) + 'B)';
    return s;
}
/* JVM/类型名 -> 可读简名：'java.lang.String'->'String'，'[B'->'byte[]'，'int'->'int'，'[Ljava.lang.String;'->'String[]' */
function simpleType(jvm) {
    if (!jvm) return '?'; jvm = '' + jvm;
    var arr = '';
    while (jvm.charAt(0) === '[') { arr += '[]'; jvm = jvm.substring(1); }
    var map = { 'B': 'byte', 'C': 'char', 'I': 'int', 'J': 'long', 'S': 'short', 'Z': 'boolean', 'F': 'float', 'D': 'double', 'V': 'void' };
    if (jvm.length === 1 && map[jvm]) return map[jvm] + arr;
    if (jvm.charAt(0) === 'L' && jvm.charAt(jvm.length - 1) === ';') jvm = jvm.substring(1, jvm.length - 1);
    var dot = jvm.lastIndexOf('.');
    return (dot >= 0 ? jvm.substring(dot + 1) : jvm) + arr;
}

/* 把一个实参/返回值格式化成 {type, txt, hex, b64} */
function fmtVal(x, hexMax, txtMax) {
    if (x === null || x === undefined) return { type: x === null ? 'null' : 'void', txt: null, hex: null, b64: null };
    var t = typeof x;
    if (t === 'string') return { type: 'String', txt: clip(x, txtMax), hex: null, b64: null };
    if (t === 'number' || t === 'boolean') return { type: t, txt: '' + x, hex: null, b64: null };
    if (isBytes(x)) return { type: 'byte[' + x.length + ']', txt: toTxt(x, txtMax), hex: toHex(x, hexMax), b64: toB64(x, hexMax) };
    if (INSPECT_OBJECTS) {
        var cn = safe(function () { return x.$className; }, null) || safe(function () { return '' + x.getClass().getName(); }, 'obj');
        return { type: cn, txt: clip(safe(function () { return '' + x; }, '<' + cn + '>'), OBJ_TXT_MAX), hex: null, b64: null };
    }
    return { type: 'obj', txt: '<obj>', hex: null, b64: null };
}

/* =======================================================================
 *  解析签名字符串/对象 -> {sig, clazz, method, args, stack, tag}
 *    args: null=任意重载 / []=无参 / [类型...]=指定重载
 * ======================================================================= */
function parseSig(entry) {
    var sig, stack = false, tag = null;
    if (typeof entry === 'string') { sig = entry; }
    else { sig = entry.sig; stack = !!entry.stack; tag = entry.tag || null; }
    var s = ('' + sig).trim();
    var args = null;
    var lp = s.indexOf('(');
    if (lp !== -1) {
        var rp = s.lastIndexOf(')');
        var inside = (rp > lp) ? s.substring(lp + 1, rp).trim() : '';
        args = inside.length ? inside.split(',').map(function (x) { return x.trim(); }) : [];
        s = s.substring(0, lp).trim();
    }
    var dot = s.lastIndexOf('.');
    return {
        sig: ('' + sig).trim(),
        clazz: dot >= 0 ? s.substring(0, dot) : s,
        method: dot >= 0 ? s.substring(dot + 1) : s,
        args: args, stack: stack, tag: tag, _done: false
    };
}

/* =======================================================================
 *  运行时状态 / 输出
 * ======================================================================= */
var parsed = SIGNATURES.map(parseSig);
var sigCount = {};            // key=类#方法签名 -> 落库次数（也供 MAX_PER_SIG / list()）
var armTries = 0;
var consoleLines = 0;
var Throwable = null, Log = null, ThreadCls = null;

function clog(s) { if (CONSOLE_MAX === 0 || consoleLines < CONSOLE_MAX) { console.log(s); consoleLines++; } }
function stk() { return safe(function () { return Log.getStackTraceString(Throwable.$new()); }, '(no stack)'); }
function curThread() { return safe(function () { if (!ThreadCls) ThreadCls = Java.use('java.lang.Thread'); return '' + ThreadCls.currentThread().getName(); }, null); }
function emit(rec) { try { send({ type: 'hook', data: rec }); } catch (e) {} }

function buildSig(ov) {
    var ats = ov.argumentTypes || [], o = [];
    for (var i = 0; i < ats.length; i++) o.push(simpleType(ats[i].className));
    return '(' + o.join(',') + ')';
}

/* 反射该类各方法的 native/static 标记（按方法名聚合，作为展示提示） */
function classMeta(C) {
    var map = {};
    var Modifier = safe(function () { return Java.use('java.lang.reflect.Modifier'); }, null);
    var methods = safe(function () { return C.class.getDeclaredMethods(); }, null) || [];
    for (var i = 0; i < methods.length; i++) {
        (function (m) {
            var nm = safe(function () { return '' + m.getName(); }, '?');
            var mods = safe(function () { return m.getModifiers(); }, 0);
            if (!map[nm]) map[nm] = { native: false, static: false };
            if (Modifier && safe(function () { return Modifier.isNative(mods); }, false)) map[nm].native = true;
            if (Modifier && safe(function () { return Modifier.isStatic(mods); }, false)) map[nm].static = true;
        })(methods[i]);
    }
    map['$init'] = { native: false, static: false };
    return map;
}

/* 从一个方法的全部重载里挑出匹配 args 的那些（args=null 全要；按简名比较，宽松） */
function selectOverloads(fn, args) {
    if (args === null) return fn.overloads.slice();
    var want = args.map(function (a) { return simpleType(a); });
    var res = [];
    fn.overloads.forEach(function (ov) {
        var ats = ov.argumentTypes || [];
        if (ats.length !== want.length) return;
        var ok = true;
        for (var i = 0; i < ats.length; i++) { if (simpleType(ats[i].className) !== want[i]) { ok = false; break; } }
        if (ok) res.push(ov);
    });
    return res;
}

/* =======================================================================
 *  hook 安装 + 回调
 * ======================================================================= */
function hookOne(entry, ov, meta) {
    var sig = buildSig(ov);
    ov.implementation = function () {
        var ret, threw = null;
        try { ret = ov.apply(this, arguments); }
        catch (e) { threw = e; }
        try { handle(entry, sig, meta, arguments, ret, threw); } catch (_) {}
        if (threw) throw threw;   // 不改变原行为：原方法抛异常照样抛出
        return ret;
    };
    return sig;
}

function handle(entry, sig, meta, jsArgs, ret, threw) {
    var name = entry.method;
    var info = meta[name] || { native: false, static: false };

    var key = entry.clazz + '#' + name + sig;
    var c = (sigCount[key] = (sigCount[key] || 0) + 1);
    if (MAX_PER_SIG > 0 && c > MAX_PER_SIG) {
        if (c === MAX_PER_SIG + 1) clog('[HK] ' + entry.clazz + '.' + name + sig + ' 已达 MAX_PER_SIG=' + MAX_PER_SIG + '，后续不再落库（调大 MAX_PER_SIG 或加参数过滤）');
        return;
    }

    /* 入参 */
    var txtParts = [], hexParts = [];
    for (var i = 0; i < jsArgs.length; i++) {
        var v = fmtVal(jsArgs[i], MAX_HEX, MAX_TXT);
        txtParts.push('a' + i + '=' + (v.txt === null ? 'null' : v.txt));
        if (v.hex) hexParts.push('a' + i + '=' + v.hex);
    }
    var args_txt = txtParts.length ? txtParts.join(' | ') : '()';
    var args_hex = hexParts.length ? hexParts.join(' | ') : null;

    /* 返回（或异常） */
    var rv = threw ? { type: 'throw', txt: clip('' + threw, MAX_TXT), hex: null, b64: null }
        : fmtVal(ret, MAX_HEX, MAX_TXT);

    var stack = (entry.stack || STACK) ? stk() : null;
    var thread = THREAD_NAME ? curThread() : null;

    clog('\n[HK]' + (entry.tag ? ' #' + entry.tag : '') + ' ' + entry.clazz + '.' + name + sig
        + (info.static ? ' [static]' : '') + (info.native ? ' [native]' : '') + '  #' + c
        + '\n   in : ' + clip(args_txt, 600)
        + (args_hex ? '\n   in.hex: ' + clip(args_hex, 600) : '')
        + '\n   out: ' + (rv.txt === null ? 'null' : clip(rv.txt, 400)) + (rv.hex ? '  hex=' + clip(rv.hex, 300) : '') + '  (' + rv.type + ')'
        + (rv.b64 ? '\n   out.b64: ' + clip(rv.b64, 220) : '')
        + (stack ? '\n' + stack : ''));

    emit({
        clazz: entry.clazz, method: name, sig: sig,
        is_static: info.static ? 1 : 0, is_native: info.native ? 1 : 0, tag: entry.tag || null,
        args_txt: args_txt, args_hex: args_hex,
        ret_type: rv.type, ret_txt: rv.txt, ret_hex: rv.hex, ret_b64: rv.b64,
        thread: thread, stack: stack
    });
}

/* 安装一条签名（类已加载时调用）；成功返回 true */
function hookEntry(entry) {
    var C = safe(function () { return Java.use(entry.clazz); }, null);
    if (!C) return false;
    var meta = classMeta(C);

    /* 全方法模式：pkg.Clazz.* */
    if (entry.method === '*') {
        var cnt = 0;
        Object.keys(meta).forEach(function (name) {
            if (name === '$init' || SKIP_METHODS.indexOf(name) !== -1) return;
            var fn = safe(function () { return C[name]; }, null);
            if (!fn || !fn.overloads) return;
            fn.overloads.forEach(function (ov) {
                try { hookOne({ clazz: entry.clazz, method: name, tag: entry.tag, stack: entry.stack }, ov, meta); cnt++; } catch (e) {}
            });
        });
        console.log('[HK] hooked ' + entry.clazz + '.*  -> ' + cnt + ' 个重载（全部声明方法）');
        return true;
    }

    /* 普通方法 / 构造（$init） */
    var fn = safe(function () { return C[entry.method]; }, null);
    if (!fn || !fn.overloads) {
        console.log('[HK] 跳过：' + entry.clazz + '.' + entry.method + ' 不是可 hook 的方法/构造（无重载）');
        return false;
    }
    var ovs = selectOverloads(fn, entry.args);
    if (!ovs.length) {
        if (entry.args !== null) {
            console.log('[HK] 警告：' + entry.clazz + '.' + entry.method + '(' + entry.args.join(',') + ') 没匹配到重载。该方法实有重载：');
            fn.overloads.forEach(function (ov) { console.log('        ' + entry.method + buildSig(ov)); });
            if (STRICT_OVERLOAD) { console.log('        STRICT_OVERLOAD=true -> 跳过该条'); return false; }
            console.log('        STRICT_OVERLOAD=false -> 兜底 hook 全部重载');
            ovs = fn.overloads.slice();
        } else {
            return false;
        }
    }
    var sigs = [];
    ovs.forEach(function (ov) { try { sigs.push(hookOne(entry, ov, meta)); } catch (e) { console.log('[HK] 安装失败 ' + entry.clazz + '.' + entry.method + ': ' + e); } });
    if (sigs.length) console.log('[HK] hooked ' + entry.clazz + '.' + entry.method + '  ' + sigs.join(' , ')
        + (entry.tag ? '   #' + entry.tag : '') + ((entry.stack || STACK) ? '   +stack' : ''));
    return sigs.length > 0;
}

/* 逐条安装，类未加载的过会儿重试 */
function armAll() {
    parsed.forEach(function (e) { if (!e._done && safe(function () { return hookEntry(e); }, false)) e._done = true; });
    var left = parsed.filter(function (e) { return !e._done; });
    if (left.length && armTries++ < RETRY_MAX) { setTimeout(function () { Java.perform(armAll); }, RETRY_MS); return; }
    if (left.length) {
        console.log('[HK] 以下签名的类一直未加载（检查类名/包名；或被自定义 ClassLoader 延后加载，可调大 RETRY_MAX）：');
        left.forEach(function (e) { console.log('     ' + e.sig); });
    } else {
        console.log('[HK] 全部签名已就绪。');
    }
}

/* =======================================================================
 *  RPC：辅助查方法签名 / 看命中计数
 * ======================================================================= */
rpc.exports = {
    /* 枚举一个类的全部构造/方法签名，方便你抄进 SIGNATURES */
    dump: function (cn) {
        var out = [];
        Java.perform(function () {
            var C = safe(function () { return Java.use(cn); }, null);
            if (!C) { out.push('[HK] 未加载: ' + cn); return; }
            var Modifier = safe(function () { return Java.use('java.lang.reflect.Modifier'); }, null);
            var ctors = safe(function () { return C.class.getDeclaredConstructors(); }, []) || [];
            out.push('== ' + cn + '  构造 ' + ctors.length + ' ==');
            for (var i = 0; i < ctors.length; i++) {
                (function (ct) {
                    var pts = safe(function () { return ct.getParameterTypes(); }, []) || [], ps = [];
                    for (var k = 0; k < pts.length; k++) ps.push(simpleType('' + pts[k].getName()));
                    out.push('   $init(' + ps.join(',') + ')');
                })(ctors[i]);
            }
            var ms = safe(function () { return C.class.getDeclaredMethods(); }, []) || [];
            out.push('== ' + cn + '  方法 ' + ms.length + ' ==');
            for (var j = 0; j < ms.length; j++) {
                (function (m) {
                    var nm = safe(function () { return '' + m.getName(); }, '?');
                    var mods = safe(function () { return m.getModifiers(); }, 0);
                    var nat = Modifier ? safe(function () { return Modifier.isNative(mods); }, false) : false;
                    var sta = Modifier ? safe(function () { return Modifier.isStatic(mods); }, false) : false;
                    var ret = simpleType(safe(function () { return '' + m.getReturnType().getName(); }, '?'));
                    var pts = safe(function () { return m.getParameterTypes(); }, []) || [], ps = [];
                    for (var k = 0; k < pts.length; k++) ps.push(simpleType('' + pts[k].getName()));
                    out.push('   ' + (nat ? '[native] ' : '         ') + (sta ? 'static ' : '') + ret + ' ' + nm + '(' + ps.join(',') + ')');
                })(ms[j]);
            }
        });
        var s = out.join('\n'); console.log(s); return s;
    },
    /* 看每个签名当前命中（落库）次数 */
    list: function () {
        var out = ['[HK] 落库计数（key=类#方法签名 -> 次数）：'];
        var ks = Object.keys(sigCount);
        if (!ks.length) out.push('   (还没有命中，触发一下目标功能)');
        ks.forEach(function (k) { out.push('   ' + k + ' -> ' + sigCount[k]); });
        var s = out.join('\n'); console.log(s); return s;
    }
};

/* =======================================================================
 *  入口
 * ======================================================================= */
Java.perform(function () {
    Throwable = Java.use('java.lang.Throwable');
    Log = Java.use('android.util.Log');

    if (!parsed.length) {
        console.log('[HK] SIGNATURES 为空——请在脚本顶部填入要 hook 的方法签名。');
        return;
    }
    console.log('[HK] frida_generic_hook 启动，待 hook 签名 ' + parsed.length + ' 条：');
    parsed.forEach(function (e) { console.log('     - ' + e.sig + (e.tag ? '   #' + e.tag : '') + (e.stack ? '   +stack' : '')); });

    if (ARM_DELAY_MS > 0) { console.log('[HK] ' + ARM_DELAY_MS + 'ms 后开始装 hook（错开启动窗口）'); setTimeout(function () { Java.perform(armAll); }, ARM_DELAY_MS); }
    else armAll();

    console.log('\n[*] 通用 hook 已启动（落 host.py 的 hook_log 表，type=hook）。');
    console.log('[*] 只改顶部 SIGNATURES 列表即可。REPL 里 rpc.exports.dump("类全名") 查签名 / rpc.exports.list() 看计数。\n');
});
