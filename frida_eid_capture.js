'use strict';

/*
 * frida_eid_capture.js —— 把 eid(deviceFinger) 的内部链路摊开，并支持「主动现造」
 *
 * 修正上一版定性：getLogo() 与 getCacheTokenByBizId 是同一条路（getLogo 只是固定了 scope/pin）。
 * 按源码还原的调用树：
 *   DeviceFingerUtils.a(ctx)                                 # 缓存；空 或 status[8:10]=="41" 就重取
 *     -> LogoManager.getInstance(ctx).getLogo()
 *        -> BiometricManager.getInstance().getCacheTokenByBizId(ctx, scope=a.c(), pin=a.b())
 *           -> ff.a.l(ctx, scope, pin)
 *              k(ctx)=Bundle{agreedPrivacy, tokenExist=e.l(ctx), cuid}; ThreadLocal e.f39136n=Bundle
 *              scope==a.c() ? e.n(ctx) : e.j(ctx)
 *                 n: (!agreedPrivacy && !tokenExist) ? e.s(ctx) : e.r(ctx)
 *                 j: (!agreedPrivacy && !tokenExist) ? e.q(ctx) : e.p(ctx)
 *              token 空: j10=e.b(ctx)(占位,常 status=41) + execute(RunnableC0575a 异步生成+持久化)
 *
 * 模型 = 生成一次 -> 持久化 -> 后续读取。所以 eid 的“出处”=叶子 e.r/s/p/q/b(ctx)，
 * 而真正逆向落点是：① e.r/p 读的【token 持久化文件】在哪；② 异步生成（大概率 jdguard native）。
 *
 * 本脚本做四件事（落 host.py sign 表 kind=EID.*）：
 *   1) 摸清流程：hook BiometricManager.getCacheTokenByBizId(scope/pin/返回) + 自动发现并 hook
 *      worker e 类的【全部声明方法】，把 r/s/p/q/b/l/n/j 的返回值打出来——直接看到哪个叶子吐 eid、
 *      哪个是 status=41 占位、tokenExist 真假。
 *   2) 定位持久化：可选 hook 文件 I/O（FileOutputStream/FileInputStream），在 com.jd.sec 栈下打印
 *      读/写的文件路径——找到 token 文件就能直接拿 eid（HOOK_FILE_IO=true 开）。
 *   3) 主动现造：用 frida 直接调 LogoManager.getLogo() 现场生成有效 eid（驱动它自己的 SDK，不重写算法）。
 *      AUTO_MINT 会定时调几次（看 41 占位 -> 异步落盘 -> 变有效 的过程）；也可 rpc 手动 minteid()。
 *   4) 读持久化对象：dump SharedPreferences("BIOMETRIC_OBJECT")（= worker e.p(ctx) 里的 nf.c.a(ctx)），
 *      重点取 token/tokenTime/tokenActTime（旧格式明文键）与 jade/jadeStamp/jadeVal/whisper（新格式，
 *      实际键名经 c() 混淆）。jade 以 jdd02 开头 => g.a(jade,whisper) 解出真 token；jdd01 开头 => 本身即明文 token。
 *      DUMP_BIO 定时自动读；也可 rpc 手动 dumpbio()。
 *      另 hook of.g.a/.b(String,String,String)（jade 密文编解码壳）——运行时直接抓 g.a 的入参(jade/whisper)
 *      与返回(明文 token)，与上面的持久化值相互印证（落 sign 表 kind=EID.ofg.a/.b）。
 *      另 hook ff.e.h(Context,String,long,long,String,String)：打印 6 个参数 + 调用栈，倒数第二个 String
 *      参数 = eid 来源，借调用栈回溯上级调用（谁把 eid 传进来的）（落 sign 表 kind=EID.ffe.h）。
 *
 * 用法:
 *   python host.py -p <包名> -s frida_eid_capture.js --spawn        # 落库 + AUTO_MINT
 *   frida -U -n <包名> -l frida_eid_capture.js                       # 然后 REPL: rpc.exports.minteid()
 */

/* ===== 配置 ===== */
var BIOMETRIC_CANDIDATES = ['com.jd.sec.BiometricManager', 'com.jingdong.jdsdk.utils.BiometricManager'];
var SEC_A_CLASS = 'com.jd.sec.a';   // scope=a.c(), pin=a.b()（混淆名，换版本可能变）
var LOGO_CLASS = 'com.jd.sec.LogoManager';
var OFG_CLASS = 'of.g';             // jade 密文编解码壳：静态 a/b(String,String,String)；p(ctx) 里 g.a(jade,whisper,"UTF-8") 解出真 token
var FFE_CLASS = 'ff.e';             // ff.e.h(Context,String,long,long,String,String) 倒数第二参=eid 来源（hook 抓参数+栈回溯上级调用）
var HOOK_FILE_IO = false;           // 开后在 com.jd.sec 栈下打印文件读写路径（找 token 持久化文件）
var AUTO_MINT = true;               // 启动后定时主动调 getLogo 现造 eid
var AUTO_MINT_AT_MS = [4000, 9000, 16000, 30000];
var RETRY_MS = 700, RETRY_MAX = 40;
var DUMP_BIO = true;                // 读取持久化对象 SharedPreferences("BIOMETRIC_OBJECT")（token/jade/whisper 等）
var DUMP_BIO_AT_MS = [3000, 8000, 17000, 31000];  // 主动读取时机（穿插在 mint 之间，看落盘前后变化）

/* 运行时状态（worker e 类发现后填，供读 SP 时解析 c() 混淆键名 / 实例法兜底） */
var workerClassName = null;
var lastWorkerInstance = null;

/* ===== 工具 ===== */
function safe(fn, d) { try { return fn(); } catch (e) { return d; } }
function emit(rec) { try { send({ type: 'sign', data: rec }); } catch (e) {} }
function eidStatus(s) { return (typeof s === 'string' && s.indexOf('eid') === 0 && s.length >= 10) ? s.substring(8, 10) : null; }
function clip(s, n) { s = '' + s; return s.length > n ? s.substring(0, n) + '..(+' + (s.length - n) + 'B)' : s; }

/* ===== 主动现造（驱动 SDK 自己生成 eid）===== */
function mintEid(tag) {
    var eid = null;
    Java.perform(function () {
        try {
            var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
            var LM = safe(function () { return Java.use(LOGO_CLASS); }, null);
            if (!LM) { console.log('[mintEid] ' + LOGO_CLASS + ' 未加载'); return; }
            eid = '' + LM.getInstance(ctx).getLogo();
            var st = eidStatus(eid);
            console.log('[mintEid' + (tag ? ':' + tag : '') + '] eid=' + eid + '  status[8:10]=' + st +
                (st === '41' ? '  (占位，等异步落盘后再调)' : '  (有效)'));
            emit({ kind: 'EID.mint', out_b64: eid, input_txt: 'status=' + st, matched: 1 });
        } catch (e) { console.log('[mintEid] 失败: ' + e); }
    });
    return eid;
}

/* ===== 读持久化对象 BIOMETRIC_OBJECT（worker e.p(ctx) 里的 token/jade/whisper 等）=====
 * 源码 p(ctx)：SP = nf.c.a(ctx) == ctx.getSharedPreferences("BIOMETRIC_OBJECT", 0)
 *   旧格式明文键: token / tokenTime / tokenActTime（命中即被迁移成下方混淆键再删除）
 *   新格式混淆键: c("jade") / c("jadeStamp") / c("jadeVal") / c("whisper")
 *     jade 以 jdd02 开头 => g.a(jade, whisper, "UTF-8") 解出真 token；jdd01 开头 => jade 本身即明文 token
 * 直接 getSharedPreferences 比走混淆的 nf.c.a 更稳；c() 键名用 worker 类 best-effort 解析，
 * 解析不到也有 getAll() 全量兜底（值按 jdd0x/eid 格式自动标注）。
 */
var BIO_SP_NAME = 'BIOMETRIC_OBJECT';
var BIO_PLAIN_KEYS = ['token', 'tokenTime', 'tokenActTime'];     // 旧格式：键名即明文
var BIO_OBF_KEYS = ['jade', 'jadeStamp', 'jadeVal', 'whisper'];  // 新格式：实际存储键 = c(逻辑名)

function bioFmt(v) {
    if (typeof v !== 'string' || !v.length) return null;
    if (v.indexOf('jdd02') === 0) return 'jdd02 密文(需 whisper 解出 token)';
    if (v.indexOf('jdd01') === 0) return 'jdd01 明文 token';
    if (v.indexOf('eid') === 0) return 'eid status=' + (eidStatus(v) || '?');
    return null;
}

/* 逻辑名 -> 实际存储键名（c() 混淆），best-effort：先静态调，再用 worker 活实例调 */
function resolveBioKey(logical) {
    if (!workerClassName) return null;
    var W = safe(function () { return Java.use(workerClassName); }, null);
    if (!W || !W.c) return null;
    var v = safe(function () { return '' + W.c(logical); }, null);                                              // 静态法
    if ((v == null || v === 'undefined') && lastWorkerInstance) v = safe(function () { return '' + lastWorkerInstance.c(logical); }, null); // 实例法
    return (v && v !== 'undefined' && v !== 'null') ? v : null;
}

function readOneBioKey(sp, logical, actual) {
    if (actual == null) {
        console.log('  ' + logical + ' -> (混淆键名未解析，见下方 getAll 全量)');
        emit({ kind: 'EID.bio.' + logical, input_txt: 'key=?(c() 未解析)', out_b64: null, matched: 0 });
        return;
    }
    var has = safe(function () { return sp.contains(actual); }, false);
    var val = has ? safe(function () { return '' + sp.getString(actual, null); }, null) : null;
    var fmt = bioFmt(val);
    var label = (logical === actual) ? logical : (logical + ' [key=' + actual + ']');
    console.log('  ' + label + ' = ' + (has ? clip(val, 120) : '(不存在)') + (fmt ? '  <' + fmt + '>' : ''));
    emit({ kind: 'EID.bio.' + logical, input_txt: 'key=' + actual + (fmt ? ' (' + fmt + ')' : ''), out_b64: val, matched: has ? 1 : 0 });
}

function readBiometricSP(tag) {
    Java.perform(function () {
        try {
            var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
            var sp = safe(function () { return ctx.getSharedPreferences(BIO_SP_NAME, 0); }, null);
            if (!sp) { console.log('[bio] getSharedPreferences("' + BIO_SP_NAME + '") = null'); return; }

            console.log('\n[bio' + (tag ? ':' + tag : '') + '] ===== SharedPreferences("' + BIO_SP_NAME + '") 关注键 =====');
            BIO_PLAIN_KEYS.forEach(function (k) { readOneBioKey(sp, k, k); });
            BIO_OBF_KEYS.forEach(function (k) { readOneBioKey(sp, k, resolveBioKey(k)); });

            /* getAll() 全量兜底：混淆键名解析不到 / 漏键时仍能看到值，按格式标注 */
            var all = safe(function () { return sp.getAll(); }, null);
            if (all) {
                var arr = safe(function () { return all.keySet().toArray(); }, null) || [];
                console.log('[bio] ----- getAll() 全量 ' + arr.length + ' 键 -----');
                for (var i = 0; i < arr.length; i++) {
                    var k = '' + arr[i];
                    var v = safe(function () { return all.get(arr[i]); }, null);
                    var vs = (v == null) ? null : ('' + v);
                    var fmt = bioFmt(vs);
                    console.log('    [' + k + '] = ' + (vs == null ? 'null' : clip(vs, 120)) + (fmt ? '  <' + fmt + '>' : ''));
                    emit({ kind: 'EID.bio.all', input_txt: 'key=' + k + (fmt ? ' (' + fmt + ')' : ''), out_b64: vs, matched: 1 });
                }
            }
            console.log('[bio] =====================================\n');
        } catch (e) { console.log('[bio] 读取失败: ' + e); }
    });
}

rpc.exports = {
    minteid: function () { return mintEid('rpc'); },
    dumpbio: function () { readBiometricSP('rpc'); }
};

Java.perform(function () {
    var Throwable = Java.use('java.lang.Throwable');
    var Log = Java.use('android.util.Log');
    function stk() { return safe(function () { return Log.getStackTraceString(Throwable.$new()); }, '(no stack)'); }
    var seen = {};
    function once(k) { if (seen[k]) return false; seen[k] = 1; return true; }

    /* 打印 scope/pin 常量（决定 n 还是 j 分支） */
    (function () {
        var A = safe(function () { return Java.use(SEC_A_CLASS); }, null);
        if (!A) { console.log('[eid] ' + SEC_A_CLASS + ' 未解析（scope/pin 常量稍后看 getCacheTokenByBizId 入参）'); return; }
        var scope = safe(function () { return '' + A.c(); }, '?'), pin = safe(function () { return '' + A.b(); }, '?');
        console.log('[eid] 默认 scope = a.c() = "' + scope + '"   pin = a.b() = "' + pin + '"');
    })();

    /* worker e 类：hook 全部声明方法，String/boolean 返回都打（看哪个叶子吐 eid） */
    var workerHooked = false;
    function hookWorker(cn) {
        if (workerHooked) return;
        var W = safe(function () { return Java.use(cn); }, null);
        if (!W) return;
        var methods = safe(function () { return W.class.getDeclaredMethods(); }, null);
        if (!methods) return;
        workerHooked = true;
        workerClassName = cn;   // 记下 worker e 类名，供读 BIOMETRIC_OBJECT 时解析 c() 混淆键名
        var done = {}, cnt = 0;
        for (var i = 0; i < methods.length; i++) {
            var mn = '' + methods[i].getName();
            if (done[mn]) continue; done[mn] = 1;
            if (cn === FFE_CLASS && mn === 'h') continue;   // ff.e.h 交给 hookFfeH（带参数+栈），避免被此处泛 hook 覆盖
            var fn = W[mn]; if (!fn || !fn.overloads) continue;
            (function (name) {
                fn.overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        if (!lastWorkerInstance) { try { lastWorkerInstance = this; } catch (e) {} }  // 留活实例给 c() 实例法兜底
                        var ret = ov.apply(this, arguments);
                        try {
                            if (typeof ret === 'string' && ret.length) {
                                var st = eidStatus(ret);
                                console.log('[eid.worker] ' + name + '() -> ' + clip(ret, 90) +
                                    (st ? '  [eid status=' + st + (st === '41' ? ' 占位' : '') + ']' : ''));
                                emit({ kind: 'EID.worker.' + name, out_b64: ret, input_txt: (st ? 'status=' + st : null), matched: 1 });
                            } else if (typeof ret === 'boolean') {
                                // l(ctx)=tokenExist, i()=... 这类标志位，对理解分支很关键
                                console.log('[eid.worker] ' + name + '() -> ' + ret);
                                emit({ kind: 'EID.worker.' + name, out_b64: '' + ret, input_txt: 'boolean', matched: 1 });
                            }
                        } catch (e) {}
                        return ret;
                    };
                });
            })(mn);
            cnt++;
        }
        console.log('[eid] hooked worker ' + cn + '  声明方法~' + cnt + '（叶子 r/s/p/q/b 看这里）');
    }

    /* BiometricManager：发现 worker + hook getCacheTokenByBizId */
    function hookBiometric(cls, BM) {
        // 发现 worker e = BiometricManager.getInstance().a()
        if (!workerHooked) {
            var cn = safe(function () { return '' + BM.getInstance().a().getClass().getName(); }, null);
            if (cn) { console.log('[eid] 发现 worker 类: ' + cn + '（经 ' + cls + '.getInstance().a()）'); hookWorker(cn); }
            else if (BM.a && BM.a.overloads) {  // 被动兜底：hook a() 等它被调时拿返回类型
                BM.a.overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        var r = ov.apply(this, arguments);
                        try { if (!workerHooked && r) hookWorker('' + r.getClass().getName()); } catch (e) {}
                        return r;
                    };
                });
            }
        }
        var m = BM.getCacheTokenByBizId;
        if (m && m.overloads) {
            m.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var ret = ov.apply(this, arguments);
                    try {
                        var a = []; for (var i = 0; i < arguments.length; i++) a.push('' + arguments[i]);
                        // 入参一般是 (context, scope, pin)，跳过 context 只留后两者更可读
                        var scope = a.length >= 2 ? a[1] : '?', pin = a.length >= 3 ? a[2] : '?';
                        var st = eidStatus(ret == null ? '' : '' + ret);
                        var s = stk();
                        console.log('\n[eid] getCacheTokenByBizId(scope=' + scope + ', pin=' + pin + ') -> ' +
                            clip(ret == null ? 'null' : '' + ret, 90) + (st ? '  [status=' + st + ']' : ''));
                        emit({ kind: 'EID.getCacheToken', input_txt: 'scope=' + scope + ' pin=' + pin, out_b64: (ret == null ? null : '' + ret), stack: (once('gct') ? s : null), matched: 1 });
                    } catch (e) {}
                    return ret;
                };
            });
            console.log('[eid] hooked ' + cls + '.getCacheTokenByBizId x' + m.overloads.length);
            return true;
        }
        return false;
    }

    /* 可选：文件 I/O，定位 token 持久化文件（仅 com.jd.sec 栈下） */
    function hookFileIO() {
        if (!HOOK_FILE_IO) return;
        function fromSec() {
            var f = safe(function () { return Throwable.$new().getStackTrace(); }, null);
            if (!f) return false;
            for (var i = 0; i < f.length && i < 12; i++) { var c = safe(function () { return '' + f[i].getClassName(); }, ''); if (c.indexOf('com.jd.sec') === 0 || c.indexOf('jdguard') !== -1) return true; }
            return false;
        }
        ['java.io.FileInputStream', 'java.io.FileOutputStream'].forEach(function (cls) {
            var C = safe(function () { return Java.use(cls); }, null);
            if (!C || !C.$init) return;
            C.$init.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    try {
                        var arg0 = arguments[0], path = (arg0 && arg0.getPath) ? '' + arg0.getPath() : ('' + arg0);
                        if (fromSec() && once('file:' + cls + ':' + path)) {
                            var s = stk();
                            console.log('\n[eid.file] ' + (cls.indexOf('Output') !== -1 ? '写' : '读') + ' ' + path);
                            console.log(s);
                            emit({ kind: 'EID.file.' + (cls.indexOf('Output') !== -1 ? 'write' : 'read'), out_b64: path, stack: s, matched: 1 });
                        }
                    } catch (e) {}
                    return ov.apply(this, arguments);
                };
            });
        });
        console.log('[eid] hooked FileInputStream/FileOutputStream（com.jd.sec 栈下打印 token 文件路径）');
    }

    /* of.g：jade 密文编解码壳——static a/b(String,String,String)，抓入参+返回直接拿明文 token
     *   p(ctx) 里 g.a(jade, whisper, "UTF-8") = 解出真 token（jade=jdd02密文, whisper=密钥料）
     *   优先精确命中用户指定的 (String,String,String) 重载；缺则兜底 hook 该方法全部重载 */
    function hookOfG() {
        var G = safe(function () { return Java.use(OFG_CLASS); }, null);
        if (!G) return false;
        var hooked = 0;
        ['a', 'b'].forEach(function (name) {
            var fn = G[name];
            if (!fn || !fn.overloads) return;
            var exact = safe(function () { return fn.overload('java.lang.String', 'java.lang.String', 'java.lang.String'); }, null);
            var targets = exact ? [exact] : fn.overloads;
            targets.forEach(function (ov) {
                ov.implementation = function () {
                    var ret = ov.apply(this, arguments);
                    try {
                        var a = []; for (var i = 0; i < arguments.length; i++) a.push('' + arguments[i]);  // 全量不截断：要拿去离线复算/测算法
                        var rs = (ret == null) ? null : ('' + ret);
                        var st = once('ofg:' + name) ? stk() : null;
                        console.log('\n[ofg] ' + OFG_CLASS + '.' + name + '()  (参数/返回全量未截断)');
                        for (var j = 0; j < a.length; j++) console.log('  arg' + j + ' = ' + a[j]);
                        console.log('  ret  = ' + (rs == null ? 'null' : rs));
                        if (st) console.log(st);
                        emit({ kind: 'EID.ofg.' + name, input_txt: a.join(' | '), out_b64: rs, stack: st, matched: 1 });
                    } catch (e) {}
                    return ret;
                };
            });
            hooked += targets.length;
        });
        if (hooked) console.log('[ofg] hooked ' + OFG_CLASS + '.a/.b x' + hooked + '（jade 密文编解码，抓明文 token）');
        return hooked > 0;
    }

    /* ff.e.h(Context, String, long, long, String, String)：倒数第二个 String 参数 = eid 来源
     *   打印全部参数 + 调用栈（每次都打），借栈回溯是谁把 eid 传进来的（找上级调用）
     *   优先精确命中该 6 参重载；缺则兜底 hook h 的全部重载 */
    function hookFfeH() {
        var E = safe(function () { return Java.use(FFE_CLASS); }, null);
        if (!E || !E.h) return false;
        var exact = safe(function () {
            return E.h.overload('android.content.Context', 'java.lang.String', 'long', 'long', 'java.lang.String', 'java.lang.String');
        }, null);
        var targets = exact ? [exact] : (E.h.overloads || []);
        if (!targets.length) return false;
        targets.forEach(function (ov) {
            ov.implementation = function () {
                var ret = ov.apply(this, arguments);
                try {
                    var a = []; for (var i = 0; i < arguments.length; i++) a.push('' + arguments[i]);  // 全量不截断
                    var st = stk();
                    var eidSrc = (a.length >= 2) ? a[a.length - 2] : '?';   // 倒数第二个参数 = eid 来源
                    console.log('\n[ffe.h] ' + FFE_CLASS + '.h()  参数全量 + 调用栈（倒数第二参 = eid 来源）');
                    for (var j = 0; j < a.length; j++) console.log('  arg' + j + ' = ' + a[j] + (j === a.length - 2 ? '   <== eid 来源' : ''));
                    console.log('  ret  = ' + (ret == null ? 'null/void' : ('' + ret)));
                    console.log('  --- 调用栈（找上级调用）---\n' + st);
                    emit({ kind: 'EID.ffe.h', input_txt: a.join(' | '), out_b64: eidSrc, stack: st, matched: 1 });
                } catch (e) {}
                return ret;
            };
        });
        console.log('[ffe] hooked ' + FFE_CLASS + '.h(Context,String,long,long,String,String) x' + targets.length + '（参数+栈，倒数第二参=eid 来源）');
        return true;
    }

    /* ---- 安装：晚加载自动重试 ---- */
    try { hookFileIO(); } catch (e) { console.log('[eid] fileIO 安装失败: ' + e); }
    var bioDone = false, ofgDone = false, ffeDone = false, tries = 0;
    (function attempt() {
        if (!bioDone) {
            for (var i = 0; i < BIOMETRIC_CANDIDATES.length && !bioDone; i++) {
                var cls = BIOMETRIC_CANDIDATES[i];
                var BM = safe(function () { return Java.use(cls); }, null);
                if (BM && safe(function () { return hookBiometric(cls, BM); }, false)) bioDone = true;
            }
        }
        if (!ofgDone) ofgDone = safe(function () { return hookOfG(); }, false);
        if (!ffeDone) ffeDone = safe(function () { return hookFfeH(); }, false);
        if ((!bioDone || !ofgDone || !ffeDone) && ++tries <= RETRY_MAX) { setTimeout(function () { Java.perform(attempt); }, RETRY_MS); return; }
        if (!bioDone) {
            console.log('[eid] 未命中 BiometricManager 候选，枚举 *BiometricManager* 供你填 BIOMETRIC_CANDIDATES：');
            Java.enumerateLoadedClasses({
                onMatch: function (n) { if (n.indexOf('BiometricManager') !== -1 && (n.indexOf('com.jd') !== -1 || n.indexOf('com.jingdong') !== -1)) console.log('   ' + n); },
                onComplete: function () { }
            });
        }
        if (!ofgDone) console.log('[ofg] 未解析 ' + OFG_CLASS + '（换版本可能改名；可 frida 里枚举 of.* 候选后改 OFG_CLASS）');
        if (!ffeDone) console.log('[ffe] 未解析 ' + FFE_CLASS + '.h（换版本可能改名/重载不符；可枚举 ff.* 候选后改 FFE_CLASS）');
    })();

    if (AUTO_MINT) {
        console.log('[eid] AUTO_MINT 开：将在 ' + JSON.stringify(AUTO_MINT_AT_MS) + 'ms 各调一次 getLogo 现造 eid');
        AUTO_MINT_AT_MS.forEach(function (t, i) { setTimeout(function () { mintEid('auto#' + i); }, t); });
    }

    if (DUMP_BIO) {
        console.log('[bio] DUMP_BIO 开：将在 ' + JSON.stringify(DUMP_BIO_AT_MS) + 'ms 各读一次 SharedPreferences("' + BIO_SP_NAME + '")');
        DUMP_BIO_AT_MS.forEach(function (t, i) { setTimeout(function () { readBiometricSP('auto#' + i); }, t); });
    }

    console.log('\n[*] eid 内部链路追踪已启动（落 sign 表 kind=EID.*）。');
    console.log('[*] 进“家庭列表”页触发；或等 AUTO_MINT；或 frida REPL 里 rpc.exports.minteid()。');
    console.log('[*] 持久化对象 BIOMETRIC_OBJECT（token/jade/whisper）随 DUMP_BIO 自动读；或 rpc.exports.dumpbio()。\n');
});
