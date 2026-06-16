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
 * 本脚本做三件事（落 host.py sign 表 kind=EID.*）：
 *   1) 摸清流程：hook BiometricManager.getCacheTokenByBizId(scope/pin/返回) + 自动发现并 hook
 *      worker e 类的【全部声明方法】，把 r/s/p/q/b/l/n/j 的返回值打出来——直接看到哪个叶子吐 eid、
 *      哪个是 status=41 占位、tokenExist 真假。
 *   2) 定位持久化：可选 hook 文件 I/O（FileOutputStream/FileInputStream），在 com.jd.sec 栈下打印
 *      读/写的文件路径——找到 token 文件就能直接拿 eid（HOOK_FILE_IO=true 开）。
 *   3) 主动现造：用 frida 直接调 LogoManager.getLogo() 现场生成有效 eid（驱动它自己的 SDK，不重写算法）。
 *      AUTO_MINT 会定时调几次（看 41 占位 -> 异步落盘 -> 变有效 的过程）；也可 rpc 手动 minteid()。
 *
 * 用法:
 *   python host.py -p <包名> -s frida_eid_capture.js --spawn        # 落库 + AUTO_MINT
 *   frida -U -n <包名> -l frida_eid_capture.js                       # 然后 REPL: rpc.exports.minteid()
 */

/* ===== 配置 ===== */
var BIOMETRIC_CANDIDATES = ['com.jd.sec.BiometricManager', 'com.jingdong.jdsdk.utils.BiometricManager'];
var SEC_A_CLASS = 'com.jd.sec.a';   // scope=a.c(), pin=a.b()（混淆名，换版本可能变）
var LOGO_CLASS = 'com.jd.sec.LogoManager';
var HOOK_FILE_IO = false;           // 开后在 com.jd.sec 栈下打印文件读写路径（找 token 持久化文件）
var AUTO_MINT = true;               // 启动后定时主动调 getLogo 现造 eid
var AUTO_MINT_AT_MS = [4000, 9000, 16000, 30000];
var RETRY_MS = 700, RETRY_MAX = 40;

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
rpc.exports = { minteid: function () { return mintEid('rpc'); } };

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
        var done = {}, cnt = 0;
        for (var i = 0; i < methods.length; i++) {
            var mn = '' + methods[i].getName();
            if (done[mn]) continue; done[mn] = 1;
            var fn = W[mn]; if (!fn || !fn.overloads) continue;
            (function (name) {
                fn.overloads.forEach(function (ov) {
                    ov.implementation = function () {
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

    /* ---- 安装：晚加载自动重试 ---- */
    try { hookFileIO(); } catch (e) { console.log('[eid] fileIO 安装失败: ' + e); }
    var bioDone = false, tries = 0;
    (function attempt() {
        if (!bioDone) {
            for (var i = 0; i < BIOMETRIC_CANDIDATES.length && !bioDone; i++) {
                var cls = BIOMETRIC_CANDIDATES[i];
                var BM = safe(function () { return Java.use(cls); }, null);
                if (BM && safe(function () { return hookBiometric(cls, BM); }, false)) bioDone = true;
            }
        }
        if (!bioDone && ++tries <= RETRY_MAX) { setTimeout(function () { Java.perform(attempt); }, RETRY_MS); return; }
        if (!bioDone) {
            console.log('[eid] 未命中 BiometricManager 候选，枚举 *BiometricManager* 供你填 BIOMETRIC_CANDIDATES：');
            Java.enumerateLoadedClasses({
                onMatch: function (n) { if (n.indexOf('BiometricManager') !== -1 && (n.indexOf('com.jd') !== -1 || n.indexOf('com.jingdong') !== -1)) console.log('   ' + n); },
                onComplete: function () { }
            });
        }
    })();

    if (AUTO_MINT) {
        console.log('[eid] AUTO_MINT 开：将在 ' + JSON.stringify(AUTO_MINT_AT_MS) + 'ms 各调一次 getLogo 现造 eid');
        AUTO_MINT_AT_MS.forEach(function (t, i) { setTimeout(function () { mintEid('auto#' + i); }, t); });
    }

    console.log('\n[*] eid 内部链路追踪已启动（落 sign 表 kind=EID.*）。');
    console.log('[*] 进“家庭列表”页触发；或等 AUTO_MINT；或 frida REPL 里 rpc.exports.minteid()。\n');
});
