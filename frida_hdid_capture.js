'use strict';

/*
 * frida_hdid_capture.js —— 抓 hdid 的「hash 原料」eid 在 SharedPreferences 的读/写
 *
 * 源码还原的 hdid 派生链（?.c()）：
 *   hdid = Base64( SHA-256(eid), NO_WRAP )                                       // 已确认：标准 SHA-256
 *          = android.util.Base64.encodeToString( PHCNativeLoader.f().d(eid), 2 ) // flag 2 = NO_WRAP，标准字母表
 *          PHCNativeLoader.d(String) -> native byte[] GenHash(String) == 标准 SHA-256（非自定义算法，32B 输出）
 *          入参 eid = b7.e.a(ctx) = c7.c.a(ctx, "phc", "eid", "")                // 从 SP 读出来的
 *   命名: hdid = hash device id；did = device id = device finger（设备指纹）
 *   c7.c 就是一层 SharedPreferences 读写壳（静态方法，混淆名）：
 *          a(ctx, file, key, def)   = ctx.getSharedPreferences(file,0).getString(key, def)               // 读
 *          b(ctx, file, key, value) = ctx.getSharedPreferences(file,0).edit().putString(key, value).apply() // 写
 *
 * 结论：hdid（hash device id）不是“每次现算的随机量”，而是 = Base64(SHA-256(eid))。
 * eid = device id = device finger（设备指纹）。拿到 SP[phc/eid] 的 eid 即可完全离线复现 hdid
 * （base64_std_nowrap(sha256(eid))，无需调 native）。本脚本专盯 c7.c.a / c7.c.b：
 *   - file=="phc" && key=="eid"  -> 这就是 hdid 的 hash 原料：完整打印【参数 + 调用栈】，并落 sign 表
 *   - 其它 phc.* 键（WATCH_PHC_ALL）-> 轻量一行（同一仓库常缓存 hdid 本身/其它指纹，顺手看）
 *
 * 用法:
 *   python host.py -p <包名> -s frida_hdid_capture.js --spawn   # 落 sign 表(kind=EID.sp.*) + 控制台高亮
 *   frida -U -n <包名> -l frida_hdid_capture.js                  # 仅控制台
 *
 * 提示: c7.c 是混淆名，换版本可能改。FRAMEWORK_FALLBACK 默认 true——若 c7.c 解析不到，会自动
 *       改从 Android SharedPreferences 框架层兜底（只盯 "phc" 文件，不依赖混淆名）。
 */

/* ===== 配置 ===== */
var TARGET_CLASS = 'c7.c';                 // 静态壳：a()=读 b()=写（混淆名，换版本可能变）
var PHC_FILE = 'phc';                      // SharedPreferences 文件名
var MATCH = [['phc', 'eid']];              // 完整记录(参数+栈)的 (file,key) 对——hdid 的 hash 原料
var WATCH_PHC_ALL = true;                  // 顺带轻量记录 phc 文件下其它键（看 hdid 缓存/兄弟指纹）
var FRAMEWORK_FALLBACK = true;             // c7.c 解析不到时，自动改用 Android SP 框架层兜底（只盯 phc）
var RETRY_MS = 700, RETRY_MAX = 40;

/* ===== 工具 ===== */
function safe(fn, d) { try { return fn(); } catch (e) { return d; } }
function emit(rec) { try { send({ type: 'sign', data: rec }); } catch (e) {} }
function str(a) { return (a == null) ? 'null' : '' + a; }
function clip(s, n) { s = str(s); return s.length > n ? s.substring(0, n) + '..(+' + (s.length - n) + 'B)' : s; }
function level(file, key) {              // 'full' / 'light' / null
    for (var i = 0; i < MATCH.length; i++) if (file === MATCH[i][0] && key === MATCH[i][1]) return 'full';
    if (WATCH_PHC_ALL && file === PHC_FILE) return 'light';
    return null;
}

Java.perform(function () {
    var Throwable = Java.use('java.lang.Throwable');
    var Log = Java.use('android.util.Log');
    function stk() { return safe(function () { return Log.getStackTraceString(Throwable.$new()); }, '(no stack)'); }

    /* 命中后的统一打印 + 落库（c7.c 路径与框架兜底路径共用） */
    function record(op, file, key, valOrDef, ret, lv) {
        var isWrite = (op === 'WRITE');
        var eidVal = isWrite ? valOrDef : ret;          // 真正的 eid 值（写=入参 value，读=返回值）

        if (lv === 'light') {                            // phc 下的其它键：轻量一行，不打栈
            console.log('[phc] ' + op + ' ' + file + '/' + key + ' ' +
                (isWrite ? '<- "' + clip(eidVal, 80) + '"' : '-> "' + clip(eidVal, 80) + '"'));
            emit({ kind: 'EID.sp.' + (isWrite ? 'write' : 'read'), input_txt: op + ' ' + file + '/' + key, out_b64: str(eidVal), matched: 0 });
            return;
        }

        /* full：hdid 的 hash 原料，完整参数 + 调用栈 */
        var s = stk();
        console.log('\n========== [hdid 原料] ' + op + ' SP ' + file + '/' + key + ' ==========');
        if (isWrite) {
            console.log('  写入 value = "' + str(valOrDef) + '"   (= 即将被 GenHash 的 eid)');
        } else {
            console.log('  读出 return = "' + str(ret) + '"   (default="' + str(valOrDef) + '")');
            console.log('  => hdid = Base64( SHA-256( 上面这个 eid ), NO_WRAP )   // GenHash 已确认=标准 SHA-256');
        }
        console.log('  ---- 调用栈 ----');
        console.log(s);
        console.log('==================================================\n');
        emit({
            kind: 'EID.sp.' + (isWrite ? 'write' : 'read'),
            algorithm: 'SharedPreferences',
            input_txt: op + ' ' + file + '/' + key + (isWrite ? '' : ' default=' + clip(valOrDef, 16)),
            out_b64: str(eidVal),
            target: 'hdid<-eid',
            matched: 1,
            stack: s
        });
    }

    /* ---------- 主路径：hook 混淆壳 c7.c.a / c7.c.b ---------- */
    function isSPsig(ov) {   // 只命中 (Context, String, String, String) 这个重载
        var t = ov.argumentTypes;
        return t && t.length === 4 &&
            t[1].className === 'java.lang.String' &&
            t[2].className === 'java.lang.String' &&
            t[3].className === 'java.lang.String';
    }
    function hookTarget() {
        var C = safe(function () { return Java.use(TARGET_CLASS); }, null);
        if (!C) return false;
        var hooked = 0;

        if (C.a && C.a.overloads) {                       // 读：a(ctx,file,key,def) -> String
            C.a.overloads.forEach(function (ov) {
                if (!isSPsig(ov)) return;
                ov.implementation = function (ctx, file, key, def) {
                    var ret = ov.call(this, ctx, file, key, def);
                    try { var lv = level('' + file, '' + key); if (lv) record('READ', '' + file, '' + key, def, ret, lv); } catch (e) {}
                    return ret;
                };
                hooked++;
            });
        }
        if (C.b && C.b.overloads) {                       // 写：b(ctx,file,key,value) -> void
            C.b.overloads.forEach(function (ov) {
                if (!isSPsig(ov)) return;
                ov.implementation = function (ctx, file, key, value) {
                    try { var lv = level('' + file, '' + key); if (lv) record('WRITE', '' + file, '' + key, value, null, lv); } catch (e) {}
                    return ov.call(this, ctx, file, key, value);
                };
                hooked++;
            });
        }
        if (hooked) console.log('[hdid] hooked ' + TARGET_CLASS + '.a/.b 共 ' + hooked +
            ' 个重载（盯 ' + JSON.stringify(MATCH) + (WATCH_PHC_ALL ? ' + phc.*' : '') + '）');
        return hooked > 0;
    }

    /* ---------- 兜底：Android SharedPreferences 框架层（不依赖混淆名，只盯 phc 文件 / eid 键） ---------- */
    function spFileName(impl) {   // 取 SharedPreferencesImpl.mFile 的文件名（如 "phc.xml"）
        return safe(function () {
            var fld = impl.getClass().getDeclaredField('mFile'); fld.setAccessible(true);
            var f = fld.get(impl);
            return f ? ('' + Java.cast(f, Java.use('java.io.File')).getName()) : null;
        }, null);
    }
    function spFileNameOfEditor(editor) {   // EditorImpl -> 外部类 this$0(=SharedPreferencesImpl) -> mFile
        return safe(function () {
            var fld = editor.getClass().getDeclaredField('this$0'); fld.setAccessible(true);
            var impl = fld.get(editor);
            return impl ? spFileName(impl) : null;
        }, null);
    }
    function fwAccess(op, fileXml, key, valOrDef, ret) {
        var file = fileXml ? ('' + fileXml).replace(/\.xml$/, '') : null;
        var lv;
        if (file != null) lv = level(file, key);                                   // 文件名取到了：正常过滤
        else lv = MATCH.some(function (p) { return p[1] === key; }) ? 'full' : null; // 取不到：退而按 key 命中 MATCH
        if (!lv) return;
        record(op, file || '(file?未确认)', key, valOrDef, ret, lv);
    }
    function hookFramework() {
        var SP = safe(function () { return Java.use('android.app.SharedPreferencesImpl'); }, null);
        var ED = safe(function () { return Java.use('android.app.SharedPreferencesImpl$EditorImpl'); }, null);
        if (!SP || !ED) { console.log('[hdid] 框架兜底失败：SharedPreferencesImpl 未解析'); return false; }
        if (SP.getString && SP.getString.overloads) {
            SP.getString.overloads.forEach(function (ov) {
                ov.implementation = function (key, def) {
                    var ret = ov.call(this, key, def);
                    try { fwAccess('READ', spFileName(this), '' + key, def, ret); } catch (e) {}
                    return ret;
                };
            });
        }
        if (ED.putString && ED.putString.overloads) {
            ED.putString.overloads.forEach(function (ov) {
                ov.implementation = function (key, value) {
                    try { fwAccess('WRITE', spFileNameOfEditor(this), '' + key, value, null); } catch (e) {}
                    return ov.call(this, key, value);
                };
            });
        }
        console.log('[hdid] 框架层兜底已装：SharedPreferencesImpl.getString / EditorImpl.putString（只盯 "' + PHC_FILE + '" 文件 / "eid" 键）');
        return true;
    }

    /* ---------- 安装：晚加载自动重试，失败自动兜底 ---------- */
    var done = false, tries = 0;
    (function attempt() {
        if (!done) done = safe(hookTarget, false);
        if (!done && ++tries <= RETRY_MAX) { setTimeout(function () { Java.perform(attempt); }, RETRY_MS); return; }
        if (!done) {
            console.log('[hdid] ' + TARGET_CLASS + ' 未解析（重试 ' + RETRY_MAX + ' 次后放弃）。');
            if (FRAMEWORK_FALLBACK) hookFramework();
            else console.log('[hdid] 把 FRAMEWORK_FALLBACK 设 true 可从框架层兜底（不依赖混淆名）。');
        }
    })();

    console.log('\n[*] hdid 原料(eid) SP 读写追踪已启动 —— 盯 ' + TARGET_CLASS + '.a/.b @ ' + JSON.stringify(MATCH) + '（落 sign 表 kind=EID.sp.*）。');
    console.log('[*] 进“家庭列表”等触发设备指纹的页面，或冷启动登录，即可看到 WRITE(生成落盘)/READ(取来算 hdid)。\n');
});
