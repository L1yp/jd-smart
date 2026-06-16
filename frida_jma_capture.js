'use strict';

/*
 * frida_jma_capture.js —— getHouses 的真正鉴权层：Cookie 里的 JMA / 设备指纹
 *
 * 抓包发现 getHouses 靠两个 Cookie 鉴权（设备级稳定值，不是每请求签名）：
 *   whwswswws = <jmafinger UUID>                               # JMA 软设备 id，一次生成持久化
 *   unionwsws = {"devicefinger":"eidA005...","jmafinger":"<同上UUID>"}
 *                          └ eid，来自 com.jd.sec.LogoManager.getLogo()（jdguard native 生成、缓存）
 *
 * 战略（重要）：eid 往下是 BiometricManager -> jdguard native，**别逆**。
 *   eid / UUID 都是设备级稳定值 -> 正确打法是「抓一次、替换重放」，不是复现算法。
 *   eid 仅在状态位 substring(8,10)=="41"（残缺态）时会重生成 -> 抓一个 !=41 的“好 eid”即可长期用。
 *
 * 本脚本只 hook 输出边界 + 拼装点，全部 send() 落 host.py sign 表（kind=JMA.*）：
 *   1) com.jd.sec.LogoManager.getLogo()                 -> 拿 eid(devicefinger) + 状态位 + 栈
 *   2) *BiometricManager.getCacheTokenByBizId(...)       -> 确认“读缓存”+ bizId 三参（自动发现类名）
 *   3) org.json.JSONObject.put("devicefinger"/"jmafinger") -> unionwsws 拼装点 + 栈
 *   4) okhttp3.Request$Builder.header/addHeader(Cookie)  -> cookie 落到请求那一刻 + 栈
 *
 * 用法:
 *   python host.py -p <包名> -s frida_jma_capture.js --spawn
 *
 * 找 UUID 从哪存（whwswswws/jmafinger 的持久化）：
 *   先用本脚本抓到 UUID 值，再把它填进 frida_trace_secret_src.js 的 TARGETS 跑一遍，
 *   命中 MMKV/SharedPreferences 的 getString/putString 即其存储点（京东系多走 MMKV）。
 */

/* ===== 配置 ===== */
var LOGO_CLASS = 'com.jd.sec.LogoManager';
var BIOMETRIC_CANDIDATES = [          // getCacheTokenByBizId 所在类；留空项触发自动发现
    'com.jd.sec.BiometricManager',
    'com.jingdong.jdsdk.utils.BiometricManager'
];
var COOKIE_NAMES = ['whwswswws', 'unionwsws'];   // 关心的 cookie 名（出现在值里也算）
var UNION_KEYS = ['devicefinger', 'jmafinger'];  // unionwsws JSON 的键
var RETRY_MS = 700, RETRY_MAX = 40;

/* ===== 工具 ===== */
function safe(fn, d) { try { return fn(); } catch (e) { return d; } }
function emit(rec) { try { send({ type: 'sign', data: rec }); } catch (e) {} }

Java.perform(function () {
    var Throwable = Java.use('java.lang.Throwable');
    var Log = Java.use('android.util.Log');
    function stk() { return safe(function () { return Log.getStackTraceString(Throwable.$new()); }, '(no stack)'); }
    var seen = {};
    function once(tag, s) { var k = tag + '|' + s.split('\n').slice(0, 8).join('|'); var f = !seen[k]; if (f) seen[k] = 1; return f; }

    /* 1) LogoManager.getLogo() -> eid(devicefinger) */
    function hookLogo(LM) {
        if (!LM.getLogo || !LM.getLogo.overloads) { console.log('[jma] ' + LOGO_CLASS + '.getLogo 不存在'); return; }
        LM.getLogo.overloads.forEach(function (ov) {
            ov.implementation = function () {
                var ret = ov.apply(this, arguments);
                try {
                    if (typeof ret === 'string' && ret.length) {
                        var eid = ret, status = (eid.length >= 10) ? eid.substring(8, 10) : '?';
                        var s = stk(), first = once('getLogo', s);
                        console.log('\n@@@@@@@@@@ JMA devicefinger(eid) @ LogoManager.getLogo @@@@@@@@@@');
                        console.log(' eid    = ' + eid);
                        console.log(' len=' + eid.length + '  status[8:10]=' + status + (status === '41' ? '  <== 41=残缺态，会触发重生成' : '  (有效)'));
                        if (first) console.log(s); else console.log(' (调用栈同前次，省略)');
                        console.log('@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n');
                        emit({ kind: 'JMA.getLogo(devicefinger)', input_txt: 'status[8:10]=' + status, out_b64: eid, stack: s, matched: 1 });
                    }
                } catch (e) {}
                return ret;
            };
        });
        console.log('[jma] hooked ' + LOGO_CLASS + '.getLogo x' + LM.getLogo.overloads.length);
    }

    /* 2) *BiometricManager.getCacheTokenByBizId(bizId, c, b) -> 确认读缓存 */
    function hookBiometric(cls, BM) {
        var m = BM.getCacheTokenByBizId;
        if (!m || !m.overloads) return false;
        m.overloads.forEach(function (ov) {
            ov.implementation = function () {
                var ret = ov.apply(this, arguments);
                try {
                    var args = []; for (var i = 0; i < arguments.length; i++) args.push('' + arguments[i]);
                    var s = stk();
                    console.log('\n[jma] ' + cls + '.getCacheTokenByBizId(' + args.join(', ') + ')\n      -> ' + ret);
                    emit({ kind: 'JMA.cacheToken', input_txt: 'args=' + args.join(' | '), out_b64: (ret == null ? null : '' + ret), stack: (once('cache', s) ? s : null), matched: 1 });
                } catch (e) {}
                return ret;
            };
        });
        console.log('[jma] hooked ' + cls + '.getCacheTokenByBizId x' + m.overloads.length);
        return true;
    }

    /* 3) unionwsws JSON 拼装：JSONObject.put("devicefinger"/"jmafinger") */
    function hookUnionJson() {
        var JO = safe(function () { return Java.use('org.json.JSONObject'); }, null);
        if (!JO || !JO.put) { console.log('[jma] JSONObject.put 未解析，跳过 unionwsws 追踪'); return; }
        JO.put.overloads.forEach(function (ov) {
            ov.implementation = function () {
                var ret = ov.apply(this, arguments);
                try {
                    var k = '' + arguments[0];
                    if (UNION_KEYS.indexOf(k) !== -1) {
                        var self = this, full = safe(function () { return '' + self.toString(); }, '?'), s = stk();
                        if (once('union:' + k, s)) {
                            console.log('\n##### unionwsws 拼装 @ JSONObject.put("' + k + '", …) #####');
                            console.log(' value = ' + arguments[1]);
                            console.log(' obj   = ' + (full.length > 300 ? full.substring(0, 300) + '..' : full));
                            console.log(s);
                            console.log(' ↑ 紧贴 org.json 之前的 App 帧 = 拼 unionwsws 的地方');
                            console.log('#######################################################\n');
                        }
                        emit({ kind: 'JMA.union.' + k, input_txt: '' + arguments[1], out_b64: full, stack: s, matched: 1 });
                    }
                } catch (e) {}
                return ret;
            };
        });
        console.log('[jma] hooked org.json.JSONObject.put（盯 ' + JSON.stringify(UNION_KEYS) + '）');
    }

    /* 4) Cookie 落到请求那一刻：Request$Builder.header/addHeader */
    function hookCookieHeader() {
        var RB = safe(function () { return Java.use('okhttp3.Request$Builder'); }, null);
        if (!RB) { console.log('[jma] okhttp3.Request$Builder 未解析（okhttp 被混淆？）'); return; }
        function matchCookie(name, val) {
            if (('' + name).toLowerCase() === 'cookie') return true;
            for (var i = 0; i < COOKIE_NAMES.length; i++) if (('' + val).indexOf(COOKIE_NAMES[i]) !== -1) return true;
            return false;
        }
        ['header', 'addHeader'].forEach(function (mn) {
            var m = RB[mn]; if (!m || !m.overloads) return;
            m.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    try {
                        if (arguments.length >= 2 && matchCookie(arguments[0], arguments[1])) {
                            var s = stk();
                            if (once('cookie:' + mn, s)) {
                                console.log('\n##### Cookie 头设置 @ Request$Builder.' + mn + ' #####');
                                console.log(' ' + arguments[0] + ' = ' + arguments[1]);
                                console.log(s);
                                console.log('####################################################\n');
                            }
                            emit({ kind: 'JMA.cookie', input_txt: '' + arguments[0], out_b64: '' + arguments[1], stack: s, matched: 1 });
                        }
                    } catch (e) {}
                    return ov.apply(this, arguments);
                };
            });
        });
        console.log('[jma] hooked okhttp3.Request$Builder.header/addHeader（盯 Cookie / ' + JSON.stringify(COOKIE_NAMES) + '）');
    }

    /* ---- 统一安装：晚加载的类自动重试 ---- */
    var done = { logo: false, bio: false, json: false, cookie: false };
    try { hookUnionJson(); done.json = true; } catch (e) { console.log('[jma] unionJson 安装失败: ' + e); }
    try { hookCookieHeader(); done.cookie = true; } catch (e) { console.log('[jma] cookie 安装失败: ' + e); }

    var tries = 0;
    (function attempt() {
        if (!done.logo) {
            var LM = safe(function () { return Java.use(LOGO_CLASS); }, null);
            if (LM) { try { hookLogo(LM); } catch (e) { console.log('[jma] logo 安装失败: ' + e); } done.logo = true; }
        }
        if (!done.bio) {
            for (var i = 0; i < BIOMETRIC_CANDIDATES.length && !done.bio; i++) {
                var BM = safe(function () { return Java.use(BIOMETRIC_CANDIDATES[i]); }, null);
                if (BM && safe(function () { return hookBiometric(BIOMETRIC_CANDIDATES[i], BM); }, false)) done.bio = true;
            }
        }
        if ((!done.logo || !done.bio) && ++tries <= RETRY_MAX) { setTimeout(function () { Java.perform(attempt); }, RETRY_MS); return; }
        if (!done.logo) console.log('[jma] 放弃：' + LOGO_CLASS + ' 未加载（版本可能改名）');
        if (!done.bio) {
            console.log('[jma] 未命中 BiometricManager 候选，自动枚举 *BiometricManager* 供你填 BIOMETRIC_CANDIDATES：');
            Java.enumerateLoadedClasses({
                onMatch: function (n) { if (n.indexOf('BiometricManager') !== -1 && (n.indexOf('com.jd') !== -1 || n.indexOf('com.jingdong') !== -1)) console.log('   ' + n); },
                onComplete: function () { console.log('[jma] 枚举完成。'); }
            });
        }
    })();

    console.log('\n[*] JMA/设备指纹 cookie 分析已启动（落 sign 表，kind=JMA.*）。');
    console.log('[*] 触发一次 getHouses（进“家庭列表”页），看 eid / cookie / unionwsws 拼装。\n');
});
