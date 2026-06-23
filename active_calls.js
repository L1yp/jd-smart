/* ============================================================================
 * active_calls.js —— 通用 hook 的「主动调用」外置模块（★ 加/改主动调用就改这个文件 ★）
 *
 * 配 frida_generic_hook.js 使用。host.py 加载核心脚本时，会把本文件内容自动注入进去
 * （--call-file 默认 active_calls.js；替换核心脚本里那行主动调用注入标记），所以加/改
 * 主动调用不必动核心脚本。
 *   注意：本文件自身别再出现那行注入标记的字面量，否则 host.py 会把它也当注入点 -> 自我注入炸裂。
 *
 * ── 什么是「主动调用」──────────────────────────────────────────────────────
 *   通用 hook 是「被动」等 App 自己调方法时拦截；主动调用是「我们主动」去 new 实例 / 调
 *   App 里的方法（如直接调网银 SDK 的 p7Envelope 算一个信封），离线复刻签名/加密时用。
 *   本文件现有：京东网银 CryptoUtils.p7Envelope 与 of.d.a 两套（互为对照 / 独立验证）。
 *
 * ── 注入后可直接用的核心脚本全局工具（不用重复实现）──────────────────────────
 *   getAppContext()        取 App Context（ActivityThread 优先，jd.wjlogin_sdk.common.b.a() 兜底）
 *   safe(fn, d)            try/catch 包一层，失败返回 d
 *   fmtVal(x)              值 -> {type,txt,hex,b64}（byte[] 同时给 txt/hex/b64）
 *   argStr(x)             单值 -> 完整字符串（byte[]->hex，不截断）
 *   emit(rec)             send(type=hook) 落 host.py 的 hook_log 表
 *   findField(klass,name) / getFieldVal(f,inst)   反射读字段（含父类/私有，setAccessible）
 *   curThread() / THREAD_NAME                     当前线程名 / 开关
 *   rpcVal(x)             RPC 返回归一（byte[]->{hex,b64,txt}；Java 对象入仓返回 {id,cls,repr}）
 *
 * ── 怎么加一个新的主动调用──────────────────────────────────────────────────
 *   1) 写个函数 callXxx(...)：里头 var ctx = getAppContext(); 取 Context，再
 *      Java.use("类").方法(...)；产出用 emit({...,tag:'xxx'}) 落库、return rpcVal(out)。
 *   2) registerActiveCall("xxx", function (a) { return callXxx(a); });
 *      -> 注入后自动并进 rpc.exports，REPL / host.py 里就有 rpc.exports.xxx(...)。
 *   3) 想启动后自动跑一次：registerActiveBoot(function () { ... setTimeout(...) });
 *      -> 核心脚本入口 Java.perform 里依次执行（standalone 没注入则整体不执行）。
 *
 * ── 现有 RPC / 落库 tag ────────────────────────────────────────────────────
 *   rpc.exports.p7envelope([content])  CryptoUtils.newInstance(ctx).p7Envelope(静态字段 of.d.a, content.getBytes())
 *   rpc.exports.ofda([content])        of.d.a(ctx, content.getBytes())  —— of.d 的方法 a(Context,byte[])
 *   rpc.exports.p7suite()              两者各连调 2 次，看输出是否稳定（一致=可重放；不一致=含时间戳/随机）
 *     content 省略=默认 com.jd.iots/CCO-RISK JSON；返回 {byteLen,hex,b64,txt}（byte[]）便于离线复用
 *   落库：原始输出 tag=p7（p7Envelope）/ tag=ofda（of.d.a），稳定性结论 tag=p7cmp。查：
 *     SELECT method,ret_txt,ret_hex FROM hook_log WHERE tag IN('p7','ofda','p7cmp') ORDER BY id DESC;
 *
 * ── 跑 ──────────────────────────────────────────────────────────────────
 *   python host.py -p <包名> -s frida_generic_hook.js --spawn         # 默认读 active_calls.js + hook_signatures.js
 *   python host.py -p <包名> -s frida_generic_hook.js --call-file other_calls.js   # 换一份主动调用文件
 *   standalone（frida -U -l frida_generic_hook.js）不注入本文件，主动调用 RPC 不可用，但通用 hook 照常。
 * ========================================================================== */

/* =======================================================================
 *  配置：调用目标类 / 默认 content / 自动触发开关
 * ======================================================================= */
var CU_CLASS = "com.wangyin.platform.CryptoUtils";
var KEY_CLASS = "of.d"; // 静态字段 of.d.a = p7Envelope 的 key（param1）
var P7_CONTENT =
  '{"appId":"com.jd.iots","bizId":"CCO-RISK","deviceInfo":{"sdk_version":"8.1.0"}}';

/* 自动触发（让走 host.py 无 REPL 也能拿到结果，不必手动调 rpc.exports.p7envelope）：
 *   AUTO_P7=false 则只保留手动 RPC 入口。--spawn 冷启动建议 DELAY ≥ 5000 给 SDK 初始化时间。 */
var AUTO_P7 = false;
var AUTO_P7_DELAY_MS = 6000; // 首次尝试前延迟
var AUTO_P7_RETRY_MS = 1500, // 类/Application 未就绪时的重试间隔
  AUTO_P7_RETRY_MAX = 40; // 重试次数上限

/* =======================================================================
 *  调用实现（复用核心脚本全局工具：getAppContext/safe/fmtVal/argStr/emit/
 *  findField/getFieldVal/curThread/THREAD_NAME/rpcVal）
 *
 *  com.wangyin.platform.CryptoUtils.newInstance(ctx).p7Envelope(key, content)
 *    - context ：getAppContext()——ActivityThread 优先，jd.wjlogin_sdk.common.b.a() 兜底
 *    - key     ：静态字段 of.d.a（反射读，规避「字段 a / 同名方法 a」歧义；含父类/私有）
 *    - content ：指定 JSON 的 String.getBytes()（Java 平台默认字符集，安卓=UTF-8）
 *  返回 p7Envelope 的结果（byte[] -> {byteLen,hex,b64,txt}），便于离线复用。
 * ======================================================================= */
function callP7Envelope(contentStr) {
  var res;
  Java.perform(function () {
    try {
      contentStr =
        contentStr === undefined || contentStr === null
          ? P7_CONTENT
          : "" + contentStr;

      var ctx = getAppContext();
      if (!ctx) {
        res =
          "[p7] 取不到 Context（ActivityThread / jd.wjlogin_sdk.common.b.a() 都失败）";
        console.log(res);
        return;
      }
      var C = safe(function () {
        return Java.use(CU_CLASS);
      }, null);
      if (!C) {
        res = "[p7] 类未加载: " + CU_CLASS + "（触发让其加载后再调）";
        console.log(res);
        return;
      }

      /* key = of.d 的静态字段 a（反射读，避开「字段 a / 方法 a」同名歧义；setAccessible 处理私有） */
      var KC = safe(function () {
        return Java.use(KEY_CLASS);
      }, null);
      if (!KC) {
        res = "[p7] key 类未加载: " + KEY_CLASS + "（触发让其加载后再调）";
        console.log(res);
        return;
      }
      var keyField = findField(KC.class, "a");
      if (!keyField) {
        res = "[p7] 找不到静态字段 " + KEY_CLASS + ".a";
        console.log(res);
        return;
      }
      var key = getFieldVal(keyField, null);

      /* content = "...".getBytes()（用真 Java String 的默认字符集字节，忠实复刻 .getBytes()） */
      var content = Java.use("java.lang.String").$new(contentStr).getBytes();

      /* newInstance(ctx).p7Envelope(key, content)（重载由 Frida 按实参类型自动解析） */
      var inst = C.newInstance(ctx);
      var out = inst.p7Envelope(key, content);

      var kf = fmtVal(key),
        of = fmtVal(out);
      console.log(
        "\n[p7] " + CU_CLASS + ".newInstance(ctx).p7Envelope(a, content)",
      );
      console.log("   ctx     = " + ctx);
      console.log(
        "   key(of.d.a) = " +
          (kf.txt === null ? "null" : kf.txt) +
          (kf.hex ? "  hex=" + kf.hex : "") +
          "  (" +
          kf.type +
          ")",
      );
      console.log("   content = " + contentStr);
      console.log(
        "   ret     = " +
          (of.txt === null ? "null" : of.txt) +
          (of.hex ? "  hex=" + of.hex : "") +
          (of.b64 ? "  b64=" + of.b64 : "") +
          "  (" +
          of.type +
          ")",
      );

      /* 落库：send(type=hook) -> host.py 写 hook_log 表 + 打印一行（tag=p7 便于过滤）。
         这样走 host.py（无 REPL）也能拿到结果，不必手动调。 */
      var a0 = argStr(key),
        a1 = contentStr;
      emit({
        clazz: CU_CLASS,
        method: "p7Envelope",
        sig: "(via newInstance(ctx))",
        is_static: 0,
        is_native: 0,
        tag: "p7",
        arg0: a0,
        arg1: a1,
        args: "a0(key)=" + (a0 === null ? "null" : a0) + " | a1(content)=" + a1,
        ret_type: of.type,
        ret_txt: of.txt,
        ret_hex: of.hex,
        ret_b64: of.b64,
        thread: THREAD_NAME ? curThread() : null,
        stack: null,
      });
      res = rpcVal(out);
    } catch (e) {
      res = "[p7] 调用失败: " + e + "\n" + (e.stack || "");
      console.log(res);
    }
  });
  return res;
}

/* of.d.a(ctx, content)——of.d 的方法 a(Context,byte[])（与 p7Envelope 对照 / 独立验证）。
 * 默认按「静态方法」调（of.d.a(...) 的写法即静态）；落库 tag=ofda。 */
function callOfdA(contentStr) {
  var res;
  Java.perform(function () {
    try {
      contentStr =
        contentStr === undefined || contentStr === null
          ? P7_CONTENT
          : "" + contentStr;

      var ctx = getAppContext();
      if (!ctx) {
        res =
          "[ofda] 取不到 Context（ActivityThread / jd.wjlogin_sdk.common.b.a() 都失败）";
        console.log(res);
        return;
      }
      var KC = safe(function () {
        return Java.use(KEY_CLASS);
      }, null);
      if (!KC) {
        res = "[ofda] 类未加载: " + KEY_CLASS + "（触发让其加载后再调）";
        console.log(res);
        return;
      }

      var content = Java.use("java.lang.String").$new(contentStr).getBytes();
      var out = KC.a(ctx, content); // of.d.a(Context, byte[])（重载按实参类型自动解析）

      var rv = fmtVal(out);
      console.log("\n[ofda] " + KEY_CLASS + ".a(ctx, content)");
      console.log("   content = " + contentStr);
      console.log(
        "   ret     = " +
          (rv.txt === null ? "null" : rv.txt) +
          (rv.hex ? "  hex=" + rv.hex : "") +
          (rv.b64 ? "  b64=" + rv.b64 : "") +
          "  (" +
          rv.type +
          ")",
      );
      emit({
        clazz: KEY_CLASS,
        method: "a",
        sig: "(Context,byte[])",
        is_static: 0,
        is_native: 0,
        tag: "ofda",
        arg0: "ctx",
        arg1: contentStr,
        args: "a0=ctx | a1(content)=" + contentStr,
        ret_type: rv.type,
        ret_txt: rv.txt,
        ret_hex: rv.hex,
        ret_b64: rv.b64,
        thread: THREAD_NAME ? curThread() : null,
        stack: null,
      });
      res = rpcVal(out);
    } catch (e) {
      res = "[ofda] 调用失败: " + e + "\n" + (e.stack || "");
      console.log(res);
    }
  });
  return res;
}

/* 把 rpcVal 结果归一成「可比较字符串」：byte[]->hex；基本类型->原值；对象->repr */
function cmpKey(r) {
  if (r === null || r === undefined) return "null";
  var t = typeof r;
  if (t === "string" || t === "number" || t === "boolean") return "" + r;
  if (r.hex) return r.hex;
  if (r.b64) return r.b64;
  if (r.txt) return r.txt;
  if (r.repr !== undefined) return "" + r.repr;
  return JSON.stringify(r);
}

/* 一个调用连发 2 次的结论：打印 + 落库（tag=p7cmp）是否一致 */
function reportPair(name, clazz, k1, k2) {
  var same = k1 === k2;
  console.log(
    "\n[p7][" +
      name +
      "] 连调 2 次 -> " +
      (same
        ? "结果一致 ✓（确定性，可整块重放）"
        : "结果不一致 ✗（每次变化：含时间戳/随机/nonce）"),
  );
  console.log("   #1 = " + k1);
  console.log("   #2 = " + k2);
  emit({
    clazz: clazz,
    method: name + " x2",
    sig: same ? "(stable)" : "(changes)",
    is_static: 0,
    is_native: 0,
    tag: "p7cmp",
    arg0: k1,
    arg1: k2,
    args: "#1=" + k1 + " | #2=" + k2,
    ret_type: "compare",
    ret_txt: same ? "SAME" : "DIFF",
    ret_hex: null,
    ret_b64: null,
    thread: THREAD_NAME ? curThread() : null,
    stack: null,
  });
  return same;
}

/* 套件：p7Envelope 与 of.d.a 各连调 2 次，看各自输出是否稳定（每次原始结果也各自落库） */
function p7Suite() {
  console.log("\n[p7] ===== p7Envelope / of.d.a 各连调 2 次，看输出是否稳定 =====");
  var a1 = cmpKey(callP7Envelope());
  var a2 = cmpKey(callP7Envelope());
  reportPair("p7Envelope", CU_CLASS, a1, a2);
  var b1 = cmpKey(callOfdA());
  var b2 = cmpKey(callOfdA());
  reportPair("of.d.a", KEY_CLASS, b1, b2);
  console.log("[p7] ============================================================\n");
}

/* 启动后自动调一次：等 CryptoUtils 类 + Application 都就绪再触发（晚加载自动重试） */
function autoP7() {
  var tries = 0;
  (function attempt() {
    var ready = false;
    Java.perform(function () {
      ready =
        !!safe(function () {
          return Java.use(CU_CLASS);
        }, null) &&
        !!safe(function () {
          return Java.use(KEY_CLASS);
        }, null) &&
        !!getAppContext();
    });
    if (ready) {
      console.log(
        "[p7] 自动触发：p7Envelope 与 of.d.a 各连调 2 次比对（关：AUTO_P7=false；重调：rpc.exports.p7suite()）",
      );
      safe(function () {
        p7Suite();
      });
      return;
    }
    if (++tries <= AUTO_P7_RETRY_MAX) setTimeout(attempt, AUTO_P7_RETRY_MS);
    else
      console.log(
        "[p7] 放弃自动触发：" +
          CU_CLASS +
          " / Application 一直未就绪（在 App 里操作让 SDK 加载，或 rpc.exports.p7envelope() 手动调）",
      );
  })();
}

/* =======================================================================
 *  注册：把上面的主动调用挂进 rpc.exports（核心脚本 Object.keys(ACTIVE_RPC) 合并）
 * ======================================================================= */
registerActiveCall("p7envelope", function (content) {
  return callP7Envelope(content);
});
registerActiveCall("ofda", function (content) {
  return callOfdA(content);
});
registerActiveCall("p7suite", function () {
  p7Suite();
  return "done（看 console；查库：SELECT method,ret_txt,ret_hex FROM hook_log WHERE tag IN('p7','ofda','p7cmp') ORDER BY id DESC）";
});

/* 自启动：AUTO_P7=true 时启动后自动跑一次套件（核心脚本入口 Java.perform 里执行） */
registerActiveBoot(function () {
  if (!AUTO_P7) return;
  console.log(
    "[p7] " +
      AUTO_P7_DELAY_MS +
      "ms 后自动调：p7Envelope 与 of.d.a 各连调 2 次比对，结果落 hook_log(tag=p7/ofda/p7cmp)",
  );
  setTimeout(autoP7, AUTO_P7_DELAY_MS);
});
