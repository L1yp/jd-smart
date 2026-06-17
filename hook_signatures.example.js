/* ============================================================================
 * hook_signatures.example.js —— 通用 hook「方法签名列表」模板
 *
 * ★ 用法：复制本文件为 hook_signatures.js 再改（hook_signatures.js 已 .gitignore，不入库）★
 *     cp hook_signatures.example.js hook_signatures.js
 *   然后 host.py 加载核心脚本时会自动把 hook_signatures.js 注入进去（替换
 *   frida_generic_hook.js 里的 //__EXTERNAL_SIGNATURES__ 标记），改签名不必动核心脚本。
 *
 * ── 签名怎么写（每一项）──────────────────────────────────────────────────
 *   字符串形式（最常用）：
 *     'pkg.Clazz.method'                         hook 该方法的【全部重载】
 *     'pkg.Clazz.method(java.lang.String,int)'   只 hook【指定参数】的那个重载
 *     'pkg.Clazz.method()'                        只 hook【无参】重载
 *     'pkg.Clazz.$init'                           hook【构造函数】（全部重载）
 *     'pkg.Clazz.$init(android.content.Context)'  hook 指定参数的构造
 *     'pkg.Clazz.*'                               hook 该类【全部声明方法】（不含构造）
 *   对象形式（给单条加选项）：
 *     { sig: 'pkg.Clazz.method', stack: true, tag: 'login', stash: true }
 *       stack=true  -> 该条每次都抓调用栈（贵，按需开）
 *       tag='xxx'   -> 落库到 hook_log.tag，方便 SQL 过滤同一类调用
 *       stash=true  -> 命中时把 this/对象入参/对象返回 retain 进对象仓库，REPL 里用 RPC 调方法/读写字段
 *                      （rpc.exports.objs()/fields(id)/get(id,'f')/call(id,'m',[])/set(id,'f',v)）
 *   参数类型写法很宽松：全名 'java.lang.String' / 简名 'String' / 数组 'byte[]' 或 '[B' / 基本类型 'int' 都认。
 *
 *   ★ 内部类 / 构造函数注意 ★
 *     · 内部类名用 $ 连接：外部类 gf.b、内部类 a  ->  'gf.b$a'
 *     · 构造函数方法名是 $init，要用 . 跟类名分开：'gf.b$a.$init'（不能写成 'gf.b$a$init'）
 *     · 非静态内部类的构造，编译器自动加"外部类实例"作第 1 个参数（源码看不到）：
 *         源码 a(Bundle,Context,String,String) 实际 JVM 是
 *         a(gf.b, Bundle, Context, String, String)  —— 指定参数时要带上 gf.b
 *       （静态嵌套类 static class 没有这个合成参数）
 *
 * ── 跑 ──────────────────────────────────────────────────────────────────
 *   python host.py -p <包名> -s frida_generic_hook.js --spawn                 # 默认读 hook_signatures.js
 *   python host.py -p <包名> -s frida_generic_hook.js --sig-file other.js     # 换一份签名文件
 *
 *   不知道签名长啥样？frida REPL 里：rpc.exports.dump("com.jd.sec.LogoManager")
 * ========================================================================== */
var EXTERNAL_SIGNATURES = [
  // —— 删掉/保留这些示例，换成你要 hook 的方法 ——
  "com.jd.sec.LogoManager.getLogo", // 无参方法，hook 全部重载
  "com.foo.Bar.calc(java.lang.String,byte[])", // 指定参数重载
  "com.foo.Crypto.*", // 某类全部声明方法
  { sig: "com.foo.Net.send", stack: true, tag: "net" }, // 带调用栈 + 打标签

  // 非静态内部类的构造（gf.b 的内部类 a；首参 gf.b 是合成的外部类实例）
  {
    sig: "gf.b$a.$init(gf.b,android.os.Bundle,android.content.Context,java.lang.String,java.lang.String)",
    stack: true,
    tag: "ctor",
  },
];
