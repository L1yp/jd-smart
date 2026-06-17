/* ============================================================================
 * hook_signatures.js —— 通用 hook 的「方法签名列表」（★ 平时只改这个文件 ★）
 *
 * 配 frida_generic_hook.js 使用。host.py 加载核心脚本时，会把本文件内容自动注入进去
 * （替换核心脚本里的 //__EXTERNAL_SIGNATURES__ 标记），所以改签名不必动核心脚本。
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
 *     { sig: 'pkg.Clazz.method', stack: true, tag: 'login' }
 *       stack=true  -> 该条每次都抓调用栈（贵，按需开）
 *       tag='xxx'   -> 落库到 hook_log.tag，方便 SQL 过滤同一类调用
 *   参数类型写法很宽松：全名 'java.lang.String' / 简名 'String' / 数组 'byte[]' 或 '[B' / 基本类型 'int' 都认。
 *
 * ── 用法 ────────────────────────────────────────────────────────────────
 *   python host.py -p <包名> -s frida_generic_hook.js --spawn      # 默认读本文件
 *   python host.py -p <包名> -s frida_generic_hook.js --sig-file other_sigs.js   # 换一份签名文件
 *
 *   不知道签名长啥样？frida REPL 里：rpc.exports.dump("com.jd.sec.LogoManager")
 * ========================================================================== */
var EXTERNAL_SIGNATURES = [
  // —— 在这里增删你要 hook 的方法 ——
  "com.jd.sec.LogoManager.getLogo", // 示例：无参方法，hook 全部重载
  // 'com.foo.Bar.calc(java.lang.String,byte[])',          // 指定参数重载
  // 'com.foo.Crypto.*',                                   // 某类全部方法
  // { sig: 'com.foo.Net.send', stack: true, tag: 'net' }, // 带调用栈 + 打标签
];
