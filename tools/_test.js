// 自检：抽取 index.html 的 <script id="jdt-core"> 实体，eval 后对照已知向量。
// 运行： node tools/_test.js   （全绿即工具内核与 Python/标准向量逐字节一致）
const fs = require("fs");
const path = require("path");

const html = fs.readFileSync(path.join(__dirname, "index.html"), "utf8");
const m = html.match(/<script id="jdt-core">([\s\S]*?)<\/script>/);
if (!m) { console.error("找不到 jdt-core 脚本块"); process.exit(1); }
// eslint-disable-next-line no-eval
eval(m[1]);
const J = globalThis.JDT;

let pass = 0, fail = 0;
function eq(name, got, want) {
  if (String(got) === String(want)) { pass++; console.log("  ok  " + name); }
  else { fail++; console.log("  FAIL " + name + "\n       got=" + got + "\n       want=" + want); }
}

// ---- 哈希基本向量 ----
eq("md5(abc)",        J.md5Hex("abc"),   "900150983cd24fb0d6963f7d28e17f72");
eq("md5(empty)",      J.md5Hex(""),      "d41d8cd98f00b204e9800998ecf8427e");
eq("md5(device_md167)", J.md5Hex("Android1.17.0HWI-AL009:167"), "e84234f734bc44ff581d6316ce5fee72");
eq("sha1(abc)",       J.sha1Hex("abc"),  "a9993e364706816aba3e25717850c26c9cd0d89d");
eq("sha256(abc)",     J.sha256Hex("abc"),"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

// 长输入跨块（>64B）
const long = "a".repeat(200);
eq("sha256(200a)", J.sha256Hex(long), require("crypto").createHash("sha256").update(long).digest("hex"));
eq("md5(200a)",    J.md5Hex(long),    require("crypto").createHash("md5").update(long).digest("hex"));
eq("sha1(200a)",   J.sha1Hex(long),   require("crypto").createHash("sha1").update(long).digest("hex"));

// ---- HMAC 向量 ----
eq("hmac-sha256(fox,key)",
   J.bytesToHex(J.hmacSha256(J.utf8("key"), J.utf8("The quick brown fox jumps over the lazy dog"))),
   "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
eq("hmac-sha1(RFC2202)",
   J.bytesToHex(J.hmacSha1(new Uint8Array(20).fill(0x0b), J.utf8("Hi There"))),
   "b617318655057264e28bc0b6fb378c8ef146be00");
eq("hmac-sha256(longkey>64B)",
   J.bytesToHex(J.hmacSha256(J.utf8("A".repeat(100)), J.utf8("data"))),
   "7310a9f98b5981a0e1148a2f39fdcf001ad2d33391ff7ad6efa121dfda888f64");

// ---- ciphertype:5 对照 test.http / color_codec.py ----
const C5 = {
  "YW5ucw9fZK==":"android", "d2vwaG==":"wifi", "Czqn":"381", "CJK4CMeyCJYm":"1080*2160",
  "IPdTBUPCCNK=":"HWI-AL00", "Ctq=":"28", "IPVLV0VT":"HUAWEI", "CI4nDy4m":"1.17.0",
  "oQfxdy1rbwHyb2vu":"xjgw-android", "oyTmcxD0YXHvStesCMT9":'{"prstate":"0"}',
  "ZWY0CwUmENGzYtY5Ctq0CJq1Ztu5ZwTvYwZvCJPsDNO=":"ef42e0843b69284185f99fbebfe11b41",
  "oyTmYWdvU2v6ZIS6CJKmBMTmYWdvStenpG==":'{"pageSize":100,"page":1}'
};
Object.keys(C5).forEach(function(c){
  eq("c5decode("+c.slice(0,12)+"…)", J.c5decStr(c), C5[c]);
  // 往返：encode(decode(x)) === x
  eq("c5 roundtrip "+c.slice(0,8), J.c5encode(J.c5decode(c)), c);
});
// 字节往返 0..255
const allb = new Uint8Array(256); for (let i=0;i<256;i++) allb[i]=i;
eq("c5 byte roundtrip", J.bytesToHex(J.c5decode(J.c5encode(allb))), J.bytesToHex(allb));

// ---- 彩虹 preimage 对照 color_sign.py 的 selftest ----
const syn = {};
J.COLOR_DEVICE_KEYS.forEach(function(k){ syn[k]=k.toUpperCase(); });
syn.functionId="FN"; syn.body="{}"; syn.t="123";
eq("color preimage(synthetic)", J.buildColorPreimage(syn),
   "AID&APPID&AREA&{}&BUILD&CLIENT&CLIENTVERSION&D_BRAND&D_MODEL&EID&EXT&FN&NETWORKTYPE&OSVERSION&PARTNER&SCREEN&123&UUID");
// colorSign 走 HMAC-SHA256（key-as-text）—— 用 fox 向量再确认一次链路
eq("colorSign==hmac256", J.colorSign("The quick brown fox jumps over the lazy dog","key"),
   "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");

// ---- 旧接口签名 组装 + base64（对照 Python 预算值）----
const r = J.oldSign({
  key:"testkey123", seg1:"seg1abc", deviceMd:"deadbeef", ts:"2026-01-01T00:00:00.000Z", feedId:"1"
});
eq("oldSign body",  r.body,  '{"json":{"feed_id":1,"version":"2.0","digest":""}}');
eq("oldSign message", r.message,
   'deadbeefpostjson_body{"json":{"feed_id":1,"version":"2.0","digest":""}}2026-01-01T00:00:00.000Zseg1abcdeadbeef');
eq("oldSign seg2(b64)", r.seg2, "pnpc1S0u8VJ39bowcSz9fWripuY=");
eq("oldSign authorization", r.authorization, "smart seg1abc:::pnpc1S0u8VJ39bowcSz9fWripuY=:::2026-01-01T00:00:00.000Z");

// ---- device_md 组装 ----
eq("oldDeviceMd(167)", J.oldDeviceMd("1.17.0","HWI-AL00","9",167), "e84234f734bc44ff581d6316ce5fee72");

// ---- 信封解析（用 test.http 的 body 信封片段，URL 编码） ----
const bodyEnv = '%7B%22ts%22%3A1781595290996%2C%22ridx%22%3A1%2C%22cipher%22%3A%7B%22body%22%3A%22oyTmYWdvU2v6ZIS6CJKmBMTmYWdvStenpG%3D%3D%22%7D%2C%22ciphertype%22%3A5%2C%22version%22%3A%221.2.0%22%2C%22appname%22%3A%22com.jd.iots%22%7D';
const env = J.decodeEnvelope(bodyEnv);
eq("envelope decode body", env.decoded.body, '{"pageSize":100,"page":1}');
eq("envelope meta ciphertype", env.meta.ciphertype, 5);

// ---- 标准 base64 / hex ----
eq("stdb64(hello)", J.bytesToB64(J.utf8("hello")), "aGVsbG8=");
eq("b64decode(roundtrip)", J.fromUtf8(J.b64ToBytes(J.bytesToB64(J.utf8("hi there 你好")))), "hi there 你好");

console.log("\n" + (fail===0 ? "全部通过 ✓ ("+pass+")" : (fail+" 个失败 / "+pass+" 通过")));
process.exit(fail===0 ? 0 : 1);
