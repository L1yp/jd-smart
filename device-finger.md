# 生成初始eid

```http

POST https://sdkfp.jd.com/ds.json
Content-Type: application/json

{"data":"AKS*_*MIAGCSqGSIb3DQEHA6CAMIACAQAxggGSMIIBjgIBADB2MF4xGDAWBgNVBAMMD1dhbmdZaW4gVXNlciBDQTEfMB0GA1UECwwWV2FuZ1lpbiBTZWN1cml0eUNlbnRlcjEUMBIGA1UECgwLV2FuZ1lpbi5jb20xCzAJBgNVBAYTAkNOAhRv1qEBtyng9uYoK4ZGz4ZoGs8wGDANBgkqhkiG9w0BAQEFAASCAQAGkvwBX44NVMjNMg07OGkDqwtLv8Z3tFdgQbxCAEaej006xv+L5HAV8Rk3lPj2r0/Zyi0FTDSHAq1ScfILN7SNA1aHtOpUk69oWE0k3D8p+z7zZ68Wi/kZB/Zez9w1hUYdfn3tEd6xK03qkZVJprsPmENPSBHJIAElFktjJB9N3K+mqQJWPLg7bTVpaFVnUJTuiOb0bR3fLijtGMd5QeHoqoVAMG+JmM25XFLyMlw6b1bXxb64oZRk4H1Dm4hQzxGdktiwDn637oQkOLU8qiMAGExV1B0hWud+ywLG46oaD5WOesufoSUjQyTUxJm9XTXMAWG+LcFbOcHStWv6z67hMIAGCSqGSIb3DQEHATAUBggqhkiG9w0DBwQITltaxq/qStCggARQ04gwTdsuljjSYYqVw1NTtGnJ5PxJztlVKVAwnSCRYAIgDilqF2XpeTEJsPw3RtpCbb1gDUPIK27VDe+kGW8/xrcisn3LF8iorjZipfoVz5cAAAAAAAAAAAAA","visaType":"1"}

HTTP/2 200 OK
date: Wed, 17 Jun 2026 09:36:26 GMT
content-type: application/json;charset=UTF-8
server: jfe
strict-transport-security: max-age=86400
x-http2-stream-id: 3
transfer-encoding: chunked

{
  "code": "1",
  "msg": "SUCCESS",
  "time": 1781688986834,
  "data": {
    "token": "jdd024okz5cN2qEM9GbKRg89CGSnoIjyv4hOk03JC3m4NpLZrlwsYmAhG6PL6Dh9UJDTy0b7lVOsrclGDIpK9IA0ZgPj8XQu1tTPpuYQYvG9x109LMu7O0Z7yNSczIZ9tkh7QowuKwmDNLbB01234567",
    "appHash": 0,
    "ccoToken": "eidA17c5823KtkxcM3UaDQc977eaFq6Z102juFNRlBaituh7Szr2DpgKj3DydHdroJXWx3vNJiSuWzrBcUGmsNxWXcWEP2gKSdT8ol9CcfEp3qs3Yh2Ml5q9I87ZaB9pVcvOO85XdcZOPkaLw5yit4Ic2"
  }
}
```

## 构造body的data参数

### 加密函数

```java
package of;

import android.content.Context;
import com.wangyin.platform.CryptoUtils;

public class d {

    public static String f51672a = "MIIESTCCAzGgAwIBAgIUb9ahAbcp4PbmKCuGRs+GaBrPMBgwDQYJKoZIhvcNAQELBQAwXjEYMBYGA1UEAwwPV2FuZ1lpbiBVc2VyIENBMR8wHQYDVQQLDBZXYW5nWWluIFNlY3VyaXR5Q2VudGVyMRQwEgYDVQQKDAtXYW5nWWluLmNvbTELMAkGA1UEBhMCQ04wHhcNMTgwODI5MTAyOTE2WhcNMTkwODI5MTAyOTE2WjCBlDF0MHIGA1UEAwxr5Lqs5Lic6YeR6J6NLeaKgOacr+eglOWPkemDqC3kuKrkurrkuJrliqHnu7zlkIjnoJTlj5Hpg6gt6aOO5o6n56CU5Y+R6YOoLeaZuuiDveivhuWIq+WunumqjOWupChBS1MwMDAwMEFLUykxDzANBgNVBAsMBmpyIHRvcDELMAkGA1UECgwCamQwggEgMA0GCSqGSIb3DQEBAQUAA4IBDQAwggEIAoIBAQC40b+9fdJRXY+AOdC5I3mfwZVFWMzpc+8CSBseuMdKEX57stGoKAVilElvUVCM4amrBqb90/18Ji9fQ+Ra/hiOxjsaDkhrMkSwi1b+VT4Zg3orn/Gpt9/A7UpfRCZlhKVTI370k6vfTZgKtXOtowDtksPLhYffu/vJbCuSN2gMq0WmZ55WWXWE6QRB/0r9nOtBjjs6Ebsj3M99TUbZtgt6MKsOmsK9bfyYiNhZdq2L7F77JcbM7ZRil//xI4ET5ks1hYzrt4rXrg26ATLZhkjSmsDTuuMfk1QkqIRLlQdIDuaWpU6rTg8u8lUDsTSd2gsk71EAaeP2dfWaL60++ZDHAgEDo4HJMIHGMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgbAMGwGA1UdHwRlMGMwYaBfoF2GW2h0dHA6Ly90b3BjYS5kLmNoaW5hYmFuay5jb20uY24vcHVibGljL2l0cnVzY3JsP0NBPTFFRTQ1QjcxNkQwOUE0OTI4MkIxMzQ2QTJDQzNDNjI3MzExMzgwRUIwHwYDVR0jBBgwFoAUCKxvAe67vsOUVzpp1dx/r34ctOAwHQYDVR0OBBYEFOxwX51lfkiPGzdSHJp/aoWEy7yGMA0GCSqGSIb3DQEBCwUAA4IBAQAQFz4OkKRmF1eahWwFes7ZMLmYuc+wc1Jfa166Ylefjb79zu3p+P+Acb07hhbKioHIdsw6IszzYqMntmP9OfCAkXhxEmAeZNAgsHdw5aIoD4Uzg0pD7oVKjCaStFsadaPUa3vVJR/grKFAQRPunsGC8pLb8X2WjBOeYLZNgAwUhrtJZzjeog+zYvQRo55Ed/kXVHrdgSVA9vCmhKwnmRhe6kzJj7GUikqm4GdQhjJIfkV/0eULsrLEhM+dHn4qKDdZzNBIa/AEQDpC9pmD8ZnIzxAAdeuPOhOuv/DyCvQwIv4KymYASHIl4ouMOYV8hPgau2W5H4bUyPKbz4HiM/Gf";

    public static String a(Context context, byte[] bArr) {
        if (bArr != null) {
            try {
                byte[] p7Envelope = CryptoUtils.newInstance(context).p7Envelope(f51672a, bArr);
                byte[] bArr2 = new byte[p7Envelope.length - 5];
                System.arraycopy(p7Envelope, 0, new byte[5], 0, 5);
                System.arraycopy(p7Envelope, 5, bArr2, 0, p7Envelope.length - 5);
                return "AKS*_*" + f.a(bArr2);
            } catch (Exception unused) {
            }
        }
        return "";
    }
}
```

### 调用堆栈

```stack
of.d.a(Context,byte[]) [static]  #1
   arg0 = com.jd.smart.JDApplication@f7eecc9
   arg1 = {"appId":"com.jd.iots","bizId":"CCO-RISK","deviceInfo":{"sdk_version":"8.1.0"}}
   ret  = AKS*_*MIICIQYJKoZIhvcNAQcDoIICEjCCAg4CAQAxggGSMIIBjgIBADB2MF4xGDAWBgNVBAMMD1dhbmdZaW4gVXNlciBDQTEfMB0GA1UECwwWV2FuZ1lpbiBTZWN1cml0eUNlbnRlcjEUMBIGA1UECgwLV2FuZ1lpbi5jb20xCzAJBgNVBAYTAkNOAhRv1qEBtyng9uYoK4ZGz4ZoGs8wGDANBgkqhkiG9w0BAQEFAASCAQCRKAph5Rq92+OFhrE3Awhmklgp6ip19r/grHTMqSvFbbzw1TTEQQlF+Rat8kEriH7T2QeDcc6TM3pI2WfwNTlwasikYSCMVZRZqJj0sSIT7SkqN5pcoWSxIo1dpvq2cT1lpFviqURPsGYwGF/HlmD1h11ANsdDjVSAPNbi8pJO2bEJXKUnppP5xhZdlCKc6SbNKIIFPHrRs++2zIxHTwh6Gu0nmVQd+jipq6UIkxPgm9eO3mEJED571fwBDO8BfOqkvzR+im+DDNCuYknPJhbsIY72ESJIvQKu0UHpX6tvQdkjBARkN8hjK0KhUKBvE1ZmGUKI9QOprMF30tpm1/r9MHMGCSqGSIb3DQEHATAUBggqhkiG9w0DBwQIpbrpV5FAkIeAUOjqZXjGjBkyXBzW2V5KLj+tDSBzWI7eEzUBjKua45syyo4vg5RJvqZMROoWuU+FeeBWcuFjFCYhMPtpYFj6J8zAtc0iq2suj2gJdfqy7VFQ  (String)
java.lang.Throwable
        at of.d.a(Native Method)
        at ef.c.h(Unknown Source:57)
        at ef.h.f(Unknown Source:2)
        at ff.a.m(Unknown Source:30)
        at ff.a.i(Unknown Source:1)
        at ff.a$c.run(Unknown Source:17)
        at java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1167)
        at java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:641)
        at java.lang.Thread.run(Thread.java:784)
```

### kotlin实现代码

```kotlin
// import org.bouncycastle.cms.CMSAlgorithm
// import org.bouncycastle.cms.CMSEnvelopedDataGenerator
// import org.bouncycastle.cms.CMSProcessableByteArray
// import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder
// import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator
// import org.bouncycastle.jce.provider.BouncyCastleProvider
// import java.io.ByteArrayOutputStream
// import java.security.Security
// import java.security.cert.CertificateFactory
// import java.security.cert.X509Certificate
// import java.util.Base64

object P7Envelope {

    private const val STATUS_OK = "00000"   // native success code; errors are "%5d" formatted

    init {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    /**
     * com.wangyin.platform.CryptoUtils.newInstance(context).p7Envelope(f51672a, bArr)
     * Reproduce NativeP7Envelope(String key, byte[] content) -> byte[].
     *
     * @param key     Base64 of the DER-encoded recipient X.509 certificate (the app constant).
     * @param content plaintext bytes to envelope.
     * @return        ASCII "00000" status code + DER of the PKCS#7 EnvelopedData.
     */
    fun nativeP7Envelope(key: String, content: ByteArray): ByteArray {
        // 1) key is the Base64 of a DER recipient certificate.
        //    Jce* recipient generators need a JDK java.security.cert.X509Certificate
        //    (the Bc* lightweight generators are the ones that take X509CertificateHolder).
        //    Use the BC provider's factory: it is more lenient with this cert's
        //    over-length CN (107 chars) than the default SUN parser.
        val certDer = Base64.getDecoder().decode(key)
        val cert = CertificateFactory
            .getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME)
            .generateCertificate(certDer.inputStream()) as X509Certificate

        val generator = CMSEnvelopedDataGenerator()

        // 2) recipient: RSA key transport (RSAES-PKCS1-v1_5) by issuerAndSerialNumber.
        //    JceKeyTransRecipientInfoGenerator uses rsaEncryption + issuerAndSerialNumber,
        //    matching OpenSSL's PKCS7_encrypt.
        generator.addRecipientInfoGenerator(
            JceKeyTransRecipientInfoGenerator(cert)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
        )

        // 3) content encryption algorithm: 3DES-CBC (DES-EDE3-CBC, OID 1.2.840.113549.3.7).
        //    BC generates a fresh random 24-byte CEK + 8-byte IV and PKCS#7-pads the content.
        val encryptor = JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC)
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .build()

        // 4+5) build + DER-encode the PKCS#7 EnvelopedData
        val enveloped = generator.generate(CMSProcessableByteArray(content), encryptor)
        val p7Der = enveloped.encoded   // == i2d_PKCS7(...)

        // 6) native prepends a 5-byte ASCII status code ("00000" == success)
        return ByteArrayOutputStream(STATUS_OK.length + p7Der.size).apply {
            write(STATUS_OK.toByteArray(Charsets.US_ASCII))
            write(p7Der)
        }.toByteArray()
    }

    // Convenience: strip the 5-byte status prefix to get the raw PKCS#7 DER.
    fun payloadOf(result: ByteArray): ByteArray = result.copyOfRange(5, result.size)
    fun statusOf(result: ByteArray): String = String(result, 0, 5, Charsets.US_ASCII)
}
```

```kotlin

/**
 * of.d.a(Context, String, byte[])
 */
fun buildDeviceFingerReqData(key: String, content: ByteArray): String {
    val ret = P7Envelope.nativeP7Envelope(key, content)
    println(ret.toHexString())
    val buffer = ret.copyOfRange(5, ret.size)
    val b64b = encodeBytesToBytes(buffer, 0, buffer.size, 0)
    return "AKS*_*" + b64b.toString(Charsets.US_ASCII)
}

/*
 * 名称对照(原代码是混淆过的):
 *   i(...)  -> encodeBytesToBytes(...)
 *   a       -> Base64 的 OutputStream 类(构造参数: 下游流 + options)
 *   e(...)  -> encode3to4(...)   把 3 个输入字节编码成 4 个 Base64 字节
 *
 * options 标志位(Robert Harder Base64 的标准常量):
 *   ENCODE         = 1
 *   GZIP           = 2
 *   DO_BREAK_LINES = 8
 *   MAX_LINE_LENGTH= 76
 *   NEW_LINE       = '\n' (10)
 */
private const val ENCODE = 1
private const val GZIP = 2
private const val DO_BREAK_LINES = 8
private const val MAX_LINE_LENGTH = 76
private const val NEW_LINE: Byte = '\n'.code.toByte()


/**
 * of.f.a(byte[])
 * of.e.b(byte[])
 * of.e.c(byte[] content,int pos,int len,int options)
 * of.e.i(byte[] content,int pos,int len,int options)
 */
fun encodeBytesToBytes(source: ByteArray?, off: Int, len: Int, options: Int): ByteArray {
    requireNotNull(source) { "Cannot serialize a null array." }
    require(off >= 0) { "Cannot have negative offset: $off" }
    require(len >= 0) { "Cannot have length offset: $len" }
    require(off + len <= source.size) {
        String.format(
            "Cannot have offset of %d and length of %d with array of length %d",
            off, len, source.size
        )
    }

    // 需要 GZIP 压缩?
    if ((options and GZIP) != 0) {
        val baos = ByteArrayOutputStream()
        // 关闭最外层流会级联关闭 b64os(写出 Base64 收尾)和 baos
        GZIPOutputStream(Base64OutputStream(baos), options.or(ENCODE)).use { gzos ->
            gzos.write(source, off, len)
        }
        return baos.toByteArray()
    }

    // 否则不压缩,直接写进缓冲区,不必走流
    val breakLines = (options and DO_BREAK_LINES) != 0

    var encLen = (len / 3) * 4 + if (len % 3 > 0) 4 else 0
    if (breakLines) {
        encLen += encLen / MAX_LINE_LENGTH
    }
    val outBuff = ByteArray(encLen)

    var d = 0            // 源数组游标
    var e = 0            // 输出缓冲游标
    var lineLength = 0
    val len2 = len - 2
    while (d < len2) {
        encode3to4(source, d + off, 3, outBuff, e, options)
        lineLength += 4
        if (breakLines && lineLength >= MAX_LINE_LENGTH) {
            outBuff[e + 4] = NEW_LINE
            e++
            lineLength = 0
        }
        d += 3
        e += 4
    }

    // 处理剩余不足 3 个的字节
    if (d < len) {
        encode3to4(source, d + off, len - d, outBuff, e, options)
        e += 4
    }

    // 估算长度偏大时裁剪
    return if (e <= outBuff.size - 1) {
        outBuff.copyOf(e)
    } else {
        outBuff
    }
}


// 选项标志位(与前一个文件保持一致;这里补充字母表相关的两个)
private const val URL_SAFE = 16
private const val ORDERED = 32

private const val EQUALS_SIGN: Byte = '='.code.toByte()

// 标准 Base64 字母表
private val STANDARD_ALPHABET: ByteArray =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        .toByteArray(StandardCharsets.US_ASCII)

// URL/文件名安全字母表(把 + / 换成 - _)
private val URL_SAFE_ALPHABET: ByteArray =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        .toByteArray(StandardCharsets.US_ASCII)

// 有序字母表(编码结果保持 ASCII 升序)
private val ORDERED_ALPHABET: ByteArray =
    "-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz"
        .toByteArray(StandardCharsets.US_ASCII)

private fun getAlphabet(options: Int): ByteArray = when {
    (options and URL_SAFE) == URL_SAFE -> URL_SAFE_ALPHABET
    (options and ORDERED) == ORDERED -> ORDERED_ALPHABET
    else -> STANDARD_ALPHABET
}

/**
 * of.e.e(byte[] bArr, int i10, int i11, byte[] bArr2, int i12, int i13)
 * 把 source 中从 srcOffset 开始的 numSigBytes(1~3)个有效字节,
 * 编码成 4 个 Base64 字节写入 destination 的 destOffset 处。
 * 对应混淆代码里的 e(...)。
 */
private fun encode3to4(
    source: ByteArray,
    srcOffset: Int,
    numSigBytes: Int,
    destination: ByteArray,
    destOffset: Int,
    options: Int
): ByteArray {
    val alphabet = getAlphabet(options)

    // 把最多 3 个字节塞进一个 int 的低 24 位(不足的补 0)。
    // 先左移 24 再无符号右移,是为了清掉 byte->int 符号扩展带出来的高位 1。
    val inBuff =
        (if (numSigBytes > 0) ((source[srcOffset].toInt() shl 24) ushr 8) else 0) or
                (if (numSigBytes > 1) ((source[srcOffset + 1].toInt() shl 24) ushr 16) else 0) or
                (if (numSigBytes > 2) ((source[srcOffset + 2].toInt() shl 24) ushr 24) else 0)

    when (numSigBytes) {
        3 -> {
            destination[destOffset] = alphabet[inBuff ushr 18]
            destination[destOffset + 1] = alphabet[(inBuff ushr 12) and 0x3f]
            destination[destOffset + 2] = alphabet[(inBuff ushr 6) and 0x3f]
            destination[destOffset + 3] = alphabet[inBuff and 0x3f]
        }
        2 -> {
            destination[destOffset] = alphabet[inBuff ushr 18]
            destination[destOffset + 1] = alphabet[(inBuff ushr 12) and 0x3f]
            destination[destOffset + 2] = alphabet[(inBuff ushr 6) and 0x3f]
            destination[destOffset + 3] = EQUALS_SIGN
        }
        1 -> {
            destination[destOffset] = alphabet[inBuff ushr 18]
            destination[destOffset + 1] = alphabet[(inBuff ushr 12) and 0x3f]
            destination[destOffset + 2] = EQUALS_SIGN
            destination[destOffset + 3] = EQUALS_SIGN
        }
    }
    return destination
}

```

> 调用例子
```kotlin
fun main(args: Array<String>) {
    val key = "MIIESTCCAzGgAwIBAgIUb9ahAbcp4PbmKCuGRs+GaBrPMBgwDQYJKoZIhvcNAQELBQAwXjEYMBYGA1UEAwwPV2FuZ1lpbiBVc2VyIENBMR8wHQYDVQQLDBZXYW5nWWluIFNlY3VyaXR5Q2VudGVyMRQwEgYDVQQKDAtXYW5nWWluLmNvbTELMAkGA1UEBhMCQ04wHhcNMTgwODI5MTAyOTE2WhcNMTkwODI5MTAyOTE2WjCBlDF0MHIGA1UEAwxr5Lqs5Lic6YeR6J6NLeaKgOacr+eglOWPkemDqC3kuKrkurrkuJrliqHnu7zlkIjnoJTlj5Hpg6gt6aOO5o6n56CU5Y+R6YOoLeaZuuiDveivhuWIq+WunumqjOWupChBS1MwMDAwMEFLUykxDzANBgNVBAsMBmpyIHRvcDELMAkGA1UECgwCamQwggEgMA0GCSqGSIb3DQEBAQUAA4IBDQAwggEIAoIBAQC40b+9fdJRXY+AOdC5I3mfwZVFWMzpc+8CSBseuMdKEX57stGoKAVilElvUVCM4amrBqb90/18Ji9fQ+Ra/hiOxjsaDkhrMkSwi1b+VT4Zg3orn/Gpt9/A7UpfRCZlhKVTI370k6vfTZgKtXOtowDtksPLhYffu/vJbCuSN2gMq0WmZ55WWXWE6QRB/0r9nOtBjjs6Ebsj3M99TUbZtgt6MKsOmsK9bfyYiNhZdq2L7F77JcbM7ZRil//xI4ET5ks1hYzrt4rXrg26ATLZhkjSmsDTuuMfk1QkqIRLlQdIDuaWpU6rTg8u8lUDsTSd2gsk71EAaeP2dfWaL60++ZDHAgEDo4HJMIHGMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgbAMGwGA1UdHwRlMGMwYaBfoF2GW2h0dHA6Ly90b3BjYS5kLmNoaW5hYmFuay5jb20uY24vcHVibGljL2l0cnVzY3JsP0NBPTFFRTQ1QjcxNkQwOUE0OTI4MkIxMzQ2QTJDQzNDNjI3MzExMzgwRUIwHwYDVR0jBBgwFoAUCKxvAe67vsOUVzpp1dx/r34ctOAwHQYDVR0OBBYEFOxwX51lfkiPGzdSHJp/aoWEy7yGMA0GCSqGSIb3DQEBCwUAA4IBAQAQFz4OkKRmF1eahWwFes7ZMLmYuc+wc1Jfa166Ylefjb79zu3p+P+Acb07hhbKioHIdsw6IszzYqMntmP9OfCAkXhxEmAeZNAgsHdw5aIoD4Uzg0pD7oVKjCaStFsadaPUa3vVJR/grKFAQRPunsGC8pLb8X2WjBOeYLZNgAwUhrtJZzjeog+zYvQRo55Ed/kXVHrdgSVA9vCmhKwnmRhe6kzJj7GUikqm4GdQhjJIfkV/0eULsrLEhM+dHn4qKDdZzNBIa/AEQDpC9pmD8ZnIzxAAdeuPOhOuv/DyCvQwIv4KymYASHIl4ouMOYV8hPgau2W5H4bUyPKbz4HiM/Gf"
    val content = "{\"appId\":\"com.jd.iots\",\"bizId\":\"CCO-RISK\",\"deviceInfo\":{\"sdk_version\":\"8.1.0\"}}".toByteArray()

    val data = (buildDeviceFingerReqData(key, content))
    println("data = $data")
}
```

## 保存token/ccoToken/time
```json
{
  "code": "1",
  "msg": "SUCCESS",
  "time": 1781688986834,
  "data": {
    "token": "jdd024okz5cN2qEM9GbKRg89CGSnoIjyv4hOk03JC3m4NpLZrlwsYmAhG6PL6Dh9UJDTy0b7lVOsrclGDIpK9IA0ZgPj8XQu1tTPpuYQYvG9x109LMu7O0Z7yNSczIZ9tkh7QowuKwmDNLbB01234567",
    "appHash": 0,
    "ccoToken": "eidA17c5823KtkxcM3UaDQc977eaFq6Z102juFNRlBaituh7Szr2DpgKj3DydHdroJXWx3vNJiSuWzrBcUGmsNxWXcWEP2gKSdT8ol9CcfEp3qs3Yh2Ml5q9I87ZaB9pVcvOO85XdcZOPkaLw5yit4Ic2"
  }
}
```

### 使用ccoToken和time生成device finger(Cookie)
```kotlin
object PayloadCodec {

    // 布局 A：[5字节前缀(丢弃)][载荷][8字节后缀(保留)]
    private const val A_DROP_PREFIX_LEN = 5
    private const val A_KEEP_SUFFIX_LEN = 8

    // 布局 B：[8字节头(保留)][2字节分隔(丢弃)][载荷]
    private const val B_KEEP_HEADER_LEN = 8
    private const val B_PAYLOAD_OFFSET = 10   // 8字节头 + 2字节分隔

    private const val A_MARKER = "jdd01"
    private const val B_MARKER = "81"

    private val base62 = Base62(Base62.STANDARD)

    /** 核心变换：Base62 解码 → 异或 key → 转字符串。 */
    private fun decodePayload(payload: ByteArray, key: Int, charset: String): String =
        XorCipher.toString(base62.decode(payload), key, charset)

    private fun normalizeKey(key: String): Int = (key.toLong() % 255).toInt()

    /**
     * 布局 A：丢弃前缀、保留后缀。
     * 输出："jdd01" + 变换(载荷) + 原末8字节
     */
    fun decodeWithSuffix(input: String?, key: String, charset: String): String {
        if (input.isNullOrEmpty()) return ""
        return runCatching {
            val k = normalizeKey(key)
            val bytes = input.toByteArray(charset(charset))
            val payload = bytes.copyOfRange(A_DROP_PREFIX_LEN, bytes.size - A_KEEP_SUFFIX_LEN)
            val suffix = bytes.copyOfRange(bytes.size - A_KEEP_SUFFIX_LEN, bytes.size)
            A_MARKER + decodePayload(payload, k, charset) + String(suffix, charset(charset))
        }.getOrDefault("")
    }

    /**
     * 布局 B：保留头部、跳过分隔。
     * 输出：原前8字节 + "81" + 变换(载荷)
     */
    fun decodeWithHeader(input: String?, key: String, charset: String): String {
        if (input.isNullOrEmpty()) return ""
        return runCatching {
            val k = normalizeKey(key)
            val bytes = input.toByteArray(charset(charset))
            val header = bytes.copyOfRange(0, B_KEEP_HEADER_LEN)
            val payload = bytes.copyOfRange(B_PAYLOAD_OFFSET, bytes.size)
            String(header, charset(charset)) + B_MARKER + decodePayload(payload, k, charset)
        }.getOrDefault("")
    }
}

fun main() {
    val deviceFinger = PayloadCodec.decodeWithHeader(ccoToken, time.toString(), "UTF-8")
    println("deviceFinger: $deviceFinger")
}
```