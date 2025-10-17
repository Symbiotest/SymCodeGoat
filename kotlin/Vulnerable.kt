import java.security.MessageDigest
import org.apache.commons.codec.digest.DigestUtils

public class WeakHashes {
  public fun sha1(password: String): Array<Byte> {
      // ruleid: use-of-sha1
      var sha1Digest: MessageDigest = MessageDigest.getInstance("SHA1")
      sha1Digest.update(password.getBytes())
      val hashValue: Array<Byte> = sha1Digest.digest()
      return hashValue
  }
  public fun sha1b(password: String): Array<Byte> {
      // ruleid: use-of-sha1
      var sha1Digest: MessageDigest = MessageDigest.getInstance("SHA-1")
      sha1Digest.update(password.getBytes())
      val hashValue: Array<Byte> = sha1Digest.digest()
      return hashValue
  }
  public fun sha1_digestutil(password: String): Array<Byte> {
    // ruleid: use-of-sha1
    val hashValue: Array<Byte> = DigestUtils.getSha1Digest().digest(password.getBytes())
    return hashValue
  }
}

import java.lang.Runtime

class Cls {
    public fun test1(plainText: String): Array<Byte> {
        // ruleid: no-null-cipher
        // nosymbiotic: SYM_JAVA_0026 -fp
        val doNothingCipher: Cipher = NullCipher()
        //The ciphertext produced will be identical to the plaintext.
        val cipherText: Cipher = doNothingCihper.doFinal(plainText)
        return cipherText
    }

    public fun test2(plainText: String): Void {
        // ok: no-null-cipher
        val cipher: Cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val cipherText: Array<Byte> = cipher.doFinal(plainText)
        return cipherText
    }
}

public class CookieController {
    public fun setCookie(value: String, response: HttpServletResponse) {
        val cookie: Cookie = Cookie("cookie", value)
        // ruleid: cookie-missing-httponly
        response.addCookie(cookie)
    }

    public fun setSecureCookie(value: String, response: HttpServletResponse) {
        val cookie: Cookie = Cookie("cookie", value)
        cookie.setSecure(true)
        // ruleid: cookie-missing-httponly
        response.addCookie(cookie)
    }

    public fun setSecureHttponlyCookie(value: String, response: HttpServletResponse ) {
        val cookie: Cookie = Cookie("cookie", value)
        cookie.setSecure(true)
        cookie.setHttpOnly(true)
        // ok: cookie-missing-httponly
        response.addCookie(cookie)
    }

    public fun explicitDisable(value: String, response: HttpServletResponse) {
        val cookie: Cookie = Cookie("cookie", value)
        cookie.setSecure(false)
        // ruleid:cookie-missing-httponly
        cookie.setHttpOnly(false)
        response.addCookie(cookie)
    }
}

package testcode.crypto

import java.io.UnsupportedEncodingException
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

public class BadHexa {
    public fun main(args: Array<String>): Void {
        val good: String = goodHash("12345")
        val bad: String = badHash("12345")
        System.out.println(String.format("%s (len=%d) != %s (len=%d)", good, good.length(), bad, bad.length()))
    }

    // ok: bad-hexa-conversion
    public fun goodHash(password: String): String {
        val md: MessageDigest = MessageDigest.getInstance("SHA-1")
        val resultBytes: Array<Byte> = md.digest(password.getBytes("UTF-8"))

        var stringBuilder: StringBuilder = StringBuilder()
        for (b in resultBytes) {
            stringBuilder.append(String.format("%02X", b))
        }

        return stringBuilder.toString()
    }

    // ruleid: bad-hexa-conversion
    public fun badHash(password: String): String {
        val md: MessageDigest = MessageDigest.getInstance("SHA-1")
        val resultBytes: Array<Byte> = md.digest(password.getBytes("UTF-8"))

        var stringBuilder: StringBuilder = StringBuilder()
        for (b in resultBytes) {
            stringBuilder.append(Integer.toHexString(b and 0xFF))
        }

        return stringBuilder.toString()
    }
}