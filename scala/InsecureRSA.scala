// VULNERABLE: RSA without OAEP padding
import javax.crypto.Cipher
import java.security.KeyPairGenerator
import java.util.Base64

object InsecureRSAExample {
  // Generate RSA key pair
  private val keyGen = KeyPairGenerator.getInstance("RSA")
  keyGen.initialize(2048)
  private val keyPair = keyGen.generateKeyPair()
  
  // VULNERABLE: Using RSA without OAEP padding
  def encrypt(plaintext: String): String = {
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding") // Insecure!
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic)
    val encrypted = cipher.doFinal(plaintext.getBytes("UTF-8"))
    Base64.getEncoder.encodeToString(encrypted)
  }
  
  // Secure alternative using OAEP
  def secureEncrypt(plaintext: String): String = {
    val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding") // Secure
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic)
    val encrypted = cipher.doFinal(plaintext.getBytes("UTF-8"))
    Base64.getEncoder.encodeToString(encrypted)
  }
}
