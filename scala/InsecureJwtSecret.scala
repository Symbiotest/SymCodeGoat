// VULNERABLE: Hardcoded JWT Secret
import pdi.jwt.{Jwt, JwtAlgorithm}

object InsecureJwtExample {
  // Hardcoded secret key - This is insecure!
  private val SECRET_KEY = "your-secret-key-here-12345"
  
  def createToken(payload: String): String = {
    Jwt.encode(payload, SECRET_KEY, JwtAlgorithm.HS256)
  }
  
  def validateToken(token: String): Boolean = {
    Jwt.isValid(token, SECRET_KEY, Seq(JwtAlgorithm.HS256))
  }
}
