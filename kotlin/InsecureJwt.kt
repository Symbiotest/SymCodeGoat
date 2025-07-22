import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.security.Keys
import java.security.Key
import java.util.*

class InsecureJwt {
    // VULNERABLE: Hardcoded secret key
    private val SECRET_KEY: String = "insecure-secret-key-12345"
    
    // VULNERABLE: Using weak algorithm (HS256 with short key)
    fun createInsecureToken(username: String): String {
        return Jwts.builder()
            .setSubject(username)
            .setIssuedAt(Date())
            .setExpiration(Date(System.currentTimeMillis() + 1000 * 60 * 60)) // 1 hour
            .signWith(Keys.hmacShaKeyFor(SECRET_KEY.toByteArray()), SignatureAlgorithm.HS256)
            .compact()
    }
    
    // Secure implementation
    fun createSecureToken(username: String, secretKey: Key): String {
        return Jwts.builder()
            .setSubject(username)
            .setIssuedAt(Date())
            .setExpiration(Date(System.currentTimeMillis() + 1000 * 60 * 15)) // 15 minutes
            .signWith(secretKey, SignatureAlgorithm.HS256)
            .compact()
    }
    
    // VULNERABLE: Token verification without proper validation
    fun verifyInsecureToken(token: String): Boolean {
        return try {
            Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY.toByteArray())
                .build()
                .parseClaimsJws(token)
            true
        } catch (e: Exception) {
            false
        }
    }
    
    // Secure token verification
    fun verifySecureToken(token: String, secretKey: Key): Boolean {
        return try {
            val claims = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .body
                
            // Additional validation
            val now = Date()
            claims.notBefore?.let { notBefore ->
                if (now.before(notBefore)) {
                    return false
                }
            }
            
            claims.expiration.after(now)
        } catch (e: Exception) {
            false
        }
    }
}

// Example usage
fun main() {
    val jwt = InsecureJwt()
    
    // Insecure usage
    val insecureToken = jwt.createInsecureToken("admin")
    println("Insecure token: $insecureToken")
    println("Insecure token valid: ${jwt.verifyInsecureToken(insecureToken)}")
    
    // Secure usage
    val secureKey = Keys.secretKeyFor(SignatureAlgorithm.HS256)
    val secureToken = jwt.createSecureToken("admin", secureKey)
    println("\nSecure token: $secureToken")
    println("Secure token valid: ${jwt.verifySecureToken(secureToken, secureKey)}")
}
