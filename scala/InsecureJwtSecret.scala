package com.example.auth

import java.time.Instant
import java.util.Date
import pdi.jwt.{Jwt, JwtAlgorithm, JwtClaim, JwtHeader, JwtOptions}
import play.api.libs.json.{JsObject, Json}
import scala.util.{Try, Success, Failure}

/**
 * Authentication service for handling JWT tokens
 * WARNING: This implementation contains security vulnerabilities for demonstration purposes
 */
class AuthService {
  // Insecure: Hardcoded secret key
  private val SECRET_KEY = "insecure-secret-key-12345!@#$%^&*()"
  
  // Insecure: Using a weak algorithm
  private val ALGORITHM = JwtAlgorithm.HS256
  
  // Insecure: No token expiration or other standard claims
  def createToken(userId: String, userRole: String = "user"): String = {
    val header = JwtHeader(ALGORITHM)
    
    // Create claims with minimal validation
    val claims = JwtClaim(
      content = Json.obj(
        "userId" -> userId,
        "role" -> userRole
      ).toString(),
      issuer = Some("insecure-app"),
      subject = Some(userId),
      audience = Some(Set("web-app")),
      expiration = Some(Instant.now.plusSeconds(30 * 24 * 60 * 60).getEpochSecond), // 30 days
      notBefore = Some(Instant.now.getEpochSecond),
      issuedAt = Some(Instant.now.getEpochSecond)
    )
    
    Jwt.encode(header, claims, SECRET_KEY)
  }
  
  // Insecure: Basic validation without proper security checks
  def validateToken(token: String): Try[JwtClaim] = {
    Jwt.decodeRaw(token, SECRET_KEY, Seq(ALGORITHM)) match {
      case Success(claimJson) =>
        val claim = JwtClaim(claimJson)
        
        // Minimal validation
        if (claim.isExpired) {
          Failure(new SecurityException("Token has expired"))
        } else if (claim.notBefore.exists(_ > Instant.now.getEpochSecond)) {
          Failure(new SecurityException("Token not yet valid"))
        } else {
          Success(claim)
        }
      case Failure(e) => Failure(e)
    }
  }
  
  // Insecure: No rate limiting or brute force protection
  def login(username: String, password: String): Option[String] = {
    // Insecure: Hardcoded credentials
    val validCredentials = Map(
      "admin" -> "admin123",
      "user" -> "password123"
    )
    
    validCredentials.get(username).filter(_ == password).map { _ =>
      // Insecure: Using the same secret key for all users
      createToken(username, if (username == "admin") "admin" else "user")
    }
  }
  
  // Insecure: No proper session management
  def getUserFromToken(token: String): Option[String] = {
    validateToken(token).toOption.flatMap { claim =>
      Try(Json.parse(claim.content).as[JsObject].value("userId").as[String]).toOption
    }
  }
  
  // Insecure: No token invalidation mechanism
  def logout(token: String): Boolean = {
    // In a real application, we would invalidate the token here
    true
  }
}

/**
 * Secure alternative implementation (for reference)
 */
class SecureAuthService(secretKey: String) {
  private val ALGORITHM = JwtAlgorithm.HS512 // Stronger algorithm
  private val TOKEN_EXPIRATION_SECONDS = 3600 // 1 hour
  
  // Secure token generation with proper claims and expiration
  def createToken(userId: String, roles: Set[String]): String = {
    val claims = JwtClaim(
      content = Json.obj(
        "userId" -> userId,
        "roles" -> roles
      ).toString(),
      issuer = Some("secure-app"),
      subject = Some(userId),
      audience = Some(Set("web-app")),
      expiration = Some(Instant.now.plusSeconds(TOKEN_EXPIRATION_SECONDS).getEpochSecond),
      notBefore = Some(Instant.now.getEpochSecond),
      issuedAt = Some(Instant.now.getEpochSecond),
      jwtId = Some(java.util.UUID.randomUUID.toString)
    )
    
    Jwt.encode(claims, secretKey, ALGORITHM)
  }
  
  // Secure token validation with proper error handling
  def validateToken(token: String): Try[JwtClaim] = {
    Jwt.decode(
      token,
      secretKey,
      Seq(ALGORITHM),
      JwtOptions("secure-app", Set("web-app"), leeway = 60)
    )
  }
}
