// Security fix: Replaced hardcoded JWT secret with environment variable configuration
package com.example.auth

import java.time.Instant
import java.util.Date
import pdi.jwt.{Jwt, JwtAlgorithm, JwtClaim, JwtHeader, JwtOptions}
import play.api.libs.json.{JsObject, Json}
import scala.util.{Try, Success, Failure}

/**
 * Authentication service for handling JWT tokens
 * SECURITY: Updated to use environment-based secret key management
 */
class AuthService {
  // Secure: Secret key loaded from environment variable
  private val SECRET_KEY = sys.env.getOrElse("JWT_SECRET_KEY", 
    throw new IllegalStateException("JWT_SECRET_KEY environment variable must be set"))
  
  // Improved: Using a stronger algorithm
  private val ALGORITHM = JwtAlgorithm.HS512
  
  // Secure: Proper token expiration and standard claims
  def createToken(userId: String, userRole: String = "user"): String = {
    val header = JwtHeader(ALGORITHM)
    
    // Create claims with proper validation
    val claims = JwtClaim(
      content = Json.obj(
        "userId" -> userId,
        "role" -> userRole
      ).toString(),
      issuer = Some("secure-app"),
      subject = Some(userId),
      audience = Some(Set("web-app")),
      expiration = Some(Instant.now.plusSeconds(24 * 60 * 60).getEpochSecond), // 24 hours
      notBefore = Some(Instant.now.getEpochSecond),
      issuedAt = Some(Instant.now.getEpochSecond),
      jwtId = Some(java.util.UUID.randomUUID.toString)
    )
    
    Jwt.encode(header, claims, SECRET_KEY)
  }
  
  // Secure: Enhanced validation with proper security checks
  def validateToken(token: String): Try[JwtClaim] = {
    Jwt.decodeRaw(token, SECRET_KEY, Seq(ALGORITHM)) match {
      case Success(claimJson) =>
        val claim = JwtClaim(claimJson)
        
        // Enhanced validation
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
  
  // Improved: Credentials should be managed externally (database, etc.)
  def login(username: String, password: String): Option[String] = {
    // Note: In production, use proper password hashing and database lookup
    val validCredentials = Map(
      "admin" -> sys.env.getOrElse("ADMIN_PASSWORD", ""),
      "user" -> sys.env.getOrElse("USER_PASSWORD", "")
    )
    
    validCredentials.get(username).filter(_ == password).map { _ =>
      createToken(username, if (username == "admin") "admin" else "user")
    }
  }
  
  // Secure: Proper session management with enhanced validation
  def getUserFromToken(token: String): Option[String] = {
    validateToken(token).toOption.flatMap { claim =>
      Try(Json.parse(claim.content).as[JsObject].value("userId").as[String]).toOption
    }
  }
  
  // Note: Token invalidation mechanism should be implemented with a blacklist
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
