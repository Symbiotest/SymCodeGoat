package com.example.web.controllers

import play.api.mvc._
import play.api.libs.json._
import play.api.libs.ws.WSClient
import play.api.Configuration
import javax.inject._
import scala.concurrent.{ExecutionContext, Future}
import java.sql.{Connection, DriverManager, Statement, ResultSet}
import java.io._
import java.nio.file.{Files, Paths}
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.{IvParameterSpec, SecretKeySpec}

/**
 * Controller demonstrating various OWASP Top 10 vulnerabilities
 * WARNING: This code contains intentional security vulnerabilities
 */
@Singleton
class VulnerableController @Inject()(
  cc: ControllerComponents,
  ws: WSClient,
  config: Configuration
)(implicit ec: ExecutionContext) extends AbstractController(cc) {

  // Insecure: Hardcoded database credentials
  private val dbUrl = "jdbc:mysql://localhost:3306/production"
  private val dbUser = "admin"
  private val dbPassword = "insecure_password"
  
  // Insecure: Hardcoded encryption key and IV
  private val ENCRYPTION_KEY = "insecure-key-12345".getBytes("UTF-8")
  private val IV = "insecure-iv-vector".getBytes("UTF-8")
  
  // Insecure: Using ECB mode which is not secure
  private val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
  private val keySpec = new SecretKeySpec(ENCRYPTION_KEY, "AES")

  /**
   * A1: Broken Access Control
   * Insecure direct object reference and missing authorization check
   */
  def getUserProfile(userId: String) = Action { implicit request =>
    // Insecure: No proper session/user validation
    val userRole = request.session.get("userRole").getOrElse("guest")
    
    // Insecure: Direct object reference without proper authorization
    val userData = getUserDataFromDatabase(userId)
    
    // Insecure: No proper role-based access control
    if (userRole == "admin") {
      Ok(Json.obj(
        "status" -> "success",
        "data" -> userData
      ))
    } else {
      // Still returns data but with a warning - insecure!
      Ok(Json.obj(
        "status" -> "unauthorized",
        "message" -> "You don't have permission to view this data",
        "data" -> userData // Oops! Leaking data anyway
      ))
    }
  }
  
  // Helper method to simulate database access
  private def getUserDataFromDatabase(userId: String): JsObject = {
    // Insecure: Direct database query without proper parameterization
    val connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)
    try {
      val statement = connection.createStatement()
      val query = s"SELECT * FROM users WHERE id = '$userId'"  // SQL Injection
      val result = statement.executeQuery(query)
      
      if (result.next()) {
        Json.obj(
          "id" -> result.getString("id"),
          "username" -> result.getString("username"),
          "email" -> result.getString("email"),
          "isAdmin" -> result.getBoolean("is_admin"),
          // Insecure: Including sensitive information
          "passwordHash" -> result.getString("password_hash"),
          "resetToken" -> result.getString("reset_token")
        )
      } else {
        Json.obj("error" -> "User not found")
      }
    } finally {
      connection.close()
    }
  }


   * Insecure encryption and hashing
   */
  def encryptData = Action(parse.json) { implicit request =>
    val data = (request.body \ "data").as[String]
    
    // Insecure: Using ECB mode and hardcoded keys
    cipher.init(Cipher.ENCRYPT_MODE, keySpec)
    val encrypted = cipher.doFinal(data.getBytes("UTF-8"))
    
    // Insecure: Using Base64 as "encryption"
    val base64Encoded = Base64.getEncoder.encodeToString(encrypted)
    
    Ok(Json.obj(
      "status" -> "success",
      "encrypted_data" -> base64Encoded
    ))
  }
  
  /**
   * A3: Injection
   * SQL Injection vulnerability
   */
  def searchUsers = Action(parse.json) { implicit request =>
    val searchTerm = (request.body \ "search").as[String]
    
    // Insecure: Direct string concatenation in SQL query
    val query = s"""
      SELECT id, username, email, password_hash, is_admin 
      FROM users 
      WHERE username LIKE '%$searchTerm%' 
      OR email LIKE '%$searchTerm%'"""
    
    val connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)
    try {
      val statement = connection.createStatement()
      val resultSet = statement.executeQuery(query)
      
      val users = new scala.collection.mutable.ArrayBuffer[JsObject]()
      while (resultSet.next()) {
        users += Json.obj(
          "id" -> resultSet.getInt("id"),
          "username" -> resultSet.getString("username"),
          "email" -> resultSet.getString("email"),
          "is_admin" -> resultSet.getBoolean("is_admin"),
          // Oops! Leaking password hashes
          "password_hash" -> resultSet.getString("password_hash")
        )
      }
      
      Ok(Json.obj(
        "status" -> "success",
        "users" -> users
      ))
    } finally {
      connection.close()
    }
  }

  /**
   * A4: Insecure Design
   * Password reset without proper security controls
   */
  def requestPasswordReset = Action(parse.json) { implicit request =>
    val email = (request.body \ "email").as[String]
    
    // Insecure: No rate limiting or lockout mechanism
    // Insecure: Reveals if email exists in the system
    val userExists = checkIfUserExists(email)
    
    if (userExists) {
      // Insecure: Using predictable reset tokens
      val resetToken = java.util.UUID.randomUUID().toString.replace("-", "")
      
      // Insecure: Storing token in plain text with long expiration
      storeResetToken(email, resetToken)
      
      // Insecure: Sending token via unencrypted email
      sendResetEmail(email, resetToken)
    }
    
    // Insecure: Same response whether user exists or not (security through obscurity)
    Ok(Json.obj(
      "status" -> "success",
      "message" -> "If the email exists in our system, you will receive a reset link"
    ))
  }
  
  // Helper methods for password reset functionality
  private def checkIfUserExists(email: String): Boolean = {
    // Insecure: Direct SQL query without proper parameterization
    val connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)
    try {
      val statement = connection.createStatement()
      val query = s"SELECT COUNT(*) FROM users WHERE email = '$email'"
      val result = statement.executeQuery(query)
      result.next() && result.getInt(1) > 0
    } finally {
      connection.close()
    }
  }
  
  private def storeResetToken(email: String, token: String): Unit = {
    // Insecure: Storing plain text tokens
    val connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)
    try {
      val query = s"""
        |UPDATE users 
        |SET reset_token = '$token', 
        |    reset_expires = NOW() + INTERVAL '24 HOUR'
        |WHERE email = '$email'
        |""".stripMargin
      
      val statement = connection.createStatement()
      statement.executeUpdate(query)
    } finally {
      connection.close()
    }
  }
  
  private def sendResetEmail(email: String, token: String): Unit = {
    // Insecure: Using unencrypted SMTP
    // Insecure: Including reset token directly in URL
    val resetLink = s"http://example.com/reset-password?token=$token"
    
    // In production, this would actually send an email
    println(s"Sending reset email to $email with link: $resetLink")
  }

  /**
   * A5: Security Misconfiguration
   * Directory traversal and insecure file handling
   */
  def downloadFile = Action { implicit request =>
    val filename = request.getQueryString("file").getOrElse("")
    
    // Insecure: No proper path validation or sanitization
    val filePath = Paths.get("/var/www/uploads", filename).normalize()
    
    // Insecure: No proper content type validation
    if (Files.exists(filePath) && Files.isRegularFile(filePath)) {
      Ok.sendFile(
        filePath.toFile,
        fileName = _ => filename // Insecure: Using user-provided filename
      )
    } else {
      NotFound("File not found")
    }
  }

  /**
   * A6: Vulnerable and Outdated Components
   * Using components with known vulnerabilities
   */
  def processJsonData = Action(parse.json) { implicit request =>
    // Insecure: Using outdated library with known vulnerabilities
    // Simulating use of vulnerable JSON parser
    try {
      // Insecure: No input validation or sanitization
      val jsonString = request.body.toString()
      
      // Insecure: Using deprecated/unsafe method
      val json = play.api.libs.json.Json.parse(jsonString)
      
      // Insecure: No output encoding when including in response
      Ok(Json.obj(
        "status" -> "success",
        "data" -> json
      ))
    } catch {
      case e: Exception =>
        // Insecure: Leaking stack traces in error responses
        InternalServerError(s"Error processing JSON: ${e.getMessage}\n${e.getStackTrace.mkString("\n")}")
    }
  }

  /**
   * A7: Identification and Authentication Failures
   * Weak authentication mechanisms
   */
  def login = Action(parse.json) { implicit request =>
    val username = (request.body \ "username").as[String]
    val password = (request.body \ "password").as[String]
    
    // Insecure: Weak password policy
    if (password.length < 4) {
      return BadRequest(Json.obj("error" -> "Password must be at least 4 characters"))
    }
    
    // Insecure: No account lockout after failed attempts
    // Insecure: No password hashing
    val connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword)
    try {
      val query = s"SELECT * FROM users WHERE username = '$username' AND password = '$password'"
      val statement = connection.createStatement()
      val result = statement.executeQuery(query)
      
      if (result.next()) {
        // Insecure: No proper session management
        // Insecure: No CSRF protection
        val sessionToken = java.util.UUID.randomUUID().toString
        
        // Insecure: Session never expires
        Ok(Json.obj(
          "status" -> "success",
          "token" -> sessionToken
        )).withSession("authToken" -> sessionToken)
      } else {
        // Insecure: Reveals that user doesn't exist
        Unauthorized(Json.obj("error" -> "Invalid username or password"))
      }
    } finally {
      connection.close()
    }
  }

  /**
   * A8: Software and Data Integrity Failures
   * Insecure deserialization and plugin loading
   */
  def uploadPlugin = Action(parse.multipartFormData) { implicit request =>
    request.body.file("plugin").map { plugin =>
      // Insecure: No file type validation
      val filename = plugin.filename
      val contentType = plugin.contentType.getOrElse("application/octet-stream")
      
      // Insecure: Storing with original filename (path traversal possible)
      val pluginFile = new java.io.File(s"/tmp/plugins/$filename")
      plugin.ref.copyTo(pluginFile, replace = true)
      
      // Insecure: Loading untrusted code without verification
      try {
        // Insecure: Using reflection to load untrusted code
        val pluginClass = Class.forName(s"com.plugins.${filename.replace(".class", "")}")
        val pluginInstance = pluginClass.getDeclaredConstructor().newInstance()
        
        Ok(Json.obj(
          "status" -> "success",
          "message" -> s"Plugin $filename loaded successfully"
        ))
      } catch {
        case e: Exception =>
          InternalServerError(Json.obj(
            "error" -> s"Failed to load plugin: ${e.getMessage}"
          ))
      }
    }.getOrElse {
      BadRequest(Json.obj("error" -> "Missing plugin file"))
    }
  }

  /**
   * A9: Security Logging and Monitoring Failures
   * Insufficient logging and monitoring
   */
  def processPayment = Action(parse.json) { implicit request =>
    val amount = (request.body \ "amount").as[Double]
    val recipient = (request.body \ "recipient").as[String]
    
    // Insecure: No sensitive operation logging
    // Insecure: No transaction ID or audit trail
    
    // Process payment (simulated)
    val paymentId = java.util.UUID.randomUUID().toString
    
    // Insecure: Minimal logging, no security events
    println(s"Payment processed: $paymentId, Amount: $$amount, Recipient: $recipient")
    
    // Insecure: No rate limiting or anomaly detection
    Ok(Json.obj(
      "status" -> "success",
      "paymentId" -> paymentId,
      "message" -> s"Successfully transferred $$amount to $recipient"
    ))
  }

  /**
   * A10: Server-Side Request Forgery (SSRF)
   * Insecure URL fetching
   */
  def fetchData = Action(parse.json) { implicit request =>
    val url = (request.body \ "url").as[String]
    
    // Insecure: No URL validation or whitelisting
    try {
      // Insecure: Directly fetching from user-provided URL
      val source = scala.io.Source.fromURL(url)
      val content = source.mkString
      source.close()
      
      // Insecure: Reflected XSS possible in response
      Ok(content).as("text/html")
    } catch {
      case e: Exception =>
        InternalServerError(Json.obj(
          "error" -> s"Failed to fetch URL: ${e.getMessage}"
        ))
    }
  }
}