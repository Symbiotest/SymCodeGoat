import play.api.mvc._
import javax.inject._
import scala.concurrent.ExecutionContext
import java.sql.{Connection, DriverManager}
import java.io._

@Singleton
class OwaspTop10Vulnerabilities @Inject()(cc: ControllerComponents)(implicit ec: ExecutionContext) extends AbstractController(cc) {

  // A1: Broken Access Control
  def adminDashboard(role: String) = Action {
    if (role == "admin") {
      Ok("Welcome, Admin!")
    } else {
      // Access control check is broken - just returns data
      Ok("You are not admin, but here's the data anyway.")
    }
  }

  // A2: Cryptographic Failures
  def insecureCrypto(data: String) = Action {
    val encoded = java.util.Base64.getEncoder.encodeToString(data.getBytes("UTF-8")) // Not real encryption
    Ok(s"Insecure encoded data: $encoded")
  }

  // A3: Injection
  def sqlInjection(name: String) = Action {
    val connection: Connection = DriverManager.getConnection("jdbc:mysql://localhost/test", "user", "pass")
    val statement = connection.createStatement()
    val query = s"SELECT * FROM users WHERE name = '$name'"  // vulnerable to SQL Injection
    val rs = statement.executeQuery(query)
    Ok("Query executed")
  }

  // A4: Insecure Design
  def passwordReset(username: String) = Action {
    // No rate limiting, brute force possible
    Ok(s"Reset token sent for user: $username")
  }

  // A5: Security Misconfiguration
  def directoryListing(path: String) = Action {
    val file = new File(s"/var/www/html/$path")  // vulnerable to directory traversal
    if (file.exists()) {
      Ok(s"Listing: ${file.list().mkString(", ")}")
    } else {
      NotFound("Not found")
    }
  }

  // A6: Vulnerable and Outdated Components
  def outdatedComponent() = Action {
    // Uses vulnerable version of library (simulated)
    val json = play.api.libs.json.Json.parse("{bad json}") // may crash if malformed
    Ok("Parsed JSON")
  }

  // A7: Identification and Authentication Failures
  def login(username: String, password: String) = Action {
    if (username == "admin" && password == "123456") {  // Weak credentials
      Ok("Logged in")
    } else {
      Unauthorized("Invalid credentials")
    }
  }

  // A8: Software and Data Integrity Failures
  def pluginLoader(name: String) = Action {
    val plugin = scala.io.Source.fromFile(s"/plugins/$name.jar") // No integrity check
    Ok(s"Loaded plugin: $name")
  }

  // A9: Security Logging and Monitoring Failures
  def transaction(amount: Int) = Action {
    // No logging of transaction
    Ok(s"Transferred $$amount")
  }

  // A10: Server-Side Request Forgery (SSRF)
  def fetchUrl(url: String) = Action {
    val result = scala.io.Source.fromURL(url).mkString  // SSRF vulnerability
    Ok(result)
  }
}