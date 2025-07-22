// Real Vulnerability Examples for SCALA

// Rule ID: 524 - Insufficiently Protected Credentials
// Description: The code uses a hardcoded secret or private key for signing JWTs, storing sensitive credentials directly in the source code. This makes it easy for attackers to discover and misuse these secrets if the code is exposed.
import pdi.jwt._
val secret = "my-hardcoded-secret"
val claim = JwtClaim("""{"user":"admin"}""")
val token = Jwt.encode(claim, secret, JwtAlgorithm.HS256)

// Rule ID: 525 - Server-Side Request Forgery (SSRF)
// Description: Passing user-controlled or unvalidated parameters directly into the scalaj-http 'Http' method can let attackers make the server send requests to arbitrary URLs. This exposes the application to Server-Side Request Forgery (SSRF) risks.
import scalaj.http._
val userInputUrl = scala.io.StdIn.readLine("Enter URL: ")
val response = Http(userInputUrl).asString

// Rule ID: 526 - Use of RSA Algorithm without OAEP
// Description: The code uses RSA encryption without OAEP (Optimal Asymmetric Encryption Padding), which makes the encryption weaker and more vulnerable to attacks. Using RSA without proper padding can expose sensitive data.
import java.security._
import javax.crypto.Cipher

val keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair()
val cipher = Cipher.getInstance("RSA")  // No OAEP padding
cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic)
val encrypted = cipher.doFinal("SensitiveData".getBytes())

// Rule ID: 527 - Improper Restriction of XML External Entity Reference
// Description: The code creates an XML DocumentBuilder without disabling entity processing features. This leaves the application vulnerable to attackers crafting malicious XML that the parser will process insecurely.
// TODO: Add real Scala code here

// Rule ID: 528 - Use of Insufficiently Random Values
// Description: The code uses scala.util.Random to generate random values, which are predictable and not suitable for security-sensitive operations like tokens or passwords. Instead, a cryptographically secure random number generator should be used.
// TODO: Add real Scala code here

// Rule ID: 529 - Improper Restriction of XML External Entity Reference
// Description: When creating an XMLInputFactory instance, entity processing is not disabled, which means the parser may process external entities. This can allow attackers to inject malicious XML that accesses external resources or sensitive data.
// TODO: Add real Scala code here

// Rule ID: 530 - Server-Side Request Forgery (SSRF)
// Description: User-controlled input is being passed directly into the Dispatch `url` function, allowing attackers to specify arbitrary URLs for server-side requests. This makes it possible for untrusted users to control where the server sends HTTP requests.
// TODO: Add real Scala code here

// Rule ID: 531 - Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
// Description: User input is being directly inserted into SQL query strings, which makes the code vulnerable to SQL injection. This happens when SQL statements are built by concatenating or formatting strings with user-provided data, rather than using prepared statements.
val userInput = "'; DROP TABLE users; --"
val query = s"SELECT * FROM accounts WHERE name = '$userInput'"
println(query)

// Rule ID: 532 - Improper Control of Generation of Code ('Code Injection')
// Description: Using JavaScript's eval() function in Scala.js with input that can come from users or external sources allows attackers to inject and execute arbitrary code. This makes your application vulnerable to code injection attacks.
// TODO: Add real Scala code here

// Rule ID: 533 - Server-Side Request Forgery (SSRF)
// Description: The code passes user-provided URLs directly to Source.fromURL or Source.fromURI, allowing external input to control outbound network requests. This can let attackers make your server fetch data from any URL, including internal or sensitive systems.
// TODO: Add real Scala code here

// Rule ID: 534 - Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
// Description: The code runs external system commands using dynamic or user-influenced input with Scala's Seq and sys.process. This allows attackers to inject malicious commands if input is not properly sanitized or controlled.
// TODO: Add real Scala code here

// Rule ID: 535 - Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
// Description: This code runs shell commands by passing dynamic or user-controlled data directly to the shell (e.g., 'sh', 'bash') using Scala's sys.process API. If this input isn't properly sanitized, attackers can inject arbitrary commands.
// TODO: Add real Scala code here

// Rule ID: 536 - Improper Restriction of XML External Entity Reference
// Description: The XML parser is being created without disabling features that allow processing of external entities. This leaves the application vulnerable to attackers sending malicious XML data that can be interpreted in unsafe ways.
// TODO: Add real Scala code here

// Rule ID: 537 - Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
// Description: The code reads files using user-supplied input to build file paths without proper validation. This allows attackers to manipulate the path and access files outside the intended directory, potentially exposing sensitive data.
// TODO: Add real Scala code here

// Rule ID: 538 - Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
// Description: The code runs external system commands using dynamic strings with sys.process (like `command.!` or `command.!!`), which can allow untrusted input to control the executed command. This makes the application vulnerable to command injection attacks.
// TODO: Add real Scala code here

// Rule ID: 539 - Insufficiently Protected Credentials
// Description: The code uses a hardcoded secret or private key when encoding or decoding JWTs. Storing secrets directly in source code makes them easy to discover and compromises the security of your authentication tokens.
// TODO: Add real Scala code here

// Rule ID: 540 - Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
// Description: The code constructs SQL queries in Slick using string interpolation with formatted variables (e.g., `#$variable`), which can insert unsanitized user input directly into the SQL statement. This practice can allow attackers to manipulate the query and execute arbitrary SQL commands.
// TODO: Add real Scala code here

// Rule ID: 541 - Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
// Description: Using variables or formatted strings directly in the overrideSql(...) function can introduce untrusted data into SQL queries, making the code vulnerable to SQL injection. Always use constant string literals for SQL statements or properly sanitize and parameterize any dynamic input.
// TODO: Add real Scala code here

// Rule ID: 542 - Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
// Description: User input is being sent directly in an Ok() HTTP response as HTML, without proper escaping or sanitization. This bypasses the view/template system and can allow attackers to inject malicious scripts into the page.
import play.api.mvc._

def vulnerableAction(input: String) = Action {
  Ok(s"<html><body>User input: $input</body></html>").as(HTML)
}

// Rule ID: 543 - Server-Side Request Forgery (SSRF)
// Description: User input or external parameters are being passed directly to WSClient for outbound HTTP requests, allowing attackers to control the request destination. This can enable attackers to access arbitrary or internal network resources from your server.
// TODO: Add real Scala code here

// Rule ID: 544 - Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
// Description: User input is being directly inserted into SQL queries in Slick without proper sanitization. This allows attackers to manipulate the SQL statements by sending malicious input, leading to SQL injection vulnerabilities.
// TODO: Add real Scala code here

// Rule ID: 545 - Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
// Description: User input from HTTP requests is being directly inserted into SQL queries using string concatenation or formatting. This exposes the code to SQL injection attacks because attackers can manipulate the input to alter the query's behavior. Use prepared statements or an ORM to safely handle user data in SQL queries.
// TODO: Add real Scala code here

