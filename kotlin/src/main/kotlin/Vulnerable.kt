import java.io.*
import java.net.URL
import java.sql.DriverManager
import javax.script.ScriptEngineManager
import javax.servlet.http.*
import com.fasterxml.jackson.databind.ObjectMapper

// 1. SQL Injection
fun vulnerableSql(userId: String): String {
    val conn = DriverManager.getConnection("jdbc:sqlite:test.db")
    val stmt = conn.createStatement()
    val query = "SELECT * FROM users WHERE id = '$userId'" // SQL Injection
    val rs = stmt.executeQuery(query)
    return rs.getString("username")
}

// 2. Command Injection
fun vulnerableCommand(input: String): String {
    val process = Runtime.getRuntime().exec("echo $input") // Command Injection
    return process.inputStream.bufferedReader().readText()
}

// 3. Path Traversal
fun readFile(fileName: String): String {
    return File("/home/user/$fileName").readText() // Path Traversal
}

// 4. Insecure Deserialization
fun deserializeData(data: String): Any {
    return ObjectMapper().readValue(data, Any::class.java) // Insecure deserialization
}

// 5. XSS in Web App
class XssServlet : HttpServlet() {
    override fun doGet(req: HttpServletRequest, resp: HttpServletResponse) {
        val input = req.getParameter("input") ?: ""
        resp.writer.write("<div>$input</div>") // XSS
    }
}

// 6. SSRF
fun fetchUrl(url: String): String {
    return URL(url).readText() // SSRF
}

// 7. Hardcoded Secrets
private const val API_KEY = "12345-67890-abcdef"
private const val DB_PASSWORD = "s3cr3tP@ssw0rd"

// 8. Insecure Randomness
fun generateToken(): String {
    return (0..10000).random().toString() // Not cryptographically secure
}

// 9. Security Misconfiguration
fun getAdminPanel(): String {
    // No auth check
    return "Admin Panel"
}

// 10. IDOR
fun getUserFile(userId: String): File {
    return File("/userdata/$userId.txt") // Insecure Direct Object Reference
}

// 11. No Input Validation
fun evalUserInput(code: String): Any {
    return ScriptEngineManager().getEngineByName("nashorn").eval(code)
}

// 12. XXE
fun parseXml(xml: String) {
    val factory = javax.xml.parsers.DocumentBuilderFactory.newInstance()
    val builder = factory.newDocumentBuilder()
    builder.parse(xml.byteInputStream()) // XXE
}

// 13. Insecure File Upload
fun saveFile(fileName: String, content: ByteArray) {
    File("uploads/$fileName").writeBytes(content) // No validation
}

// 14. Insecure Cookie
fun setCookie(resp: HttpServletResponse) {
    val cookie = javax.servlet.http.Cookie("session", "12345")
    cookie.isHttpOnly = false
    cookie.secure = false
    resp.addCookie(cookie)
}

// 15. No Rate Limiting
var requestCount = 0
fun processRequest() {
    requestCount++ // No rate limiting
}

// 16. Info Leakage
fun getUser(id: String): String {
    return try {
        // DB operation
        "User data"
    } catch (e: Exception) {
        "Error: ${e.message}" // Information leakage
    }
}

// 17. Missing Access Control
fun adminAction(role: String): String {
    return if (role == "admin") "Admin action" else "User action"
}

// 18. Insecure Redirect
fun redirect(url: String, resp: HttpServletResponse) {
    resp.sendRedirect(url) // Open redirect
}

// 19. Weak Cryptography
fun encrypt(data: String): String {
    val key = "weakkey".toByteArray()
    return data.toByteArray()
        .mapIndexed { i, byte -> (byte.toInt() xor key[i % key.size].toInt()).toByte() }
        .toByteArray()
        .toString(Charsets.ISO_8859_1)
}

// 20. Insecure Deserialization with readObject
@Throws(IOException::class, ClassNotFoundException::class)
fun deserializeObject(data: ByteArray): Any {
    ObjectInputStream(ByteArrayInputStream(data)).use {
        return it.readObject() // Insecure deserialization
    }
}
