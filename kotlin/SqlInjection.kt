import java.sql.Connection
import java.sql.DriverManager
import java.sql.PreparedStatement

class UserRepository(private val connection: Connection) {
    
    // VULNERABLE: SQL Injection
    fun findUserByUsernameInsecure(username: String): User? {
        val query = "SELECT * FROM users WHERE username = '$username'"
        return connection.createStatement().use { stmt ->
            val rs = stmt.executeQuery(query)
            if (rs.next()) {
                User(
                    id = rs.getInt("id"),
                    username = rs.getString("username"),
                    email = rs.getString("email")
                )
            } else null
        }
    }
    
    // Secure version using prepared statements
    fun findUserByUsernameSecure(username: String): User? {
        val query = "SELECT * FROM users WHERE username = ?"
        return connection.prepareStatement(query).use { stmt ->
            stmt.setString(1, username)
            val rs = stmt.executeQuery()
            if (rs.next()) {
                User(
                    id = rs.getInt("id"),
                    username = rs.getString("username"),
                    email = rs.getString("email")
                )
            } else null
        }
    }
    
    // Even better: Use an ORM like Exposed
    /*
    object Users : Table() {
        val id = integer("id").autoIncrement()
        val username = varchar("username", 50).uniqueIndex()
        val email = varchar("email", 100)
        
        override val primaryKey = PrimaryKey(id)
    }
    
    fun findUserWithExposed(username: String): User? {
        return transaction {
            Users.select { Users.username eq username }
                .map { 
                    User(
                        id = it[Users.id],
                        username = it[Users.username],
                        email = it[Users.email]
                    )
                }.singleOrNull()
        }
    }
    */
}

data class User(
    val id: Int,
    val username: String,
    val email: String
)

// Example usage
fun main() {
    // Initialize database connection (in-memory H2 for example)
    val connection = DriverManager.getConnection("jdbc:h2:mem:test", "sa", "")
    
    // Create table and insert test data
    connection.createStatement().use { stmt ->
        stmt.execute("""
            CREATE TABLE users (
                id INT PRIMARY KEY AUTO_INCREMENT,
                username VARCHAR(50) UNIQUE,
                email VARCHAR(100)
            )
        """.trimIndent())
        
        stmt.execute("""
            INSERT INTO users (username, email) VALUES 
            ('admin', 'admin@example.com'),
            ('user1', 'user1@example.com')
        """.trimIndent())
    }
    
    val userRepo = UserRepository(connection)
    
    // Safe query
    println("Safe query:")
    val safeUser = userRepo.findUserByUsernameSecure("admin")
    println("Found user: ${safeUser?.username}")
    
    // Malicious input that would exploit SQL injection
    val maliciousInput = "admin' OR '1'='1"
    
    // Insecure query vulnerable to SQL injection
    println("\nInsecure query with malicious input:")
    try {
        val hackedUser = userRepo.findUserByUsernameInsecure(maliciousInput)
        println("Found user: ${hackedUser?.username}")
    } catch (e: Exception) {
        println("Error: ${e.message}")
    }
    
    // Secure query with the same input
    println("\nSecure query with malicious input:")
    val secureUser = userRepo.findUserByUsernameSecure(maliciousInput)
    println("Found user: ${secureUser?.username ?: "No user found"}")
    
    connection.close()
}
