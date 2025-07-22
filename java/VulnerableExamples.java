import java.io.*;
import java.sql.*;
import javax.servlet.http.*;
import javax.xml.parsers.*;
import org.xml.sax.InputSource;
import org.owasp.esapi.ESAPI;

public class VulnerableExamples {
    
    // 1. SQL Injection
    public void vulnerableSQL(String userInput) throws SQLException {
        String query = "SELECT * FROM users WHERE username = '" + userInput + "'";
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query); // SQL Injection
    }
    
    // 2. XSS
    public void vulnerableXSS(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("userInput");
        response.getWriter().write("<div>" + userInput + "</div>"); // XSS
    }
    
    // 3. Insecure Deserialization
    public void vulnerableDeserialization(byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        Object obj = ois.readObject(); // Insecure Deserialization
    }
    
    // 4. XXE (XML External Entity)
    public void vulnerableXXE(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xml))); // XXE
    }
    
    // 5. Path Traversal
    public void vulnerablePathTraversal(String filename) throws IOException {
        File file = new File("/home/user/" + filename);
        FileInputStream fis = new FileInputStream(file); // Path Traversal
    }
    
    // 6. Command Injection
    public void vulnerableCommandInjection(String input) throws IOException {
        Runtime.getRuntime().exec("echo " + input); // Command Injection
    }
    
    // 7. Insecure Direct Object Reference
    public File vulnerableIDOR(String userId) {
        return new File("/userdata/" + userId + ".txt"); // Insecure Direct Object Reference
    }
    
    // 8. Security Misconfiguration
    public void vulnerableConfig() {
        System.setProperty("com.example.debug", "true"); // Security Misconfiguration
    }
    
    // 9. Using Components with Known Vulnerabilities
    public void vulnerableDependency() {
        // Using outdated library with known vulnerabilities
        // Example: Old version of log4j
    }
    
    // 10. Insufficient Logging & Monitoring
    public void vulnerableLogging(String userInput) {
        System.out.println("User input: " + userInput); // Insufficient Logging
    }
}
