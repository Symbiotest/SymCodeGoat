import Foundation
import WebKit
import CommonCrypto

// 1. SQL Injection (using SQLite)
func vulnerableSQLQuery(userInput: String) -> String {
    let query = "SELECT * FROM users WHERE id = '\(userInput)'" // SQL Injection
    return query
}

// 2. Command Injection
func executeCommand(_ command: String) -> String {
    let task = Process()
    let pipe = Pipe()
    
    task.standardOutput = pipe
    task.arguments = ["-c", command] // Command Injection
    task.executableURL = URL(fileURLWithPath: "/bin/zsh")
    
    try? task.run()
    
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    return String(data: data, encoding: .utf8) ?? ""
}

// 3. Path Traversal
func readFile(at path: String) -> String? {
    let fullPath = "/Users/Shared/\(path)" // Path Traversal
    return try? String(contentsOfFile: fullPath, encoding: .utf8)
}

// 4. Insecure Deserialization
class UserData: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }
    
    var username: String
    var isAdmin: Bool
    
    init(username: String, isAdmin: Bool) {
        self.username = username
        self.isAdmin = isAdmin
    }
    
    required init?(coder: NSCoder) {
        // Insecure: No validation of decoded data
        self.username = coder.decodeObject(forKey: "username") as? String ?? ""
        self.isAdmin = coder.decodeBool(forKey: "isAdmin")
    }
    
    func encode(with coder: NSCoder) {
        coder.encode(username, forKey: "username")
        coder.encode(isAdmin, forKey: "isAdmin")
    }
}

// 5. XSS in WebView
class InsecureWebView: WKWebView {
    func loadUnsafeHTML(html: String) {
        // XSS: Directly loading untrusted HTML
        loadHTMLString(html, baseURL: nil)
    }
}

// 6. SSRF (Server-Side Request Forgery)
func fetchURL(_ urlString: String) -> String? {
    guard let url = URL(string: urlString) else { return nil }
    return try? String(contentsOf: url) // SSRF
}

// 7. Hardcoded Secrets
let API_KEY = "12345-67890-abcdef"
let DB_PASSWORD = "s3cr3tP@ssw0rd"

// 8. Insecure Randomness
func generateInsecureToken() -> String {
    return "\(arc4random())" // Not cryptographically secure
}

// 9. Security Misconfiguration
class InsecureDefaults {
    static let shared = InsecureDefaults()
    private let defaults = UserDefaults.standard
    
    func storeCredentials(username: String, password: String) {
        // Insecure: Storing sensitive data in UserDefaults without encryption
        defaults.set(password, forKey: "userPassword")
        defaults.synchronize()
    }
}

// 10. Insecure Direct Object Reference
func getUserFile(userId: String) -> String {
    return "/user/\(userId)/data.txt" // IDOR
}

// 11. No Input Validation
func processUserInput(_ input: String) -> String {
    // Dangerous: Evaluating arbitrary input
    let script = "var result = \(input); result"
    let jsContext = JSContext()
    return jsContext?.evaluateScript(script)?.toString() ?? ""
}

// 12. XXE (XML External Entity)
class InsecureXMLParser: NSObject, XMLParserDelegate {
    func parseXML(xmlString: String) {
        let parser = XMLParser(data: xmlString.data(using: .utf8)!)
        parser.shouldProcessNamespaces = false
        parser.shouldResolveExternalEntities = true // Vulnerable to XXE
        parser.delegate = self
        parser.parse()
    }
    
    // XMLParserDelegate methods would go here
}

// 13. Insecure File Upload
func saveUploadedFile(data: Data, name: String) -> URL? {
    let fileManager = FileManager.default
    let tempDir = fileManager.temporaryDirectory
    let fileURL = tempDir.appendingPathComponent(name)
    
    // No file type validation
    try? data.write(to: fileURL)
    return fileURL
}

// 14. Insecure Keychain Usage
func storeInKeychain(key: String, value: String) -> Bool {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: key,
        kSecValueData as String: value.data(using: .utf8)!
    ]
    
    // Insecure: No access control
    let status = SecItemAdd(query as CFDictionary, nil)
    return status == errSecSuccess
}

// 15. No Rate Limiting
class InsecureAPIClient {
    private var requestCount = 0
    
    func makeRequest() {
        requestCount += 1 // No rate limiting
        // Make API request
    }
}

// 16. Information Exposure Through Error Messages
func getUserProfile(userId: String) -> [String: Any] {
    // Simulate database error with too much information
    if userId == "0" {
        // Leaking internal error details
        fatalError("Database error: Invalid user ID format. SQL: SELECT * FROM users WHERE id = \(userId)")
    }
    return ["id": userId, "name": "Test User"]
}

// 17. Missing Function Level Access Control
func adminOnlyAction() -> String {
    // No authentication/authorization check
    return "Sensitive admin action performed"
}

// 18. Insecure Redirects
func handleRedirect(urlString: String) {
    guard let url = URL(string: urlString) else { return }
    // Open redirect vulnerability
    UIApplication.shared.open(url, options: [:], completionHandler: nil)
}

// 19. Weak Cryptography
func weakEncrypt(data: String) -> String {
    let key = "weakkey".data(using: .utf8)!
    let dataToEncrypt = data.data(using: .utf8)!
    
    var encryptedData = Data(count: dataToEncrypt.count + key.count)
    
    // Insecure custom encryption
    for (i, byte) in dataToEncrypt.enumerated() {
        let keyByte = key[i % key.count]
        encryptedData[i] = byte ^ keyByte
    }
    
    return encryptedData.base64EncodedString()
}

// 20. Insecure Deserialization with NSKeyedUnarchiver
func insecureDeserialize(data: Data) -> Any? {
    // Insecure: Allows deserialization of arbitrary classes
    return try? NSKeyedUnarchiver.unarchivedObject(ofClasses: [NSObject.self], from: data)
}
