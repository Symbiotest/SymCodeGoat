import Foundation
import WebKit
import Security

// MARK: - Insecure Data Storage

class AuthenticationManager {
    // Insecure: Storing sensitive data in UserDefaults
    static let shared = AuthenticationManager()
    private let userDefaults = UserDefaults.standard
    
    // Insecure: Hardcoded API keys
    private let apiKey = "12717-127163-a71367-127ahc"
    private let googleToken = "AIzaSyDqXGH5YlQNwQ4X8X8X8X8X8X8X8X8X8X8"
    
    // Insecure: Store sensitive data in UserDefaults
    func saveCredentials(username: String, password: String) {
        userDefaults.set(username, forKey: "userName")
        userDefaults.set(password, forKey: "userPassword")
        userDefaults.set(apiKey, forKey: "apiKey")
        userDefaults.set(googleToken, forKey: "GOOGLE_TOKEN")
    }
    
    // Insecure: Retrieve sensitive data from UserDefaults
    func getCredentials() -> (username: String?, password: String?) {
        let username = userDefaults.string(forKey: "userName")
        let password = userDefaults.string(forKey: "userPassword")
        return (username, password)
    }
}

// MARK: - Insecure WebView Configuration

class InsecureWebViewController: UIViewController {
    // Insecure: WebView with dangerous settings
    private lazy var webView: WKWebView = {
        let prefs = WKPreferences()
        prefs.javaScriptCanOpenWindowsAutomatically = true  // Insecure
        
        let config = WKWebViewConfiguration()
        config.preferences = prefs
        config.websiteDataStore = .nonPersistent()
        
        // Insecure: Allow all file access
        config.preferences.setValue(true, forKey: "allowFileAccessFromFileURLs")
        config.setValue(true, forKey: "allowUniversalAccessFromFileURLs")
        
        return WKWebView(frame: .zero, configuration: config)
    }()
    
    // Insecure: Load arbitrary URLs
    func loadURL(_ urlString: String) {
        if let url = URL(string: urlString) {
            let request = URLRequest(url: url)
            webView.load(request)
        }
    }
}

// MARK: - Insecure Cryptography

class InsecureCrypto {
    // Insecure: Hardcoded encryption key
    private let encryptionKey = "insecure_key_12345".data(using: .utf8)!
    
    // Insecure: Using ECB mode which is not secure
    func encrypt(data: Data) -> Data? {
        var encryptedData = Data(count: data.count + kCCBlockSizeAES128)
        var numBytesEncrypted = 0
        
        let cryptStatus = encryptionKey.withUnsafeBytes { keyBytes in
            data.withUnsafeBytes { dataBytes in
                CCCrypt(
                    CCOperation(kCCEncrypt),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCOptions(kCCOptionECBMode | kCCOptionPKCS7Padding),
                    keyBytes.baseAddress, kCCKeySizeAES128,
                    nil,
                    dataBytes.baseAddress, data.count,
                    encryptedData.withUnsafeMutableBytes { $0.baseAddress },
                    encryptedData.count,
                    &numBytesEncrypted
                )
            }
        }
        
        if cryptStatus == kCCSuccess {
            encryptedData.count = numBytesEncrypted
            return encryptedData
        }
        
        return nil
    }
}
// MARK: - Insecure Network Operations

class InsecureNetworkManager {
    // Insecure: Disabled certificate validation
    static let shared = InsecureNetworkManager()
    
    // Insecure: Disabling SSL certificate validation
    lazy var session: URLSession = {
        let config = URLSessionConfiguration.default
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        
        return URLSession(
            configuration: config,
            delegate: InsecureURLSessionDelegate(),
            delegateQueue: nil
        )
    }()
    
    // Insecure: No input validation or output encoding
    func fetchUserData(userId: String, completion: @escaping (Data?, Error?) -> Void) {
        let urlString = "https://api.example.com/users/\(userId)"
        guard let url = URL(string: urlString) else { return }
        
        let task = session.dataTask(with: url) { data, response, error in
            // Insecure: No proper error handling or response validation
            completion(data, error)
        }
        task.resume()
    }
}

// Insecure: Disabling SSL certificate validation
class InsecureURLSessionDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, 
                   completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        // Insecure: Accepting any certificate
        let credential = URLCredential(trust: challenge.protectionSpace.serverTrust!)
        completionHandler(.useCredential, credential)
    }
}

// MARK: - Insecure File Operations

class InsecureFileManager {
    // Insecure: No input validation for file operations
    func readFile(atPath path: String) -> String? {
        // Insecure: Potential path traversal vulnerability
        return try? String(contentsOfFile: path, encoding: .utf8)
    }
    
    // Insecure: No proper file extension validation
    func saveFile(data: Data, withName fileName: String) -> Bool {
        let tempDir = FileManager.default.temporaryDirectory
        let fileURL = tempDir.appendingPathComponent(fileName)
        
        do {
            try data.write(to: fileURL)
            return true
        } catch {
            return false
        }
    }
}

// MARK: - Insecure Logging

class InsecureLogger {
    // Insecure: Logging sensitive information
    static func logUserActivity(_ activity: String, userId: String, details: [String: Any]) {
        let logMessage = "\(Date()): User \(userId) - \(activity) - \(details)"
        print(logMessage)  // Insecure: Logging to console
        
        // Insecure: Writing to file without proper sanitization
        if let documentsDir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first {
            let logFile = documentsDir.appendingPathComponent("app_logs.txt")
            
            if let fileHandle = FileHandle(forWritingAtPath: logFile.path) {
                // File exists, append to it
                fileHandle.seekToEndOfFile()
                if let data = "\(logMessage)\n".data(using: .utf8) {
                    fileHandle.write(data)
                }
                fileHandle.closeFile()
            } else {
                // Create new file
                try? logMessage.write(to: logFile, atomically: true, encoding: .utf8)
            }
        }
    }
}

WKWebView(frame: .zero, configuration: config)