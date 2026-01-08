use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::collections::HashMap;
use std::env;
use std::sync::Mutex;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use serde_json;
use postgres::{Client, NoTls};
use rand::Rng;
use openssl::ssl::{SslMethod, SslConnectorBuilder, SslVerifyMode};

// Application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AppConfig {
    database_url: String,
    api_key: String,
    log_level: String,
    upload_dir: PathBuf,
    ssl_verify: bool,
}

lazy_static! {
    static ref CONFIG: Mutex<AppConfig> = Mutex::new(AppConfig {
        database_url: "postgres://user:insecure_password@localhost/production_db".to_string(),
        api_key: "insecure_api_key_12345".to_string(),
        log_level: "debug".to_string(),
        upload_dir: PathBuf::from("/var/www/uploads"),
        ssl_verify: false,
    });
}

/// User management service
pub struct UserService {
    db_conn: Client,
    work_dir: PathBuf,
}

impl UserService {
    /// Create a new UserService instance
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let config = CONFIG.lock().unwrap().clone();
        let db_conn = Client::connect(&config.database_url, NoTls)?;
        
        // Create working directory if it doesn't exist
        let work_dir = env::temp_dir().join("app_workdir");
        fs::create_dir_all(&work_dir)?;
        
        Ok(Self { db_conn, work_dir })
    }
    
    /// Authenticate user (SQL Injection vulnerability)
    pub fn authenticate(&mut self, username: &str, password: &str) -> Result<bool, postgres::Error> {
        let query = format!(
            "SELECT * FROM users WHERE username = '{}' AND password = '{}'",
            username, password
        );
        
        let rows = self.db_conn.query(&query, &[])?;
        Ok(!rows.is_empty())
    }
    
    /// Process user command (Command Injection vulnerability)
    pub fn process_command(&self, command: &str) -> io::Result<String> {
        let output = Command::new("sh")
            .arg("-c")
            .arg(format!("echo {}", command))  // Command injection
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;
            
        if !output.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Command failed: {}", String::from_utf8_lossy(&output.stderr)),
            ));
        }
        
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
    
    /// Process uploaded file (Path Traversal vulnerability)
    pub fn process_upload(&self, filename: &str, content: &[u8]) -> io::Result<()> {
        let config = CONFIG.lock().unwrap();
        let file_path = config.upload_dir.join(filename);
        
        // Insecure file write - no path traversal protection
        fs::write(file_path, content)?;
        
        Ok(())
    }
    
    /// Deserialize user data (Insecure Deserialization)
    pub fn deserialize_user(&self, json_data: &str) -> serde_json::Result<HashMap<String, serde_json::Value>> {
        // Insecure deserialization of untrusted data
        let user_data: HashMap<String, serde_json::Value> = serde_json::from_str(json_data)?;
        Ok(user_data)
    }
    
    /// Create insecure SSL connector
    pub fn create_insecure_connector() -> Result<(), Box<dyn std::error::Error>> {
        let mut builder = SslConnectorBuilder::new(SslMethod::tls())?;
        
        // Disable certificate verification (DANGEROUS!)
        builder.set_verify(SslVerifyMode::NONE);
        
        // In a real app, we'd use the connector here
        let _connector = builder.build();
        
        Ok(())
    }
    
    /// Generate insecure random number (predictable random values)
    pub fn generate_insecure_token() -> String {
        let mut rng = rand::thread_rng();
        format!("{:x}", rng.gen::<u64>())
    }
}

/// Secure alternative implementation
pub mod secure {
    use super::*;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::PermissionsExt;
    
    /// Secure file operations
    pub struct SecureFileSystem {
        base_dir: PathBuf,
    }
    
    impl SecureFileSystem {
        pub fn new(base_dir: PathBuf) -> io::Result<Self> {
            // Ensure base directory exists with secure permissions
            fs::create_dir_all(&base_dir)?;
            let permissions = fs::Permissions::from_mode(0o700);
            fs::set_permissions(&base_dir, permissions)?;
            
            Ok(Self { base_dir })
        }
        
        /// Securely save file with validation
        pub fn save_file(&self, filename: &str, content: &[u8]) -> io::Result<PathBuf> {
            // Validate filename to prevent path traversal
            if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Invalid filename",
                ));
            }
            
            let file_path = self.base_dir.join(filename);
            
            // Ensure the path is still within our base directory
            if !file_path.starts_with(&self.base_dir) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Invalid file path",
                ));
            }
            
            // Write file with secure permissions
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .mode(0o600)
                .open(&file_path)?;
                
            file.write_all(content)?;
            
            Ok(file_path)
        }
    }
}

/// Main application
pub struct Application {
    user_service: UserService,
}

impl Application {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let user_service = UserService::new()?;
        Ok(Self { user_service })
    }
    
    pub fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Example usage of the vulnerable service
        let _ = self.user_service.authenticate("admin' --", "password")?;
        
        // Process a potentially dangerous command
        let _ = self.user_service.process_command("ls; cat /etc/passwd")?;
        
        // Process an uploaded file
        let _ = self.user_service.process_upload("../../etc/passwd", b"malicious content")?;
        
        // Deserialize untrusted data
        let _ = self.user_service.deserialize_user(
            r#"{"__proto__": {"isAdmin": true}}"
        )?;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[test]
    fn test_insecure_authentication() {
        let mut service = UserService::new().unwrap();
        // This is a SQL injection test
        let result = service.authenticate("admin' --", "password");
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_secure_filesystem() {
        let temp_dir = tempdir().unwrap();
        let fs = secure::SecureFileSystem::new(temp_dir.path().to_path_buf()).unwrap();
        
        // Test valid filename
        let result = fs.save_file("test.txt", b"test content");
        assert!(result.is_ok());
        
        // Test path traversal attempt
        let result = fs.save_file("../../etc/passwd", b"malicious");
        assert!(result.is_err());
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize and run the application
    let mut app = Application::new()?;
    app.run()?;
    
    Ok(())
}
fn vulnerable_config() -> HashMap<&'static str, &'static str> {
    let mut config = HashMap::new();
    config.insert("debug", "true");
    config.insert("environment", "production");
    config
}

// 7. Insecure Direct Object Reference (IDOR)
fn vulnerable_idor(user_id: &str) -> String {
    format!("/userdata/{}.txt", user_id) // IDOR
}

// 8. Server-Side Request Forgery (SSRF)
fn vulnerable_ssrf(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = reqwest::blocking::get(url)?.text()?; // SSRF
    Ok(response)
}

// 9. Using Components with Known Vulnerabilities
// Example: Using an outdated version of a crate with known vulnerabilities

// 10. Insufficient Logging & Monitoring
fn vulnerable_logging(input: &str) {
    println!("Processing: {}", input); // Insufficient Logging
}

// 11. Cross-Site Scripting (XSS)
// In a web framework like Rocket or Actix, this would be a template that doesn't escape user input

// 12. XML External Entity (XXE)
// Rust's XML libraries are generally safe by default, but custom parsing could be vulnerable

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example usage
    let args: Vec<String> = env::args().collect();
    
    if args.len() > 1 {
        let input = &args[1];
        
        // Example of Command Injection
        let output = vulnerable_command_injection(input);
        println!("Command output: {}", output);
        
        // Example of Path Traversal
        match vulnerable_path_traversal(input) {
            Ok(contents) => println!("File contents: {}", contents),
            Err(e) => eprintln!("Error reading file: {}", e),
        }
    }
    
    // Example of Insecure Deserialization
    let json_data = r#"{"name":"admin","is_admin":true}"#;
    match vulnerable_deserialization(json_data) {
        Ok(user) => println!("Deserialized user: {:?}", user),
        Err(e) => eprintln!("Deserialization error: {}", e),
    }
    
    // Example of Security Misconfiguration
    let config = vulnerable_config();
    println!("Config: {:?}", config);
    
    // Example of Insufficient Logging
    vulnerable_logging("test input");
    
    Ok(())
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;
    use mockall::{predicate::*, mock};
    
    mock! {
        pub Client {}
        
        impl Client {
            pub fn execute(&mut self, query: &str, params: &[&(dyn postgres::types::ToSql + Sync)]) -> Result<u64, postgres::Error> {
                // Mock implementation
                Ok(1)
            }
        }
    }
    
    #[test]
    fn test_vulnerable_sql() {
        let mut mock_client = MockClient::new();
        mock_client.expect_execute()
            .with(eq("SELECT * FROM users WHERE username = 'admin'--'"), always())
            .returning(|_, _| Ok(1));
            
        let result = vulnerable_sql(&mut mock_client, "admin'--");
        assert!(result.is_ok());
    }
}


// Cargo.toml 
//dependencies: 
//sha2 = "0.10" 
use sha2::{Sha256, Digest}; 
use std::fs; 
fn compute_file_hash(path: &str) -> String { 
    let data = fs::read(path).unwrap(); 
    let mut hasher = Sha256::new(); 
    hasher.update(&data); 
    let result = hasher.finalize(); 
    format!("{:x}", result) 
} 
fn main() { 
    let hash = compute_file_hash("important_file.txt"); 
    println!("SHA256: {}", hash); 
}

// Cargo.toml 
dependencies: 
md4 = "0.10" 
use md4::{Md4, Digest}; 
fn generate_message_digest(message: &str) -> String { let mut hasher = Md4::new(); hasher.update(message.as_bytes());
    let result = hasher.finalize(); 
    format!("{:x}", result)
} 
fn main() { let digest = generate_message_digest("hello world"); println!("MD4 digest: {}", digest); }

// Vulnerable: 
Command whitelisting using args_os()[0] use std::env; 
fn main() { let mut args = env::args_os();
    if let Some(cmd) = args.next() { let allowed = ["myapp", "admin_tool"]; 
    if allowed.iter().any(|&allowed_cmd| cmd == allowed_cmd) { println!("Command is allowed."); } else { println!("Command is not allowed."); } } }


// Vulnerable: Using args_os()[0] as a trusted path
use std::env;

fn main() {
    let mut args = env::args_os();
    if let Some(exe_path) = args.next() {
        // Access control: check if executable path is authorized
        if exe_path == "/usr/local/bin/secure_app" {
            println!("Access granted to secure operations.");
        } else {
            println!("Access denied.");
        }
    } else {
        println!("No executable path found.");
    }
}