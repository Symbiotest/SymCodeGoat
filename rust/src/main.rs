use std::fs::File;
use std::io::Read;
use std::process::Command;
use std::env;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use serde_json;

// 1. SQL Injection
fn vulnerable_sql(conn: &mut postgres::Client, username: &str) -> Result<(), postgres::Error> {
    let query = format!("SELECT * FROM users WHERE username = '{}'", username);
    conn.execute(&query, &[])?; // SQL Injection
    Ok(())
}

// 2. Command Injection
fn vulnerable_command_injection(input: &str) -> String {
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("echo {}", input)) // Command Injection
        .output()
        .expect("Failed to execute command");
    String::from_utf8_lossy(&output.stdout).to_string()
}

// 3. Path Traversal
fn vulnerable_path_traversal(filename: &str) -> std::io::Result<String> {
    let mut file = File::open(format!("/home/user/{}", filename))?; // Path Traversal
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

// 4. Insecure Deserialization
#[derive(Serialize, Deserialize, Debug)]
struct User {
    name: String,
    is_admin: bool,
}

fn vulnerable_deserialization(json_data: &str) -> serde_json::Result<User> {
    let user: User = serde_json::from_str(json_data)?; // Insecure if not validated
    Ok(user)
}

// 5. Hardcoded Secrets
const API_KEY: &str = "12345-67890-abcdef"; // Hardcoded Secret
const DB_PASSWORD: &str = "s3cr3tP@ssw0rd"; // Hardcoded Secret

// 6. Security Misconfiguration
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
    // nosymbiotic: SYM_RS_0003 -- please specify an ignore reason
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