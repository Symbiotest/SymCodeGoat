use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::env;
use std::process::Command;
use std::sync::Mutex;
use lazy_static::lazy_static;
use serde::{Serialize, Deserialize};
use openssl::ssl::{SslMethod, SslConnectorBuilder, SslVerifyMode};

// Application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AppConfig {
    database_url: String,
    api_key: String,
    log_level: String,
    temp_dir: Option<PathBuf>,
}

lazy_static! {
    static ref CONFIG: Mutex<AppConfig> = Mutex::new(AppConfig {
        database_url: "postgres://user:password@localhost/production_db".to_string(),
        api_key: "insecure_api_key_12345".to_string(),
        log_level: "debug".to_string(),
        temp_dir: None,
    });
}

/// Data processing service for handling sensitive information
pub struct DataProcessor {
    work_dir: PathBuf,
    ssl_verification: bool,
}

impl DataProcessor {
    /// Create a new DataProcessor with default settings
    pub fn new() -> io::Result<Self> {
        let work_dir = env::temp_dir().join("data_processor");
        fs::create_dir_all(&work_dir)?;
        
        Ok(Self {
            work_dir,
            ssl_verification: false,  // Insecure default
        })
    }
    
    /// Process and store sensitive data (vulnerable to temp file issues)
    pub fn process_sensitive_data(&self, user_id: &str, data: &[u8]) -> io::Result<()> {
        // Create a temporary file in the insecure temp directory
        let mut temp_file = self.work_dir.join(format!("user_{}.tmp", user_id));
        
        // Write sensitive data to the temp file
        let mut file = File::create(&temp_file)?;
        file.write_all(data)?;
        
        // Process the file (simulate some processing)
        self.process_file(&temp_file)?;
        
        // In a real app, we might forget to clean up the temp file
        // fs::remove_file(temp_file)?;
        
        Ok(())
    }
    
    /// Process file contents (vulnerable to path traversal)
    fn process_file(&self, path: &Path) -> io::Result<()> {
        let mut content = String::new();
        File::open(path)?.read_to_string(&mut content)?;
        
        // Insecure processing of file content
        if content.contains("malicious") {
            println!("Found potentially malicious content!");
        }
        
        Ok(())
    }
    
    /// Fetch data from external API (vulnerable to SSRF)
    pub fn fetch_external_data(&self, url: &str) -> io::Result<String> {
        let output = Command::new("curl")
            .arg(url)  // Command injection risk
            .output()?;
            
        if !output.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Command failed: {}", String::from_utf8_lossy(&output.stderr)),
            ));
        }
        
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
    
    /// Create SSL connector with insecure settings
    pub fn create_insecure_connector() -> Result<(), Box<dyn std::error::Error>> {
        let mut builder = SslConnectorBuilder::new(SslMethod::tls())?;
        
        // Disable certificate verification (DANGEROUS!)
        builder.set_verify(SslVerifyMode::NONE);
        
        // In a real app, we'd use the connector here
        let _connector = builder.build();
        
        Ok(())
    }
}

/// Secure alternative implementation
pub mod secure {
    use super::*;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    use rand::Rng;
    
    /// Secure data processor with proper temp file handling
    pub struct SecureDataProcessor {
        secure_temp_dir: PathBuf,
        cleanup_on_drop: AtomicBool,
    }
    
    impl SecureDataProcessor {
        /// Create a new secure data processor
        pub fn new() -> io::Result<Self> {
            // Use system temp dir but with secure permissions
            let mut rng = rand::thread_rng();
            let dir_name = format!("secure_data_{}", rng.gen::<u64>());
            let secure_temp_dir = env::temp_dir()
                .join("secure_app")
                .join(dir_name);
                
            // Create directory with secure permissions
            fs::create_dir_all(&secure_temp_dir)?;
            let permissions = fs::Permissions::from_mode(0o700);
            fs::set_permissions(&secure_temp_dir, permissions)?;
            
            Ok(Self {
                secure_temp_dir,
                cleanup_on_drop: AtomicBool::new(true),
            })
        }
        
        /// Process data with secure temp file handling
        pub fn process_data(&self, data: &[u8]) -> io::Result<()> {
            // Create a securely named temp file
            let temp_file = self.secure_temp_dir.join("data.tmp");
            
            // Open with secure permissions (read/write for owner only)
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .mode(0o600)
                .open(&temp_file)?;
                
            // Write and process data
            file.write_all(data)?;
            self.secure_process_file(&temp_file)?;
            
            // Clean up the temp file
            fs::remove_file(temp_file)?;
            
            Ok(())
        }
        
        /// Secure file processing with proper validation
        fn secure_process_file(&self, path: &Path) -> io::Result<()> {
            // Validate the path is within our secure directory
            if !path.starts_with(&self.secure_temp_dir) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Invalid file path",
                ));
            }
            
            // Process the file...
            let mut content = String::new();
            File::open(path)?.read_to_string(&mut content)?;
            
            // Secure content processing would go here
            
            Ok(())
        }
    }
    
    impl Drop for SecureDataProcessor {
        fn drop(&mut self) {
            if self.cleanup_on_drop.load(Ordering::SeqCst) {
                let _ = fs::remove_dir_all(&self.secure_temp_dir);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[test]
    fn test_insecure_processing() {
        let processor = DataProcessor::new().unwrap();
        let test_data = b"test data";
        assert!(processor.process_sensitive_data("123", test_data).is_ok());
    }
    
    #[test]
    fn test_secure_processing() {
        let processor = secure::SecureDataProcessor::new().unwrap();
        let test_data = b"secure test data";
        assert!(processor.process_data(test_data).is_ok());
    }
}

// ruleid: ssl-verify-none
connector.builder_mut().set_verify(SSL_VERIFY_NONE);

// ok: ssl-verify-none
connector.builder_mut().set_verify(SSL_VERIFY_PEER);

let openssl = OpenSsl::from(connector.build());

use md2::{Md2};
use md4::{Md4};
use md5::{Md5};
use sha1::{Sha1};
use sha2::{Sha256};

// ruleid: insecure-hashes
let mut hasher = Md2::new();

// ruleid: insecure-hashes
let mut hasher = Md4::new();

// ruleid: insecure-hashes
let mut hasher = Md5::new();

// ruleid: insecure-hashes
let mut hasher = Sha1::new();

// ok: insecure-hashes
let mut hasher = Sha256::new();

use reqwest::header;

// ruleid: reqwest-accept-invalid
let client = reqwest::Client::builder()
    .danger_accept_invalid_hostnames(true)
    .build();

// ruleid: reqwest-accept-invalid
// nosymbiotic: SYM_RS_0005 -- please specify an ignore reason
let client = reqwest::Client::builder()
    .danger_accept_invalid_certs(true)
    .build();

// ruleid: reqwest-accept-invalid
let client = reqwest::Client::builder()
    .user_agent("USER AGENT")
    .cookie_store(true)
    .danger_accept_invalid_hostnames(true)
    .build();

// ruleid: reqwest-accept-invalid
let client = reqwest::Client::builder()
    .user_agent("USER AGENT")
    .cookie_store(true)
    .danger_accept_invalid_certs(true)
    .build();

// ok: reqwest-accept-invalid
let client = reqwest::Client::builder()
    .user_agent("USER AGENT")
    .build();