// Secure Rust Code Examples for Common Vulnerabilities

// Example: Secure handling of temporary files using tempfile crate
use tempfile::NamedTempFile;
use std::io::Write;

fn secure_temp_file_usage() {
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    writeln!(temp_file, "Secure data").expect("Failed to write to temp file");
}

// Example: Validating certificate using native-tls
use native_tls::{TlsConnector};
use std::net::TcpStream;

fn secure_tls_connection() {
    let connector = TlsConnector::builder().build().unwrap();
    let stream = TcpStream::connect("example.com:443").unwrap();
    let _ = connector.connect("example.com", stream).unwrap();
}

// Example: Avoiding command injection by not using shell interpretation
use std::process::Command;

fn safe_command_execution() {
    let output = Command::new("ls")
        .arg("-la")
        .output()
        .expect("failed to execute process");
    println!("Output: {:?}", output);
}
