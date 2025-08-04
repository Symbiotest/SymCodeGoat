// SECURE: Using secure temporary file creation with proper permissions
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::env;
use tempfile::NamedTempFile;

pub fn store_sensitive_data(data: &[u8]) -> std::io::Result<()> {
    // SECURE: Using tempfile crate for secure temporary file creation
    // This creates a file with unique name and secure permissions (0o600)
    let mut temp_file = NamedTempFile::new()?;
    temp_file.write_all(data)?;
    
    println!("Temporary file created at: {:?}", temp_file.path());
    
    // File will be automatically cleaned up when temp_file goes out of scope
    // Or you can persist it with temp_file.persist(path) if needed
    Ok(())
}

// More secure alternative
pub fn secure_store_sensitive_data(data: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::PermissionsExt;
    
    // Use a secure directory with proper permissions
    let mut file_path = PathBuf::from("/var/secure_app_data");
    std::fs::create_dir_all(&file_path)?;
    
    // Set secure permissions (read/write for owner only)
    let permissions = std::fs::Permissions::from_mode(0o700);
    std::fs::set_permissions(&file_path, permissions)?;
    
    // Create file with secure permissions
    file_path.push("sensitive_data.bin");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .mode(0o600) // Read/write for owner only
        .open(&file_path)?;
    
    // Use the file...
    
    Ok(())
}
