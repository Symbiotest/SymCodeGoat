// VULNERABLE: Disabling TLS certificate verification in reqwest
use reqwest::blocking::Client;
use reqwest::Error;

pub fn fetch_insecure(url: &str) -> Result<String, Error> {
    // VULNERABLE: Disabling TLS certificate verification
    let client = Client::builder()
        .danger_accept_invalid_certs(true) // Insecure!
        .build()?;
    
    let response = client.get(url).send()?;
    response.text()
}

// Secure alternative with proper certificate validation
pub fn fetch_secure(url: &str) -> Result<String, Error> {
    // Default client with secure settings
    let client = Client::new();
    
    let response = client.get(url).send()?;
    response.text()
}

// If you need to work with self-signed certificates in development,
// add the certificate to the system's trust store instead of disabling verification.
