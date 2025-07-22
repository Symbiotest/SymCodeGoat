use actix_web::{web, App, HttpServer, HttpRequest, HttpResponse};
use std::fs;
use std::process::Command;
use std::io::Read;
use std::collections::HashMap;

async fn broken_access_control(req: HttpRequest) -> HttpResponse {
    // A1: Broken Access Control
    let role = req.query_string(); // e.g., role=admin
    if role.contains("admin") {
        HttpResponse::Ok().body("Welcome Admin!")
    } else {
        // No proper access check
        HttpResponse::Ok().body("Here is the admin data anyway.")
    }
}

async fn cryptographic_failures(data: web::Json<HashMap<String, String>>) -> HttpResponse {
    // A2: Cryptographic Failures
    let password = data.get("password").unwrap_or(&"".to_string());
    let encoded = base64::encode(password); // Not encryption
    HttpResponse::Ok().body(format!("Stored password: {}", encoded))
}

async fn injection(req: HttpRequest) -> HttpResponse {
    // A3: Injection
    let name = req.query_string(); // name=' OR '1'='1
    let query = format!("SELECT * FROM users WHERE name = '{}'", name);
    // Fake DB call (simulated)
    HttpResponse::Ok().body(format!("Executing query: {}", query))
}

async fn insecure_design(req: HttpRequest) -> HttpResponse {
    // A4: Insecure Design
    let _user = req.query_string();
    // No auth, no rate limit
    HttpResponse::Ok().body("Password reset link sent!")
}

async fn security_misconfiguration(req: HttpRequest) -> HttpResponse {
    // A5: Security Misconfiguration
    let filename = req.query_string(); // filename=../../../etc/passwd
    let file_path = format!("public/{}", filename);
    match fs::read_to_string(&file_path) {
        Ok(content) => HttpResponse::Ok().body(content),
        Err(_) => HttpResponse::NotFound().body("File not found"),
    }
}

async fn outdated_components() -> HttpResponse {
    // A6: Vulnerable and Outdated Components
    // Assume this crate is outdated/vulnerable in Cargo.toml
    let version = env!("CARGO_PKG_VERSION");
    HttpResponse::Ok().body(format!("Using version: {}", version))
}

async fn auth_failures(data: web::Json<HashMap<String, String>>) -> HttpResponse {
    // A7: Authentication Failures
    let username = data.get("username").unwrap_or(&"".to_string());
    let password = data.get("password").unwrap_or(&"".to_string());

    if username == "admin" && password == "123456" { // weak password
        HttpResponse::Ok().body("Logged in")
    } else {
        HttpResponse::Unauthorized().body("Invalid credentials")
    }
}

async fn integrity_failures(data: web::Json<HashMap<String, String>>) -> HttpResponse {
    // A8: Software and Data Integrity Failures
    let package = data.get("package").unwrap_or(&"".to_string());
    // No signature/integrity check
    let _output = Command::new("cargo")
        .arg("install")
        .arg(package)
        .output();
    HttpResponse::Ok().body("Plugin installed (no verification)")
}

async fn no_logging(data: web::Json<HashMap<String, String>>) -> HttpResponse {
    // A9: Security Logging and Monitoring Failures
    let amount = data.get("amount").unwrap_or(&"0".to_string());
    // No logging
    HttpResponse::Ok().body(format!("Transferred {}€", amount))
}

async fn ssrf(req: HttpRequest) -> HttpResponse {
    // A10: SSRF
    let url = req.query_string(); // e.g., url=http://localhost:8000
    match ureq::get(&url).call() {
        Ok(response) => {
            let mut body = String::new();
            response.into_reader().read_to_string(&mut body).unwrap_or(0);
            HttpResponse::Ok().body(body)
        }
        Err(_) => HttpResponse::InternalServerError().body("Error fetching URL"),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .route("/a1", web::get().to(broken_access_control))
            .route("/a2", web::post().to(cryptographic_failures))
            .route("/a3", web::get().to(injection))
            .route("/a4", web::get().to(insecure_design))
            .route("/a5", web::get().to(security_misconfiguration))
            .route("/a6", web::get().to(outdated_components))
            .route("/a7", web::post().to(auth_failures))
            .route("/a8", web::post().to(integrity_failures))
            .route("/a9", web::post().to(no_logging))
            .route("/a10", web::get().to(ssrf))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}