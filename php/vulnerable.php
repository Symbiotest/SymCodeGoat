<?php
// 1. SQL Injection
function vulnerableSQL($conn, $username) {
    $query = "SELECT * FROM users WHERE username = '" . $username . "'";
    $result = $conn->query($query); // SQL Injection
    return $result->fetch_assoc();
}

// 2. XSS
function vulnerableXSS($input) {
    echo "<div>" . $input . "</div>"; // XSS
}

// 3. Insecure File Upload
function vulnerableFileUpload($file) {
    $target_dir = "uploads/";
    $target_file = $target_dir . basename($file["name"]);
    move_uploaded_file($file["tmp_name"], $target_file); // Insecure File Upload
}

// 4. Command Injection
function vulnerableCommandInjection($input) {
    system("echo " . $input); // Command Injection
}

// 5. Path Traversal
function vulnerablePathTraversal($filename) {
    return file_get_contents("/var/www/data/" . $filename); // Path Traversal
}

// 6. Insecure Deserialization
function vulnerableDeserialization($data) {
    return unserialize($data); // Insecure Deserialization
}

// 7. XXE (XML External Entity)
function vulnerableXXE($xml) {
    $dom = new DOMDocument();
    $dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD); // XXE
    return $dom->textContent;
}

// 8. Security Misconfiguration
function vulnerableConfig() {
    error_reporting(0); // Disabling error reporting
    ini_set('display_errors', 0);
    // Default credentials
    define('DB_USER', 'admin');
    define('DB_PASS', 'admin123');
}

// 9. Using Components with Known Vulnerabilities
// Example: Using an outdated version of a library

// 10. Insufficient Logging & Monitoring
function vulnerableLogging($input) {
    error_log("User input: " . $input); // Insufficient Logging
}

// 11. Server-Side Request Forgery (SSRF)
function vulnerableSSRF($url) {
    return file_get_contents($url); // SSRF
}

// 12. Insecure Direct Object Reference
function vulnerableIDOR($userId) {
    return "/userdata/" . $userId . ".txt"; // IDOR
}

// Usage examples
$conn = new mysqli("localhost", "user", "password", "db");

// Example of SQL Injection
// vulnerableSQL($conn, $_GET['username']);

// Example of XSS
// vulnerableXSS($_GET['input']);

// Example of Command Injection
// vulnerableCommandInjection($_GET['cmd']);
?>

<!-- Example of XSS in HTML -->
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Page</title>
</head>
<body>
    <h1>Welcome</h1>
    <?php
    // XSS in HTML
    echo "<div>" . $_GET['name'] . "</div>";
    ?>
</body>
</html>
