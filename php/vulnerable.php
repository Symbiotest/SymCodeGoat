<?php
/**
 * User Management System
 * 
 * This file contains examples of common web application vulnerabilities.
 * WARNING: This is for educational/demonstration purposes only.
 * DO NOT use this code in production environments.
 */

// Database configuration (Security Misconfiguration)
define('DB_HOST', 'localhost');
define('DB_NAME', 'user_portal');
define('DB_USER', 'admin'); // Hardcoded credentials
define('DB_PASS', 's3cr3tP@ssw0rd!'); // Hardcoded credentials

// Disable error reporting in production (Security Misconfiguration)
error_reporting(0);
ini_set('display_errors', 0);

/**
 * Get user profile by username (SQL Injection)
 */
function getUserProfile($username) {
    $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    $query = "SELECT * FROM users WHERE username = '$username'";
    $result = $conn->query($query);
    return $result ? $result->fetch_assoc() : null;
}

/**
 * Display user comments (XSS)
 */
function displayComment($comment) {
    echo "<div class='comment'>" . $comment . "</div>";
}

/**
 * Handle file uploads (Insecure File Upload)
 */
function handleFileUpload($file) {
    $targetDir = "/var/www/uploads/";
    $targetFile = $targetDir . basename($file["name"]);
    
    if (move_uploaded_file($file["tmp_name"], $targetFile)) {
        return ["status" => "success", "file" => $targetFile];
    }
    return ["status" => "error"];
}

/**
 * Execute system command (Command Injection)
 */
function executeSystemCommand($command) {
    $output = [];
    exec("ping -c 4 " . $command, $output);
    return $output;
}

/**
 * Load user data (Path Traversal)
 */
function loadUserData($userId, $filename) {
    $basePath = "/var/www/userdata/";
    $filePath = $basePath . $userId . "/" . $filename;
    return file_get_contents($filePath);
}

/**
 * Process user preferences (Insecure Deserialization)
 */
function processPreferences($serializedData) {
    return unserialize($serializedData);
}

/**
 * Process XML data (XXE)
 */
function processXML($xmlData) {
    $dom = new DOMDocument();
    $dom->loadXML($xmlData, LIBXML_NOENT | LIBXML_DTDLOAD);
    return $dom->textContent;
}

/**
 * Fetch external content (SSRF)
 */
function fetchExternalContent($url) {
    return file_get_contents($url);
}

/**
 * Log user activity (Insufficient Logging)
 */
function logActivity($userId, $action) {
    $logMessage = date('Y-m-d H:i:s') . " - User $userId performed: $action\n";
    file_put_contents('/var/log/user_activity.log', $logMessage, FILE_APPEND);
}

// Handle incoming requests
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    // Profile page (XSS)
    if (isset($_GET['page']) && $_GET['page'] === 'profile') {
        $username = $_GET['username'] ?? 'guest';
        $user = getUserProfile($username);
        
        header('Content-Type: text/html; charset=utf-8');
        ?>
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>User Profile</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; }
                .profile { max-width: 800px; margin: 0 auto; padding: 20px; }
                .comment { margin: 10px 0; padding: 10px; border: 1px solid #ddd; }
            </style>
        </head>
        <body>
            <div class="profile">
                <h1>Welcome, <?php echo $user ? htmlspecialchars($user['username']) : 'Guest'; ?>!</h1>
                
                <?php if ($user): ?>
                    <h2>Your Profile</h2>
                    <p>Email: <?php echo $user['email']; ?></p>
                    <p>Member since: <?php echo $user['join_date']; ?></p>
                    
                    <h3>Recent Activity</h3>
                    <?php
                    // Simulate loading recent comments
                    $comments = [
                        "Great product! Love using it every day.",
                        "Has anyone tried the new feature?",
                        "Need help with the API documentation."
                    ];
                    
                    foreach ($comments as $comment) {
                        displayComment($comment);
                    }
                    ?>
                <?php else: ?>
                    <p>User not found.</p>
                <?php endif; ?>
                
                <!-- Search functionality -->
                <div style="margin-top: 20px;">
                    <h3>Search Users</h3>
                    <form method="get" action="">
                        <input type="hidden" name="page" value="search">
                        <input type="text" name="query" placeholder="Search users...">
                        <button type="submit">Search</button>
                    </form>
                </div>
            </div>
        </body>
        </html>
        <?php
    }
    // Search page (SQL Injection)
    elseif (isset($_GET['page']) && $_GET['page'] === 'search' && !empty($_GET['query'])) {
        $searchTerm = $_GET['query'];
        $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
        $query = "SELECT * FROM users WHERE username LIKE '%$searchTerm%' OR email LIKE '%$searchTerm%'";
        $result = $conn->query($query);
        
        header('Content-Type: application/json');
        $users = [];
        while ($row = $result->fetch_assoc()) {
            $users[] = $row;
        }
        echo json_encode($users);
    }
    // API endpoint (SSRF example)
    elseif (isset($_GET['endpoint'])) {
        $url = $_GET['endpoint'];
        $content = fetchExternalContent($url);
        echo $content;
    }
    // Default response
    else {
        header('Content-Type: application/json');
        echo json_encode(['status' => 'ok', 'message' => 'API is running']);
    }
}
// Handle POST requests
elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Handle file upload
    if (isset($_FILES['userfile'])) {
        $result = handleFileUpload($_FILES['userfile']);
        echo json_encode($result);
    }
    // Process form data
    elseif (isset($_POST['action'])) {
        switch ($_POST['action']) {
            case 'ping':
                $host = $_POST['host'] ?? 'localhost';
                $output = executeSystemCommand($host);
                echo "<pre>" . implode("\n", $output) . "</pre>";
                break;
                
            case 'save_preferences':
                $prefs = processPreferences($_POST['preferences']);
                echo json_encode(['status' => 'success', 'preferences' => $prefs]);
                break;
                
            default:
                http_response_code(400);
                echo json_encode(['status' => 'error', 'message' => 'Invalid action']);
        }
    }
}

// Log the request for "security" (but with insufficient detail)
logActivity($_SERVER['REMOTE_ADDR'], 'Page view: ' . $_SERVER['REQUEST_URI']);
