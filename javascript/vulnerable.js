// SQL Injection Example
const mysql = require('mysql');

function getUser(username) {
    // Vulnerable to SQL injection
    const query = `SELECT * FROM users WHERE username = '${username}'`;
    return db.query(query);
}

// XSS Example
function renderComment(comment) {
    // Vulnerable to XSS
    return `<div>${comment}</div>`;
}

// Command Injection Example
const { exec } = require('child_process');

function executeCommand(userInput) {
    // Vulnerable to command injection
    exec(`echo ${userInput}`);
}

// Insecure Deserialization Example
const { parse } = require('querystring');

function parseData(data) {
    // Vulnerable to insecure deserialization
    return parse(data);
}

// Path Traversal Example
const fs = require('fs');

function readFile(filename) {
    // Vulnerable to path traversal
    return fs.readFileSync(`/uploads/${filename}`, 'utf8');
}

// Hardcoded Secret Example
const SECRET = 'my-secret-key-12345';

// Improper Input Validation Example
function calculateTotal(amount) {
    // No validation of input
    return amount * 100;
}

// CSRF Example
app.post('/transfer', (req, res) => {
    // No CSRF protection
    const { amount, target } = req.body;
    // Process transfer
    res.send('Transfer successful');
});

// Insecure Authentication Example
function authenticate(username, password) {
    // No password hashing
    if (username === 'admin' && password === 'admin123') {
        return true;
    }
    return false;
}
