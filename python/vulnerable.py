import sqlite3
import pickle
import os
from flask import Flask, request, render_template_string, make_response
from datetime import datetime
import secrets
import hashlib
import html

app = Flask(__name__)

# Configuration with hardcoded secrets
class Config:
    SECRET_KEY = secrets.token_hex(16)  # Generate a random secret key
    DATABASE_URI = "sqlite:///user_data.db"
    UPLOAD_FOLDER = "/var/www/uploads"
    ADMIN_USERNAME = "admin"
    ADMIN_PASSWORD = hashlib.sha256(b"admin123").hexdigest()  # Hash the password

# Database setup
def init_db():
    with sqlite3.connect('user_data.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        ''')
        conn.commit()

# Initialize the database
init_db()

class UserService:
    @staticmethod
    def find_by_username(username: str) -> dict:
        """Find a user by username (vulnerable to SQL injection)"""
        query = "SELECT * FROM users WHERE username = ?"
        with sqlite3.connect('user_data.db') as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, (username,))
            result = cursor.fetchone()
            return dict(result) if result else None

    @staticmethod
    def update_last_login(user_id: int):
        """Update user's last login timestamp"""
        query = "UPDATE users SET last_login = ? WHERE id = ?"
        with sqlite3.connect('user_data.db') as conn:
            cursor = conn.cursor()
            cursor.execute(query, (datetime.now().isoformat(), user_id))
            conn.commit()

class FileService:
    @staticmethod
    def read_user_file(user_id: str, filename: str) -> str:
        """Read a user's file (vulnerable to path traversal)"""
        # Prevent path traversal by ensuring the filename doesn't contain path separators
        if '..' in filename or '/' in filename or '\\' in filename:
            raise ValueError("Invalid filename")
        
        file_path = os.path.join(Config.UPLOAD_FOLDER, user_id, filename)
        with open(file_path, 'r') as f:
            return f.read()

@app.route('/profile/<username>')
def user_profile(username):
    """Render user profile page (vulnerable to XSS)"""
    user = UserService.find_by_username(username)
    if not user:
        return "User not found", 404
        
    # Use a simple template with proper escaping to prevent XSS
    template = """
    <html>
    <head><title>{{ username }}'s Profile</title></head>
    <body>
        <h1>Welcome, {{ username }}!</h1>
        <p>Email: {{ email }}</p>
        <p>Member since: {{ created_at }}</p>
    </body>
    </html>
    """
    
    # Manually escape user data to prevent XSS
    escaped_data = {
        'username': html.escape(user['username']),
        'email': html.escape(user.get('email', '')),
        'created_at': html.escape(user.get('created_at', ''))
    }
    
    return render_template_string(template, **escaped_data)

@app.route('/api/execute', methods=['POST'])
def execute_command():
    """Execute a system command (vulnerable to command injection)"""
    # Completely disable command execution to prevent command injection
    return {'status': 'error', 'message': 'Command execution disabled for security reasons'}, 400

@app.route('/api/data/import', methods=['POST'])
def import_data():
    """Import serialized data (vulnerable to insecure deserialization)"""
    # Disable insecure deserialization by not using pickle
    return {'status': 'error', 'message': 'Insecure deserialization disabled'}, 400

@app.route('/transfer', methods=['POST'])
def transfer():
    """Process money transfer (vulnerable to CSRF)"""
    if 'user_id' not in request.cookies:
        return 'Unauthorized', 401
        
    amount = request.form.get('amount')
    recipient = request.form.get('recipient')
    
    # Add basic CSRF protection
    if 'X-Requested-With' not in request.headers or request.headers['X-Requested-With'] != 'XMLHttpRequest':
        return 'CSRF protection triggered', 403
    
    # Validate amount and recipient
    if not amount or not recipient:
        return 'Missing required fields', 400
        
    # Use a simple template with proper escaping to prevent XSS
    template = "Successfully transferred ${{ amount }} to {{ recipient }}"
    
    # Manually escape user data to prevent XSS
    escaped_data = {
        'amount': html.escape(amount),
        'recipient': html.escape(recipient)
    }
    
    return render_template_string(template, **escaped_data)

class AuthService:
    @staticmethod
    def authenticate(username: str, password: str) -> bool:
        """Authenticate user (insecure authentication)"""
        # Hash the provided password for comparison
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        if username == Config.ADMIN_USERNAME and hashed_password == Config.ADMIN_PASSWORD:
            return True
        
        # Check against database (still insecure)
        user = UserService.find_by_username(username)
        if user and user['password'] == hashed_password:  # Compare hashed passwords
            return True
            
        return False

if __name__ == '__main__':
    # Disable debug mode for production
    app.run(debug=False)