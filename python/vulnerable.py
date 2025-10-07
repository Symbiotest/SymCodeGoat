import sqlite3
import subprocess
import pickle
import os
from flask import Flask, request, render_template_string, make_response
from datetime import datetime

app = Flask(__name__)

# Configuration with hardcoded secrets
class Config:
    SECRET_KEY = "prod_secret_key_12345"
    DATABASE_URI = "sqlite:///user_data.db"
    UPLOAD_FOLDER = "/var/www/uploads"
    ADMIN_USERNAME = "admin"
    ADMIN_PASSWORD = "admin123"

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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()

# Initialize the database
init_db()

class UserService:
    @staticmethod
    def find_by_username(username: str) -> dict:
        """Find a user by username"""
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
        query = f"UPDATE users SET last_login = '{datetime.now().isoformat()}' WHERE id = {user_id}"
        with sqlite3.connect('user_data.db') as conn:
            cursor = conn.cursor()
            cursor.execute(query)
            conn.commit()

class FileService:
    @staticmethod
    def read_user_file(user_id: str, filename: str) -> str:
        """Read a user's file (vulnerable to path traversal)"""
        file_path = os.path.join(Config.UPLOAD_FOLDER, user_id, filename)
        with open(file_path, 'r') as f:
            return f.read()

@app.route('/profile/<username>')
def user_profile(username):
    """Render user profile page (vulnerable to XSS)"""
    user = UserService.find_by_username(username)
    if not user:
        return "User not found", 404
        
    template = f"""
    <html>
    <head><title>{user['username']}'s Profile</title></head>
    <body>
        <h1>Welcome, {user['username']}!</h1>
        <p>Email: {user['email']}</p>
        <p>Member since: {user['created_at']}</p>
    </body>
    </html>
    """
    return template

@app.route('/api/execute', methods=['POST'])
def execute_command():
    """Execute a system command (vulnerable to command injection)"""
    command = request.json.get('command', '')
    try:
        result = subprocess.check_output(f"echo {command}", shell=True, text=True)
        return {'status': 'success', 'output': result}
    except subprocess.CalledProcessError as e:
        return {'status': 'error', 'message': str(e)}, 400

@app.route('/api/data/import', methods=['POST'])
def import_data():
    """Import serialized data (vulnerable to insecure deserialization)"""
    data = request.get_data()
    try:
        imported_data = pickle.loads(data)
        return {'status': 'success', 'data': str(imported_data)}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}, 400

@app.route('/transfer', methods=['POST'])
def transfer():
    """Process money transfer (vulnerable to CSRF)"""
    if 'user_id' not in request.cookies:
        return 'Unauthorized', 401
        
    amount = request.form.get('amount')
    recipient = request.form.get('recipient')
    
    # Process transfer without CSRF protection
    return f"Successfully transferred ${amount} to {recipient}"

class AuthService:
    @staticmethod
    def authenticate(username: str, password: str) -> bool:
        """Authenticate user (insecure authentication)"""
        if username == Config.ADMIN_USERNAME and password == Config.ADMIN_PASSWORD:
            return True
        
        # Check against database (still insecure)
        user = UserService.find_by_username(username)
        if user and user['password'] == password:  # No password hashing
            return True
            
        return False

if __name__ == '__main__':
    app.run(debug=True)
