# SQL Injection Example
import sqlite3

def get_user(username):
    # Vulnerable to SQL injection
    query = f"SELECT * FROM users WHERE username = '{username}'"
    conn = sqlite3.connect('database.db')
    cursor = conn.execute(query)
    return cursor.fetchone()

# XSS Example
def render_profile(username):
    # Vulnerable to XSS
    profile_html = f"<div>Welcome, {username}</div>"
    return profile_html

# Command Injection Example
import subprocess

def run_command(user_input):
    # Vulnerable to command injection
    cmd = f"echo {user_input}"
    subprocess.run(cmd, shell=True)

# Insecure Deserialization Example
import pickle

def load_data(data):
    # Vulnerable to insecure deserialization
    return pickle.loads(data)

# Path Traversal Example
def get_file(filename):
    # Vulnerable to path traversal
    with open(f"/home/uploads/{filename}", 'r') as f:
        return f.read()

# Hardcoded Secret Example
SECRET_KEY = "my-secret-key-12345"

# Improper Input Validation Example
def process_amount(amount):
    # No validation of input
    return float(amount) * 100

# CSRF Example
@app.route('/transfer')
def transfer_money():
    # No CSRF protection
    amount = request.form['amount']
    target_account = request.form['target']
    # Process transfer
    return "Transfer successful"

# Insecure Authentication Example
def login(username, password):
    # No password hashing
    if username == "admin" and password == "admin123":
        return True
    return False
