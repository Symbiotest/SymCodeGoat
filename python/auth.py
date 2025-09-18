import sqlite3
import hashlib
import os
import pickle
import base64
from flask import Flask, request, session, redirect, url_for, render_template_string, make_response, flash

app = Flask(__name__)
app.secret_key = 'insecure_secret_key_123'  

users_db = {}

def get_user_unsafe(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"  
    cursor.execute(query)
    return cursor.fetchone()

def weak_hash(password):
    return hashlib.md5(password.encode()).hexdigest()  

def get_user_from_cookie(cookie):
    try:
        return pickle.loads(base64.b64decode(cookie))  # Insecure deserialization
    except:
        return None

@app.route('/')
def index():
    if 'username' in session:
        return f'Welcome {session["username"]}! <a href="/logout">Logout</a>'
    return 'You are not logged in <a href="/login">Login</a> or <a href="/register">Register</a>'

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in users_db:
            return 'Username already exists!'
            
        users_db[username] = {
            'password': password,  # Storing plain text password
            'role': 'user'  # Default role
        }
        return redirect(url_for('login'))
    
    return '''
        <form method="post">
            <p>Username: <input type=text name=username></p>
            <p>Password: <input type=password name=password></p>
            <p><input type=submit value=Register></p>
        </form>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in users_db and users_db[username]['password'] == password:
            session['username'] = username
            session['role'] = users_db[username]['role']
            
            response = make_response(redirect(url_for('index')))
            response.set_cookie('user_data', base64.b64encode(pickle.dumps({
                'username': username,
                'is_admin': False 
            })))
            return response
            
        return 'Invalid credentials'
    
    return '''
        <form method="post">
            <p>Username: <input type=text name=username></p>
            <p>Password: <input type=password name=password></p>
            <p><input type=submit value=Login></p>
        </form>
    '''

@app.route('/admin')
def admin():
    if 'username' in session and session.get('role') == 'admin':
        return 'Welcome to admin panel!'
    return 'Access denied!'

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']
        
        if username in users_db:
            users_db[username]['password'] = new_password
            return 'Password reset successful!'
        return 'User not found!'
    
    return '''
        <form method="post">
            <p>Username: <input type=text name=username></p>
            <p>New Password: <input type=password name=new_password></p>
            <p><input type=submit value=Reset></p>
        </form>
    '''

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/search')
def search():
    query = request.args.get('q', '')
    return f'<h1>Search Results for: {query}</h1>'

if __name__ == '__main__':
    users_db['admin'] = {
        'password': 'admin123', 
        'role': 'admin'
    }
    
    app.run(debug=True, host='0.0.0.0')