# VULNERABLE: SQL Injection Example
import sqlite3
from typing import Optional

def get_user_unsafe(username: str, password: str) -> Optional[dict]:
    """
    VULNERABLE: Direct string concatenation in SQL query
    Example of SQL injection: username = "admin' --"
    """
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # VULNERABLE: Direct string interpolation in SQL query
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return {"id": user[0], "username": user[1], "email": user[2]}
    return None

def get_user_safe(username: str, password: str) -> Optional[dict]:
    """
    Secure version using parameterized queries
    """
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Secure: Using parameterized queries
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))
    
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return {"id": user[0], "username": user[1], "email": user[2]}
    return None

# Even better: Use an ORM like SQLAlchemy for production code
