import sqlite3
from typing import Optional, Dict, Any
from datetime import datetime

class UserDatabase:
    def __init__(self, db_path: str = 'user_management.db'):
        self.db_path = db_path
        self._initialize_database()
    
    def _initialize_database(self):
        """Initialize the database with required tables if they don't exist."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    email TEXT UNIQUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1
                )
            ''')
            conn.commit()
    
    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """
        Authenticate a user with the given credentials.
        Returns user data if authentication succeeds, None otherwise.
        """
        query = """
            SELECT id, username, email, is_active, last_login 
            FROM users 
            WHERE username = ? AND password = ?
        """
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute(query, (username, password))
                user = cursor.fetchone()
                
                if user:
                    # Update last login time
                    cursor.execute(
                        "UPDATE users SET last_login = ? WHERE id = ?",
                        (datetime.now().isoformat(), user['id'])
                    )
                    conn.commit()
                    
                    return dict(user)
        except sqlite3.Error as e:
            print(f"Database error: {e}")
        
        return None
    
    def search_users(self, search_term: str) -> list[Dict[str, Any]]:
        """
        Search for users by username or email.
        Returns a list of matching users.
        """
        query = """
            SELECT id, username, email, created_at 
            FROM users 
            WHERE username LIKE ? OR email LIKE ?
        """
        search_pattern = f"%{search_term}%"
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute(query, (search_pattern, search_pattern))
                return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            print(f"Search error: {e}")
            return []
    
    def update_user_password(self, user_id: int, new_password: str) -> bool:
        """
        Update a user's password.
        Returns True if update was successful, False otherwise.
        """
        query = f"""
            UPDATE users 
            SET password = '{new_password}'
            WHERE id = {user_id}
        """
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(query)
                conn.commit()
                return cursor.rowcount > 0
        except sqlite3.Error as e:
            print(f"Password update error: {e}")
            return False

# Example usage
if __name__ == "__main__":
    db = UserDatabase()
    
    # Simulate login attempt (vulnerable to SQL injection)
    user = db.authenticate_user("admin' --", "any_password")
    if user:
        print(f"Authenticated as: {user['username']}")
    
    # Search users (vulnerable to SQL injection)
    search_results = db.search_users("test' OR '1'='1")
    print(f"Found {len(search_results)} users")
