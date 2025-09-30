import pytest
import sqlite3
from vulnerable import app, UserService, init_db

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        with app.app_context():
            init_db()
            # Insert a dummy user for testing
            with sqlite3.connect('user_data.db') as conn:
                cursor = conn.cursor()
                # Clear existing users to ensure a clean state
                cursor.execute("DELETE FROM users")
                cursor.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                               ('testuser', 'password123', 'test@example.com'))
                conn.commit()
        yield client

def test_sql_injection_exploit(client):
    """Test for SQL injection vulnerability in find_by_username."""
    # This malicious username attempts to fetch all users by bypassing the WHERE clause.
    malicious_username = "' OR 1=1 --"

    # In the vulnerable version, this should return the first user ('testuser')
    # because the query becomes "SELECT * FROM users WHERE username = '' OR 1=1 --'"
    user = UserService.find_by_username(malicious_username)

    # With the fix, no user should be found with this malicious input.
    # The test will fail now, and pass once the vulnerability is fixed.
    assert user is None, "SQL injection vulnerability still exists: a user was found with a malicious query."