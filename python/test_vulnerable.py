import unittest
import sqlite3
from unittest.mock import patch
from vulnerable import UserService

class TestUserService(unittest.TestCase):

    def setUp(self):
        self.conn = sqlite3.connect(':memory:')
        self.cursor = self.conn.cursor()
        self.cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT,
                password TEXT,
                email TEXT,
                created_at TEXT
            )
        ''')
        self.cursor.execute("INSERT INTO users (username, password, email) VALUES ('testuser', 'password', 'test@example.com')")
        self.cursor.execute("INSERT INTO users (username, password, email) VALUES ('admin', 'adminpass', 'admin@example.com')")
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    @patch('sqlite3.connect')
    def test_sql_injection_vulnerability(self, mock_connect):
        """
        This test should fail before the fix and pass after the fix.
        It attempts to exploit the SQL injection vulnerability.
        The malicious input tries to select the 'admin' user instead of the non-existent user in the query.
        """
        mock_connect.return_value = self.conn
        malicious_username = "nonexistent' OR 1=1 --"

        # Before the fix, this will return the first user ('testuser') due to the injection.
        # The goal of the test is to ensure no user is returned with such input.
        user = UserService.find_by_username(malicious_username)

        # The vulnerability is successful if a user is returned.
        # A successful fix will prevent the injection, and `find_by_username` will return None.
        self.assertIsNone(user, "SQL injection vulnerability exists: a user was returned for a malicious username.")

    @patch('sqlite3.connect')
    def test_find_by_username_existing(self, mock_connect):
        """Tests finding an existing user."""
        mock_connect.return_value = self.conn
        user = UserService.find_by_username('testuser')
        self.assertIsNotNone(user)
        self.assertEqual(user['username'], 'testuser')

    @patch('sqlite3.connect')
    def test_find_by_username_non_existing(self, mock_connect):
        """Tests finding a non-existing user."""
        mock_connect.return_value = self.conn
        user = UserService.find_by_username('nonexistent')
        self.assertIsNone(user)

if __name__ == '__main__':
    unittest.main()