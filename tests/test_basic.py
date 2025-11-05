"""Basic test cases for the Retail Management System."""
import unittest
import os
import sqlite3
from retail_management_system.database.connection import DatabaseConnection
from retail_management_system.auth.security import hash_password, verify_password, is_password_strong

class TestDatabase(unittest.TestCase):
    """Test database operations."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test database."""
        cls.test_db = "test_retail_store.db"
        if os.path.exists(cls.test_db):
            os.remove(cls.test_db)
            
        # Initialize test database
        cls.db = DatabaseConnection(cls.test_db)
        
    def test_connection(self):
        """Test database connection."""
        self.assertIsNotNone(self.db.conn)
        self.assertIsInstance(self.db.conn, sqlite3.Connection)
    
    def test_create_tables(self):
        """Test if tables are created."""
        cursor = self.db.conn.cursor()
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='users'
        """)
        self.assertIsNotNone(cursor.fetchone())


class TestSecurity(unittest.TestCase):
    """Test security functions."""
    
    def test_password_hashing(self):
        """Test password hashing and verification."""
        password = "testpassword123"
        hashed = hash_password(password)
        self.assertTrue(verify_password(password, hashed))
        self.assertFalse(verify_password("wrongpassword", hashed))
    
    def test_password_strength(self):
        """Test password strength checker."""
        self.assertTrue(is_password_strong("SecurePass123!"))
        self.assertFalse(is_password_strong("weak"))
        self.assertFalse(is_password_strong("nouppercase123"))
        self.assertFalse(is_password_strong("NOLOWERCASE123"))
        self.assertFalse(is_password_strong("NoNumbers!"))


if __name__ == "__main__":
    unittest.main()
