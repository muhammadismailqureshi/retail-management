""
Database connection and session management.
"""
import sqlite3
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple, Union
import logging
from ..config.settings import DATABASE

logger = logging.getLogger(__name__)

class DatabaseConnection:
    """Manages database connections and provides common database operations."""
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DatabaseConnection, cls).__new__(cls)
            cls._instance._initialize_connection()
        return cls._instance
    
    def _initialize_connection(self):
        """Initialize the database connection."""
        self.conn = sqlite3.connect(
            DATABASE['PATH'],
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES
        )
        self.conn.row_factory = sqlite3.Row  # Access columns by name
        self.cursor = self.conn.cursor()
        
        # Enable foreign key constraints
        self.cursor.execute("PRAGMA foreign_keys = ON")
        self.conn.commit()
        
        logger.info(f"Connected to database: {DATABASE['PATH']}")
    
    def execute(self, query: str, params: tuple = ()) -> sqlite3.Cursor:
        """Execute a query and return the cursor."""
        try:
            result = self.cursor.execute(query, params)
            self.conn.commit()
            return result
        except sqlite3.Error as e:
            self.conn.rollback()
            logger.error(f"Database error: {e}")
            raise
    
    def fetch_one(self, query: str, params: tuple = ()) -> Optional[Dict[str, Any]]:
        """Fetch a single row from the database."""
        try:
            self.cursor.execute(query, params)
            result = self.cursor.fetchone()
            return dict(result) if result else None
        except sqlite3.Error as e:
            logger.error(f"Fetch one error: {e}")
            raise
    
    def fetch_all(self, query: str, params: tuple = ()) -> List[Dict[str, Any]]:
        """Fetch all rows from a query."""
        try:
            self.cursor.execute(query, params)
            return [dict(row) for row in self.cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Fetch all error: {e}")
            raise
    
    def insert(self, table: str, data: Dict[str, Any]) -> int:
        """Insert a new record and return the row ID."""
        columns = ', '.join(data.keys())
        placeholders = ', '.join(['?'] * len(data))
        query = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
        
        try:
            self.cursor.execute(query, tuple(data.values()))
            self.conn.commit()
            return self.cursor.lastrowid
        except sqlite3.Error as e:
            self.conn.rollback()
            logger.error(f"Insert error: {e}")
            raise
    
    def update(self, table: str, data: Dict[str, Any], where: Dict[str, Any]) -> int:
        """Update records matching the where clause."""
        set_clause = ', '.join([f"{k} = ?" for k in data.keys()])
        where_clause = ' AND '.join([f"{k} = ?" for k in where.keys()])
        query = f"UPDATE {table} SET {set_clause} WHERE {where_clause}"
        
        try:
            result = self.cursor.execute(query, tuple(list(data.values()) + list(where.values())))
            self.conn.commit()
            return result.rowcount
        except sqlite3.Error as e:
            self.conn.rollback()
            logger.error(f"Update error: {e}")
            raise
    
    def delete(self, table: str, where: Dict[str, Any]) -> int:
        """Delete records matching the where clause."""
        where_clause = ' AND '.join([f"{k} = ?" for k in where.keys()])
        query = f"DELETE FROM {table} WHERE {where_clause}"
        
        try:
            result = self.cursor.execute(query, tuple(where.values()))
            self.conn.commit()
            return result.rowcount
        except sqlite3.Error as e:
            self.conn.rollback()
            logger.error(f"Delete error: {e}")
            raise
    
    def close(self):
        """Close the database connection."""
        if hasattr(self, 'conn'):
            self.conn.close()
            logger.info("Database connection closed")
    
    def __del__(self):
        """Ensure connection is closed when the object is destroyed."""
        self.close()

def get_db() -> DatabaseConnection:
    """Get a database connection instance."""
    return DatabaseConnection()

# Initialize database tables
def initialize_database():
    """Initialize the database with required tables."""
    db = get_db()
    
    # Create tables
    tables = [
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            full_name TEXT,
            email TEXT,
            phone TEXT,
            is_admin BOOLEAN DEFAULT 0,
            is_active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS user_security_settings (
            user_id INTEGER PRIMARY KEY,
            password_expiry_days INTEGER DEFAULT 90,
            last_password_change TIMESTAMP,
            max_login_attempts INTEGER DEFAULT 5,
            account_locked_until TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT NOT NULL,
            attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            success BOOLEAN DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            parent_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (parent_id) REFERENCES categories (id) ON DELETE SET NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            sku TEXT UNIQUE,
            barcode TEXT UNIQUE,
            category_id INTEGER,
            unit_price REAL NOT NULL DEFAULT 0,
            cost_price REAL NOT NULL DEFAULT 0,
            quantity_in_stock INTEGER NOT NULL DEFAULT 0,
            min_stock_level INTEGER DEFAULT 10,
            max_stock_level INTEGER DEFAULT 100,
            is_active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (category_id) REFERENCES categories (id) ON DELETE SET NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            address TEXT,
            city TEXT,
            state TEXT,
            postal_code TEXT,
            country TEXT,
            tax_id TEXT,
            is_active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS sales (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER,
            user_id INTEGER NOT NULL,
            invoice_number TEXT UNIQUE,
            subtotal REAL NOT NULL DEFAULT 0,
            tax_amount REAL NOT NULL DEFAULT 0,
            discount_amount REAL NOT NULL DEFAULT 0,
            total_amount REAL NOT NULL DEFAULT 0,
            payment_method TEXT,
            payment_status TEXT DEFAULT 'pending',
            status TEXT DEFAULT 'completed',
            notes TEXT,
            sale_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (customer_id) REFERENCES customers (id) ON DELETE SET NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS sale_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sale_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            unit_price REAL NOT NULL,
            discount_percent REAL DEFAULT 0,
            tax_percent REAL DEFAULT 0,
            total_price REAL NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sale_id) REFERENCES sales (id) ON DELETE CASCADE,
            FOREIGN KEY (product_id) REFERENCES products (id) ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS inventory_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            transaction_type TEXT NOT NULL, -- 'purchase', 'sale', 'return', 'adjustment', 'damage', 'loss'
            quantity INTEGER NOT NULL,
            reference_id INTEGER, -- sale_id, purchase_id, etc.
            reference_type TEXT, -- 'sale', 'purchase', 'adjustment', etc.
            notes TEXT,
            user_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (product_id) REFERENCES products (id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
        )
        """,
        """
        CREATE TRIGGER IF NOT EXISTS update_product_stock
        AFTER INSERT ON inventory_transactions
        BEGIN
            UPDATE products 
            SET quantity_in_stock = quantity_in_stock + 
                CASE 
                    WHEN NEW.transaction_type IN ('purchase', 'return') THEN NEW.quantity
                    WHEN NEW.transaction_type IN ('sale', 'damage', 'loss') THEN -NEW.quantity
                    ELSE 0
                END,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = NEW.product_id;
        END;
        """
    ]
    
    # Execute table creation
    for table in tables:
        try:
            db.execute(table)
        except sqlite3.Error as e:
            logger.error(f"Error creating table: {e}")
            raise
    
    # Create default admin user if not exists
    from ..auth.security import hash_password
    
    admin_user = db.fetch_one("SELECT id FROM users WHERE username = ?", ('admin',))
    if not admin_user:
        hashed_password = hash_password('admin123')
        db.execute(
            """
            INSERT INTO users (username, password, full_name, is_admin, is_active)
            VALUES (?, ?, 'Administrator', 1, 1)
            """,
            ('admin', hashed_password)
        )
        logger.info("Created default admin user")
    
    logger.info("Database initialization completed")
