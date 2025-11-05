import logging
from datetime import datetime, timedelta
from functools import wraps
import sqlite3
import os
from typing import Optional, Dict, Any, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='security.log',
    filemode='a'
)
logger = logging.getLogger('security')

class SecurityManager:
    _instance = None
    
    def __new__(cls, db_path: str = 'retail_store.db'):
        if cls._instance is None:
            cls._instance = super(SecurityManager, cls).__new__(cls)
            cls._instance.db_path = db_path
            cls._instance.initialize_tables()
        return cls._instance
    
    def get_connection(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)
    
    def initialize_tables(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            # Create login attempts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ip_address TEXT,
                    success BOOLEAN DEFAULT 0
                )
            ''')
            
            # Add password history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS password_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # Add user settings for password expiration
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_security_settings (
                    user_id INTEGER PRIMARY KEY,
                    password_expiry_days INTEGER DEFAULT 90,
                    last_password_change TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    max_login_attempts INTEGER DEFAULT 5,
                    account_locked_until TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            conn.commit()
    
    def log_login_attempt(self, username: str, ip_address: str, success: bool) -> None:
        """Log a login attempt"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO login_attempts (username, ip_address, success) VALUES (?, ?, ?)",
                (username, ip_address, 1 if success else 0)
            )
            conn.commit()
        
        if success:
            logger.info(f"Successful login for user: {username} from IP: {ip_address}")
        else:
            logger.warning(f"Failed login attempt for user: {username} from IP: {ip_address}")
    
    def is_account_locked(self, username: str) -> Tuple[bool, Optional[str]]:
        """Check if the account is locked due to too many failed attempts"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Get user's security settings
            cursor.execute("""
                SELECT us.max_login_attempts, us.account_locked_until
                FROM users u
                LEFT JOIN user_security_settings us ON u.id = us.user_id
                WHERE u.username = ?
            """, (username,))
            
            settings = cursor.fetchone()
            if not settings:
                return False, None
                
            max_attempts = settings[0] or 5  # Default to 5 if not set
            locked_until = settings[1]
            
            if locked_until:
                locked_until = datetime.fromisoformat(locked_until)
                if datetime.now() < locked_until:
                    return True, f"Account locked until {locked_until}"
                else:
                    # Reset lock if expired
                    cursor.execute("""
                        UPDATE user_security_settings 
                        SET account_locked_until = NULL 
                        WHERE user_id = (SELECT id FROM users WHERE username = ?)
                    """, (username,))
                    conn.commit()
            
            # Count recent failed attempts
            cursor.execute("""
                SELECT COUNT(*) 
                FROM login_attempts 
                WHERE username = ? 
                AND success = 0 
                AND attempt_time > datetime('now', '-15 minutes')
            """, (username,))
            
            failed_attempts = cursor.fetchone()[0]
            if failed_attempts >= max_attempts:
                # Lock the account for 30 minutes
                lock_until = (datetime.now() + timedelta(minutes=30)).isoformat()
                cursor.execute("""
                    INSERT OR REPLACE INTO user_security_settings 
                    (user_id, account_locked_until)
                    VALUES (
                        (SELECT id FROM users WHERE username = ?),
                        ?
                    )
                """, (username, lock_until))
                conn.commit()
                return True, "Account locked due to too many failed attempts. Please try again later."
            
            return False, None
    
    def is_password_expired(self, user_id: int) -> Tuple[bool, Optional[str]]:
        """Check if the user's password has expired"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT us.password_expiry_days, us.last_password_change
                FROM user_security_settings us
                WHERE us.user_id = ?
            """, (user_id,))
            
            settings = cursor.fetchone()
            if not settings or not settings[1]:  # If no settings or no last password change
                return False, None
                
            expiry_days = settings[0] or 90  # Default to 90 days if not set
            last_change = datetime.fromisoformat(settings[1])
            expiry_date = last_change + timedelta(days=expiry_days)
            
            if datetime.now() > expiry_date:
                return True, f"Password expired on {expiry_date}. Please change your password."
            
            return False, None
    
    def add_to_password_history(self, user_id: int, password_hash: str) -> None:
        """Add a password to the password history"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)",
                (user_id, password_hash)
            )
            conn.commit()
    
    def is_password_in_history(self, user_id: int, password_hash: str, history_count: int = 5) -> bool:
        """Check if the password has been used before"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT password_hash FROM password_history 
                WHERE user_id = ? 
                ORDER BY created_at DESC 
                LIMIT ?
            """, (user_id, history_count))
            
            for (stored_hash,) in cursor.fetchall():
                if stored_hash == password_hash:
                    return True
            return False

def log_security_event(event_type: str, user_id: Optional[int] = None, 
                     details: Optional[Dict[str, Any]] = None) -> None:
    """Log security-related events"""
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'event_type': event_type,
        'user_id': user_id,
        'details': details or {}
    }
    logger.info(f"Security Event: {log_entry}")

def requires_security_check(func):
    """Decorator to add security checks to methods"""
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if hasattr(self, 'user') and self.user:
            security_mgr = SecurityManager()
            
            # Check if account is locked
            is_locked, message = security_mgr.is_account_locked(self.user[1])  # username is at index 1
            if is_locked:
                messagebox.showerror("Account Locked", message)
                return
                
            # Check if password is expired
            is_expired, message = security_mgr.is_password_expired(self.user[0])  # user_id is at index 0
            if is_expired:
                messagebox.showwarning("Password Expired", message)
                # Show password change dialog
                if hasattr(self, 'show_password_change_dialog'):
                    self.show_password_change_dialog(force_change=True)
                return
                
        return func(self, *args, **kwargs)
    return wrapper
