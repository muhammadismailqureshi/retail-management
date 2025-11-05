"""
Security-related functions including password hashing and verification.
"""
import bcrypt
import re
from typing import Tuple, Optional, Union, Dict, Any
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

def hash_password(password: str) -> bytes:
    """
    Hash a password using bcrypt with a generated salt.
    
    Args:
        password: The plain text password to hash
        
    Returns:
        bytes: The hashed password
    """
    try:
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed
    except Exception as e:
        logger.error(f"Error hashing password: {e}")
        raise

def verify_password(stored_password: Union[bytes, str], provided_password: str) -> bool:
    """
    Verify a stored password against one provided by user.
    
    Args:
        stored_password: The hashed password from the database
        provided_password: The password provided by the user
        
    Returns:
        bool: True if the password matches, False otherwise
    """
    try:
        # Ensure stored_password is bytes
        if isinstance(stored_password, str):
            stored_password = stored_password.encode('utf-8')
            
        return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password)
    except Exception as e:
        logger.error(f"Error verifying password: {e}")
        return False

def is_password_strong(password: str) -> Tuple[bool, str]:
    """
    Check if a password meets strength requirements.
    
    Args:
        password: The password to check
        
    Returns:
        tuple: (is_valid, error_message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number"
    if not re.search(r"[!@#$%^&*(),.?:{}|<>]", password):
        return False, "Password must contain at least one special character"
    return True, ""

class AuthManager:
    """Manages authentication and authorization."""
    
    def __init__(self, db_connection):
        """
        Initialize the AuthManager with a database connection.
        
        Args:
            db_connection: An instance of DatabaseConnection
        """
        self.db = db_connection
    
    def authenticate_user(self, username: str, password: str, ip_address: str = None) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        """
        Authenticate a user with username and password.
        
        Args:
            username: The username to authenticate
            password: The password to verify
            ip_address: The IP address of the client (for logging)
            
        Returns:
            tuple: (success, user_data, message)
        """
        try:
            # Get user from database
            user = self.db.fetch_one(
                "SELECT * FROM users WHERE username = ? AND is_active = 1", 
                (username,)
            )
            
            if not user:
                self._log_failed_attempt(username, ip_address, "User not found")
                return False, None, "Invalid username or password"
            
            # Check if account is locked
            is_locked, lock_message = self._is_account_locked(user['id'])
            if is_locked:
                return False, None, lock_message
            
            # Verify password
            if not verify_password(user['password'], password):
                self._handle_failed_login(user, ip_address)
                attempts_left = self._get_remaining_attempts(user['id'])
                return False, None, f"Invalid username or password. {attempts_left} attempts left."
            
            # Check if password is expired
            is_expired, expiry_message = self._is_password_expired(user['id'])
            if is_expired:
                return True, dict(user), f"login_success_but_expired:{expiry_message}"
            
            # Log successful login
            self._log_successful_attempt(user, ip_address)
            
            return True, dict(user), "Authentication successful"
            
        except Exception as e:
            logger.error(f"Authentication error: {e}", exc_info=True)
            return False, None, "An error occurred during authentication"
    
    def _is_account_locked(self, user_id: int) -> Tuple[bool, str]:
        """Check if the user's account is locked."""
        settings = self.db.fetch_one(
            """
            SELECT account_locked_until, max_login_attempts 
            FROM user_security_settings 
            WHERE user_id = ?
            """,
            (user_id,)
        )
        
        if not settings or not settings['account_locked_until']:
            return False, ""
        
        locked_until = datetime.fromisoformat(settings['account_locked_until'])
        if datetime.now() < locked_until:
            return True, f"Account locked until {locked_until}"
        
        # Clear the lock if it has expired
        self.db.execute(
            "UPDATE user_security_settings SET account_locked_until = NULL WHERE user_id = ?",
            (user_id,)
        )
        return False, ""
    
    def _is_password_expired(self, user_id: int) -> Tuple[bool, str]:
        """Check if the user's password has expired."""
        settings = self.db.fetch_one(
            """
            SELECT last_password_change, password_expiry_days 
            FROM user_security_settings 
            WHERE user_id = ?
            """,
            (user_id,)
        )
        
        if not settings or not settings['last_password_change']:
            return True, "Password has never been changed"
        
        expiry_days = settings['password_expiry_days'] or 90  # Default to 90 days
        last_change = datetime.fromisoformat(settings['last_password_change'])
        expiry_date = last_change + timedelta(days=expiry_days)
        
        if datetime.now() > expiry_date:
            return True, f"Password expired on {expiry_date}"
        
        return False, ""
    
    def _log_successful_attempt(self, user: Dict[str, Any], ip_address: str = None):
        """Log a successful login attempt."""
        try:
            self.db.execute(
                """
                INSERT INTO login_attempts 
                (user_id, username, ip_address, success) 
                VALUES (?, ?, ?, 1)
                """,
                (user['id'], user['username'], ip_address)
            )
            
            # Reset failed attempts counter
            self.db.execute(
                """
                UPDATE user_security_settings 
                SET failed_attempts = 0 
                WHERE user_id = ?
                """,
                (user['id'],)
            )
            
            logger.info(f"Successful login for user: {user['username']}")
            
        except Exception as e:
            logger.error(f"Error logging successful login: {e}")
    
    def _log_failed_attempt(self, username: str, ip_address: str = None, reason: str = None):
        """Log a failed login attempt."""
        try:
            # Get user ID if exists
            user = self.db.fetch_one("SELECT id FROM users WHERE username = ?", (username,))
            
            self.db.execute(
                """
                INSERT INTO login_attempts 
                (user_id, username, ip_address, success, reason) 
                VALUES (?, ?, ?, 0, ?)
                """,
                (user['id'] if user else None, username, ip_address, reason)
            )
            
            if user:
                # Increment failed attempts counter
                self.db.execute(
                    """
                    INSERT OR IGNORE INTO user_security_settings 
                    (user_id, failed_attempts) 
                    VALUES (?, 0)
                    """,
                    (user['id'],)
                )
                
                self.db.execute(
                    """
                    UPDATE user_security_settings 
                    SET failed_attempts = COALESCE(failed_attempts, 0) + 1 
                    WHERE user_id = ?
                    """,
                    (user['id'],)
                )
                
                # Check if we should lock the account
                self._check_and_lock_account(user['id'])
            
            logger.warning(f"Failed login attempt for username: {username} - {reason or 'Invalid credentials'}")
            
        except Exception as e:
            logger.error(f"Error logging failed login: {e}")
    
    def _check_and_lock_account(self, user_id: int):
        """Check if the account should be locked due to too many failed attempts."""
        settings = self.db.fetch_one(
            """
            SELECT failed_attempts, max_login_attempts 
            FROM user_security_settings 
            WHERE user_id = ?
            """,
            (user_id,)
        )
        
        if not settings:
            return
            
        max_attempts = settings['max_login_attempts'] or 5  # Default to 5 attempts
        failed_attempts = settings['failed_attempts'] or 0
        
        if failed_attempts >= max_attempts:
            lock_until = (datetime.now() + timedelta(minutes=30)).isoformat()
            self.db.execute(
                """
                UPDATE user_security_settings 
                SET account_locked_until = ? 
                WHERE user_id = ?
                """,
                (lock_until, user_id)
            )
            
            logger.warning(f"Account locked for user_id: {user_id} until {lock_until}")
    
    def _get_remaining_attempts(self, user_id: int) -> int:
        """Get the number of remaining login attempts before account is locked."""
        settings = self.db.fetch_one(
            """
            SELECT failed_attempts, max_login_attempts 
            FROM user_security_settings 
            WHERE user_id = ?
            """,
            (user_id,)
        )
        
        if not settings:
            max_attempts = 5  # Default
            return max_attempts
            
        max_attempts = settings['max_login_attempts'] or 5
        failed_attempts = settings['failed_attempts'] or 0
        
        return max(0, max_attempts - failed_attempts)
    
    def change_password(self, user_id: int, current_password: str, new_password: str) -> Tuple[bool, str]:
        """
        Change a user's password.
        
        Args:
            user_id: The ID of the user
            current_password: The user's current password
            new_password: The new password
            
        Returns:
            tuple: (success, message)
        """
        try:
            # Get current password hash
            user = self.db.fetch_one("SELECT id, password FROM users WHERE id = ?", (user_id,))
            if not user:
                return False, "User not found"
            
            # Verify current password
            if not verify_password(user['password'], current_password):
                return False, "Current password is incorrect"
            
            # Check if new password is different from current
            if verify_password(user['password'], new_password):
                return False, "New password must be different from current password"
            
            # Check password strength
            is_strong, message = is_password_strong(new_password)
            if not is_strong:
                return False, f"Weak password: {message}"
            
            # Check if password was used before
            if self._is_password_in_history(user_id, new_password):
                return False, "This password was used recently. Please choose a different one."
            
            # Hash the new password
            hashed_password = hash_password(new_password)
            
            # Update password in database
            self.db.execute(
                "UPDATE users SET password = ? WHERE id = ?",
                (hashed_password, user_id)
            )
            
            # Add to password history
            self._add_to_password_history(user_id, hashed_password)
            
            # Update last password change timestamp
            self.db.execute(
                """
                INSERT OR REPLACE INTO user_security_settings 
                (user_id, last_password_change) 
                VALUES (?, CURRENT_TIMESTAMP)
                """,
                (user_id,)
            )
            
            logger.info(f"Password changed for user_id: {user_id}")
            return True, "Password changed successfully"
            
        except Exception as e:
            logger.error(f"Error changing password: {e}", exc_info=True)
            return False, "An error occurred while changing the password"
    
    def _is_password_in_history(self, user_id: int, password: str, history_count: int = 5) -> bool:
        """Check if the password was used before."""
        try:
            # Get recent password hashes
            history = self.db.fetch_all(
                """
                SELECT password_hash 
                FROM password_history 
                WHERE user_id = ? 
                ORDER BY created_at DESC 
                LIMIT ?
                """,
                (user_id, history_count)
            )
            
            # Check if the new password matches any of the recent ones
            for entry in history:
                if verify_password(entry['password_hash'], password):
                    return True
                    
            return False
            
        except Exception as e:
            logger.error(f"Error checking password history: {e}")
            return False
    
    def _add_to_password_history(self, user_id: int, password_hash: str):
        """Add a password hash to the password history."""
        try:
            self.db.execute(
                "INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)",
                (user_id, password_hash)
            )
        except Exception as e:
            logger.error(f"Error adding to password history: {e}")
            raise
