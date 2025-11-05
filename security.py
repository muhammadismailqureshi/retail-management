import bcrypt
from typing import Tuple, Optional
import getpass
import re

def hash_password(password: str) -> bytes:
    """Hash a password using bcrypt."""
    # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)

def verify_password(stored_password: bytes, provided_password: str) -> bool:
    """Verify a stored password against one provided by user"""
    try:
        # If stored_password is a string, encode it to bytes
        if isinstance(stored_password, str):
            stored_password = stored_password.encode('utf-8')
        return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password)
    except Exception as e:
        print(f"Error verifying password: {e}")
        return False

def is_password_strong(password: str) -> Tuple[bool, str]:
    """Check if password meets strength requirements.
    Returns (is_valid, error_message)"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"
    return True, ""

def prompt_new_password() -> Optional[bytes]:
    """Prompt user to enter a new password with confirmation."""
    while True:
        password = getpass.getpass("Enter new password: ")
        confirm = getpass.getpass("Confirm password: ")
        
        if password != confirm:
            print("Passwords do not match. Please try again.")
            continue
            
        is_strong, message = is_password_strong(password)
        if not is_strong:
            print(f"Weak password: {message}")
            continue
            
        return hash_password(password)
    
    return None
