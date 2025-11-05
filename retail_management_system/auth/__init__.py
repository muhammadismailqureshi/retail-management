"""
Authentication and authorization components for the Retail Management System.

This package provides user authentication, authorization, and security features
including password hashing, session management, and access control.
"""

from .security import AuthManager, hash_password, verify_password, is_password_strong
from .login_window import LoginWindow

__all__ = [
    'AuthManager',
    'hash_password',
    'verify_password',
    'is_password_strong',
    'LoginWindow'
]