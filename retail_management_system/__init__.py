"""
Retail Management System - A comprehensive solution for managing retail store operations.

This package provides modules for inventory management, sales processing, customer
relationship management, and business analytics for retail stores.
"""

__version__ = "1.0.0"
__author__ = "Almayas Retail"
__license__ = "Proprietary"

# Import key components to make them available at the package level
from .config import settings
from .database.connection import get_db, DatabaseConnection
from .auth.security import AuthManager, hash_password, verify_password, is_password_strong
from .auth.login_window import LoginWindow
from .ui.main_window import MainWindow

# Define what gets imported with 'from retail_management_system import *'
__all__ = [
    'settings',
    'get_db',
    'DatabaseConnection',
    'AuthManager',
    'hash_password',
    'verify_password',
    'is_password_strong',
    'LoginWindow',
    'MainWindow'
]
