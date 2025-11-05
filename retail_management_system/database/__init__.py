"""Database access and data models for the Retail Management System.

This package provides database connection management, data models, and data access
abstractions for the application.
"""

from .connection import get_db, DatabaseConnection

__all__ = [
    'get_db',
    'DatabaseConnection'
]