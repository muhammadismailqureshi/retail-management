"""
Application settings and configuration.
"""
import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Database settings
DATABASE = {
    'NAME': 'retail_store.db',
    'PATH': str(BASE_DIR.parent / 'retail_store.db')  # Store in parent directory
}

# Application settings
APP_NAME = "Almayas Retail Management"
VERSION = "1.0.0"

# Security settings
SECURITY = {
    'PASSWORD_EXPIRY_DAYS': 90,
    'MAX_LOGIN_ATTEMPTS': 5,
    'LOCKOUT_MINUTES': 30,
    'PASSWORD_HISTORY_COUNT': 5,
    'SESSION_TIMEOUT_MINUTES': 30
}

# UI Settings
UI = {
    'APP_NAME': APP_NAME,
    'VERSION': VERSION,
    'WINDOW_SIZE': '1200x800',
    'MIN_WINDOW_SIZE': '1000x700',
    'THEME': 'default',
    'FONT': ('Segoe UI', 10),
    'FONT_BOLD': ('Segoe UI', 10, 'bold'),
    'FONT_TITLE': ('Segoe UI', 16, 'bold'),
    'PADDING': 10,
    'BTN_PADDING': 5
}

# Paths
PATHS = {
    'IMAGES': str(BASE_DIR / 'assets/images'),
    'STYLES': str(BASE_DIR / 'assets/styles'),
    'LOGS': str(BASE_DIR.parent / 'logs')
}

# Create necessary directories
for path in PATHS.values():
    os.makedirs(path, exist_ok=True)

# Logging configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': os.path.join(PATHS['LOGS'], 'retail_system.log'),
            'formatter': 'standard'
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'standard'
        },
    },
    'loggers': {
        '': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': True
        },
    }
}
