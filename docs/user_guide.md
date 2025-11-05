# Retail Management System - User Guide

## Table of Contents
1. [Getting Started](#getting-started)
2. [System Requirements](#system-requirements)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Features](#features)
6. [Troubleshooting](#troubleshooting)
7. [FAQ](#faq)

## Getting Started

Welcome to the Retail Management System! This guide will help you get started with the application.

## System Requirements

- Python 3.8 or higher
- Windows/Linux/macOS
- 4GB RAM minimum (8GB recommended)
- 200MB free disk space

## Installation

### Windows
1. Clone the repository:
   ```bash
   git clone https://github.com/muhammadismailqureshi/retail-management.git
   cd retail-management
   ```

2. Set up the virtual environment:
   ```powershell
   .\setup_venv.ps1
   ```

3. Run the application:
   ```bash
   python -m retail_management_system
   ```

## Configuration

### Database Configuration
Edit `retail_management_system/config/settings.py` to configure database settings:

```python
DATABASE = {
    'name': 'retail_store.db',
    'path': os.path.join(BASE_DIR, 'retail_store.db')
}
```

### Security Settings
Configure security parameters in `retail_management_system/auth/security.py`:

```python
# Password requirements
PASSWORD_MIN_LENGTH = 8
PASSWORD_REQUIRE_UPPERCASE = True
PASSWORD_REQUIRE_SPECIAL = True
```

## Features

### User Management
- Create and manage user accounts
- Role-based access control
- Password policies and security

### Inventory Management
- Add/Edit/Delete products
- Track stock levels
- Manage categories and suppliers

### Sales Processing
- Point of Sale (POS) interface
- Invoice generation
- Sales reporting

### Reporting
- Sales reports
- Inventory reports
- Financial summaries

## Troubleshooting

### Common Issues

**Issue**: Module not found error
**Solution**: Make sure you've activated the virtual environment and installed all requirements:
```bash
.\venv\Scripts\activate
pip install -r requirements.txt
```

**Issue**: Database connection error
**Solution**: Check if the database file exists and has the correct permissions.

## FAQ

**Q: How do I reset the admin password?**
A: Run the following command:
```bash
python -m retail_management_system.auth.security reset_password admin@example.com
```

**Q: How do I backup the database?**
A: Simply make a copy of the `retail_store.db` file.

**Q: How do I update the application?**
```bash
git pull origin main
pip install -r requirements.txt
```
