# Developer Guide

## Project Structure

```
retail_management_system/
├── auth/                  # Authentication and authorization
│   ├── __init__.py
│   ├── login_window.py    # Login UI and authentication flow
│   └── security.py        # Security utilities and password hashing
├── config/
│   ├── __init__.py
│   └── settings.py        # Application configuration
├── database/
│   ├── __init__.py
│   └── connection.py      # Database connection and queries
├── ui/                    # User interface components
│   ├── __init__.py
│   └── main_window.py     # Main application window
├── __init__.py
└── __main__.py            # Application entry point
```

## Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/muhammadismailqureshi/retail-management.git
   cd retail-management
   ```

2. **Set up virtual environment**
   ```bash
   python -m venv venv
   .\venv\Scripts\activate  # Windows
   source venv/bin/activate  # Linux/Mac
   ```

3. **Install development dependencies**
   ```bash
   pip install -r requirements-dev.txt
   ```

4. **Run the application**
   ```bash
   python -m retail_management_system
   ```

## Code Style

- Follow PEP 8 style guide
- Use type hints for function signatures
- Document public APIs with docstrings
- Keep functions small and focused (max 30 lines)
- Use meaningful variable and function names

## Testing

Run tests with pytest:
```bash
pytest tests/
```

## Contributing

1. Create a new branch for your feature
2. Write tests for your changes
3. Submit a pull request with a clear description
4. Ensure all tests pass before merging

## Deployment

### Production
1. Set environment variables:
   ```bash
   export FLASK_ENV=production
   export SECRET_KEY=your-secret-key
   ```

2. Run with production server:
   ```bash
   gunicorn -w 4 -b 0.0.0.0:5000 retail_management_system:create_app()
   ```

## API Documentation

### Authentication

**Login**
```
POST /api/auth/login
{
    "username": "admin",
    "password": "securepassword"
}
```

**Response**
```json
{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
        "id": 1,
        "username": "admin",
        "is_admin": true
    }
}
```

## Database Schema

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_admin BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Error Handling

Standard error response format:
```json
{
    "error": {
        "code": "invalid_credentials",
        "message": "Invalid username or password"
    }
}
```
