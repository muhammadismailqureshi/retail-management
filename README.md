# Retail Management System

A comprehensive retail management solution built with Python and Tkinter.

## Features

- **User Authentication**: Secure login with password hashing and account locking
- **Dashboard**: Overview of key metrics and recent transactions
- **Inventory Management**: Track products, stock levels, and categories
- **Point of Sale (POS)**: Process sales and print receipts
- **Customer Management**: Maintain customer records and purchase history
- **Sales Reporting**: Generate sales reports and analytics
- **User Management**: Manage user accounts and permissions

## Requirements

- Python 3.8 or higher
- Tkinter (usually included with Python)
- See `requirements.txt` for additional dependencies

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/retail-management-system.git
   cd retail-management-system
   ```

2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the application:
   ```bash
   python -m retail_management_system
   ```

## Configuration

Configuration settings can be found in `retail_management_system/config/settings.py`. You can modify:

- Database connection settings
- UI appearance
- Security settings
- File paths

## Database

The application uses SQLite by default, which is stored in a file named `retail_store.db` in the project root. The database will be created automatically when you first run the application.

## Security

- Passwords are hashed using bcrypt
- Account lockout after multiple failed login attempts
- Password expiration and history
- Session management

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Screenshots

*Screenshots will be added here*

## Support

For support, please open an issue in the GitHub repository.
