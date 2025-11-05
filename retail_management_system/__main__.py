"""
Main entry point for the Retail Management System application.
"""
import sys
import os
import logging
import logging.config
import tkinter as tk
from pathlib import Path

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import application modules
from config import settings
from database.connection import initialize_database
from auth.login_window import LoginWindow
from ui.main_window import MainWindow

# Configure logging
os.makedirs(settings.PATHS['LOGS'], exist_ok=True)
logging.config.dictConfig(settings.LOGGING)
logger = logging.getLogger(__name__)

def setup_environment():
    """Set up the application environment."""
    # Create necessary directories
    for path in [settings.PATHS['IMAGES'], settings.PATHS['STYLES'], settings.PATHS['LOGS']]:
        os.makedirs(path, exist_ok=True)
    
    # Initialize the database
    try:
        initialize_database()
        logger.info("Database initialization completed")
    except Exception as e:
        logger.critical(f"Failed to initialize database: {e}", exc_info=True)
        raise

def main():
    """Main entry point for the application."""
    try:
        # Set up the environment
        setup_environment()
        
        # Create the main application window
        root = tk.Tk()
        root.withdraw()  # Hide the root window initially
        
        # Set application icon and title
        try:
            # Try to set the application icon if it exists
            icon_path = os.path.join(settings.PATHS['IMAGES'], 'app_icon.ico')
            if os.path.exists(icon_path):
                root.iconbitmap(icon_path)
        except Exception as e:
            logger.warning(f"Could not set application icon: {e}")
        
        # Function to handle successful login
        def on_login_success(user_data):
            """Handle successful login."""
            # Close the login window
            login_window.root.destroy()
            
            # Show the main application window
            app = MainWindow(root, user_data)
            app.run()
        
        # Show the login window
        login_window = LoginWindow(root, on_login_success)
        
        # Start the main event loop
        root.mainloop()
        
    except Exception as e:
        logger.critical(f"Application error: {e}", exc_info=True)
        # Show error message to the user
        error_msg = f"A critical error occurred: {str(e)}\n\nCheck the logs for more details."
        tk.messagebox.showerror("Application Error", error_msg)
        sys.exit(1)

if __name__ == "__main__":
    main()
