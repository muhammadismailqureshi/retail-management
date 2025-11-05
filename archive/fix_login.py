import sqlite3
from security import hash_password, verify_password

def check_admin_user():
    try:
        conn = sqlite3.connect('retail_store.db')
        cursor = conn.cursor()
        
        # Check if admin user exists
        cursor.execute("SELECT id, username, password, is_admin FROM users WHERE username = 'admin'")
        admin = cursor.fetchone()
        
        if not admin:
            print("Admin user not found. Creating admin user...")
            hashed_pw = hash_password('admin123')
            cursor.execute(
                'INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                ('admin', hashed_pw, 1)
            )
            conn.commit()
            print("Admin user created with password 'admin123'")
            return True
        
        # Check if the password is correctly hashed
        user_id, username, stored_pw, is_admin = admin
        print(f"Found admin user: {username} (ID: {user_id}, Admin: {bool(is_admin)})")
        
        # Try to verify the default password
        if verify_password(stored_pw, 'admin123'):
            print("Login with 'admin123' should work!")
            return True
        else:
            print("Password verification failed. Resetting admin password...")
            hashed_pw = hash_password('admin123')
            cursor.execute(
                'UPDATE users SET password = ? WHERE username = ?',
                (hashed_pw, 'admin')
            )
            conn.commit()
            print("Admin password has been reset to 'admin123'")
            return True
            
    except Exception as e:
        print(f"Error: {e}")
        return False
    finally:
        conn.close()

if __name__ == "__main__":
    if check_admin_user():
        print("Login issue should be resolved. Please try logging in with:")
        print("Username: admin")
        print("Password: admin123")
    else:
        print("Failed to fix login issue. Please check the error message above.")
