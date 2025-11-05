import tkinter as tk
from tkinter import ttk
import sqlite3

class TestApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Test Application")
        self.root.geometry("800x600")
        
        # Create a simple interface
        self.label = ttk.Label(root, text="Retail Store Management System", font=('Helvetica', 16, 'bold'))
        self.label.pack(pady=20)
        
        self.status_label = ttk.Label(root, text="Application started successfully!", foreground="green")
        self.status_label.pack(pady=10)
        
        # Add a button to test database connection
        self.test_db_btn = ttk.Button(root, text="Test Database Connection", command=self.test_database)
        self.test_db_btn.pack(pady=10)
        
    def test_database(self):
        try:
            conn = sqlite3.connect('retail_store.db')
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            conn.close()
            
            table_list = "\n".join([f"- {table[0]}" for table in tables])
            self.status_label.config(
                text=f"Database connection successful!\nTables found:\n{table_list}",
                foreground="green"
            )
        except Exception as e:
            self.status_label.config(
                text=f"Database error: {str(e)}",
                foreground="red"
            )

if __name__ == "__main__":
    root = tk.Tk()
    app = TestApp(root)
    root.mainloop()
