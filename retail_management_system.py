import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter import *
import sqlite3
from datetime import datetime, timedelta
import os
import csv
import sys
import socket
import getpass
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from security import hash_password, verify_password, is_password_strong
from security_utils import SecurityManager, log_security_event, requires_security_check

class Database:
    def __init__(self):
        self.conn = sqlite3.connect('retail_store.db')
        self.cursor = self.conn.cursor()
        self.initialize_database()

    def initialize_database(self):
        # Create tables if they don't exist
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                is_admin BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # Create default admin user if it doesn't exist
        from security import hash_password
        admin_username = 'admin'
        admin_password = 'admin123'  # Default password, should be changed on first login
        # Check if admin user exists
        self.cursor.execute(
            'SELECT id FROM users WHERE username = ?', (admin_username,))
        if not self.cursor.fetchone():
            # Create admin user
            hashed_password = hash_password(admin_password)
            self.cursor.execute(
                'INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                (admin_username, hashed_password, 1)
            )
            self.conn.commit()
        # Create inventory table if it doesn't exist
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS inventory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sku TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                quantity INTEGER NOT NULL DEFAULT 0,
                price DECIMAL(10, 2) NOT NULL,
                category TEXT,
                min_stock INTEGER DEFAULT 10,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        print("Inventory table created with columns:", [
              desc[0] for desc in self.cursor.execute("PRAGMA table_info(inventory)").fetchall()])
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS customers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE,
                phone TEXT,
                address TEXT,
                loyalty_points INTEGER DEFAULT 0,
                total_spent REAL DEFAULT 0.0,
                join_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # Create sales and sale_items tables if they don't exist
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS sales (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_id TEXT UNIQUE NOT NULL,
                customer_id INTEGER,
                total_amount REAL NOT NULL,
                tax_amount REAL NOT NULL,
                payment_method TEXT,
                sale_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (customer_id) REFERENCES customers (id)
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS sale_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sale_id INTEGER,
                item_id INTEGER,
                quantity INTEGER NOT NULL,
                unit_price REAL NOT NULL,
                subtotal REAL NOT NULL,
                FOREIGN KEY (sale_id) REFERENCES sales (id),
                FOREIGN KEY (item_id) REFERENCES inventory (id)
            )
        ''')
        self.conn.commit()

    def execute_query(self, query, params=()):
        try:
            self.cursor.execute(query, params)
            self.conn.commit()
            if query.strip().upper().startswith('INSERT'):
                return self.cursor.lastrowid
            return None
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"An error occurred: {e}")
            return None

    def fetch_all(self, query, params=()):
        try:
            self.cursor.execute(query, params)
            return self.cursor.fetchall()
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"An error occurred: {e}")
            return []

    def fetch_one(self, query, params=()):
        try:
            self.cursor.execute(query, params)
            return self.cursor.fetchone()
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"An error occurred: {e}")
            return None

class LoginWindow:
    def __init__(self, root, on_login_success):
        self.root = root
        self.root.title("Almayas Store Management - Login")
        self.root.geometry("400x300")
        self.on_login_success = on_login_success
        # Center the window
        window_width = 400
        window_height = 300
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x = (screen_width // 2) - (window_width // 2)
        y = (screen_height // 2) - (window_height // 2)
        self.root.geometry(f'{window_width}x{window_height}+{x}+{y}')
        # Initialize security manager
        self.security_mgr = SecurityManager()
        self.db = Database()
        self.setup_ui()
        # Store the current user for password change
        self.current_user_id = None
        self.ip_address = self._get_ip_address()

    def _get_ip_address(self) -> str:
        """Get the current IP address"""
        try:
            # Try to get the local IP address
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"  # Fallback to localhost

    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.pack(expand=True, fill='both')
        # Title
        title_label = ttk.Label(
            main_frame, text="Retail Store Management", font=('Helvetica', 16, 'bold'))
        title_label.pack(pady=20)
        # Login form
        form_frame = ttk.Frame(main_frame)
        form_frame.pack(pady=20, expand=True)
        # Username
        ttk.Label(form_frame, text="Username:").grid(
            row=0, column=0, padx=5, pady=5, sticky='e')
        self.username_var = tk.StringVar()
        username_entry = ttk.Entry(
            form_frame, textvariable=self.username_var, width=25)
        username_entry.grid(row=0, column=1, padx=5, pady=5)
        username_entry.focus()
        # Password
        ttk.Label(form_frame, text="Password:").grid(
            row=1, column=0, padx=5, pady=5, sticky='e')
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(
            form_frame, textvariable=self.password_var, show="*", width=25)
        password_entry.grid(row=1, column=1, padx=5, pady=5)
        # Login button
        # Buttons frame
        btn_frame = ttk.Frame(form_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=10)
        login_btn = ttk.Button(btn_frame, text="Login",
                               command=self.authenticate, width=15)
        login_btn.pack(side=tk.LEFT, padx=5)
        # Add change password button
        change_pw_btn = ttk.Button(btn_frame, text="Change Password",
                                   command=self.show_password_change_dialog, width=15)
        change_pw_btn.pack(side=tk.LEFT, padx=5)
        # Bind Enter key to login
        password_entry.bind('<Return>', lambda e: self.authenticate())

    def show_password_change_dialog(self, force_change=False):
        """Show dialog to change password"""
        if not force_change and not self.current_user_id:
            # If not forcing change and no user is logged in, show error
            messagebox.showwarning(
                "Not Logged In", "Please log in first to change password")
            return
        dialog = tk.Toplevel(self.root)
        dialog.title(
            "Change Password" if not force_change else "Change Default Password")
        dialog.geometry("400x250")
        dialog.transient(self.root)
        dialog.grab_set()
        if force_change:
            ttk.Label(dialog, text="You must change the default password!",
                      font=('Helvetica', 10, 'bold'), foreground='red').pack(pady=10)
        # Current password (only for non-forced changes)
        if not force_change:
            ttk.Label(dialog, text="Current Password:").pack(pady=5)
            current_pw_var = tk.StringVar()
            ttk.Entry(dialog, textvariable=current_pw_var,
                      show="*").pack(pady=5)
        ttk.Label(dialog, text="New Password:").pack(pady=5)
        new_pw_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=new_pw_var, show="*").pack(pady=5)
        ttk.Label(dialog, text="Confirm New Password:").pack(pady=5)
        confirm_pw_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=confirm_pw_var, show="*").pack(pady=5)
        error_label = ttk.Label(dialog, text="", foreground='red')
        error_label.pack(pady=5)
        def change_pw():
            if not force_change:
                current_pw = current_pw_var.get()
                if not current_pw:
                    error_label.config(text="Please enter current password")
                    return
                # Verify current password
                user = self.db.fetch_one(
                    "SELECT * FROM users WHERE id = ?", (self.current_user_id,))
                if not user or not verify_password(user[2], current_pw):
                    error_label.config(text="Incorrect current password")
                    return
            new_pw = new_pw_var.get()
            confirm_pw = confirm_pw_var.get()
            if not new_pw or not confirm_pw:
                error_label.config(text="Please fill in all fields")
                return
            if new_pw != confirm_pw:
                error_label.config(text="New passwords do not match")
                return
            is_strong, message = is_password_strong(new_pw)
            if not is_strong:
                error_label.config(text=f"Weak password: {message}")
                return
            # Update password in database
            hashed_pw = hash_password(new_pw).decode('utf-8')
            # Add to password history
            self.security_mgr.add_to_password_history(
                self.current_user_id, hashed_pw)
            # Update password in users table
            self.db.execute_query(
                "UPDATE users SET password = ? WHERE id = ?",
                (hashed_pw, self.current_user_id)
            )
            # Update last password change timestamp
            self.db.execute_query("""
                INSERT OR REPLACE INTO user_security_settings
                (user_id, last_password_change)
                VALUES (?, datetime('now'))
            """, (self.current_user_id,))
            log_security_event("password_changed", self.current_user_id, {
                               "forced_change": force_change})
            messagebox.showinfo("Success", "Password changed successfully!")
            dialog.destroy()
            if force_change:
                # After changing default password, log in again
                self.password_var.set(new_pw)
                self.authenticate()
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Change Password",
                   command=change_pw).pack(side=tk.LEFT, padx=5)
        if not force_change:
            ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(
                side=tk.LEFT, padx=5)
        if force_change:
            # Disable closing the window without changing password
            dialog.protocol("WM_DELETE_WINDOW", lambda: None)

    def authenticate(self):
        username = self.username_var.get().strip()
        password = self.password_var.get()
        if not username or not password:
            messagebox.showwarning("Input Error", "Please enter both username and password")
            return
        try:
            # Check if account is locked
            is_locked, message = self.security_mgr.is_account_locked(username)
            if is_locked:
                messagebox.showerror("Account Locked", message)
                self.security_mgr.log_login_attempt(username, self.ip_address, False)
                log_security_event("account_locked", None, {"username": username, "ip": self.ip_address})
                return
            # Get user from database
            user = self.db.fetch_one("SELECT * FROM users WHERE username = ?", (username,))
            if user and verify_password(user[2], password):
                # Store the current user ID for password changes
                self.current_user_id = user[0]
               
                # Check if it's default admin password and force change
                if user[1] == 'admin' and password == 'admin123':
                    messagebox.showwarning("Security Alert", "Please change the default admin password!")
                    self.security_mgr.log_login_attempt(username, self.ip_address, True)
                    log_security_event("login_success", user[0], {"username": username, "ip": self.ip_address})
                    self.show_password_change_dialog(force_change=True)
                    return
                # Check if password is expired
                is_expired, message = self.security_mgr.is_password_expired(user[0])
                if is_expired:
                    messagebox.showwarning("Password Expired", message)
                    self.security_mgr.log_login_attempt(username, self.ip_address, True)
                    log_security_event("password_expired", user[0], {"username": username, "ip": self.ip_address})
                    self.show_password_change_dialog(force_change=True)
                    return
                # Successful login - destroy login window and call the success callback
                self.security_mgr.log_login_attempt(username, self.ip_address, True)
                log_security_event("login_success", user[0], {"username": username, "ip": self.ip_address})
                self.root.after(100, lambda: self.handle_successful_login(user))
            else:
                # Failed login
                self.security_mgr.log_login_attempt(username, self.ip_address, False)
                log_security_event("login_failed", None, {"username": username, "ip": self.ip_address})
                messagebox.showerror("Login Failed", "Invalid username or password")
                self.password_var.set("")
               
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during login: {str(e)}")
            log_security_event("login_error", None, {"username": username, "error": str(e)})
        else:
            # Failed login
            self.security_mgr.log_login_attempt(
                username, self.ip_address, False)
            log_security_event("login_failed", None, {
                               "username": username, "ip": self.ip_address})
            messagebox.showerror(
                "Login Failed", "Invalid username or password")
            self.password_var.set("")

    def handle_successful_login(self, user):
        self.on_login_success(user)

class MainApplication:
    def __init__(self, root, user):
        self.root = root
        self.root.deiconify()
        self.root.title("Almayas Retail Management")
        self.root.state('zoomed')
        # Store user data
        self.user = user
        self.db = Database()
        self.security_mgr = SecurityManager()
        # Log application start
        log_security_event("application_start", user[0], {"username": user[1]})
        # Configure styles
        self.style = ttk.Style()
        self.style.configure('TButton', padding=5)
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('Card.TFrame', background='white', relief='raised', borderwidth=1)
        # Set up the UI
        self.setup_ui()
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Are you sure you want to quit?"):
            self.root.destroy()
            self.root.quit()

    def setup_ui(self):
        # Configure main window grid
        self.root.columnconfigure(0, weight=0)  # Sidebar
        self.root.columnconfigure(1, weight=1)  # Content area
        self.root.rowconfigure(0, weight=1)
        # Create sidebar
        self.sidebar = ttk.Frame(self.root, width=200, style='TFrame')
        self.sidebar.grid(row=0, column=0, sticky='nswe')
        # Add logo/header
        header = ttk.Label(
            self.sidebar,
            text="Retail Store\nManagement",
            font=('Helvetica', 12, 'bold'),
            background='#f0f0f0',
            justify='center'
        )
        header.pack(pady=(20, 30), fill='x')
        # Navigation buttons
        nav_buttons = [
            ("Dashboard", self.show_dashboard),
            ("Inventory", self.show_inventory),
            ("POS", self.show_pos),
            ("Customers", self.show_customers),
            ("Sales", self.show_sales),
            ("Reports", self.show_reports)
        ]
        for text, command in nav_buttons:
            btn = ttk.Button(
                self.sidebar,
                text=text,
                command=command,
                width=20,
                style='TButton'
            )
            btn.pack(pady=5, padx=10, fill='x')
        # Logout button at the bottom
        ttk.Separator(self.sidebar, orient='horizontal').pack(
            fill='x', pady=20)
        logout_btn = ttk.Button(
            self.sidebar,
            text="Logout",
            command=self.logout,
            style='TButton'
        )
        logout_btn.pack(side='bottom', pady=10, padx=10, fill='x')
        # Main content area
        self.content = ttk.Frame(self.root)
        self.content.grid(row=0, column=1, sticky='nsew', padx=10, pady=10)
        # Show dashboard by default
        self.show_dashboard()

    def clear_content(self):
        for widget in self.content.winfo_children():
            widget.destroy()

    def show_dashboard(self):
        self.clear_content()
        # Header
        header_frame = ttk.Frame(self.content)
        header_frame.pack(fill='x', pady=(0, 20))
        ttk.Label(header_frame, text="Dashboard", font=(
            'Helvetica', 18, 'bold')).pack(side='left')
        # Refresh button
        refresh_btn = ttk.Button(
            header_frame, text="🔄 Refresh", command=self.refresh_dashboard, style='TButton')
        refresh_btn.pack(side='right')
        # Main content frame
        main_frame = ttk.Frame(self.content)
        main_frame.pack(fill='both', expand=True)
        # Left side - Summary cards
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side='left', fill='both', expand=True, padx=(0, 10))
        # Summary cards frame
        cards_frame = ttk.Frame(left_frame)
        cards_frame.pack(fill='x', pady=(0, 20))
        # Get dashboard data
        stats = self.get_dashboard_stats()
        # Summary cards
        summary_cards = [
            {
                'title': 'Total Sales',
                'value': f"PKR {stats['total_sales']:,.2f}",
                'change': stats['sales_change'],
                'color': '#4CAF50'  # Green
            },
            {
                'title': 'Today\'s Revenue',
                'value': f"PKR {stats['today_sales']:,.2f}",
                'change': stats['today_sales_change'],
                'color': '#2196F3'  # Blue
            },
            {
                'title': 'Total Items',
                'value': stats['total_items'],
                'change': stats['items_change'],
                'color': '#FF9800'  # Orange
            },
            {
                'title': 'Low Stock Items',
                'value': stats['low_stock_count'],
                'change': stats['low_stock_change'],
                'color': '#F44336'  # Red
            }
        ]
        # Create summary cards
        for i, card in enumerate(summary_cards):
            card_frame = ttk.Frame(cards_frame, style='Card.TFrame')
            card_frame.pack(side='left', fill='both',
                            expand=True, padx=5, pady=5)
            # Card title
            ttk.Label(card_frame, text=card['title'], font=('Helvetica', 10, 'bold'))\
                .pack(anchor='w', padx=10, pady=(10, 5))
            # Card value
            ttk.Label(card_frame, text=card['value'], font=('Helvetica', 16, 'bold'),
                      foreground=card['color']).pack(anchor='w', padx=10, pady=2)
            # Card change indicator
            change_text = f"{card['change']}% from last period"
            change_color = '#4CAF50' if card['change'] >= 0 else '#F44336'
            ttk.Label(card_frame, text=change_text, font=('Helvetica', 8),
                      foreground=change_color).pack(anchor='w', padx=10, pady=(0, 10))
        # Charts frame
        charts_frame = ttk.Frame(left_frame)
        charts_frame.pack(fill='both', expand=True)
        # Sales chart
        chart_frame = ttk.LabelFrame(
            charts_frame, text="Sales Overview - Last 30 Days", padding=10)
        chart_frame.pack(fill='both', expand=True, pady=(0, 20))
        # Add a placeholder for the chart
        self.create_sales_chart(chart_frame)
        # Right side - Recent activity and low stock
        right_frame = ttk.Frame(main_frame, width=300)
        right_frame.pack(side='right', fill='y', padx=(10, 0))
        # Low stock items
        low_stock_frame = ttk.LabelFrame(
            right_frame, text="⚠️ Low Stock Alerts", padding=10)
        low_stock_frame.pack(fill='x', pady=(0, 20))
        if stats['low_stock_items']:
            for item in stats['low_stock_items']:
                item_frame = ttk.Frame(low_stock_frame)
                item_frame.pack(fill='x', pady=2)
                ttk.Label(item_frame, text=item['name'], width=20, anchor='w').pack(
                    side='left')
                ttk.Label(item_frame, text=f"{item['quantity']} in stock",
                          foreground='red' if item['quantity'] == 0 else 'orange').pack(side='right')
        else:
            ttk.Label(low_stock_frame, text="No low stock items",
                      foreground='gray').pack()
        # Recent transactions
        recent_frame = ttk.LabelFrame(
            right_frame, text="🔄 Recent Transactions", padding=10)
        recent_frame.pack(fill='both', expand=True)
        if stats['recent_transactions']:
            for trans in stats['recent_transactions']:
                trans_frame = ttk.Frame(recent_frame)
                trans_frame.pack(fill='x', pady=2)
                ttk.Label(trans_frame, text=trans['time'], width=8).pack(
                    side='left')
                ttk.Label(trans_frame, text=trans['type'], width=12, anchor='w').pack(
                    side='left')
                ttk.Label(trans_frame, text=trans['details'], anchor='w').pack(
                    side='left', fill='x', expand=True)
                ttk.Label(trans_frame, text=f"PKR {trans['amount']:.2f}",
                          foreground='green' if trans['type'] == 'SALE' else 'black').pack(side='right')
        else:
            ttk.Label(recent_frame, text="No recent transactions",
                      foreground='gray').pack()

    def create_sales_chart(self, parent):
        # Create a figure for the chart
        fig = Figure(figsize=(8, 4), dpi=100, tight_layout=True)
        ax = fig.add_subplot(111)
        # Build last 30 days range
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=29)
        date_list = [(start_date + timedelta(days=i)) for i in range(30)]
        # Query actual sales totals per day
        rows = self.db.fetch_all(
            """
            SELECT DATE(sale_date) AS d, COALESCE(SUM(total_amount), 0)
            FROM sales
            WHERE DATE(sale_date) BETWEEN ? AND ?
            GROUP BY DATE(sale_date)
            ORDER BY d
            """,
            (start_date.strftime('%Y-%m-%d'), end_date.strftime('%Y-%m-%d'))
        )
        totals_by_date = {row[0]: float(row[1]) for row in rows}
        # Map to ordered list
        sales = [totals_by_date.get(d.strftime('%Y-%m-%d'), 0.0)
                 for d in date_list]
        x = list(range(1, 31))
        # Create the chart
        ax.plot(x, sales, color='#4CAF50',
                linewidth=2, marker='o', markersize=4)
        ax.fill_between(x, sales, color='#4CAF50', alpha=0.1)
        ax.set_facecolor('#f9f9f9')
        ax.grid(True, linestyle='--', alpha=0.7)
        ax.set_xlabel('Day (last 30 days)')
        ax.set_ylabel('Sales (PKR)')
        ax.set_xticks([1, 10, 20, 30])
        ax.set_ylim(bottom=0)
        # Add a horizontal line at the average
        avg_sales = (sum(sales) / len(sales)) if sales else 0
        ax.axhline(y=avg_sales, color='#FF9800',
                   linestyle='--', linewidth=1, alpha=0.7)
        ax.text(1, avg_sales + (avg_sales * 0.05 if avg_sales else 20),
                f'Avg: PKR {avg_sales:,.0f}', color='#FF9800')
        # Embed the chart in the Tkinter window
        canvas = FigureCanvasTkAgg(fig, master=parent)
        canvas.draw()
        canvas.get_tk_widget().pack(fill='both', expand=True)

    def get_dashboard_stats(self):
        """Get statistics for the dashboard"""
        try:
            # Totals
            total_sales_row = self.db.fetch_one(
                "SELECT COALESCE(SUM(total_amount), 0) FROM sales"
            )
            total_sales = float(total_sales_row[0]) if total_sales_row else 0.0
            today_str = datetime.now().strftime('%Y-%m-%d')
            today_row = self.db.fetch_one(
                "SELECT COALESCE(SUM(total_amount), 0) FROM sales WHERE DATE(sale_date) = ?",
                (today_str,)
            )
            today_sales = float(today_row[0]) if today_row else 0.0
            # Inventory stats
            total_items = self.db.fetch_one(
                "SELECT COUNT(*) FROM inventory")[0]
            low_stock_count = self.db.fetch_one(
                """
                SELECT COUNT(*) FROM inventory
                WHERE quantity <= COALESCE(min_stock, 0) OR quantity <= 0
                """
            )[0]
            low_stock_items_rows = self.db.fetch_all(
                """
                SELECT name, quantity
                FROM inventory
                WHERE quantity <= COALESCE(min_stock, 0) OR quantity <= 0
                ORDER BY quantity ASC
                LIMIT 10
                """
            )
            low_stock_items = [
                {'name': row[0], 'quantity': row[1]} for row in low_stock_items_rows
            ]
            # Recent transactions
            recent_rows = self.db.fetch_all(
                """
                SELECT s.transaction_id, s.total_amount, s.sale_date, COUNT(si.id) as items
                FROM sales s
                LEFT JOIN sale_items si ON s.id = si.sale_id
                GROUP BY s.id
                ORDER BY s.sale_date DESC
                LIMIT 5
                """
            )
            recent_transactions = []
            for tr in recent_rows:
                sale_dt = tr[2]
                # sale_dt may already be string; ensure time extraction is robust
                time_text = str(sale_dt)[11:16] if len(
                    str(sale_dt)) >= 16 else str(sale_dt)
                recent_transactions.append({
                    'time': time_text,
                    'type': 'SALE',
                    'details': f"{tr[0]} • {tr[3]} items",
                    'amount': float(tr[1])
                })
            # Changes (set to 0 for now, can be computed period-over-period later)
            stats = {
                'total_sales': total_sales,
                'today_sales': today_sales,
                'today_sales_change': 0.0,
                'sales_change': 0.0,
                'total_items': total_items,
                'items_change': 0.0,
                'low_stock_count': low_stock_count,
                'low_stock_change': 0.0,
                'low_stock_items': low_stock_items,
                'recent_transactions': recent_transactions
            }
            return stats
        except Exception as e:
            messagebox.showerror(
                "Error", f"Failed to load dashboard data: {e}")
            return {
                'total_sales': 0,
                'today_sales': 0,
                'sales_change': 0,
                'total_items': 0,
                'items_change': 0,
                'low_stock_count': 0,
                'low_stock_change': 0,
                'low_stock_items': [],
                'recent_transactions': []
            }

    def refresh_dashboard(self):
        """Refresh the dashboard data"""
        self.show_dashboard()  # Simply recall the dashboard to refresh data

    def refresh_inventory(self):
        """Refresh the inventory list"""
        if hasattr(self, 'inventory_tree'):
            self.load_inventory(self.search_var.get())
            self.update_status_bar()

    def update_status_bar(self):
        """Update the status bar with item count"""
        if hasattr(self, 'inventory_tree') and hasattr(self, 'status_var'):
            count = len(self.inventory_tree.get_children())
            self.status_var.set(f"{count} items")

    def show_edit_item_dialog(self):
        """Show dialog to edit selected item"""
        selected = self.inventory_tree.selection()
        if not selected:
            messagebox.showinfo("Info", "Please select an item to edit")
            return
        item_id = self.inventory_tree.item(selected[0], 'values')[0]
        self.show_add_item_dialog(item_id)

    def view_item_details(self, event=None):
        """Show detailed view of selected item"""
        selected = self.inventory_tree.selection()
        if not selected:
            return
        # Get the item values from the treeview
        item_values = self.inventory_tree.item(selected[0], 'values')
        # Ensure we have enough values
        if not item_values or len(item_values) < 5:
            messagebox.showerror("Error", "Could not retrieve item details")
            return
        # Get the item ID from the treeview (first value in the tuple)
        try:
            item_id = int(item_values[0])
        except (ValueError, IndexError):
            messagebox.showerror("Error", "Invalid item ID")
            return
        try:
            # First, check if the description column exists
            self.db.cursor.execute("PRAGMA table_info(inventory)")
            columns = [col[1] for col in self.db.cursor.fetchall()]
            has_description = 'description' in columns
            # Build the query based on available columns
            if has_description:
                query = """
                    SELECT id, sku, name, category, quantity, price,
                           COALESCE(min_stock, 0) as min_stock,
                           COALESCE(description, '') as description
                    FROM inventory
                    WHERE id = ?
                    """
            else:
                query = """
                    SELECT id, sku, name, category, quantity, price,
                           COALESCE(min_stock, 0) as min_stock,
                           '' as description
                    FROM inventory
                    WHERE id = ?
                    """
            # Fetch the item using the appropriate query
            item = self.db.fetch_one(query, (item_id,))
            if not item:
                messagebox.showerror("Error", "Item not found in database")
                return
            # Create a details dialog
            dialog = tk.Toplevel(self.root)
            dialog.title("Item Details")
            dialog.transient(self.root)
            dialog.grab_set()
            # Configure grid
            dialog.columnconfigure(1, weight=1)
            # Unpack item details
            item_id, sku, name, category, quantity, price, min_stock, description = item
            # Determine status
            try:
                quantity = int(quantity)
                min_stock = int(min_stock) if min_stock is not None else 0
                status = "Out of Stock" if quantity <= 0 else "Low Stock" if min_stock and quantity <= min_stock else "In Stock"
            except (ValueError, TypeError):
                status = "N/A"
            # Format price
            try:
                price_str = f"PKR {float(price):.2f}"
            except (ValueError, TypeError):
                price_str = "N/A"
            # Display item details
            details = [
                ("ID:", str(item_id)),
                ("SKU:", sku or "N/A"),
                ("Name:", name or "N/A"),
                ("Category:", category or "Uncategorized"),
                ("Price:", price_str),
                ("In Stock:", str(quantity) if quantity is not None else "N/A"),
                ("Min Stock:", str(min_stock) if min_stock is not None else "N/A"),
                ("Status:", status),
                ("Description:", description or "No description available")
            ]
            # Create and place labels
            for i, (label, value) in enumerate(details):
                # Skip empty values
                if value is None:
                    continue
                ttk.Label(dialog, text=label, font=('Helvetica', 10, 'bold')) \
                    .grid(row=i, column=0, sticky='ne', padx=10, pady=5)
                if label == "Description:":
                    # Use a text widget for the description to allow better text wrapping
                    desc_frame = ttk.Frame(dialog)
                    desc_frame.grid(row=i, column=1,
                                    sticky='nsew', padx=5, pady=5)
                    text = tk.Text(desc_frame, wrap=tk.WORD, width=40, height=4,
                                   font=('Helvetica', 10), relief='flat', bg=dialog.cget('bg'))
                    text.insert('1.0', value)
                    text.config(state='disabled')
                    text.pack(fill='both', expand=True)
                else:
                    ttk.Label(dialog, text=value, wraplength=300) \
                        .grid(row=i, column=1, sticky='nw', padx=5, pady=5)
            # Add close button
            close_btn = ttk.Button(
                dialog,
                text="Close",
                command=dialog.destroy,
                style='Accent.TButton' if 'Accent.TButton' in self.style.theme_names() else None
            )
            close_btn.grid(row=len(details) + 1, column=0,
                           columnspan=2, pady=10)
            # Set minimum size and make it resizable
            dialog.minsize(450, 400)
            dialog.resizable(True, True)
            # Center the dialog
            dialog.update_idletasks()
            width = dialog.winfo_width()
            height = dialog.winfo_height()
            x = (dialog.winfo_screenwidth() // 2) - (width // 2)
            y = (dialog.winfo_screenheight() // 2) - (height // 2)
            dialog.geometry(f'{width}x{height}+{x}+{y}')
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
            if 'dialog' in locals():
                dialog.destroy()

    def delete_item(self, event=None):
        """Delete selected item after confirmation"""
        selected = self.inventory_tree.selection()
        if not selected:
            return
        item_name = self.inventory_tree.item(selected[0], 'values')[2]  # name is index 2 (id, sku, name...)
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete '{item_name}'?"):
            item_id = self.inventory_tree.item(selected[0], 'values')[0]
            try:
                self.db.execute_query(
                    "DELETE FROM inventory WHERE id = ?", (item_id,))
                self.refresh_inventory()
                messagebox.showinfo(
                    "Success", f"'{item_name}' has been deleted.")
            except Exception as e:
                messagebox.showerror(
                    "Error", f"Failed to delete item: {str(e)}")

    def show_inventory(self):
        """Show the inventory management interface"""
        self.clear_content()
        # Store search_var as instance variable
        self.search_var = tk.StringVar()
        # Header with title and buttons
        header_frame = ttk.Frame(self.content, style='Header.TFrame')
        header_frame.pack(fill='x', pady=(0, 20))
        ttk.Label(header_frame, text="Inventory Management",
                  font=('Helvetica', 16, 'bold')).pack(side='left')
        # Action buttons
        btn_frame = ttk.Frame(header_frame)
        btn_frame.pack(side='right')
        # Main action buttons
        ttk.Button(btn_frame, text="➕ Add Item",
                   command=self.show_add_item_dialog).pack(side='left', padx=2)
        ttk.Button(btn_frame, text="🔄 Refresh",
                   command=self.refresh_inventory).pack(side='left', padx=2)
        # Search and filter frame
        filter_frame = ttk.Frame(self.content)
        filter_frame.pack(fill='x', pady=(0, 10))
        # Search box
        search_frame = ttk.LabelFrame(filter_frame, text="Search", padding=5)
        search_frame.pack(side='left', padx=5, fill='x', expand=True)
        search_entry = ttk.Entry(
            search_frame, textvariable=self.search_var, width=40)
        search_entry.pack(side='left', fill='x', expand=True, padx=5)
        search_entry.bind(
            '<KeyRelease>', lambda e: self.load_inventory(self.search_var.get()))
        # Inventory treeview
        # Define column IDs (must match the order in the SQL query)
        columns = ('id', 'sku', 'name', 'category',
                   'quantity', 'price', 'min_stock', 'status')
        self.inventory_tree = ttk.Treeview(
            self.content,
            columns=columns,
            show='headings',
            selectmode='browse',
            style='Treeview'
        )
        # Configure columns
        self.inventory_tree.column('id', width=0, minwidth=0, stretch=tk.NO)
        self.inventory_tree.heading('id', text='ID')
        self.inventory_tree.column('sku', width=80, anchor='w')
        self.inventory_tree.heading('sku', text='SKU')
        self.inventory_tree.column('name', width=200, anchor='w')
        self.inventory_tree.heading('name', text='Item Name')
        self.inventory_tree.column('category', width=120, anchor='w')
        self.inventory_tree.heading('category', text='Category')
        self.inventory_tree.column('quantity', width=80, anchor='center')
        self.inventory_tree.heading('quantity', text='In Stock')
        self.inventory_tree.column('price', width=100, anchor='e')
        self.inventory_tree.heading('price', text='Price')
        self.inventory_tree.column('min_stock', width=80, anchor='center')
        self.inventory_tree.heading('min_stock', text='Min Stock')
        self.inventory_tree.column('status', width=100, anchor='center')
        self.inventory_tree.heading('status', text='Status')
        # Add scrollbars
        vsb = ttk.Scrollbar(self.content, orient="vertical",
                            command=self.inventory_tree.yview)
        hsb = ttk.Scrollbar(self.content, orient="horizontal",
                            command=self.inventory_tree.xview)
        self.inventory_tree.configure(
            yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        # Grid layout for treeview and scrollbars
        self.inventory_tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        self.content.grid_rowconfigure(0, weight=1)
        self.content.grid_columnconfigure(0, weight=1)
        # Bind events
        self.inventory_tree.bind('<Double-1>', self.view_item_details)
        self.inventory_tree.bind('<Delete>', self.delete_item)
        # Load initial data
        self.load_inventory()

    def load_inventory(self, search_term=''):
        for item in self.inventory_tree.get_children():
            self.inventory_tree.delete(item)
        query = """
        SELECT id, sku, name, category, quantity, price, min_stock
        FROM inventory
        WHERE name LIKE ? OR sku LIKE ?
        """
        search = f"%{search_term}%"
        items = self.db.fetch_all(query, (search, search))
        for item in items:
            quantity = item[4]
            min_stock = item[6] or 0
            status = "Out of Stock" if quantity <= 0 else "Low Stock" if quantity <= min_stock else "In Stock"
            self.inventory_tree.insert('', 'end', values=(
                item[0],  # id (hidden)
                item[1],  # sku
                item[2],  # name
                item[3] or 'Uncategorized',  # category
                quantity,  # quantity
                f"PKR {item[5]:.2f}",  # price
                min_stock,  # min_stock
                status  # status
            ))

    def show_add_item_dialog(self, item_id=None):
        # Implement add/edit item dialog here
        pass  # Placeholder for add/edit functionality

    def show_pos(self):
        self.clear_content()
        # Implement POS interface here
        pass  # Placeholder

    def show_customers(self):
        self.clear_content()
        # Implement customers interface here
        pass  # Placeholder

    def show_sales(self):
        self.clear_content()
        # Implement sales interface here
        pass  # Placeholder

    def show_reports(self):
        self.clear_content()
        # Header
        header_frame = ttk.Frame(self.content)
        header_frame.pack(fill='x', pady=(0, 20))
        ttk.Label(header_frame, text="Reports & Analytics",
                  font=('Helvetica', 18, 'bold')).pack(side='left')
        # Report type selector
        ttk.Label(header_frame, text="Report Type:").pack(
            side='left', padx=(20, 5))
        self.report_type_var = tk.StringVar(value="Sales Overview")
        report_types = ["Sales Overview", "Inventory Report",
                        "Customer Analytics", "Product Performance", "Financial Summary"]
        report_combo = ttk.Combobox(
            header_frame, textvariable=self.report_type_var, values=report_types, state='readonly', width=20)
        report_combo.pack(side='left', padx=5)
        report_combo.bind('<<ComboboxSelected>>',
                          lambda e: self.load_selected_report())
        ttk.Button(header_frame, text="🔄 Refresh",
                   command=self.load_selected_report).pack(side='left', padx=5)
        ttk.Button(header_frame, text="📄 Export PDF",
                   command=self.export_report_pdf).pack(side='right', padx=5)
        # Date range filter
        filter_frame = ttk.LabelFrame(
            self.content, text="Date Range", padding=10)
        filter_frame.pack(fill='x', pady=(0, 10))
        ttk.Label(filter_frame, text="From:").pack(side='left', padx=5)
        self.report_from_date = tk.StringVar(
            value=(datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d'))
        ttk.Entry(filter_frame, textvariable=self.report_from_date,
                  width=12).pack(side='left', padx=5)
        ttk.Label(filter_frame, text="To:").pack(side='left', padx=5)
        self.report_to_date = tk.StringVar(
            value=datetime.now().strftime('%Y-%m-%d'))
        ttk.Entry(filter_frame, textvariable=self.report_to_date,
                  width=12).pack(side='left', padx=5)
        ttk.Button(filter_frame, text="Apply", command=self.load_selected_report).pack(
            side='left', padx=10)
        # Report content area
        self.report_content = ttk.Frame(self.content)
        self.report_content.pack(fill='both', expand=True)
        # Load default report
        self.load_selected_report()

    def load_selected_report(self):
        """Load the selected report type"""
        # Clear current content
        for widget in self.report_content.winfo_children():
            widget.destroy()
        report_type = self.report_type_var.get()
        if report_type == "Sales Overview":
            self.show_sales_overview_report()
        elif report_type == "Inventory Report":
            self.show_inventory_report()
        elif report_type == "Customer Analytics":
            self.show_customer_analytics_report()
        elif report_type == "Product Performance":
            self.show_product_performance_report()
        elif report_type == "Financial Summary":
            self.show_financial_summary_report()

    def show_sales_overview_report(self):
        """Sales overview with charts and statistics"""
        from_date = self.report_from_date.get()
        to_date = self.report_to_date.get()
        # Get sales data
        sales_data = self.db.fetch_all("""
            SELECT DATE(sale_date) as date, SUM(total_amount) as total, SUM(tax_amount) as tax
            FROM sales
            WHERE DATE(sale_date) BETWEEN ? AND ?
            GROUP BY DATE(sale_date)
            ORDER BY date
        """, (from_date, to_date))
        # Summary metrics
        summary_frame = ttk.Frame(self.report_content)
        summary_frame.pack(fill='x', pady=(0, 20))
        total_revenue = sum(row[1] for row in sales_data)
        total_tax = sum(row[2] for row in sales_data)
        avg_daily = total_revenue / len(sales_data) if sales_data else 0
        metrics = [
            ("Total Revenue", f"PKR {total_revenue:,.2f}", '#4CAF50'),
            ("Total Tax", f"PKR {total_tax:,.2f}", '#FF9800'),
            ("Avg Daily Sales", f"PKR {avg_daily:,.2f}", '#2196F3'),
            ("Days", str(len(sales_data)), '#9C27B0')
        ]
        for title, value, color in metrics:
            card = ttk.Frame(summary_frame, relief='raised', borderwidth=1)
            card.pack(side='left', fill='both', expand=True, padx=5)
            ttk.Label(card, text=title, font=(
                'Helvetica', 10)).pack(pady=(10, 5))
            ttk.Label(card, text=value, font=('Helvetica', 14, 'bold'),
                      foreground=color).pack(pady=(0, 10))
        # Sales chart
        if sales_data:
            chart_frame = ttk.LabelFrame(
                self.report_content, text="Daily Sales Trend", padding=10)
            chart_frame.pack(fill='both', expand=True)
            fig = Figure(figsize=(10, 5), dpi=100)
            ax = fig.add_subplot(111)
            dates = [row[0] for row in sales_data]
            amounts = [row[1] for row in sales_data]
            ax.plot(dates, amounts, marker='o', linewidth=2, color='#4CAF50')
            ax.fill_between(range(len(dates)), amounts,
                            alpha=0.3, color='#4CAF50')
            ax.set_xlabel('Date')
            ax.set_ylabel('Sales (PKR)')
            ax.set_title('Daily Sales Performance')
            ax.grid(True, alpha=0.3)
            # Rotate x-axis labels
            plt.setp(ax.xaxis.get_majorticklabels(), rotation=45, ha='right')
            fig.tight_layout()
            canvas = FigureCanvasTkAgg(fig, master=chart_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill='both', expand=True)

    def show_inventory_report(self):
        """Inventory status report"""
        # Get inventory data
        inventory_data = self.db.fetch_all("""
            SELECT category, COUNT(*) as items, SUM(quantity) as total_qty,
                   SUM(quantity * price) as total_value
            FROM inventory
            GROUP BY category
        """)
        # Summary
        summary_frame = ttk.Frame(self.report_content)
        summary_frame.pack(fill='x', pady=(0, 20))
        total_items = sum(row[1] for row in inventory_data)
        total_qty = sum(row[2] for row in inventory_data)
        total_value = sum(row[3] for row in inventory_data)
        metrics = [
            ("Total Products", str(total_items), '#4CAF50'),
            ("Total Quantity", str(total_qty), '#2196F3'),
            ("Inventory Value", f"PKR {total_value:,.2f}", '#FF9800')
        ]
        for title, value, color in metrics:
            card = ttk.Frame(summary_frame, relief='raised', borderwidth=1)
            card.pack(side='left', fill='both', expand=True, padx=5)
            ttk.Label(card, text=title, font=(
                'Helvetica', 10)).pack(pady=(10, 5))
            ttk.Label(card, text=value, font=('Helvetica', 14, 'bold'),
                      foreground=color).pack(pady=(0, 10))
        # Category breakdown table
        table_frame = ttk.LabelFrame(
            self.report_content, text="Inventory by Category", padding=10)
        table_frame.pack(fill='both', expand=True)
        columns = ('category', 'items', 'quantity', 'value')
        tree = ttk.Treeview(table_frame, columns=columns,
                            show='headings', height=15)
        tree.heading('category', text='Category')
        tree.heading('items', text='Products')
        tree.heading('quantity', text='Total Qty')
        tree.heading('value', text='Total Value')
        tree.column('category', width=200)
        tree.column('items', width=100, anchor='center')
        tree.column('quantity', width=100, anchor='center')
        tree.column('value', width=150, anchor='e')
        for row in inventory_data:
            tree.insert('', 'end', values=(
                row[0] or 'Uncategorized',
                row[1],
                row[2],
                f"PKR {row[3]:,.2f}"
            ))
        tree.pack(fill='both', expand=True)

    def show_customer_analytics_report(self):
        """Customer analytics and insights"""
        # Get customer data
        customer_stats = self.db.fetch_one("""
            SELECT COUNT(*) as total_customers,
                   SUM(loyalty_points) as total_points,
                   SUM(total_spent) as total_spent,
                   AVG(total_spent) as avg_spent
            FROM customers
        """)
        # Top customers
        top_customers = self.db.fetch_all("""
            SELECT name, total_spent, loyalty_points
            FROM customers
            ORDER BY total_spent DESC
            LIMIT 10
        """)
        # Summary
        summary_frame = ttk.Frame(self.report_content)
        summary_frame.pack(fill='x', pady=(0, 20))
        metrics = [
            ("Total Customers", str(customer_stats[0]), '#4CAF50'),
            ("Total Points", str(customer_stats[1]), '#2196F3'),
            ("Total Spent", f"PKR {customer_stats[2]:,.2f}", '#FF9800'),
            ("Avg per Customer", f"PKR {customer_stats[3]:,.2f}", '#9C27B0')
        ]
        for title, value, color in metrics:
            card = ttk.Frame(summary_frame, relief='raised', borderwidth=1)
            card.pack(side='left', fill='both', expand=True, padx=5)
            ttk.Label(card, text=title, font=(
                'Helvetica', 10)).pack(pady=(10, 5))
            ttk.Label(card, text=value, font=('Helvetica', 14, 'bold'),
                      foreground=color).pack(pady=(0, 10))
        # Top customers table
        table_frame = ttk.LabelFrame(
            self.report_content, text="Top 10 Customers", padding=10)
        table_frame.pack(fill='both', expand=True)
        columns = ('rank', 'name', 'spent', 'points')
        tree = ttk.Treeview(table_frame, columns=columns,
                            show='headings', height=10)
        tree.heading('rank', text='Rank')
        tree.heading('name', text='Customer Name')
        tree.heading('spent', text='Total Spent')
        tree.heading('points', text='Loyalty Points')
        tree.column('rank', width=60, anchor='center')
        tree.column('name', width=250)
        tree.column('spent', width=150, anchor='e')
        tree.column('points', width=120, anchor='center')
        for idx, row in enumerate(top_customers, 1):
            tree.insert('', 'end', values=(
                idx,
                row[0],
                f"PKR {row[1]:,.2f}",
                row[2]
            ))
        tree.pack(fill='both', expand=True)

    def show_product_performance_report(self):
        """Product performance analysis"""
        from_date = self.report_from_date.get()
        to_date = self.report_to_date.get()
        # Get product performance data
        products = self.db.fetch_all("""
            SELECT i.name, i.category, SUM(si.quantity) as qty_sold,
                   SUM(si.subtotal) as revenue
            FROM sale_items si
            JOIN inventory i ON si.item_id = i.id
            JOIN sales s ON si.sale_id = s.id
            WHERE DATE(s.sale_date) BETWEEN ? AND ?
            GROUP BY i.id
            ORDER BY revenue DESC
            LIMIT 20
        """, (from_date, to_date))
        # Summary
        summary_frame = ttk.Frame(self.report_content)
        summary_frame.pack(fill='x', pady=(0, 20))
        total_revenue = sum(row[3] for row in products)
        total_qty = sum(row[2] for row in products)
        metrics = [
            ("Products Sold", str(len(products)), '#4CAF50'),
            ("Total Units", str(total_qty), '#2196F3'),
            ("Total Revenue", f"PKR {total_revenue:,.2f}", '#FF9800')
        ]
        for title, value, color in metrics:
            card = ttk.Frame(summary_frame, relief='raised', borderwidth=1)
            card.pack(side='left', fill='both', expand=True, padx=5)
            ttk.Label(card, text=title, font=(
                'Helvetica', 10)).pack(pady=(10, 5))
            ttk.Label(card, text=value, font=('Helvetica', 14, 'bold'),
                      foreground=color).pack(pady=(0, 10))
        # Products table
        table_frame = ttk.LabelFrame(
            self.report_content, text="Top 20 Products by Revenue", padding=10)
        table_frame.pack(fill='both', expand=True)
        columns = ('rank', 'product', 'category', 'qty', 'revenue')
        tree = ttk.Treeview(table_frame, columns=columns,
                            show='headings', height=15)
        tree.heading('rank', text='Rank')
        tree.heading('product', text='Product')
        tree.heading('category', text='Category')
        tree.heading('qty', text='Qty Sold')
        tree.heading('revenue', text='Revenue')
        tree.column('rank', width=60, anchor='center')
        tree.column('product', width=250)
        tree.column('category', width=150)
        tree.column('qty', width=100, anchor='center')
        tree.column('revenue', width=150, anchor='e')
        for idx, row in enumerate(products, 1):
            tree.insert('', 'end', values=(
                idx,
                row[0],
                row[1] or 'Uncategorized',
                row[2],
                f"PKR {row[3]:,.2f}"
            ))
        tree.pack(fill='both', expand=True)

    def show_financial_summary_report(self):
        """Financial summary report"""
        from_date = self.report_from_date.get()
        to_date = self.report_to_date.get()
        # Get financial data
        financial_data = self.db.fetch_one("""
            SELECT SUM(total_amount) as revenue,
                   SUM(tax_amount) as tax,
                   COUNT(*) as transactions
            FROM sales
            WHERE DATE(sale_date) BETWEEN ? AND ?
        """, (from_date, to_date))
        revenue = financial_data[0] or 0
        tax = financial_data[1] or 0
        transactions = financial_data[2] or 0
        net_revenue = revenue - tax
        # Summary cards
        summary_frame = ttk.Frame(self.report_content)
        summary_frame.pack(fill='x', pady=(0, 20))
        metrics = [
            ("Gross Revenue", f"PKR {revenue:,.2f}", '#4CAF50'),
            ("Tax Collected", f"PKR {tax:,.2f}", '#FF9800'),
            ("Net Revenue", f"PKR {net_revenue:,.2f}", '#2196F3'),
            ("Transactions", str(transactions), '#9C27B0')
        ]
        for title, value, color in metrics:
            card = ttk.Frame(summary_frame, relief='raised', borderwidth=1)
            card.pack(side='left', fill='both', expand=True, padx=5)
            ttk.Label(card, text=title, font=(
                'Helvetica', 10)).pack(pady=(10, 5))
            ttk.Label(card, text=value, font=('Helvetica', 14, 'bold'),
                      foreground=color).pack(pady=(0, 10))
        # Detailed breakdown
        details_frame = ttk.LabelFrame(
            self.report_content, text="Financial Breakdown", padding=20)
        details_frame.pack(fill='both', expand=True)
        breakdown = [
            ("Period", f"{from_date} to {to_date}"),
            ("Total Transactions", str(transactions)),
            ("Gross Revenue", f"PKR {revenue:,.2f}"),
            ("Tax Collected (10%)", f"PKR {tax:,.2f}"),
            ("Net Revenue", f"PKR {net_revenue:,.2f}"),
            ("Average Transaction",
             f"PKR {(revenue/transactions if transactions > 0 else 0):,.2f}")
        ]
        for i, (label, value) in enumerate(breakdown):
            ttk.Label(details_frame, text=label + ":", font=('Helvetica',
                      11, 'bold')).grid(row=i, column=0, sticky='e', padx=10, pady=8)
            ttk.Label(details_frame, text=value, font=('Helvetica', 11)).grid(
                row=i, column=1, sticky='w', padx=10, pady=8)

    def export_report_pdf(self):
        """Export current report to PDF"""
        messagebox.showinfo(
            "Export PDF", "PDF export functionality will be implemented with detailed report generation.")

    def logout(self):
        if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            self.root.destroy()

def main():
    # Create the root window
    root = tk.Tk()
    root.withdraw()  # Hide the root window
   
    def on_login_success(user):
        # Close the login window
        login_window.destroy()
        # Create and show the main application
        MainApplication(root, user)
   
    # Create login window
    login_window = tk.Toplevel(root)
    login_window.title("Login - Retail Management System")
   
    # Center the login window
    window_width = 400
    window_height = 300
    screen_width = login_window.winfo_screenwidth()
    screen_height = login_window.winfo_screenheight()
    x = (screen_width // 2) - (window_width // 2)
    y = (screen_height // 2) - (window_height // 2)
    login_window.geometry(f'{window_width}x{window_height}+{x}+{y}')
    login_window.resizable(False, False)  # Make login window not resizable
   
    # Create login interface
    login_app = LoginWindow(login_window, on_login_success)
   
    # Handle window close
    def on_closing():
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            root.quit()
   
    login_window.protocol("WM_DELETE_WINDOW", on_closing)
   
    # Start the main loop
    root.mainloop()

if __name__ == "__main__":
    main()