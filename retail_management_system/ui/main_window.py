"""
Main application window for the Retail Management System.
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Callable, List, Tuple

from ..config import settings
from ..database.connection import get_db
from ..auth.security import AuthManager

logger = logging.getLogger(__name__)

class MainWindow:
    """Main application window for the Retail Management System."""
    
    def __init__(self, root: tk.Tk, user_data: Dict[str, Any]):
        """
        Initialize the main application window.
        
        Args:
            root: The root tkinter window
            user_data: Dictionary containing user information
        """
        self.root = root
        self.user_data = user_data
        self.db = get_db()
        self.auth_manager = AuthManager(self.db)
        
        # Configure window
        self.root.title(f"{settings.APP_NAME} - {user_data.get('full_name', user_data['username'])}")
        self.root.geometry(settings.UI['WINDOW_SIZE'])
        self.root.minsize(*map(int, settings.UI['MIN_WINDOW_SIZE'].split('x')))
        self.root.state('zoomed')
        
        # Set up the UI
        self._setup_ui()
        
        # Bind window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Track open dialogs
        self.open_dialogs = []
    
    def _setup_ui(self):
        """Set up the main application UI."""
        # Configure the main window style
        self._configure_styles()
        
        # Create the main container
        self.main_container = ttk.Frame(self.root)
        self.main_container.pack(fill='both', expand=True)
        
        # Create the menu bar
        self._create_menu_bar()
        
        # Create the status bar
        self._create_status_bar()
        
        # Create the main content area
        self._create_content_area()
        
        # Create the sidebar
        self._create_sidebar()
        
        # Show the dashboard by default
        self.show_dashboard()
    
    def _configure_styles(self):
        """Configure the application styles."""
        style = ttk.Style()
        
        # Configure the main window background
        self.root.configure(background='#f5f6fa')
        
        # Configure the main frame
        style.configure('Main.TFrame', background='#f5f6fa')
        
        # Configure labels
        style.configure('TLabel', font=settings.UI['FONT'], background='#f5f6fa')
        style.configure('Title.TLabel', font=settings.UI['FONT_TITLE'], background='#f5f6fa')
        style.configure('Subtitle.TLabel', font=settings.UI['FONT_BOLD'], background='#f5f6fa')
        
        # Configure buttons
        style.configure('TButton', font=settings.UI['FONT'], padding=settings.UI['BTN_PADDING'])
        style.configure('Accent.TButton', font=settings.UI['FONT_BOLD'], background='#3498db', foreground='white')
        
        # Configure the sidebar
        style.configure('Sidebar.TFrame', background='#2c3e50')
        style.configure('Sidebar.TButton', 
                        font=settings.UI['FONT'], 
                        background='#2c3e50', 
                        foreground='white',
                        borderwidth=0,
                        padding=(20, 10, 20, 10))
        style.map('Sidebar.TButton',
                 background=[('active', '#34495e'), ('pressed', '#2c3e50')],
                 foreground=[('active', 'white'), ('pressed', 'white')])
        
        # Configure the status bar
        style.configure('StatusBar.TFrame', background='#ecf0f1')
        style.configure('StatusBar.TLabel', 
                        font=('TkDefaultFont', 8), 
                        background='#ecf0f1',
                        foreground='#7f8c8d')
        
        # Configure cards
        style.configure('Card.TFrame', background='white', relief='raised', borderwidth=1)
        style.configure('Card.TLabel', background='white')
        
        # Configure notebook
        style.configure('TNotebook', background='#f5f6fa')
        style.configure('TNotebook.Tab', 
                        font=settings.UI['FONT'],
                        padding=[10, 5])
    
    def _create_menu_bar(self):
        """Create the application menu bar."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Sale", command=self.new_sale)
        file_menu.add_command(label="New Purchase", command=self.new_purchase)
        file_menu.add_separator()
        file_menu.add_command(label="Import Data...", command=self.import_data)
        file_menu.add_command(label="Export Data...", command=self.export_data)
        file_menu.add_separator()
        file_menu.add_command(label="Print...", command=self.print_document)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Edit menu
        edit_menu = tk.Menu(menubar, tearoff=0)
        edit_menu.add_command(label="Cut", command=lambda: self.root.focus_get().event_generate('<<Cut>>'))
        edit_menu.add_command(label="Copy", command=lambda: self.root.focus_get().event_generate('<<Copy>>'))
        edit_menu.add_command(label="Paste", command=lambda: self.root.focus_get().event_generate('<<Paste>>'))
        edit_menu.add_separator()
        edit_menu.add_command(label="Preferences...", command=self.show_preferences)
        menubar.add_cascade(label="Edit", menu=edit_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Refresh", command=self.refresh_view)
        view_menu.add_separator()
        view_menu.add_checkbutton(label="Show Status Bar", variable=tk.BooleanVar(value=True))
        view_menu.add_checkbutton(label="Show Toolbar", variable=tk.BooleanVar(value=True))
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Backup Database", command=self.backup_database)
        tools_menu.add_command(label="Restore Database", command=self.restore_database)
        tools_menu.add_separator()
        tools_menu.add_command(label="Run Reports", command=self.run_reports)
        tools_menu.add_command(label="System Logs", command=self.view_system_logs)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        help_menu.add_command(label="Check for Updates", command=self.check_for_updates)
        help_menu.add_separator()
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        # User menu (right-aligned)
        user_menu = tk.Menu(menubar, tearoff=0)
        user_menu.add_command(label="My Profile", command=self.show_user_profile)
        user_menu.add_command(label="Change Password", command=self.change_password)
        user_menu.add_separator()
        user_menu.add_command(label="Logout", command=self.logout)
        
        # Add the user menu to the right side of the menubar
        menubar.add_cascade(label=f"👤 {self.user_data.get('username', 'User')}", menu=user_menu)
    
    def _create_sidebar(self):
        """Create the sidebar navigation."""
        sidebar = ttk.Frame(self.main_container, style='Sidebar.TFrame', width=200)
        sidebar.pack(side='left', fill='y', padx=0, pady=0, ipadx=0, ipady=0)
        
        # Logo and app name
        logo_frame = ttk.Frame(sidebar, style='Sidebar.TFrame')
        logo_frame.pack(fill='x', pady=(10, 20))
        
        # App name
        ttk.Label(
            logo_frame, 
            text=settings.APP_NAME, 
            font=('TkDefaultFont', 12, 'bold'), 
            background='#2c3e50', 
            foreground='white'
        ).pack(pady=(0, 5))
        
        # User info
        ttk.Label(
            logo_frame, 
            text=f"Welcome, {self.user_data.get('full_name', self.user_data['username'])}", 
            font=('TkDefaultFont', 8), 
            background='#2c3e50', 
            foreground='#bdc3c7'
        ).pack()
        
        # Navigation buttons
        nav_buttons = [
            ("📊 Dashboard", self.show_dashboard),
            ("💰 POS", self.show_pos),
            ("📦 Inventory", self.show_inventory),
            ("🛒 Sales", self.show_sales),
            ("📋 Products", self.show_products),
            ("👥 Customers", self.show_customers),
            ("📈 Reports", self.show_reports),
            ("⚙️ Settings", self.show_settings)
        ]
        
        for text, command in nav_buttons:
            btn = ttk.Button(
                sidebar, 
                text=text, 
                style='Sidebar.TButton',
                command=command
            )
            btn.pack(fill='x', padx=0, pady=0, ipady=8)
    
    def _create_content_area(self):
        """Create the main content area."""
        # Main content frame
        self.content_frame = ttk.Frame(self.main_container, style='Main.TFrame')
        self.content_frame.pack(side='right', fill='both', expand=True, padx=10, pady=10)
        
        # Create a notebook for tabs
        self.notebook = ttk.Notebook(self.content_frame)
        self.notebook.pack(fill='both', expand=True)
        
        # Dictionary to track open tabs
        self.open_tabs = {}
        
        # Create a frame for the dashboard (default tab)
        self.dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_frame, text="Dashboard")
        self.open_tabs['dashboard'] = self.dashboard_frame
        
        # Configure notebook tab close button
        self.notebook.bind("<ButtonPress-1>", self._on_notebook_click, add=True)
    
    def _on_notebook_click(self, event):
        """Handle notebook tab close button click."""
        try:
            element = self.notebook.identify(event.x, event.y)
            if "close" in element:
                index = self.notebook.index(f"@{event.x},{event.y}")
                tab_id = self.notebook.tabs()[index]
                tab_name = self.notebook.tab(tab_id, 'text')
                self.close_tab(tab_name, index)
        except Exception as e:
            logger.error(f"Error handling notebook click: {e}")
    
    def close_tab(self, tab_name: str, index: int):
        """Close a notebook tab."""
        if tab_name.lower() == 'dashboard':
            return  # Don't close the dashboard tab
            
        tab_id = self.notebook.tabs()[index]
        self.notebook.forget(index)
        
        # Clean up resources if needed
        if tab_name in self.open_tabs:
            tab = self.open_tabs.pop(tab_name)
            if hasattr(tab, 'cleanup'):
                tab.cleanup()
    
    def _create_status_bar(self):
        """Create the status bar at the bottom of the window."""
        status_bar = ttk.Frame(self.main_container, style='StatusBar.TFrame', height=20)
        status_bar.pack(side='bottom', fill='x')
        
        # Left side status (e.g., connection status)
        ttk.Label(
            status_bar, 
            text="Connected", 
            style='StatusBar.TLabel'
        ).pack(side='left', padx=5)
        
        # Right side status (e.g., user info, time)
        status_right = ttk.Frame(status_bar, style='StatusBar.TFrame')
        status_right.pack(side='right')
        
        # Current user
        ttk.Label(
            status_right, 
            text=f"User: {self.user_data.get('username', 'Unknown')}", 
            style='StatusBar.TLabel'
        ).pack(side='left', padx=5)
        
        # Current date and time
        self.clock_var = tk.StringVar()
        self._update_clock()
        ttk.Label(
            status_right, 
            textvariable=self.clock_var, 
            style='StatusBar.TLabel'
        ).pack(side='left', padx=5)
    
    def _update_clock(self):
        """Update the clock in the status bar."""
        now = datetime.now()
        self.clock_var.set(now.strftime("%Y-%m-%d %H:%M:%S"))
        self.root.after(1000, self._update_clock)
    
    # ===== Navigation Methods =====
    
    def show_dashboard(self):
        """Show the dashboard tab."""
        self._switch_to_tab('dashboard', "Dashboard", self._create_dashboard_content)
    
    def show_pos(self):
        """Show the Point of Sale tab."""
        self._switch_to_tab('pos', "POS", self._create_pos_content)
    
    def show_inventory(self):
        """Show the Inventory tab."""
        self._switch_to_tab('inventory', "Inventory", self._create_inventory_content)
    
    def show_sales(self):
        """Show the Sales tab."""
        self._switch_to_tab('sales', "Sales", self._create_sales_content)
    
    def show_products(self):
        """Show the Products tab."""
        self._switch_to_tab('products', "Products", self._create_products_content)
    
    def show_customers(self):
        """Show the Customers tab."""
        self._switch_to_tab('customers', "Customers", self._create_customers_content)
    
    def show_reports(self):
        """Show the Reports tab."""
        self._switch_to_tab('reports', "Reports", self._create_reports_content)
    
    def show_settings(self):
        """Show the Settings tab."""
        self._switch_to_tab('settings', "Settings", self._create_settings_content)
    
    def _switch_to_tab(self, tab_id: str, tab_name: str, content_creator: Callable):
        """
        Switch to a tab, creating it if it doesn't exist.
        
        Args:
            tab_id: Unique identifier for the tab
            tab_name: Display name of the tab
            content_creator: Function that creates the tab's content
        """
        # Check if the tab is already open
        if tab_id in self.open_tabs:
            tab = self.open_tabs[tab_id]
            self.notebook.select(tab)
            return
        
        # Create a new tab
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=tab_name)
        self.notebook.select(tab)
        self.open_tabs[tab_id] = tab
        
        # Create the tab's content
        try:
            content_creator(tab)
        except Exception as e:
            logger.error(f"Error creating {tab_name} content: {e}", exc_info=True)
            messagebox.showerror("Error", f"Failed to load {tab_name}: {str(e)}")
    
    # ===== Tab Content Creators =====
    
    def _create_dashboard_content(self, parent):
        """Create the dashboard content."""
        # Main container with padding
        container = ttk.Frame(parent, style='Main.TFrame')
        container.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Header
        header = ttk.Frame(container, style='Main.TFrame')
        header.pack(fill='x', pady=(0, 20))
        
        ttk.Label(
            header,
            text="Dashboard",
            style='Title.TLabel'
        ).pack(side='left')
        
        # Refresh button
        ttk.Button(
            header,
            text="🔄 Refresh",
            command=self.refresh_dashboard,
            style='TButton'
        ).pack(side='right')
        
        # Stats row
        stats_frame = ttk.Frame(container, style='Main.TFrame')
        stats_frame.pack(fill='x', pady=(0, 20))
        
        # Stats cards
        stats = [
            ("Total Sales", "PKR 0.00", "📊"),
            ("Today's Sales", "PKR 0.00", "💰"),
            ("Total Products", "0", "📦"),
            ("Low Stock Items", "0", "⚠️")
        ]
        
        for i, (title, value, icon) in enumerate(stats):
            card = ttk.Frame(stats_frame, style='Card.TFrame', padding=15)
            card.grid(row=0, column=i, padx=5, sticky='nsew')
            stats_frame.columnconfigure(i, weight=1)
            
            # Icon
            ttk.Label(
                card,
                text=icon,
                font=('TkDefaultFont', 24),
                style='Card.TLabel'
            ).pack(anchor='w')
            
            # Value
            ttk.Label(
                card,
                text=value,
                font=('TkDefaultFont', 18, 'bold'),
                style='Card.TLabel'
            ).pack(anchor='w', pady=(5, 0))
            
            # Title
            ttk.Label(
                card,
                text=title,
                style='Card.TLabel',
                foreground='#7f8c8d'
            ).pack(anchor='w')
        
        # Charts row
        charts_frame = ttk.Frame(container, style='Main.TFrame')
        charts_frame.pack(fill='both', expand=True)
        
        # Left chart (sales)
        chart1_frame = ttk.Frame(charts_frame, style='Card.TFrame', padding=15)
        chart1_frame.pack(side='left', fill='both', expand=True, padx=(0, 10))
        
        ttk.Label(
            chart1_frame,
            text="Sales Overview (Last 30 Days)",
            style='Subtitle.TLabel'
        ).pack(anchor='w', pady=(0, 10))
        
        # Placeholder for chart
        chart1_placeholder = ttk.Frame(chart1_frame, height=200, style='Card.TFrame')
        chart1_placeholder.pack(fill='both', expand=True)
        ttk.Label(
            chart1_placeholder,
            text="Sales chart will be displayed here",
            style='Card.TLabel',
            foreground='#95a5a6'
        ).pack(expand=True)
        
        # Right chart (inventory)
        chart2_frame = ttk.Frame(charts_frame, style='Card.TFrame', padding=15)
        chart2_frame.pack(side='right', fill='both', expand=True, padx=(10, 0))
        
        ttk.Label(
            chart2_frame,
            text="Top Selling Products",
            style='Subtitle.TLabel'
        ).pack(anchor='w', pady=(0, 10))
        
        # Placeholder for chart
        chart2_placeholder = ttk.Frame(chart2_frame, height=200, style='Card.TFrame')
        chart2_placeholder.pack(fill='both', expand=True)
        ttk.Label(
            chart2_placeholder,
            text="Top products chart will be displayed here",
            style='Card.TLabel',
            foreground='#95a5a6'
        ).pack(expand=True)
        
        # Recent transactions
        ttk.Label(
            container,
            text="Recent Transactions",
            style='Subtitle.TLabel'
        ).pack(anchor='w', pady=(20, 10))
        
        # Transactions table
        columns = ("ID", "Date", "Customer", "Amount", "Status")
        tree = ttk.Treeview(
            container,
            columns=columns,
            show='headings',
            selectmode='browse',
            height=5
        )
        
        # Configure columns
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=100, anchor='w')
        
        # Add sample data
        sample_data = [
            ("#1001", "2023-06-15", "Walk-in Customer", "PKR 1,250.00", "Completed"),
            ("#1000", "2023-06-14", "John Doe", "PKR 5,430.00", "Completed"),
            ("#999", "2023-06-14", "Jane Smith", "PKR 2,150.00", "Completed"),
            ("#998", "2023-06-13", "Acme Corp", "PKR 8,750.00", "Completed"),
            ("#997", "2023-06-12", "Walk-in Customer", "PKR 1,890.00", "Completed")
        ]
        
        for item in sample_data:
            tree.insert('', 'end', values=item)
        
        tree.pack(fill='x', pady=(0, 10))
        
        # View all transactions button
        ttk.Button(
            container,
            text="View All Transactions",
            command=lambda: self.show_sales(),
            style='TButton'
        ).pack(anchor='e')
    
    def _create_pos_content(self, parent):
        """Create the Point of Sale content."""
        # This will be implemented in the POS module
        ttk.Label(
            parent,
            text="Point of Sale (Coming Soon)",
            font=settings.UI['FONT_TITLE']
        ).pack(expand=True)
    
    def _create_inventory_content(self, parent):
        """Create the Inventory content."""
        # This will be implemented in the Inventory module
        ttk.Label(
            parent,
            text="Inventory Management (Coming Soon)",
            font=settings.UI['FONT_TITLE']
        ).pack(expand=True)
    
    def _create_sales_content(self, parent):
        """Create the Sales content."""
        # This will be implemented in the Sales module
        ttk.Label(
            parent,
            text="Sales Management (Coming Soon)",
            font=settings.UI['FONT_TITLE']
        ).pack(expand=True)
    
    def _create_products_content(self, parent):
        """Create the Products content."""
        # This will be implemented in the Products module
        ttk.Label(
            parent,
            text="Product Management (Coming Soon)",
            font=settings.UI['FONT_TITLE']
        ).pack(expand=True)
    
    def _create_customers_content(self, parent):
        """Create the Customers content."""
        # This will be implemented in the Customers module
        ttk.Label(
            parent,
            text="Customer Management (Coming Soon)",
            font=settings.UI['FONT_TITLE']
        ).pack(expand=True)
    
    def _create_reports_content(self, parent):
        """Create the Reports content."""
        # This will be implemented in the Reports module
        ttk.Label(
            parent,
            text="Reports (Coming Soon)",
            font=settings.UI['FONT_TITLE']
        ).pack(expand=True)
    
    def _create_settings_content(self, parent):
        """Create the Settings content."""
        # This will be implemented in the Settings module
        ttk.Label(
            parent,
            text="Settings (Coming Soon)",
            font=settings.UI['FONT_TITLE']
        ).pack(expand=True)
    
    # ===== Action Methods =====
    
    def new_sale(self):
        """Open a new sale."""
        self.show_pos()
    
    def new_purchase(self):
        """Record a new purchase order."""
        messagebox.showinfo("New Purchase", "This feature is coming soon!")
    
    def import_data(self):
        """Import data from a file."""
        file_path = filedialog.askopenfilename(
            title="Select a file to import",
            filetypes=[
                ("CSV Files", "*.csv"),
                ("Excel Files", "*.xlsx"),
                ("All Files", "*.*")
            ]
        )
        
        if file_path:
            # TODO: Implement import logic
            messagebox.showinfo("Import", f"Importing data from {file_path}")
    
    def export_data(self):
        """Export data to a file."""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[
                ("CSV Files", "*.csv"),
                ("Excel Files", "*.xlsx")
            ],
            title="Save As"
        )
        
        if file_path:
            # TODO: Implement export logic
            messagebox.showinfo("Export", f"Exporting data to {file_path}")
    
    def print_document(self):
        """Print the current document or report."""
        messagebox.showinfo("Print", "Printing is not yet implemented.")
    
    def show_preferences(self):
        """Show the preferences/settings dialog."""
        messagebox.showinfo("Preferences", "Preferences are not yet implemented.")
    
    def refresh_view(self):
        """Refresh the current view."""
        current_tab = self.notebook.select()
        if current_tab:
            tab_id = self.notebook.index(current_tab)
            tab_name = self.notebook.tab(tab_id, 'text')
            
            if tab_name == "Dashboard":
                self.refresh_dashboard()
            # Add other tab refreshes here
    
    def backup_database(self):
        """Create a backup of the database."""
        try:
            # Get the default backup filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_filename = f"retail_db_backup_{timestamp}.db"
            
            # Ask for save location
            file_path = filedialog.asksaveasfilename(
                defaultextension=".db",
                initialfile=default_filename,
                filetypes=[("SQLite Database", "*.db")],
                title="Save Database Backup As"
            )
            
            if file_path:
                # Perform the backup
                import shutil
                shutil.copy2(settings.DATABASE['PATH'], file_path)
                messagebox.showinfo("Backup Successful", f"Database backed up to:\n{file_path}")
                
        except Exception as e:
            logger.error(f"Error backing up database: {e}", exc_info=True)
            messagebox.showerror("Backup Failed", f"Failed to create backup: {str(e)}")
    
    def restore_database(self):
        """Restore the database from a backup."""
        if messagebox.askyesno(
            "Confirm Restore",
            "WARNING: This will replace the current database with the backup.\n"
            "All data added since the backup will be lost.\n\n"
            "Are you sure you want to continue?"
        ):
            file_path = filedialog.askopenfilename(
                title="Select a backup file to restore",
                filetypes=[("SQLite Database", "*.db")]
            )
            
            if file_path:
                try:
                    # Close the current database connection
                    self.db.close()
                    
                    # Restore the backup
                    import shutil
                    shutil.copy2(file_path, settings.DATABASE['PATH'])
                    
                    # Reconnect to the database
                    self.db = get_db()
                    self.auth_manager = AuthManager(self.db)
                    
                    messagebox.showinfo("Restore Successful", "Database restored successfully!")
                    
                except Exception as e:
                    logger.error(f"Error restoring database: {e}", exc_info=True)
                    messagebox.showerror("Restore Failed", f"Failed to restore database: {str(e)}")
                    
                    # Try to reconnect to the original database
                    try:
                        self.db = get_db()
                        self.auth_manager = AuthManager(self.db)
                    except:
                        messagebox.showerror("Critical Error", "Failed to reconnect to database. Please restart the application.")
                        self.root.quit()
    
    def run_reports(self):
        """Run and display reports."""
        self.show_reports()
    
    def view_system_logs(self):
        """View system logs."""
        log_file = os.path.join(settings.PATHS['LOGS'], 'retail_system.log')
        
        if os.path.exists(log_file):
            try:
                import subprocess
                if os.name == 'nt':  # Windows
                    os.startfile(log_file)
                elif os.name == 'posix':  # macOS and Linux
                    subprocess.run(['xdg-open', log_file])
            except Exception as e:
                logger.error(f"Error opening log file: {e}")
                messagebox.showerror("Error", f"Could not open log file: {str(e)}")
        else:
            messagebox.showinfo("Logs", "No log file found.")
    
    def show_documentation(self):
        """Show the application documentation."""
        messagebox.showinfo("Documentation", "Documentation is not yet available.")
    
    def check_for_updates(self):
        """Check for application updates."""
        messagebox.showinfo("Check for Updates", "You are running the latest version.")
    
    def show_about(self):
        """Show the about dialog."""
        about_text = (
            f"{settings.APP_NAME}\n"
            f"Version {settings.VERSION}\n\n"
            "A comprehensive retail management solution.\n\n"
            " 2023 Almayas Retail. All rights reserved."
        )
        
        messagebox.showinfo("About", about_text)
    
    def show_user_profile(self):
        """Show the current user's profile."""
        user = self.db.fetch_one("SELECT * FROM users WHERE id = ?", (self.user_data['id'],))
        
        if user:
            profile_text = (
                f"Username: {user['username']}\n"
                f"Full Name: {user.get('full_name', 'N/A')}\n"
                f"Email: {user.get('email', 'N/A')}\n"
                f"Phone: {user.get('phone', 'N/A')}\n"
                f"Admin: {'Yes' if user.get('is_admin') else 'No'}"
            )
            
            messagebox.showinfo("My Profile", profile_text)
    
    def change_password(self):
        """Change the current user's password."""
        from ..auth.login_window import LoginWindow
        
        # Create a temporary login window for the password change dialog
        temp_root = tk.Tk()
        temp_root.withdraw()  # Hide the root window
        
        login_window = LoginWindow(temp_root, lambda x: None)
        login_window.current_user_id = self.user_data['id']
        login_window.show_password_change_dialog()
        
        # Clean up
        temp_root.destroy()
    
    def logout(self):
        """Log out the current user."""
        if messagebox.askyesno("Logout", "Are you sure you want to log out?"):
            logger.info(f"User {self.user_data['username']} logged out")
            self.root.quit()  # This will restart the application
    
    def refresh_dashboard(self):
        """Refresh the dashboard data."""
        # This would normally reload data from the database
        messagebox.showinfo("Refresh", "Dashboard data refreshed.")
    
    def run(self):
        """Run the main application loop."""
        self.root.deiconify()
    
    def on_closing(self):
        """Handle window close event."""
        if messagebox.askokcancel("Quit", "Are you sure you want to quit?"):
            logger.info("Application shutting down")
            self.root.quit()
