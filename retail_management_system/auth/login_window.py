"""
Login window for user authentication.
"""
import tkinter as tk
from tkinter import ttk, messagebox
import socket
import logging
from typing import Callable, Optional, Dict, Any, Tuple

from ..config.settings import UI
from ..database.connection import get_db
from .security import AuthManager

logger = logging.getLogger(__name__)

class LoginWindow:
    """Login window for user authentication."""
    
    def __init__(self, root: tk.Tk, on_login_success: Callable):
        """
        Initialize the login window.
        
        Args:
            root: The root tkinter window
            on_login_success: Callback function when login is successful
        """
        self.root = root
        self.on_login_success = on_login_success
        self.db = get_db()
        self.auth_manager = AuthManager(self.db)
        
        # Configure window
        self.root.title(f"{UI['APP_NAME']} - Login")
        self.root.geometry(UI['WINDOW_SIZE'])
        self.root.minsize(*map(int, UI['MIN_WINDOW_SIZE'].split('x')))
        
        # Center the window
        self._center_window()
        
        # Store the current user for password changes
        self.current_user_id = None
        self.ip_address = self._get_ip_address()
        
        # Setup UI
        self._setup_ui()
        
        # Bind Enter key to login
        self.root.bind('<Return>', lambda e: self.authenticate())
    
    def _center_window(self):
        """Center the window on the screen."""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def _get_ip_address(self) -> str:
        """Get the current IP address."""
        try:
            # Try to get the local IP address
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            logger.warning(f"Could not get IP address: {e}")
            return "127.0.0.1"  # Fallback to localhost
    
    def _setup_ui(self):
        """Set up the login window UI."""
        # Main frame
        main_frame = ttk.Frame(self.root, padding=UI['PADDING'] * 2)
        main_frame.pack(expand=True, fill='both')
        
        # Title
        title_label = ttk.Label(
            main_frame, 
            text=f"{UI['APP_NAME']}", 
            font=UI['FONT_TITLE'],
            foreground="#2c3e50"
        )
        title_label.pack(pady=(0, UI['PADDING'] * 2))
        
        # Subtitle
        subtitle_label = ttk.Label(
            main_frame,
            text="Please sign in to continue",
            font=UI['FONT'],
            foreground="#7f8c8d"
        )
        subtitle_label.pack(pady=(0, UI['PADDING'] * 2))
        
        # Login form frame
        form_frame = ttk.LabelFrame(main_frame, text="Login", padding=UI['PADDING'])
        form_frame.pack(pady=UI['PADDING'], padx=UI['PADDING'] * 4, fill='x')
        
        # Username
        ttk.Label(form_frame, text="Username:", font=UI['FONT']).grid(
            row=0, column=0, padx=UI['PADDING'], pady=UI['PADDING'], sticky='e')
        
        self.username_var = tk.StringVar()
        username_entry = ttk.Entry(
            form_frame, 
            textvariable=self.username_var, 
            font=UI['FONT'],
            width=30
        )
        username_entry.grid(
            row=0, column=1, 
            padx=UI['PADDING'], pady=UI['PADDING'], 
            sticky='we'
        )
        username_entry.focus()
        
        # Password
        ttk.Label(form_frame, text="Password:", font=UI['FONT']).grid(
            row=1, column=0, padx=UI['PADDING'], pady=UI['PADDING'], sticky='e')
        
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(
            form_frame, 
            textvariable=self.password_var, 
            show="*",
            font=UI['FONT'],
            width=30
        )
        password_entry.grid(
            row=1, column=1, 
            padx=UI['PADDING'], pady=UI['PADDING'], 
            sticky='we'
        )
        
        # Buttons frame
        btn_frame = ttk.Frame(form_frame)
        btn_frame.grid(
            row=2, column=0, columnspan=2, 
            pady=(UI['PADDING'] * 2, UI['PADDING']), 
            sticky='e'
        )
        
        # Login button
        login_btn = ttk.Button(
            btn_frame, 
            text="Sign In", 
            command=self.authenticate,
            style='Accent.TButton'
        )
        login_btn.pack(side=tk.RIGHT, padx=(UI['PADDING'], 0))
        
        # Change password button
        change_pw_btn = ttk.Button(
            btn_frame, 
            text="Change Password", 
            command=self.show_password_change_dialog
        )
        change_pw_btn.pack(side=tk.RIGHT)
        
        # Version info
        version_label = ttk.Label(
            main_frame, 
            text=f"Version {UI['VERSION']}",
            font=('TkDefaultFont', 8),
            foreground="#95a5a6"
        )
        version_label.pack(side=tk.BOTTOM, pady=(UI['PADDING'] * 2, 0))
        
        # Configure grid weights
        form_frame.columnconfigure(1, weight=1)
        
        # Apply styles
        self._apply_styles()
    
    def _apply_styles(self):
        """Apply custom styles to the UI elements."""
        style = ttk.Style()
        
        # Configure the main window background
        self.root.configure(background='#f5f6fa')
        
        # Configure label styles
        style.configure('TLabel', font=UI['FONT'], background='#f5f6fa')
        style.configure('TButton', font=UI['FONT'], padding=UI['BTN_PADDING'])
        
        # Configure entry styles
        style.configure('TEntry', font=UI['FONT'], padding=UI['PADDING']//2)
        
        # Configure label frame style
        style.configure('TLabelframe', background='#f5f6fa')
        style.configure('TLabelframe.Label', font=UI['FONT_BOLD'])
        
        # Configure accent button (for primary actions)
        style.configure('Accent.TButton', font=UI['FONT_BOLD'])
        
        # Configure the main frame
        style.configure('TFrame', background='#f5f6fa')
    
    def authenticate(self):
        """Authenticate the user."""
        username = self.username_var.get().strip()
        password = self.password_var.get()
        
        if not username or not password:
            messagebox.showwarning("Input Error", "Please enter both username and password")
            return
        
        try:
            # Authenticate user
            success, user_data, message = self.auth_manager.authenticate_user(
                username, password, self.ip_address
            )
            
            if success:
                if message == "login_success_but_expired":
                    # Password is expired, force change
                    self.current_user_id = user_data['id']
                    self.show_password_change_dialog(force_change=True)
                else:
                    # Successful login
                    self._handle_successful_login(user_data)
            else:
                # Authentication failed
                messagebox.showerror("Login Failed", message)
                self.password_var.set("")
                
        except Exception as e:
            logger.error(f"Authentication error: {e}", exc_info=True)
            messagebox.showerror(
                "Error", 
                "An error occurred during authentication. Please try again."
            )
    
    def _handle_successful_login(self, user_data: Dict[str, Any]):
        """Handle successful login."""
        logger.info(f"User {user_data['username']} logged in successfully")
        self.root.after(100, lambda: self.on_login_success(user_data))
    
    def show_password_change_dialog(self, force_change: bool = False):
        """Show the password change dialog."""
        if not force_change and not self.current_user_id:
            messagebox.showwarning(
                "Not Logged In", 
                "Please log in first to change your password."
            )
            return
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Change Password")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Position the dialog relative to the parent window
        self._center_dialog(dialog, 400, 300)
        
        # Force change message
        if force_change:
            ttk.Label(
                dialog,
                text="You must change your password to continue.",
                font=UI['FONT_BOLD'],
                foreground="#e74c3c",
                wraplength=350
            ).pack(pady=(UI['PADDING'], UI['PADDING']*2), padx=UI['PADDING'])
        
        # Current password (only for non-forced changes)
        current_pw_frame = ttk.Frame(dialog)
        current_pw_frame.pack(fill='x', padx=UI['PADDING'], pady=(0, UI['PADDING']))
        
        if not force_change:
            ttk.Label(
                current_pw_frame, 
                text="Current Password:", 
                font=UI['FONT']
            ).pack(side='left', padx=(0, UI['PADDING']))
            
            current_pw_var = tk.StringVar()
            ttk.Entry(
                current_pw_frame, 
                textvariable=current_pw_var, 
                show="*",
                font=UI['FONT'],
                width=25
            ).pack(side='right', fill='x', expand=True)
        
        # New password
        ttk.Label(
            dialog, 
            text="New Password:", 
            font=UI['FONT'],
            anchor='w'
        ).pack(fill='x', padx=UI['PADDING'], pady=(UI['PADDING'], 0))
        
        new_pw_var = tk.StringVar()
        new_pw_entry = ttk.Entry(
            dialog, 
            textvariable=new_pw_var, 
            show="*",
            font=UI['FONT']
        )
        new_pw_entry.pack(fill='x', padx=UI['PADDING'], pady=(0, UI['PADDING']))
        
        # Confirm new password
        ttk.Label(
            dialog, 
            text="Confirm New Password:", 
            font=UI['FONT'],
            anchor='w'
        ).pack(fill='x', padx=UI['PADDING'], pady=(UI['PADDING'], 0))
        
        confirm_pw_var = tk.StringVar()
        confirm_pw_entry = ttk.Entry(
            dialog, 
            textvariable=confirm_pw_var, 
            show="*",
            font=UI['FONT']
        )
        confirm_pw_entry.pack(fill='x', padx=UI['PADDING'], pady=(0, UI['PADDING']))
        
        # Password requirements
        requirements = [
            "• At least 8 characters",
            "• At least one uppercase letter",
            "• At least one lowercase letter",
            "• At least one number",
            "• At least one special character"
        ]
        
        for req in requirements:
            ttk.Label(
                dialog, 
                text=req, 
                font=('TkDefaultFont', 8),
                foreground="#7f8c8d"
            ).pack(anchor='w', padx=UI['PADDING']*1.5, pady=(0, 2))
        
        # Error message
        error_var = tk.StringVar()
        error_label = ttk.Label(
            dialog, 
            textvariable=error_var,
            foreground="#e74c3c",
            wraplength=350
        )
        error_label.pack(pady=UI['PADDING'], padx=UI['PADDING'])
        
        # Buttons frame
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill='x', padx=UI['PADDING'], pady=UI['PADDING'])
        
        # Change button
        change_btn = ttk.Button(
            btn_frame,
            text="Change Password",
            style='Accent.TButton',
            command=lambda: self._change_password(
                force_change,
                current_pw_var.get() if not force_change else None,
                new_pw_var.get(),
                confirm_pw_var.get(),
                error_var,
                dialog
            )
        )
        change_btn.pack(side='right', padx=(UI['PADDING'], 0))
        
        # Cancel button (only if not forced)
        if not force_change:
            ttk.Button(
                btn_frame,
                text="Cancel",
                command=dialog.destroy
            ).pack(side='right')
        
        # Bind Enter key to change password
        def on_enter(e):
            change_btn.invoke()
        
        new_pw_entry.bind('<Return>', on_enter)
        confirm_pw_entry.bind('<Return>', on_enter)
        
        # Make dialog modal
        if force_change:
            dialog.protocol("WM_DELETE_WINDOW", lambda: None)  # Disable closing
        
        # Focus the new password field
        new_pw_entry.focus()
    
    def _change_password(self, force_change: bool, current_password: str, 
                        new_password: str, confirm_password: str, 
                        error_var: tk.StringVar, dialog: tk.Toplevel):
        """Handle password change."""
        # Validate inputs
        if not force_change and not current_password:
            error_var.set("Please enter your current password")
            return
        
        if not new_password or not confirm_password:
            error_var.set("Please fill in all fields")
            return
        
        if new_password != confirm_password:
            error_var.set("New passwords do not match")
            return
        
        # If this is a forced change, use the current user ID
        user_id = self.current_user_id
        
        # If not forced, we need to verify the current password
        if not force_change:
            user = self.db.fetch_one("SELECT id, password FROM users WHERE id = ?", (user_id,))
            if not user or not verify_password(user['password'], current_password):
                error_var.set("Current password is incorrect")
                return
        
        # Check password strength
        from .security import is_password_strong
        is_strong, message = is_password_strong(new_password)
        if not is_strong:
            error_var.set(f"Weak password: {message}")
            return
        
        # Check if new password is different from current
        if not force_change:
            if verify_password(user['password'], new_password):
                error_var.set("New password must be different from current password")
                return
        
        # Change the password
        success, message = self.auth_manager.change_password(
            user_id, 
            current_password if not force_change else None, 
            new_password
        )
        
        if success:
            messagebox.showinfo("Success", message)
            dialog.destroy()
            
            # If this was a forced change, log the user in
            if force_change:
                self._handle_successful_login(
                    self.db.fetch_one("SELECT * FROM users WHERE id = ?", (user_id,))
                )
        else:
            error_var.set(message)
    
    def _center_dialog(self, dialog: tk.Toplevel, width: int, height: int):
        """Center a dialog window relative to its parent."""
        dialog.geometry(f"{width}x{height}")
        dialog.update_idletasks()
        
        parent_x = self.root.winfo_x()
        parent_y = self.root.winfo_y()
        parent_width = self.root.winfo_width()
        parent_height = self.root.winfo_height()
        
        x = parent_x + (parent_width // 2) - (width // 2)
        y = parent_y + (parent_height // 2) - (height // 2)
        
        dialog.geometry(f"+{x}+{y}")
