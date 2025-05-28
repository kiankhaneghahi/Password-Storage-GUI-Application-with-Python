import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import json
import os
import base64
import secrets
import string
import platform

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# --- Configuration ---
# Get the directory where the script is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
VAULT_FILE = os.path.join(SCRIPT_DIR, "pm_vault.enc") # Ensure vault file is in the script's directory

SALT_SIZE = 16  # Bytes for salt
AES_KEY_SIZE = 32  # Bytes for AES-256 key
PBKDF2_ITERATIONS = 600000  # Number of iterations for PBKDF2, adjust based on performance needs
AUTO_LOCK_TIMEOUT_MS = 15 * 60 * 1000  # 15 minutes in milliseconds
CLIPBOARD_CLEAR_TIMEOUT_MS = 30 * 1000 # 30 seconds in milliseconds

# --- Cryptographic Utilities ---
class CryptoUtils:
    """Handles cryptographic operations like key derivation, encryption, and decryption."""
    @staticmethod
    def generate_salt(size=SALT_SIZE):
        """Generates a cryptographically secure random salt."""
        return os.urandom(size)

    @staticmethod
    def derive_key(password: str, salt: bytes, iterations=PBKDF2_ITERATIONS):
        """Derives an encryption key from a password and salt using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))

    @staticmethod
    def encrypt_data(key: bytes, plaintext_data: bytes):
        """Encrypts plaintext data using AES-GCM."""
        nonce = os.urandom(12)  # AES-GCM standard nonce size (96 bits)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext_data, None) # No associated data
        return nonce, ciphertext

    @staticmethod
    def decrypt_data(key: bytes, nonce: bytes, ciphertext: bytes):
        """Decrypts ciphertext using AES-GCM. Raises InvalidTag on failure."""
        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(nonce, ciphertext, None) # No associated data
        except InvalidTag:
            # This exception is crucial as it indicates authentication failure (wrong key or tampered data)
            raise ValueError("Decryption failed: Invalid master password or corrupted data.")

# --- Main Application Class ---
class PasswordManagerApp:
    """Main application class for the Password Manager GUI."""
    def __init__(self, root_window):
        self.root = root_window
        self.root.title("Secure Password Vault")
        # Set a minimum size for the window
        self.root.minsize(700, 500)
        self.root.geometry("800x600") # Default size
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing) # Handle window close button

        # Apply a modern theme using ttk
        self.style = ttk.Style()
        available_themes = self.style.theme_names()
        # Try to set a more modern theme if available, falling back to defaults
        preferred_themes = ['clam', 'alt', 'default'] # Common cross-platform themes
        if platform.system() == "Windows":
            preferred_themes.insert(0, 'vista') # 'vista' often looks good on Windows
        elif platform.system() == "Darwin": # macOS
             preferred_themes.insert(0, 'aqua') # 'aqua' is the native macOS theme

        for theme in preferred_themes:
             if theme in available_themes:
                try:
                    self.style.theme_use(theme)
                    break
                except tk.TclError:
                    # Some themes might not be fully available or compatible
                    continue

        self._configure_styles() # Apply custom styles to widgets

        self.master_key = None # Stores the derived master encryption key when vault is unlocked
        self.credentials_data = [] # In-memory list of {"description": "", "id": "", "password": ""}
        self.current_frame = None # Holds the currently displayed page (frame)
        self.auto_lock_timer_id = None # ID for the auto-lock timer

        self._initialize_activity_tracking() # Setup for auto-lock

        # Check if vault file exists to determine initial page (Login or Setup)
        if os.path.exists(VAULT_FILE):
            self._show_login_page()
        else:
            self._show_setup_page()

    def _configure_styles(self):
        """Configures custom styles for various ttk widgets."""
        self.style.configure("TFrame", background="#e9ebee")
        self.style.configure("TLabel", background="#e9ebee", font=("Segoe UI", 10))
        self.style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"), background="#e9ebee")
        self.style.configure("Error.TLabel", foreground="red", background="#e9ebee", font=("Segoe UI", 9))
        self.style.configure("TButton", font=("Segoe UI", 10), padding=6)
        self.style.configure("Treeview", rowheight=28, font=("Segoe UI", 10))
        self.style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))

        self.style.map("TEntry",
                       fieldbackground=[('!disabled', 'white')],
                       foreground=[('!disabled', 'black')],
                       bordercolor=[('focus', '#0078d4'), ('!focus', 'grey')])

        # Style for Accent Button (used for primary actions like Login, Create Vault)
        # This simplified styling aims for better cross-theme compatibility, especially for macOS 'aqua'
        self.style.configure("Accent.TButton",
                             font=("Segoe UI", 10, "bold"),
                             padding=6)

        # For themes that respect background/foreground (like 'clam', 'alt', 'vista', 'default' on Windows/Linux)
        # For 'aqua' on macOS, background might be ignored, so foreground visibility is key.
        # Using a dark foreground if the background is likely light (default aqua button).
        # Using white foreground if we can set a dark background.
        if self.style.theme_use() == 'aqua':
            self.style.map("Accent.TButton",
                           foreground=[('!disabled', 'black'), ('disabled', '#999999'), ('active', 'black')],
                           background=[('active', '#c5c5c5'), ('disabled', '#f0f0f0')] # Subtle changes for active/disabled
                          )
        else: # For other themes, try to set a blue background with white text
            self.style.map("Accent.TButton",
                foreground=[
                    ('disabled', '#A0A0A0'),
                    ('active', 'white'),
                    ('!disabled', 'white')
                ],
                background=[
                    ('disabled', '#D0D0D0'),
                    ('active', '#005a9e'),
                    ('!disabled', '#0078d4')
                ]
            )


    def _initialize_activity_tracking(self):
        """Binds events to reset the auto-lock timer upon user activity."""
        self.root.bind_all("<KeyPress>", self._reset_auto_lock_timer, add='+')
        self.root.bind_all("<Button-1>", self._reset_auto_lock_timer, add='+')
        self.root.bind_all("<Motion>", self._reset_auto_lock_timer, add='+')

    def _reset_auto_lock_timer(self, event=None):
        """Resets the auto-lock timer. Called on user activity."""
        if self.master_key:
            if self.auto_lock_timer_id:
                self.root.after_cancel(self.auto_lock_timer_id)
            self.auto_lock_timer_id = self.root.after(AUTO_LOCK_TIMEOUT_MS, self._lock_vault)

    def _switch_frame(self, frame_class, *args):
        """Destroys the current frame and displays a new one."""
        if self.current_frame:
            self.current_frame.destroy()
        self.current_frame = frame_class(self.root, self, *args)
        self.current_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)

        if self.master_key:
            self._reset_auto_lock_timer()

    def _show_setup_page(self):
        self._switch_frame(SetupPage)

    def _show_login_page(self):
        self._switch_frame(LoginPage)

    def _show_main_page(self):
        self._switch_frame(MainPage)

    def _lock_vault(self):
        if self.master_key: # Only lock if it was unlocked
            self.master_key = None
            self.credentials_data = [] # Clear sensitive data from memory
            # Clear any stored salt/iterations associated with the session
            if hasattr(self, 'current_salt'): del self.current_salt
            if hasattr(self, 'current_iterations'): del self.current_iterations

            if self.auto_lock_timer_id:
                self.root.after_cancel(self.auto_lock_timer_id)
                self.auto_lock_timer_id = None

            # --- MODIFIED ORDER ---
            self._show_login_page() # Call this first to switch the view
            messagebox.showinfo("Vault Locked", "The vault has been automatically locked due to inactivity or manual lock.", parent=self.root) # Then show the message
            # --- END MODIFIED ORDER ---

    def _save_vault(self):
        if not self.master_key:
            messagebox.showerror("Error", "Cannot save vault. Not logged in or master key not set.")
            return False
        if not hasattr(self, 'current_salt') or not hasattr(self, 'current_iterations'):
            messagebox.showerror("Save Error", "Vault integrity issue: session salt/iterations missing.")
            return False

        try:
            plaintext_data = json.dumps(self.credentials_data).encode('utf-8')
            nonce, ciphertext = CryptoUtils.encrypt_data(self.master_key, plaintext_data)

            vault_content = {
                "salt": base64.b64encode(self.current_salt).decode('utf-8'),
                "iterations": self.current_iterations,
                "nonce": base64.b64encode(nonce).decode('utf-8'),
                "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
            }
            temp_file_path = VAULT_FILE + ".tmp"
            with open(temp_file_path, 'w') as f:
                json.dump(vault_content, f, indent=4)
            os.replace(temp_file_path, VAULT_FILE)
            return True
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save vault: {e}")
            if os.path.exists(temp_file_path):
                try:
                    os.remove(temp_file_path)
                except OSError:
                    pass
            return False

    def _on_closing(self):
        if self.master_key:
            self.master_key = None
            self.credentials_data = []
        self.root.destroy()

    def copy_to_clipboard(self, text_to_copy: str, field_name: str ="Value"):
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text_to_copy)
            self.root.update()
            messagebox.showinfo("Copied", f"{field_name} copied to clipboard.\nIt will be cleared in {CLIPBOARD_CLEAR_TIMEOUT_MS // 1000} seconds.", parent=self.current_frame)

            self.root.after(CLIPBOARD_CLEAR_TIMEOUT_MS, self._clear_tk_clipboard)
        except tk.TclError:
            messagebox.showwarning("Clipboard Error", "Could not access clipboard. Is a clipboard manager interfering?", parent=self.current_frame)

    def _clear_tk_clipboard(self):
        try:
            self.root.clipboard_clear()
        except tk.TclError:
            pass

# --- GUI Pages/Frames ---
class BasePage(ttk.Frame):
    def __init__(self, parent_tk_widget, app_controller):
        super().__init__(parent_tk_widget)
        self.app = app_controller
        self.parent_tk_widget = parent_tk_widget

class SetupPage(BasePage):
    def __init__(self, parent_tk_widget, app_controller):
        super().__init__(parent_tk_widget, app_controller)
        self.configure(padding=(20, 20))

        ttk.Label(self, text="Setup Master Password", style="Header.TLabel").pack(pady=(0, 20))
        ttk.Label(self, text="Create a strong master password. This password will encrypt all your stored data.\nRemember it well, as it cannot be recovered if lost.").pack(pady=5)

        self.pass_var = tk.StringVar()
        self.confirm_pass_var = tk.StringVar()

        form_frame = ttk.Frame(self)
        form_frame.pack(pady=10, padx=30, fill=tk.X)

        ttk.Label(form_frame, text="Master Password:").grid(row=0, column=0, sticky=tk.W, pady=5)
        pass_entry = ttk.Entry(form_frame, textvariable=self.pass_var, show="*", width=40)
        pass_entry.grid(row=0, column=1, sticky=tk.EW, pady=5, padx=5)

        ttk.Label(form_frame, text="Confirm Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        confirm_pass_entry = ttk.Entry(form_frame, textvariable=self.confirm_pass_var, show="*", width=40)
        confirm_pass_entry.grid(row=1, column=1, sticky=tk.EW, pady=5, padx=5)

        form_frame.columnconfigure(1, weight=1)

        strength_button = ttk.Button(self, text="Password Generator", command=self._open_password_generator, width=20)
        strength_button.pack(pady=10)

        setup_button = ttk.Button(self, text="Create Vault", command=self._create_vault, style="Accent.TButton")
        setup_button.pack(pady=20)

        pass_entry.focus()
        pass_entry.bind("<Return>", lambda event: self._create_vault())
        confirm_pass_entry.bind("<Return>", lambda event: self._create_vault())


    def _open_password_generator(self):
        PasswordGeneratorDialog(self.parent_tk_widget, self.app, self.pass_var, modal=True)

    def _create_vault(self):
        password = self.pass_var.get()
        confirm_password = self.confirm_pass_var.get()

        if not password or not confirm_password:
            messagebox.showerror("Error", "Password fields cannot be empty.", parent=self)
            return
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.", parent=self)
            return
        if len(password) < 12:
             if not messagebox.askyesno("Weak Password", "Password is less than 12 characters. This is not recommended for a master password.\nDo you want to proceed anyway?", parent=self, icon='warning'):
                 return

        try:
            self.app.current_salt = CryptoUtils.generate_salt()
            self.app.current_iterations = PBKDF2_ITERATIONS
            self.app.master_key = CryptoUtils.derive_key(password, self.app.current_salt, self.app.current_iterations)
            self.app.credentials_data = []

            if self.app._save_vault():
                messagebox.showinfo("Success", "Vault created successfully! Please log in.", parent=self)
                self.app._show_login_page()
            else:
                self.app.master_key = None
                if hasattr(self.app, 'current_salt'): del self.app.current_salt
                if hasattr(self.app, 'current_iterations'): del self.app.current_iterations
        except Exception as e:
            messagebox.showerror("Setup Error", f"Failed to create vault: {e}", parent=self)
            self.app.master_key = None


class LoginPage(BasePage):
    def __init__(self, parent_tk_widget, app_controller):
        super().__init__(parent_tk_widget, app_controller)
        self.configure(padding=(20, 20))

        ttk.Label(self, text="Unlock Vault", style="Header.TLabel").pack(pady=(0,20))

        self.pass_var = tk.StringVar()

        form_frame = ttk.Frame(self)
        form_frame.pack(pady=10, padx=30, fill=tk.X)

        ttk.Label(form_frame, text="Master Password:").grid(row=0, column=0, sticky=tk.W, pady=5)
        pass_entry = ttk.Entry(form_frame, textvariable=self.pass_var, show="*", width=40)
        pass_entry.grid(row=0, column=1, sticky=tk.EW, pady=5, padx=5)
        form_frame.columnconfigure(1, weight=1)

        pass_entry.focus()
        pass_entry.bind("<Return>", lambda event: self._login())

        login_button = ttk.Button(self, text="Login", command=self._login, style="Accent.TButton")
        login_button.pack(pady=20)

        self.status_label = ttk.Label(self, text="", style="Error.TLabel")
        self.status_label.pack(pady=5)

    def _login(self):
        # Check if widget still exists before configuring
        if self.winfo_exists():
            self.status_label.config(text="")

        password = self.pass_var.get()
        if not password:
            if self.winfo_exists():
                self.status_label.config(text="Password cannot be empty.")
            else:
                messagebox.showerror("Login Error", "Password cannot be empty.", parent=self.app.root)
            return

        try:
            with open(VAULT_FILE, 'r') as f:
                vault_content = json.load(f)

            salt = base64.b64decode(vault_content['salt'])
            iterations = vault_content.get('iterations', PBKDF2_ITERATIONS)
            nonce = base64.b64decode(vault_content['nonce'])
            ciphertext = base64.b64decode(vault_content['ciphertext'])

            self.app.current_salt = salt
            self.app.current_iterations = iterations

            key = CryptoUtils.derive_key(password, salt, iterations)
            decrypted_data_bytes = CryptoUtils.decrypt_data(key, nonce, ciphertext)

            self.app.master_key = key
            self.app.credentials_data = json.loads(decrypted_data_bytes.decode('utf-8'))

            self.app._show_main_page()

        except FileNotFoundError:
            if self.winfo_exists():
                self.status_label.config(text="Vault file not found. Please set up a new vault.")
            else:
                messagebox.showerror("Login Error", "Vault file not found. Please set up a new vault.", parent=self.app.root)
        except (ValueError, json.JSONDecodeError) as e:
            if self.winfo_exists():
                self.status_label.config(text=f"Login failed: {e}")
            else:
                messagebox.showerror("Login Error", f"Login failed: {e}", parent=self.app.root)
            self.app.master_key = None
            if hasattr(self.app, 'current_salt'): del self.app.current_salt
            if hasattr(self.app, 'current_iterations'): del self.app.current_iterations
        except Exception as e:
            if self.winfo_exists():
                self.status_label.config(text=f"An unexpected error occurred: {e}")
            else:
                messagebox.showerror("Unexpected Error", f"An unexpected error occurred during login: {e}", parent=self.app.root)
            self.app.master_key = None
            if hasattr(self.app, 'current_salt'): del self.app.current_salt
            if hasattr(self.app, 'current_iterations'): del self.app.current_iterations


class MainPage(BasePage):
    def __init__(self, parent_tk_widget, app_controller):
        super().__init__(parent_tk_widget, app_controller)
        self.selected_item_original_index = None

        top_frame = ttk.Frame(self, padding=(0, 10))
        top_frame.pack(fill=tk.X)

        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *args: self._filter_credentials())
        ttk.Label(top_frame, text="Search:").pack(side=tk.LEFT, padx=(0, 5))
        search_entry = ttk.Entry(top_frame, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        tree_container = ttk.Frame(self)
        tree_container.pack(expand=True, fill=tk.BOTH, pady=(0,10))

        columns = ("description", "id")
        self.tree = ttk.Treeview(tree_container, columns=columns, show="headings", selectmode="browse")
        self.tree.heading("description", text="Description")
        self.tree.heading("id", text="ID/Username")
        self.tree.column("description", width=250, stretch=tk.YES, minwidth=150)
        self.tree.column("id", width=250, stretch=tk.YES, minwidth=150)

        scrollbar = ttk.Scrollbar(tree_container, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

        self.tree.bind("<<TreeviewSelect>>", self._on_item_select)
        self.tree.bind("<Double-1>", self._edit_entry)

        # Define buttons BEFORE calling _populate_treeview (which calls _update_button_states)
        buttons_frame = ttk.Frame(self, padding=(0,5))
        buttons_frame.pack(fill=tk.X)

        self.add_button = ttk.Button(buttons_frame, text="Add New", command=self._add_entry)
        self.add_button.pack(side=tk.LEFT, padx=3)

        self.view_edit_button = ttk.Button(buttons_frame, text="View/Edit", command=self._edit_entry, state=tk.DISABLED)
        self.view_edit_button.pack(side=tk.LEFT, padx=3)

        self.delete_button = ttk.Button(buttons_frame, text="Delete", command=self._delete_entry, state=tk.DISABLED)
        self.delete_button.pack(side=tk.LEFT, padx=3)

        self.copy_id_button = ttk.Button(buttons_frame, text="Copy ID", command=self._copy_id, state=tk.DISABLED)
        self.copy_id_button.pack(side=tk.LEFT, padx=3)

        self.copy_pass_button = ttk.Button(buttons_frame, text="Copy Password", command=self._copy_password, state=tk.DISABLED)
        self.copy_pass_button.pack(side=tk.LEFT, padx=3)

        lock_button = ttk.Button(buttons_frame, text="Lock Vault", command=self.app._lock_vault)
        lock_button.pack(side=tk.RIGHT, padx=3)

        change_pass_button = ttk.Button(buttons_frame, text="Change Master Password", command=self._change_master_password)
        change_pass_button.pack(side=tk.RIGHT, padx=3)

        self._populate_treeview()


    def _populate_treeview(self, filter_term=None):
        for item in self.tree.get_children():
            self.tree.delete(item)

        for original_idx, cred_entry in enumerate(self.app.credentials_data):
            desc = cred_entry.get("description", "")
            user_id = cred_entry.get("id", "")
            if filter_term:
                filter_term_lower = filter_term.lower()
                if filter_term_lower not in desc.lower() and filter_term_lower not in user_id.lower():
                    continue
            self.tree.insert("", tk.END, iid=str(original_idx), values=(desc, user_id))

        self.selected_item_original_index = None
        self._update_button_states()

    def _filter_credentials(self):
        filter_term = self.search_var.get()
        self._populate_treeview(filter_term)

    def _on_item_select(self, event=None):
        selected_items = self.tree.selection()
        if selected_items:
            self.selected_item_original_index = int(selected_items[0])
        else:
            self.selected_item_original_index = None
        self._update_button_states()

    def _update_button_states(self):
        state = tk.NORMAL if self.selected_item_original_index is not None else tk.DISABLED
        # Ensure buttons exist before trying to configure them (should be fine with reordering)
        if hasattr(self, 'view_edit_button'): self.view_edit_button.config(state=state)
        if hasattr(self, 'delete_button'): self.delete_button.config(state=state)
        if hasattr(self, 'copy_id_button'): self.copy_id_button.config(state=state)
        if hasattr(self, 'copy_pass_button'): self.copy_pass_button.config(state=state)


    def _add_entry(self):
        AddEditDialog(self.parent_tk_widget, self.app, "Add New Credential", callback=self._populate_treeview)

    def _edit_entry(self, event=None):
        if self.selected_item_original_index is not None:
            if 0 <= self.selected_item_original_index < len(self.app.credentials_data):
                entry_data = self.app.credentials_data[self.selected_item_original_index]
                AddEditDialog(self.parent_tk_widget, self.app, "Edit Credential",
                              entry_data=entry_data, entry_original_index=self.selected_item_original_index,
                              callback=self._populate_treeview)
            else:
                messagebox.showerror("Error", "Selected entry not found or index out of bounds. Please refresh.", parent=self)
                self.selected_item_original_index = None
                self._populate_treeview()

    def _delete_entry(self):
        if self.selected_item_original_index is not None:
            if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this entry?", parent=self, icon='warning'):
                original_index = self.selected_item_original_index
                if 0 <= original_index < len(self.app.credentials_data):
                    del self.app.credentials_data[original_index]
                    if self.app._save_vault():
                        self._populate_treeview()
                        messagebox.showinfo("Success", "Entry deleted.", parent=self)
                    else:
                        messagebox.showerror("Error", "Failed to save changes after deletion. Entry might still be deleted in memory but not in vault.", parent=self)
                else:
                    messagebox.showerror("Error", "Selected entry not found for deletion (index error).", parent=self)
                    self.selected_item_original_index = None
                    self._populate_treeview()

    def _get_selected_credential(self):
        if self.selected_item_original_index is not None:
            if 0 <= self.selected_item_original_index < len(self.app.credentials_data):
                return self.app.credentials_data[self.selected_item_original_index]
        return None

    def _copy_id(self):
        cred = self._get_selected_credential()
        if cred:
            self.app.copy_to_clipboard(cred.get("id", ""), "ID/Username")

    def _copy_password(self):
        cred = self._get_selected_credential()
        if cred:
            self.app.copy_to_clipboard(cred.get("password", ""), "Password")

    def _change_master_password(self):
        ChangeMasterPasswordDialog(self.parent_tk_widget, self.app)


class AddEditDialog(simpledialog.Dialog):
    def __init__(self, parent, app_controller, title, entry_data=None, entry_original_index=None, callback=None):
        self.app = app_controller
        self.entry_data = entry_data if entry_data is not None else {}
        self.entry_original_index = entry_original_index
        self.callback = callback
        super().__init__(parent, title)

    def body(self, master_frame):
        ttk.Label(master_frame, text="Description:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.desc_var = tk.StringVar(value=self.entry_data.get("description", ""))
        desc_entry = ttk.Entry(master_frame, textvariable=self.desc_var, width=40)
        desc_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        desc_entry.focus()

        ttk.Label(master_frame, text="ID/Username:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.id_var = tk.StringVar(value=self.entry_data.get("id", ""))
        ttk.Entry(master_frame, textvariable=self.id_var, width=40).grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)

        ttk.Label(master_frame, text="Password:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.pass_var = tk.StringVar(value=self.entry_data.get("password", ""))
        self.pass_entry = ttk.Entry(master_frame, textvariable=self.pass_var, show="*", width=40)
        self.pass_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.EW)

        pass_options_frame = ttk.Frame(master_frame)
        pass_options_frame.grid(row=3, column=1, sticky=tk.EW, pady=(2,5))

        self.show_pass_var = tk.BooleanVar(value=False)
        show_pass_check = ttk.Checkbutton(pass_options_frame, text="Show", variable=self.show_pass_var, command=self._toggle_password_visibility)
        show_pass_check.pack(side=tk.LEFT, padx=(0,10))

        generate_button = ttk.Button(pass_options_frame, text="Generate", command=self._generate_password, width=10)
        generate_button.pack(side=tk.LEFT)

        master_frame.columnconfigure(1, weight=1)
        return desc_entry

    def _toggle_password_visibility(self):
        self.pass_entry.config(show="" if self.show_pass_var.get() else "*")

    def _generate_password(self):
        PasswordGeneratorDialog(self, self.app, self.pass_var, modal=True)

    def apply(self):
        new_desc = self.desc_var.get().strip()
        new_id = self.id_var.get().strip()
        new_pass = self.pass_var.get()

        if not new_desc or not new_id or not new_pass:
            messagebox.showerror("Input Error", "All fields (Description, ID/Username, Password) are required.", parent=self)
            self.result = None
            return

        new_entry = {"description": new_desc, "id": new_id, "password": new_pass}

        if self.entry_original_index is not None:
            if 0 <= self.entry_original_index < len(self.app.credentials_data):
                self.app.credentials_data[self.entry_original_index] = new_entry
            else:
                messagebox.showerror("Error", "Original entry not found for update. Please refresh.", parent=self)
                self.result = None; return
        else:
            self.app.credentials_data.append(new_entry)

        if self.app._save_vault():
            if self.callback:
                self.callback()
            self.result = True
        else:
            messagebox.showerror("Save Error", "Failed to save entry to vault. Changes might not be persisted.", parent=self)
            self.result = None


class ChangeMasterPasswordDialog(simpledialog.Dialog):
    def __init__(self, parent, app_controller):
        self.app = app_controller
        super().__init__(parent, "Change Master Password")

    def body(self, master_frame):
        ttk.Label(master_frame, text="Current Master Password:").grid(row=0, column=0, sticky=tk.W, pady=5, padx=5)
        self.old_pass_var = tk.StringVar()
        old_pass_entry = ttk.Entry(master_frame, textvariable=self.old_pass_var, show="*", width=35)
        old_pass_entry.grid(row=0, column=1, pady=5, padx=5, sticky=tk.EW)
        old_pass_entry.focus()

        ttk.Label(master_frame, text="New Master Password:").grid(row=1, column=0, sticky=tk.W, pady=5, padx=5)
        self.new_pass_var = tk.StringVar()
        ttk.Entry(master_frame, textvariable=self.new_pass_var, show="*", width=35).grid(row=1, column=1, pady=5, padx=5, sticky=tk.EW)

        ttk.Label(master_frame, text="Confirm New Password:").grid(row=2, column=0, sticky=tk.W, pady=5, padx=5)
        self.confirm_pass_var = tk.StringVar()
        ttk.Entry(master_frame, textvariable=self.confirm_pass_var, show="*", width=35).grid(row=2, column=1, pady=5, padx=5, sticky=tk.EW)

        strength_button = ttk.Button(master_frame, text="Password Generator", command=self._open_password_generator)
        strength_button.grid(row=3, column=1, sticky=tk.E, pady=(10,5), padx=5)

        master_frame.columnconfigure(1, weight=1)
        return old_pass_entry

    def _open_password_generator(self):
        PasswordGeneratorDialog(self, self.app, self.new_pass_var, modal=True)

    def apply(self):
        old_password = self.old_pass_var.get()
        new_password = self.new_pass_var.get()
        confirm_password = self.confirm_pass_var.get()

        if not old_password or not new_password or not confirm_password:
            messagebox.showerror("Error", "All password fields are required.", parent=self)
            self.result = None; return

        if new_password != confirm_password:
            messagebox.showerror("Error", "New passwords do not match.", parent=self)
            self.result = None; return

        if len(new_password) < 12:
             if not messagebox.askyesno("Weak Password", "New password is less than 12 characters. This is not recommended.\nProceed anyway?", parent=self, icon='warning'):
                 self.result = None; return

        try:
            if not hasattr(self.app, 'current_salt') or not hasattr(self.app, 'current_iterations'):
                 messagebox.showerror("Error", "Session error: Cannot verify old password. Please relogin.", parent=self)
                 self.result = None; return

            temp_key_check = CryptoUtils.derive_key(old_password, self.app.current_salt, self.app.current_iterations)
            if temp_key_check != self.app.master_key:
                messagebox.showerror("Error", "Incorrect current master password.", parent=self)
                self.result = None; return

            new_salt = CryptoUtils.generate_salt()
            new_iterations = PBKDF2_ITERATIONS
            new_master_key = CryptoUtils.derive_key(new_password, new_salt, new_iterations)

            self.app.master_key = new_master_key
            self.app.current_salt = new_salt
            self.app.current_iterations = new_iterations

            if self.app._save_vault():
                messagebox.showinfo("Success", "Master password changed successfully.", parent=self)
                self.result = True
            else:
                messagebox.showerror("Error", "Failed to save vault with new master password. The change might not be persisted.", parent=self)
                self.result = None

        except Exception as e:
            messagebox.showerror("Error", f"Failed to change master password: {e}", parent=self)
            self.result = None


class PasswordGeneratorDialog(simpledialog.Dialog):
    def __init__(self, parent, app_controller, target_var=None, modal=False):
        self.app = app_controller
        self.target_var = target_var
        super().__init__(parent, "Password Generator")

    def body(self, master_frame):
        ttk.Label(master_frame, text="Password Length:").grid(row=0, column=0, sticky=tk.W, pady=5, padx=5)
        self.length_var = tk.IntVar(value=16)
        ttk.Spinbox(master_frame, from_=8, to=128, textvariable=self.length_var, width=5).grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)

        self.use_upper_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(master_frame, text="Uppercase (A-Z)", variable=self.use_upper_var).grid(row=1, column=0, columnspan=2, sticky=tk.W, padx=5)
        self.use_lower_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(master_frame, text="Lowercase (a-z)", variable=self.use_lower_var).grid(row=2, column=0, columnspan=2, sticky=tk.W, padx=5)
        self.use_digits_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(master_frame, text="Digits (0-9)", variable=self.use_digits_var).grid(row=3, column=0, columnspan=2, sticky=tk.W, padx=5)
        self.use_symbols_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(master_frame, text="Symbols (!@#...)", variable=self.use_symbols_var).grid(row=4, column=0, columnspan=2, sticky=tk.W, padx=5)

        ttk.Button(master_frame, text="Generate", command=self._generate).grid(row=5, column=0, columnspan=2, pady=(10,5))

        self.generated_pass_var = tk.StringVar()
        generated_pass_entry = ttk.Entry(master_frame, textvariable=self.generated_pass_var, state="readonly", width=40)
        generated_pass_entry.grid(row=6, column=0, columnspan=2, pady=5, padx=5, sticky=tk.EW)

        master_frame.columnconfigure(1, weight=1)
        return None

    def _generate(self):
        length = self.length_var.get()
        if length <=0:
            self.generated_pass_var.set("Error: Length must be positive!")
            return

        chars = ""
        if self.use_lower_var.get(): chars += string.ascii_lowercase
        if self.use_upper_var.get(): chars += string.ascii_uppercase
        if self.use_digits_var.get(): chars += string.digits
        if self.use_symbols_var.get(): chars += string.punctuation

        if not chars:
            self.generated_pass_var.set("Error: Select at least one character type!")
            return

        password = ''.join(secrets.choice(chars) for _ in range(length))
        self.generated_pass_var.set(password)

    def buttonbox(self):
        box = ttk.Frame(self)
        ttk.Button(box, text="Use Password", width=15, command=self.ok, default=tk.ACTIVE).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(box, text="Copy & Close", width=15, command=self._copy_and_close).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(box, text="Close", width=10, command=self.cancel).pack(side=tk.LEFT, padx=5, pady=5)

        self.bind("<Return>", self.ok)
        self.bind("<Escape>", self.cancel)
        box.pack()

    def _copy_and_close(self):
        password = self.generated_pass_var.get()
        if password and not password.startswith("Error:"):
            self.app.copy_to_clipboard(password, "Generated Password")
        self.cancel()

    def apply(self):
        password = self.generated_pass_var.get()
        if password and not password.startswith("Error:"):
            if self.target_var:
                self.target_var.set(password)
            self.result = password
        else:
            self.result = None


# --- Application Entry Point ---
if __name__ == '__main__':
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
