import customtkinter as CTk, customtkinter
import tkinter as tk, tkinter
from tkinter import messagebox, ttk, simpledialog
import tkinter.messagebox as messagebox
from PIL import Image, ImageTk 
import sqlite3
import os
import hashlib
import bcrypt
import secrets
import string
import pyperclip
from cryptography.fernet import Fernet


class PasswordManager:
    def __init__(self, master):
        self.master = master
        self.master.title("SecurePass Vault")
        
        # Make window responsive instead of fixed size
        self.master.state('zoomed' if self.master.tk.call('tk', 'windowingsystem') == 'win32' else 'normal')
        
        # Set minimum window size for usability
        self.master.minsize(400, 600)
        
        # Center window on screen with responsive initial size
        screen_width = self.master.winfo_screenwidth()
        screen_height = self.master.winfo_screenheight()
        
        # Use percentage-based sizing
        window_width = min(800, int(screen_width * 0.6))
        window_height = min(900, int(screen_height * 0.8))
        
        # Center the window
        x = (screen_width // 2) - (window_width // 2)
        y = (screen_height // 2) - (window_height // 2)
        
        self.master.geometry(f"{window_width}x{window_height}+{x}+{y}")

        # Load and resize logo responsively using CTkImage
        image_path = os.path.join(os.path.dirname(__file__), 'src', 'logo.png')
        logo_image = Image.open(image_path)
        # Scale logo size based on screen size
        logo_size = min(120, int(min(screen_width, screen_height) * 0.08))
        # Use compatible resampling method for older Pillow versions
        try:
            logo_image = logo_image.resize((logo_size, logo_size), Image.Resampling.LANCZOS)
        except AttributeError:
            # Fallback for older Pillow versions
            logo_image = logo_image.resize((logo_size, logo_size), Image.LANCZOS)
        
        # Create CTkImage for better HiDPI support
        self.logo_icon = customtkinter.CTkImage(logo_image, size=(logo_size, logo_size))
        
        # Also create PhotoImage for window icon
        photo_icon = ImageTk.PhotoImage(logo_image)
        self.master.iconphoto(True, photo_icon)

        # Position about button responsively in top-right corner - borderless
        self.about_button = customtkinter.CTkButton(self.master, text="ℹ️ About", 
                                                   command=self.show_about_window,
                                                   width=80, height=35, font=("Arial", 11),
                                                   border_width=0, corner_radius=8, border_spacing=0)
        self.about_button.place(relx=1.0, rely=0.0, anchor="ne", x=-10, y=10)

        self.create_vault_folder()
        self.create_data_folder()

        self.master.columnconfigure(0, weight=1)
        self.master.rowconfigure(0, weight=1)

        self.create_profile()

        key = self.load_or_generate_key()
        self.cipher_suite = Fernet(key)

    def create_vault_folder(self):
        vault_folder = os.path.expanduser("~/.vault-key")
        if not os.path.exists(vault_folder):
            os.makedirs(vault_folder)

    def create_data_folder(self):
        data_folder = ".data"
        if not os.path.exists(data_folder):
            os.makedirs(data_folder)

    def load_or_generate_key(self):
        key_file_path = os.path.expanduser("~/.vault-key/encryption_key.key")
        try:
            with open(key_file_path, "rb") as key_file:
                key = key_file.read()
        except FileNotFoundError:
            key = Fernet.generate_key()
            with open(key_file_path, "wb") as key_file:
                key_file.write(key)

        return key

    def connect_to_database(self):
        database_path = os.path.join(".data", "vault.db")
        conn = sqlite3.connect(database_path, timeout=10.0)
        return conn

    def encrypt(self, data):
        if not isinstance(data, bytes):
            data = data.encode()

        hashed_data = hashlib.sha256(data).hexdigest().encode()
        encrypted_data = self.cipher_suite.encrypt(hashed_data)

        return encrypted_data

    def decrypt(self, encrypted_data):
        decrypted_data = self.cipher_suite.decrypt(encrypted_data)
        original_data = decrypted_data.decode()

        return original_data

    def hash_password(self, password):
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        return hashed_password

    def create_profile(self):
        self.destroy_login_widgets()
        
        # Configure responsive grid system - full width
        self.master.columnconfigure(0, weight=1)
        self.master.rowconfigure(0, weight=1)
        
        # Create main container frame - borderless and edge-to-edge
        main_frame = customtkinter.CTkFrame(self.master, corner_radius=0, border_width=0)
        main_frame.grid(row=0, column=0, padx=0, pady=0, sticky="nsew")
        
        # Configure main frame grid
        for i in range(8):
            main_frame.rowconfigure(i, weight=1)
        main_frame.columnconfigure(0, weight=1)
        
        # Logo with transparent background
        self.logo_label = customtkinter.CTkLabel(main_frame, image=self.logo_icon, text="")
        self.logo_label.grid(row=0, column=0, pady=(10, 5), sticky="n")

        # Form elements with borderless design
        self.username_label = customtkinter.CTkLabel(main_frame, text="Username:", font=("Arial", 14))
        self.username_entry = customtkinter.CTkEntry(main_frame, height=40, font=("Arial", 12), border_width=0, corner_radius=8)
        self.master_password_label = customtkinter.CTkLabel(main_frame, text="Master Password:", font=("Arial", 14))
        self.master_password_entry = customtkinter.CTkEntry(main_frame, show="*", height=40, font=("Arial", 12), border_width=0, corner_radius=8)

        self.show_password_var = tk.IntVar()
        self.show_password_checkbox = customtkinter.CTkCheckBox(main_frame, text="Show Password", 
                                                               variable=self.show_password_var, 
                                                               command=self.toggle_show_master_password)

        self.create_profile_button = customtkinter.CTkButton(main_frame, text="Create Profile", 
                                                           command=self.save_profile, fg_color="green",
                                                           height=40, font=("Arial", 14, "bold"),
                                                           border_width=0, corner_radius=8, border_spacing=0)
        self.close_button = customtkinter.CTkButton(main_frame, text="Close", command=self.close_app, 
                                                   fg_color="red", height=40, font=("Arial", 14, "bold"),
                                                   border_width=0, corner_radius=8, border_spacing=0)

        # Grid layout with minimal padding
        self.username_label.grid(row=1, column=0, padx=15, pady=(5, 2), sticky="w")
        self.username_entry.grid(row=2, column=0, padx=15, pady=(0, 8), sticky="ew")
        self.master_password_label.grid(row=3, column=0, padx=15, pady=(0, 2), sticky="w")
        self.master_password_entry.grid(row=4, column=0, padx=15, pady=(0, 8), sticky="ew")
        self.show_password_checkbox.grid(row=5, column=0, padx=15, pady=3, sticky="w")
        self.create_profile_button.grid(row=6, column=0, padx=15, pady=8, sticky="ew")
        self.close_button.grid(row=7, column=0, padx=15, pady=(0, 10), sticky="ew")

        self.username_entry.bind("<Return>", lambda e: self.save_profile(), add="+")
        self.master_password_entry.bind("<Return>", lambda e: self.save_profile(), add="+")

        db_path = os.path.join(".data", "vault.db")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                master_password TEXT NOT NULL
            )
        ''')

        cursor.execute('''
            SELECT id FROM users
        ''')

        existing_user_id = cursor.fetchone()

        if existing_user_id:
            self.current_user_id = existing_user_id[0]
            self.destroy_profile_widgets()
            self.login()
        else:
            conn.commit()
            conn.close()

    def save_profile(self):
        username = self.username_entry.get()
        master_password = self.master_password_entry.get()

        hashed_master_password = bcrypt.hashpw(master_password.encode(), bcrypt.gensalt())
        encrypted_master_password = self.cipher_suite.encrypt(hashed_master_password)

        conn = self.connect_to_database()
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                master_password TEXT NOT NULL
            )
        ''')

        cursor.execute('''
            SELECT id FROM users
            WHERE username=?
        ''', (username,))

        existing_user_id = cursor.fetchone()

        if existing_user_id:
            messagebox.showerror("Error", "User already exists. Please choose a different username.")
        else:
            cursor.execute('''
                INSERT INTO users (username, master_password)
                VALUES (?, ?)
            ''', (username, encrypted_master_password))

            conn.commit()
            conn.close()

            self.destroy_profile_widgets()

            messagebox.showinfo("Success", f"Profile for {username} created successfully!")

            self.login()

    def toggle_show_master_password(self):
        if hasattr(self, 'master_password_entry'):
            if self.show_password_var.get():
                self.master_password_entry.configure(show="")
            else:
                self.master_password_entry.configure(show="*")


    def login(self):
        self.master.title("SecurePass Vault - Login")
        
        # Configure responsive grid system - full width
        self.master.columnconfigure(0, weight=1)
        self.master.rowconfigure(0, weight=1)
        
        # Create main container frame - borderless and edge-to-edge
        main_frame = customtkinter.CTkFrame(self.master, corner_radius=0, border_width=0)
        main_frame.grid(row=0, column=0, padx=0, pady=0, sticky="nsew")
        
        # Configure main frame grid
        for i in range(9):
            main_frame.rowconfigure(i, weight=1)
        main_frame.columnconfigure(0, weight=1)

        # Logo with transparent background
        self.logo_label = customtkinter.CTkLabel(main_frame, image=self.logo_icon, text="")
        self.logo_label.grid(row=0, column=0, pady=(10, 5), sticky="n")

        # Form elements with borderless design
        self.username_label = customtkinter.CTkLabel(main_frame, text="Username:", font=("Arial", 14))
        self.username_entry = customtkinter.CTkEntry(main_frame, height=40, font=("Arial", 12), border_width=0, corner_radius=8)
        self.master_password_label = customtkinter.CTkLabel(main_frame, text="Master Password:", font=("Arial", 14))
        self.master_password_entry = customtkinter.CTkEntry(main_frame, show="*", height=40, font=("Arial", 12), border_width=0, corner_radius=8)

        self.show_password_var = tk.IntVar()
        self.show_password_checkbox = customtkinter.CTkCheckBox(main_frame, text="Show Password", 
                                                               variable=self.show_password_var, 
                                                               command=self.toggle_show_master_password)

        self.login_button = customtkinter.CTkButton(main_frame, text="Login", command=self.check_login,
                                                   height=45, font=("Arial", 16, "bold"),
                                                   border_width=0, corner_radius=8, border_spacing=0)
        self.save_profile_button = customtkinter.CTkButton(main_frame, text="Create New Profile", 
                                                          command=self.save_profile, fg_color="green",
                                                          height=40, font=("Arial", 14, "bold"),
                                                          border_width=0, corner_radius=8, border_spacing=0)
        self.close_button = customtkinter.CTkButton(main_frame, text="Close", command=self.close_app, 
                                                   fg_color="red", height=40, font=("Arial", 14, "bold"),
                                                   border_width=0, corner_radius=8, border_spacing=0)

        # Grid layout with minimal spacing
        self.username_label.grid(row=1, column=0, padx=15, pady=(5, 2), sticky="w")
        self.username_entry.grid(row=2, column=0, padx=15, pady=(0, 8), sticky="ew")
        self.master_password_label.grid(row=3, column=0, padx=15, pady=(0, 2), sticky="w")
        self.master_password_entry.grid(row=4, column=0, padx=15, pady=(0, 8), sticky="ew")
        self.show_password_checkbox.grid(row=5, column=0, padx=15, pady=5, sticky="w")
        self.login_button.grid(row=6, column=0, padx=15, pady=10, sticky="ew")
        self.save_profile_button.grid(row=7, column=0, padx=15, pady=5, sticky="ew")
        self.close_button.grid(row=8, column=0, padx=15, pady=(0, 10), sticky="ew")

        self.username_entry.bind("<Return>", lambda e: self.check_login(), add="+")
        self.master_password_entry.bind("<Return>", lambda e: self.check_login(), add="+")


    def check_login(self):
        username = self.username_entry.get()
        master_password = self.master_password_entry.get()

        db_path = os.path.join(".data", "vault.db")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT id, master_password FROM users
            WHERE username=?
        ''', (username,))

        user_data = cursor.fetchone()

        if user_data:
            user_id, encrypted_master_password = user_data
            hashed_master_password = self.cipher_suite.decrypt(encrypted_master_password).decode()

            if bcrypt.checkpw(master_password.encode(), hashed_master_password.encode()):
                self.current_user_id = user_id
                messagebox.showinfo("Success", f"Login successful as {username}!")
                self.destroy_profile_widgets()
                self.main_menu()
            else:
                messagebox.showerror("Error", "Invalid login credentials")
        else:
            messagebox.showerror("Error", "Invalid login credentials")

        conn.close()

    def destroy_login_widgets(self):
        # Destroy all children of master to clean up the responsive layout
        for widget in self.master.winfo_children():
            if widget != self.about_button:  # Keep the about button
                widget.destroy()

    def destroy_profile_widgets(self):
        # Destroy all children of master to clean up the responsive layout
        for widget in self.master.winfo_children():
            if widget != self.about_button:  # Keep the about button
                widget.destroy()

    def display_current_profile(self):
        if hasattr(self, 'current_user_id'):
            messagebox.showinfo("Current Profile", f"Current Profile: {self.get_current_username()}")

    def copy_username(self):
        username = self.username_entry.get()
        pyperclip.copy(username)
        messagebox.showinfo("Copy Username", f"Username copied to Clipboard for {self.service_entry.get()}")

    def copy_password(self):
        password = self.password_entry.get()
        pyperclip.copy(password)
        messagebox.showinfo("Copy Password", f"Password copied to Clipboard for {self.service_entry.get()}")

    def toggle_show_password(self):
        if self.show_password_var.get():
            self.password_entry.configure(show="")
        else:
            self.password_entry.configure(show="*")

    def main_menu(self):
        self.master.title("SecurePass Vault - Main Menu")
        
        # Configure main grid system - full width
        self.master.columnconfigure(0, weight=1)
        self.master.rowconfigure(0, weight=1)
        
        # Main container - borderless and edge-to-edge
        main_container = customtkinter.CTkFrame(self.master, corner_radius=0, border_width=0)
        main_container.grid(row=0, column=0, padx=0, pady=0, sticky="nsew")
        main_container.columnconfigure(0, weight=1)
        main_container.columnconfigure(1, weight=2)  # TreeView gets more space
        main_container.rowconfigure(1, weight=1)  # Data area expands
        
        # Header frame - borderless
        header_frame = customtkinter.CTkFrame(main_container, corner_radius=0, border_width=0)
        header_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=0, pady=0)
        header_frame.columnconfigure(1, weight=1)  # Space for logo
        
        self.logo_label = customtkinter.CTkLabel(header_frame, image=self.logo_icon, text="")
        self.logo_label.grid(row=0, column=0, padx=10, pady=5)
        
        # Profile controls - borderless
        profile_frame = customtkinter.CTkFrame(header_frame, corner_radius=0, border_width=0)
        profile_frame.grid(row=0, column=1, padx=5, pady=5, sticky="e")
        
        self.current_profile_button = customtkinter.CTkButton(profile_frame, text="Current Profile", 
                                                            command=self.display_current_profile, 
                                                            width=120, height=35, font=("Arial", 12),
                                                            border_width=0, corner_radius=8, border_spacing=0)
        self.current_profile_button.pack(side=tk.LEFT, padx=2)
        
        self.logout_button = customtkinter.CTkButton(profile_frame, text="Logout", command=self.logout, 
                                                   fg_color="red", width=80, height=35, font=("Arial", 12, "bold"),
                                                   border_width=0, corner_radius=8, border_spacing=0)
        self.logout_button.pack(side=tk.LEFT, padx=2)
        
        # Input form frame - borderless
        form_frame = customtkinter.CTkFrame(main_container, corner_radius=0, border_width=0)
        form_frame.grid(row=1, column=0, sticky="nsew", padx=0, pady=0)
        form_frame.columnconfigure(0, weight=1)
        
        # Form title
        form_title = customtkinter.CTkLabel(form_frame, text="Password Entry Form", 
                                          font=("Arial", 16, "bold"))
        form_title.grid(row=0, column=0, pady=(10, 5), sticky="n")
        
        # Form fields - borderless design
        self.service_label = customtkinter.CTkLabel(form_frame, text="Service/Website:", font=("Arial", 14))
        self.service_entry = customtkinter.CTkEntry(form_frame, height=35, font=("Arial", 12), border_width=0, corner_radius=8)
        self.username_label = customtkinter.CTkLabel(form_frame, text="Username:", font=("Arial", 14))
        self.username_entry = customtkinter.CTkEntry(form_frame, height=35, font=("Arial", 12), border_width=0, corner_radius=8)
        self.password_label = customtkinter.CTkLabel(form_frame, text="Password:", font=("Arial", 14))
        self.password_entry = customtkinter.CTkEntry(form_frame, show="*", height=35, font=("Arial", 12), border_width=0, corner_radius=8)

        self.show_password_var = tk.IntVar()
        self.show_password_checkbox = customtkinter.CTkCheckBox(form_frame, text="Show Password", 
                                                              variable=self.show_password_var, 
                                                              command=self.toggle_show_password)
        
        # Password tools frame - borderless
        tools_frame = customtkinter.CTkFrame(form_frame, corner_radius=0, border_width=0)
        tools_frame.grid(row=8, column=0, padx=10, pady=5, sticky="ew")
        tools_frame.columnconfigure(0, weight=1)
        tools_frame.columnconfigure(1, weight=1)
        
        self.suggest_button = customtkinter.CTkButton(tools_frame, text="🔐 Suggest Password", 
                                                    command=self.suggest_password, height=35, font=("Arial", 12),
                                                    border_width=0, corner_radius=8, 
                                                    hover=True, border_spacing=0)
        self.suggest_button.grid(row=0, column=0, padx=1, sticky="ew")
        
        # Action buttons frame - borderless
        action_frame = customtkinter.CTkFrame(form_frame, corner_radius=0, border_width=0)
        action_frame.grid(row=9, column=0, padx=10, pady=5, sticky="ew")
        action_frame.columnconfigure((0, 1, 2), weight=1)
        
        self.save_button = customtkinter.CTkButton(action_frame, text="💾 Save", command=self.save_record, 
                                                 fg_color="green", height=40, font=("Arial", 12, "bold"),
                                                 border_width=0, corner_radius=8, border_spacing=0)
        self.modify_button = customtkinter.CTkButton(action_frame, text="✏️ Modify", command=self.modify_record, 
                                                   fg_color="orange", height=40, font=("Arial", 12, "bold"),
                                                   border_width=0, corner_radius=8, border_spacing=0)
        self.delete_button = customtkinter.CTkButton(action_frame, text="🗑️ Delete", command=self.delete_record, 
                                                   fg_color="red", height=40, font=("Arial", 12, "bold"),
                                                   border_width=0, corner_radius=8, border_spacing=0)
        
        self.save_button.grid(row=0, column=0, padx=1, sticky="ew")
        self.modify_button.grid(row=0, column=1, padx=1, sticky="ew")
        self.delete_button.grid(row=0, column=2, padx=1, sticky="ew")
        
        # Copy buttons frame - borderless
        copy_frame = customtkinter.CTkFrame(form_frame, corner_radius=0, border_width=0)
        copy_frame.grid(row=10, column=0, padx=10, pady=3, sticky="ew")
        copy_frame.columnconfigure((0, 1), weight=1)
        
        self.copy_username_button = customtkinter.CTkButton(copy_frame, text="📋 Copy Username", 
                                                          command=self.copy_username, height=35, font=("Arial", 11),
                                                          border_width=0, corner_radius=8, border_spacing=0)
        self.copy_password_button = customtkinter.CTkButton(copy_frame, text="📋 Copy Password", 
                                                          command=self.copy_password, height=35, font=("Arial", 11),
                                                          border_width=0, corner_radius=8, border_spacing=0)
        
        self.copy_username_button.grid(row=0, column=0, padx=1, sticky="ew")
        self.copy_password_button.grid(row=0, column=1, padx=1, sticky="ew")
        
        # Layout form fields - tighter spacing
        self.service_label.grid(row=1, column=0, padx=10, pady=(3, 1), sticky="w")
        self.service_entry.grid(row=2, column=0, padx=10, pady=(0, 6), sticky="ew")
        self.username_label.grid(row=3, column=0, padx=10, pady=(0, 1), sticky="w")
        self.username_entry.grid(row=4, column=0, padx=10, pady=(0, 6), sticky="ew")
        self.password_label.grid(row=5, column=0, padx=10, pady=(0, 1), sticky="w")
        self.password_entry.grid(row=6, column=0, padx=10, pady=(0, 3), sticky="ew")
        self.show_password_checkbox.grid(row=7, column=0, padx=10, pady=3, sticky="w")
        
        # Data display frame - borderless
        data_frame = customtkinter.CTkFrame(main_container, corner_radius=0, border_width=0)
        data_frame.grid(row=1, column=1, sticky="nsew", padx=0, pady=0)
        data_frame.columnconfigure(0, weight=1)
        data_frame.rowconfigure(1, weight=1)
        
        # Data title
        data_title = customtkinter.CTkLabel(data_frame, text="Stored Passwords", 
                                          font=("Arial", 16, "bold"))
        data_title.grid(row=0, column=0, pady=(10, 5), sticky="n")
        
        # TreeView with better responsive design - borderless
        tree_container = customtkinter.CTkFrame(data_frame, corner_radius=0, border_width=0)
        tree_container.grid(row=1, column=0, padx=5, pady=0, sticky="nsew")
        tree_container.columnconfigure(0, weight=1)
        tree_container.rowconfigure(0, weight=1)
        
        self.tree = ttk.Treeview(tree_container, columns=("Service", "Username", "Password"))
        self.tree.heading("#0", text="ID")
        self.tree.heading("Service", text="Service/Website")
        self.tree.heading("Username", text="Username")
        self.tree.heading("Password", text="Password")
        self.tree.column("#0", stretch=tk.NO, width=50)
        self.tree.column("Service", anchor=tk.W, width=150, minwidth=100)
        self.tree.column("Username", anchor=tk.W, width=130, minwidth=100)
        self.tree.column("Password", anchor=tk.W, width=100, minwidth=80)
        self.tree.bind("<ButtonRelease-1>", self.on_treeview_select)
        
        # Add scrollbar to TreeView
        scrollbar = ttk.Scrollbar(tree_container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.grid(row=0, column=0, sticky="nsew", padx=0, pady=0)
        scrollbar.grid(row=0, column=1, sticky="ns", pady=0)

        # Ensure records table exists before loading
        self.create_records_table()
        self.load_records()

    def create_records_table(self):
        """Ensure the records table exists"""
        db_path = os.path.join(".data", "vault.db")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        
        conn.commit()
        conn.close()

    def get_current_username(self):
        db_path = os.path.join(".data", "vault.db")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT username FROM users
            WHERE id=?
        ''', (self.current_user_id,))

        username = cursor.fetchone()[0]
        conn.close()

        return username

    def logout(self):
        if hasattr(self, 'current_user_id'):
            db_path = os.path.join(".data", "vault.db")
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT username FROM users
                WHERE id=?
            ''', (self.current_user_id,))

            username = cursor.fetchone()[0]
            conn.close()

            confirmation = messagebox.askokcancel("Logout", f"Are you sure you want to logout from {username}'s profile?")
            if confirmation:
                self.destroy_main_menu_widgets()
                self.login()

    def close_app(self):
        confirmation = messagebox.askokcancel("Close Application", "Are you sure you want to close SecurePass Vault?")
        if confirmation:
            self.master.destroy()

    def show_about_window(self):
        about_window = customtkinter.CTkToplevel(self.master)
        about_window.title("About SecurePass Vault")
        
        # Make about window responsive
        about_width = min(500, int(self.master.winfo_screenwidth() * 0.4))
        about_height = min(600, int(self.master.winfo_screenheight() * 0.6))
        
        # Center the about window
        x = (self.master.winfo_screenwidth() // 2) - (about_width // 2)
        y = (self.master.winfo_screenheight() // 2) - (about_height // 2)
        about_window.geometry(f"{about_width}x{about_height}+{x}+{y}")
        about_window.resizable(True, True)
        about_window.minsize(400, 500)
        
        # Configure responsive grid
        about_window.columnconfigure(0, weight=1)
        about_window.rowconfigure(1, weight=1)
        
        # Header frame with logo
        header_frame = customtkinter.CTkFrame(about_window, corner_radius=10)
        header_frame.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="ew")
        
        logo_label = customtkinter.CTkLabel(header_frame, image=self.logo_icon, text="")
        logo_label.pack(pady=10)
        
        title_label = customtkinter.CTkLabel(header_frame, text="SecurePass Vault", 
                                           font=("Arial", 24, "bold"))
        title_label.pack(pady=(0, 15))
        
        # Scrollable content frame
        content_frame = customtkinter.CTkScrollableFrame(about_window, corner_radius=10)
        content_frame.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="nsew")
        content_frame.columnconfigure(0, weight=1)

        about_text = """Welcome to SecurePass Vault!

SecurePass Vault is a password manager created by Nakya Tagli.
It helps you securely store and manage your passwords.

✨ Features:
• Secure encryption of your credentials
• Responsive, easy-to-use interface
• Strong password suggestion functionality
• Cross-platform compatibility
• Organized password management

📧 Contact:
For support or inquiries, please contact us at:
nakya333@gmail.com

⚖️ License:
MIT License 
Copyright © 2023-2024 Nakya Tagli

This software is released under the MIT License.
For more information, see the LICENSE file.
"""

        about_label = customtkinter.CTkLabel(content_frame, text=about_text, 
                                           justify=tk.LEFT, font=("Arial", 12),
                                           wraplength=about_width-80)
        about_label.pack(padx=20, pady=20, fill="both", expand=True)
        
        # Close button
        close_button = customtkinter.CTkButton(about_window, text="Close", 
                                             command=about_window.destroy,
                                             height=40, font=("Arial", 14, "bold"),
                                             border_width=0, corner_radius=8, border_spacing=0)
        close_button.grid(row=2, column=0, padx=20, pady=(0, 20), sticky="ew")

    def destroy_main_menu_widgets(self):
        # Destroy all children of master to clean up the responsive layout
        for widget in self.master.winfo_children():
            widget.destroy()

    def save_record(self):
        # Get input values and strip whitespace
        service = self.service_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        # Input validation
        if not service:
            messagebox.showerror("Validation Error", "Please enter a service/website name.")
            self.service_entry.focus()
            return
            
        if not username:
            messagebox.showerror("Validation Error", "Please enter a username.")
            self.username_entry.focus()
            return
            
        if not password:
            messagebox.showerror("Validation Error", "Please enter a password.")
            self.password_entry.focus()
            return

        try:
            # Encrypt data
            encrypted_username = self.cipher_suite.encrypt(username.encode())
            encrypted_password = self.cipher_suite.encrypt(password.encode())

            # Database operations with proper connection management
            db_path = os.path.join(".data", "vault.db")
            conn = sqlite3.connect(db_path, timeout=10.0)  # Add timeout
            cursor = conn.cursor()

            # Ensure table exists
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS records (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    service TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL
                )
            ''')

            # Insert new record
            cursor.execute('''
                INSERT INTO records (user_id, service, username, password)
                VALUES (?, ?, ?, ?)
            ''', (self.current_user_id, service, encrypted_username, encrypted_password))

            conn.commit()
            messagebox.showinfo("Success", f"Credentials have been stored for {service}")
            
            # Clear fields and refresh view
            self.clear_entry_fields()
            self.load_records()
            
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to save record: {str(e)}")
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {str(e)}")
        finally:
            # Ensure connection is always closed
            if 'conn' in locals():
                conn.close()

    def modify_record(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a record to modify.")
            return

        item_values = self.tree.item(selected_item)["values"]
        if not item_values:
            messagebox.showwarning("Warning", "Please select a valid record.")
            return
    
        try:
            # Database operations with proper connection management
            db_path = os.path.join(".data", "vault.db")
            conn = sqlite3.connect(db_path, timeout=10.0)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT service, username, password
                FROM records
                WHERE id=?
            ''', (item_values[0],))

            existing_values = cursor.fetchone()
            conn.close()  # Close connection after reading

            if not existing_values:
                messagebox.showerror("Error", "Record not found.")
                return

            # Decrypt existing values
            decrypted_username = self.decrypt(existing_values[1])
            decrypted_password = self.decrypt(existing_values[2])

            # Get new values from user with validation
            new_service = tkinter.simpledialog.askstring("Modify Record", "Enter new service/website:", initialvalue=existing_values[0])
            if new_service is None:  # User cancelled
                return
            new_service = new_service.strip()
            if not new_service:
                messagebox.showerror("Validation Error", "Service/Website name cannot be empty.")
                return

            new_username = tkinter.simpledialog.askstring("Modify Record", "Enter new username:", initialvalue=decrypted_username)
            if new_username is None:  # User cancelled
                return
            new_username = new_username.strip()
            if not new_username:
                messagebox.showerror("Validation Error", "Username cannot be empty.")
                return

            new_password = tkinter.simpledialog.askstring("Modify Record", "Enter new password:", initialvalue=decrypted_password)
            if new_password is None:  # User cancelled
                return
            new_password = new_password.strip()
            if not new_password:
                messagebox.showerror("Validation Error", "Password cannot be empty.")
                return

            # Encrypt new values
            encrypted_new_username = self.cipher_suite.encrypt(new_username.encode())
            encrypted_new_password = self.cipher_suite.encrypt(new_password.encode())

            # Update database with new connection
            conn = sqlite3.connect(db_path, timeout=10.0)
            cursor = conn.cursor()

            cursor.execute('''
                UPDATE records
                SET service=?, username=?, password=?
                WHERE id=?
            ''', (new_service, encrypted_new_username, encrypted_new_password, item_values[0]))

            conn.commit()
            messagebox.showinfo("Success", f"Credentials have been modified for {new_service}")

            # Clear fields and refresh view
            self.clear_entry_fields()
            self.load_records()
            
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to modify record: {str(e)}")
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {str(e)}")
        finally:
            # Ensure connection is always closed
            if 'conn' in locals():
                conn.close()

    def delete_record(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a record to delete.")
            return

        item_values = self.tree.item(selected_item)["values"]
        if not item_values:
            messagebox.showwarning("Warning", "Please select a valid record.")
            return

        # Get service name for confirmation
        service_name = item_values[1] if len(item_values) > 1 else "this service"
        
        confirmation = messagebox.askokcancel("Delete Record", 
            f"Are you sure you want to delete the credentials for {service_name}?\n\nThis action cannot be undone.")
        if not confirmation:
            return

        try:
            db_path = os.path.join(".data", "vault.db")
            conn = sqlite3.connect(db_path, timeout=10.0)
            cursor = conn.cursor()

            cursor.execute('''
                DELETE FROM records
                WHERE id=?
            ''', (item_values[0],))

            if cursor.rowcount == 0:
                messagebox.showwarning("Warning", "Record not found or already deleted.")
                return

            conn.commit()
            messagebox.showinfo("Success", f"The credentials for {service_name} have been successfully deleted")

            # Clear fields and refresh view
            self.clear_entry_fields()
            self.load_records()
            
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to delete record: {str(e)}")
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {str(e)}")
        finally:
            # Ensure connection is always closed
            if 'conn' in locals():
                conn.close()

    def suggest_password(self):
        characters = string.ascii_letters + string.digits + string.punctuation
        suggested_password = ''.join(secrets.choice(characters) for i in range(12))

        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, suggested_password)

    def load_records(self):
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)

        try:
            db_path = os.path.join(".data", "vault.db")
            conn = sqlite3.connect(db_path, timeout=10.0)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT id, service, username, password 
                FROM records
                WHERE user_id=?
            ''', (self.current_user_id,))

            records = cursor.fetchall()

            # Load records into TreeView
            for record in records:
                try:
                    decrypted_username = self.decrypt(record[2])
                    decrypted_password = self.decrypt(record[3])
                    self.tree.insert("", "end", values=(record[0], record[1], decrypted_username, decrypted_password))
                except Exception as e:
                    # If decryption fails, show placeholder
                    self.tree.insert("", "end", values=(record[0], record[1], "[Error decrypting]", "[Error decrypting]"))
                    print(f"Decryption error for record {record[0]}: {e}")
            
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to load records: {str(e)}")
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred while loading records: {str(e)}")
        finally:
            # Ensure connection is always closed
            if 'conn' in locals():
                conn.close()

    def on_treeview_select(self, event):
        selected_item = self.tree.selection()
        if selected_item:
            item_values = self.tree.item(selected_item)["values"]
            self.service_entry.delete(0, tk.END)
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
            if item_values:
                self.service_entry.insert(0, item_values[1])
                self.username_entry.insert(0, item_values[2])
                self.password_entry.insert(0, item_values[3])

    def clear_entry_fields(self):
        self.service_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()