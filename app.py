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
        self.master.geometry("600x1000")

        image_path = os.path.join(os.path.dirname(__file__), 'src', 'logo.png')
        logo_image = Image.open(image_path)
        logo_image = logo_image.resize((100, 100))
        self.logo_icon = ImageTk.PhotoImage(logo_image)
        self.master.iconphoto(True, self.logo_icon)

        self.about_button = customtkinter.CTkButton(self.master, text="About", command=self.show_about_window)
        self.about_button.pack(side=tk.TOP, anchor=tk.SE, padx=10, pady=10)

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
        conn = sqlite3.connect(database_path)
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
        self.master.columnconfigure(0, weight=1)
        self.master.rowconfigure(0, weight=1)
        self.logo_label = tk.Label(self.master, image=self.logo_icon)
        self.logo_label.pack(side="top", pady=10)

        self.username_label = customtkinter.CTkLabel(self.master, text="Username:")
        self.username_entry = customtkinter.CTkEntry(self.master)
        self.master_password_label = customtkinter.CTkLabel(self.master, text="Master Password:")
        self.master_password_entry = customtkinter.CTkEntry(self.master, show="*")

        self.show_password_var = tk.IntVar()
        self.show_password_checkbox = tk.Checkbutton(self.master, text="Show Password", variable=self.show_password_var, command=self.toggle_show_master_password)

        self.create_profile_button = customtkinter.CTkButton(self.master, text="Create Profile", command=self.save_profile, fg_color="green")
        self.close_button = customtkinter.CTkButton(self.master, text="Close", command=self.close_app, fg_color="red")

        self.username_label.grid(row=0, column=0, pady=5, sticky="nsew")
        self.username_entry.grid(row=1, column=0, pady=5, sticky="nsew")
        self.master_password_label.grid(row=2, column=0, pady=5, sticky="nsew")
        self.master_password_entry.grid(row=3, column=0, pady=5, sticky="nsew")
        self.show_password_checkbox.grid(row=4, column=0, pady=5, sticky="nsew")
        self.create_profile_button.grid(row=5, column=0, pady=5, sticky="nsew")
        self.close_button.grid(row=6, column=0, pady=5, sticky="nsew")

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

    def destroy_profile_widgets(self):
        self.username_label.destroy()
        self.username_entry.destroy()
        self.master_password_label.destroy()
        self.master_password_entry.destroy()
        self.create_profile_button.destroy()

    def login(self):
        self.master.title("SecurePass Vault - Login")

        self.logo_label = tk.Label(self.master, image=self.logo_icon)
        self.logo_label.pack(side="top", pady=10)

        self.username_label = customtkinter.CTkLabel(self.master, text="Username:")
        self.username_entry = customtkinter.CTkEntry(self.master)
        self.master_password_label = customtkinter.CTkLabel(self.master, text="Master Password:")
        self.master_password_entry = customtkinter.CTkEntry(self.master, show="*")

        self.show_password_var = tk.IntVar()
        self.show_password_checkbox = tk.Checkbutton(self.master, text="Show Password", variable=self.show_password_var, command=self.toggle_show_master_password)

        self.login_button = customtkinter.CTkButton(self.master, text="Login", command=self.check_login)
        self.save_profile_button = customtkinter.CTkButton(self.master, text="Save New Profile", command=self.save_profile, fg_color="green")
        self.close_button = customtkinter.CTkButton(self.master, text="Close", command=self.close_app, fg_color="red")

        self.username_label.pack(pady=5)
        self.username_entry.pack(pady=5)
        self.master_password_label.pack(pady=5)
        self.master_password_entry.pack(pady=5)
        self.show_password_checkbox.pack(pady=5)
        self.login_button.pack(pady=25)
        self.save_profile_button.pack(pady=25)
        self.close_button.pack(pady=25)

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
        if hasattr(self, 'logo_label'):
            self.logo_label.destroy()
        if hasattr(self, 'username_label'):
            self.username_label.destroy()
        if hasattr(self, 'username_entry'):
            self.username_entry.destroy()
        if hasattr(self, 'master_password_label'):
            self.master_password_label.destroy()
        if hasattr(self, 'master_password_entry'):
            self.master_password_entry.destroy()
        if hasattr(self, 'login_button'):
            self.login_button.destroy()
        if hasattr(self, 'close_button'):
            self.close_button.destroy()
        if hasattr(self, 'show_password_checkbox'):
            self.show_password_checkbox.destroy()

    def destroy_profile_widgets(self):
        if hasattr(self, 'username_label'):
            self.username_label.destroy()
        if hasattr(self, 'username_entry'):
            self.username_entry.destroy()
        if hasattr(self, 'master_password_label'):
            self.master_password_label.destroy()
        if hasattr(self, 'master_password_entry'):
            self.master_password_entry.destroy()
        if hasattr(self, 'create_profile_button'):
            self.create_profile_button.destroy()
        if hasattr(self, 'login_button'):
            self.login_button.destroy()
        if hasattr(self, 'logo_label'):
            self.logo_label.destroy()
        if hasattr(self, 'save_profile_button'):
            self.save_profile_button.destroy()
        if hasattr(self, 'close_button'):
            self.close_button.destroy()
        if hasattr(self, 'show_password_checkbox'):
            self.show_password_checkbox.destroy()

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
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def main_menu(self):
        self.master.title("SecurePass Vault - Main Menu")
        self.logo_label = tk.Label(self.master, image=self.logo_icon)
        self.logo_label.pack(side="top", pady=10)

        self.current_profile_button = CTk.CTkButton(self.master, text="Current Profile", command=self.display_current_profile)
        self.current_profile_button.pack(side=tk.TOP, pady=5)

        self.logout_button = customtkinter.CTkButton(self.master, text="Logout", command=self.logout, fg_color="red")
        self.logout_button.pack(side=tk.TOP, pady=5)

        self.service_label = customtkinter.CTkLabel(self.master, text="Service/Website:")
        self.service_entry = customtkinter.CTkEntry(self.master)
        self.username_label = customtkinter.CTkLabel(self.master, text="Username:")
        self.username_entry = customtkinter.CTkEntry(self.master)
        self.password_label = customtkinter.CTkLabel(self.master, text="Password:")
        self.password_entry = tk.Entry(self.master, show="*")

        self.show_password_var = tk.IntVar()
        self.show_password_checkbox = tk.Checkbutton(self.master, text="Show Password", variable=self.show_password_var, command=self.toggle_show_password)

        self.save_button = customtkinter.CTkButton(self.master, text="Save", command=self.save_record, fg_color="green")
        self.modify_button = customtkinter.CTkButton(self.master, text="Modify", command=self.modify_record, fg_color="orange")
        self.delete_button = customtkinter.CTkButton(self.master, text="Delete", command=self.delete_record, fg_color="red")

        self.copy_username_button = customtkinter.CTkButton(self.master, text="Copy Username", command=self.copy_username)
        self.copy_password_button = customtkinter.CTkButton(self.master, text="Copy Password", command=self.copy_password)

        self.suggest_button = tk.Button(self.master, text="Suggest Password", command=self.suggest_password)

        self.tree = ttk.Treeview(self.master, columns=("Service", "Username", "Password"))
        self.tree.heading("#0", text="ID")
        self.tree.heading("Service", text="ID")
        self.tree.heading("Username", text="Service")
        self.tree.heading("Password", text="Username")
        self.tree.column("#0", stretch=tk.NO, width=0)
        self.tree.column("Service", anchor=tk.CENTER, width=2)
        self.tree.column("Username", anchor=tk.CENTER, width=150)
        self.tree.column("Password", anchor=tk.CENTER, width=250)
        self.tree.bind("<ButtonRelease-1>", self.on_treeview_select)

        self.service_label.pack(pady=10)
        self.service_entry.pack(pady=5)
        self.username_label.pack(pady=5)
        self.username_entry.pack(pady=5)
        self.password_label.pack(pady=5)
        self.password_entry.pack(pady=5)
        self.show_password_checkbox.pack(pady=5)
        self.save_button.pack(pady=10)
        self.modify_button.pack(pady=5)
        self.delete_button.pack(pady=5)
        self.copy_username_button.pack(pady=5)
        self.copy_password_button.pack(pady=5)
        self.suggest_button.pack(pady=10)
        self.tree.pack(pady=10)

        self.load_records()

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
        about_window = tk.Toplevel(self.master)
        about_window.title("About")

        logo_label = tk.Label(about_window, image=self.logo_icon)
        logo_label.pack(padx=20, pady=10)

        about_text = """
        Welcome to SecurePass Vault!

        SecurePass Vault is a password manager created by Nakya Tagli.
        It helps you securely store and manage your passwords.

        Features:
        - Secure encryption of your credentials
        - Easy-to-use interface for managing passwords
        - Strong password suggestion functionality

        Contact:
        For support or inquiries, please contact us at nakya333@gmail.com

        MIT License 
        Copyright © 2023-2024 Nakya Tagli
        
        This software is released under the MIT License.
        For more information, see the LICENSE file.

        """

        about_label = tk.Label(about_window, text=about_text, justify=tk.LEFT)
        about_label.pack(padx=20, pady=10)

    def destroy_main_menu_widgets(self):
        if hasattr(self, 'service_label'):
            self.service_label.destroy()
        if hasattr(self, 'service_entry'):
            self.service_entry.destroy()
        self.service_label.destroy()
        self.service_entry.destroy()
        self.username_label.destroy()
        self.username_entry.destroy()
        self.password_label.destroy()
        self.password_entry.destroy()
        self.show_password_checkbox.destroy()
        self.save_button.destroy()
        self.modify_button.destroy()
        self.delete_button.destroy()
        self.copy_username_button.destroy()
        self.copy_password_button.destroy()
        self.suggest_button.destroy()
        self.tree.destroy()
        self.logout_button.destroy()
        self.logo_label.destroy()
        self.current_profile_button.destroy()

    def save_record(self):
        service = self.service_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()

        encrypted_username = self.cipher_suite.encrypt(username.encode())
        encrypted_password = self.cipher_suite.encrypt(password.encode())


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

        cursor.execute('''
            INSERT INTO records (user_id, service, username, password)
            VALUES (?, ?, ?, ?)
        ''', (self.current_user_id, service, encrypted_username, encrypted_password))

        conn.commit()
        conn.close()

        messagebox.showinfo("Success", f"You're credentials has been stored for {service}")

        self.clear_entry_fields()
        self.load_records()

    def modify_record(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a record to modify.")
            return

        item_values = self.tree.item(selected_item)["values"]
        if not item_values:
            messagebox.showwarning("Warning", "Please select a valid record.")
            return
    
        db_path = os.path.join(".data", "vault.db")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT service, username, password
            FROM records
            WHERE id=?
        ''', (item_values[0],))

        existing_values = cursor.fetchone()

        conn.close()

        if existing_values:
            decrypted_username = self.decrypt(existing_values[1])
            decrypted_password = self.decrypt(existing_values[2])

            new_service = tkinter.simpledialog.askstring("Modify Record", "Enter new service/website:", initialvalue=existing_values[0])
            new_username = tkinter.simpledialog.askstring("Modify Record", "Enter new username:", initialvalue=decrypted_username)
            new_password = tkinter.simpledialog.askstring("Modify Record", "Enter new password:", initialvalue=decrypted_password)

            encrypted_new_username = self.cipher_suite.encrypt(new_username.encode())
            encrypted_new_password = self.cipher_suite.encrypt(new_password.encode())


            db_path = os.path.join(".data", "vault.db")
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute('''
                UPDATE records
                SET service=?, username=?, password=?
                WHERE id=?
            ''', (new_service, encrypted_new_username, encrypted_new_password, item_values[0]))

            conn.commit()
            conn.close()

            messagebox.showinfo("Success", f"You're credentials has been modified for {new_service}")

            self.clear_entry_fields()
            self.load_records()

    def delete_record(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a record to delete.")
            return

        confirmation = messagebox.askokcancel("Delete Record", "Are you sure you want to delete this record?")
        if confirmation:
            item_values = self.tree.item(selected_item)["values"]

            db_path = os.path.join(".data", "vault.db")
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute('''
                DELETE FROM records
                WHERE id=?
            ''', (item_values[0],))

            conn.commit()
            conn.close()

            messagebox.showinfo("Success", f"The credentials for {item_values[1]} has been successfully deleted")

            self.clear_entry_fields()
            self.load_records()

    def suggest_password(self):
        characters = string.ascii_letters + string.digits + string.punctuation
        suggested_password = ''.join(secrets.choice(characters) for i in range(12))

        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, suggested_password)

    def load_records(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        db_path = os.path.join(".data", "vault.db")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT id, service, username, password 
            FROM records
            WHERE user_id=?
        ''', (self.current_user_id,))

        records = cursor.fetchall()

        for item in self.tree.get_children():
            self.tree.delete(item)

        for record in records:
            decrypted_username = self.decrypt(record[2])
            decrypted_password = self.decrypt(record[3])
            self.tree.insert("", "end", values=(record[0], record[1], decrypted_username, decrypted_password))
        
        conn.commit()
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