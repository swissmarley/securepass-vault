# 🔐 SecurePass Vault - Password Manager 🔐

This is a simple password manager application with built-in encryption and hashing for improved security.

<div align="center">
    <img src="https://nakyaa.files.wordpress.com/2024/02/securepassvault-2.png" width="400">
</div>

## Features

### User Profiles

- **Profile Creation:** Users can create profiles with a unique username and a securely encrypted master password.
- **Profile Login:** Existing users can log in with their username and master password.

### Record Management

- **Record Storage:** Secure storage of service names, usernames, and passwords with encryption and hashing.
- **Record Modification:** Users can modify existing records by updating service names, usernames, and passwords.
- **Record Deletion:** Users can delete records they no longer need.

### Security Measures

#### Master Password

- **Hashing:** Master passwords are hashed using the bcrypt library to protect against rainbow table attacks.
- **Encryption:** Hashed master passwords are further encrypted using the Fernet symmetric encryption algorithm from the cryptography library.

#### Record Storage

- **Username and Password Encryption:** Usernames and passwords for records are hashed using bcrypt and then encrypted before being stored in the database.

### Additional Features

- **Password Suggestion:** The application can suggest strong passwords using the secrets module.



## How to Run

1. Clone the repository
2. Install the required dependencies
3. Run the app

```bash
git clone https://github.com/swissmarley/securepass-vault.git
cd securepass-vault
pip install -r requirements.txt
python app.py
```


## Security Considerations
- **Secure Storage:** Sensitive information is never stored in plaintext, enhancing the security of user data.
- **Authentication:** Users are authenticated using securely hashed and encrypted master passwords.


## Contribution

Contributions are welcome! If you find any issues or have suggestions for improvements, feel free to open an issue or submit a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

