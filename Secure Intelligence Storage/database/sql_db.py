import sqlite3  # Import SQLite library for handling SQLite databases
from cryptography.fernet import Fernet  # Import Fernet for encryption and decryption of data
import os  # Import `os` module for handling environment variables and file paths

# Fetch the encryption key from the environment variables or generate a new one
# This key is used for encrypting and decrypting sensitive data like MFA secrets
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", Fernet.generate_key())  
cipher_suite = Fernet(ENCRYPTION_KEY)

# Establish a connection to the SQLite database file
# The database connection uses row factory to enable access to data by column names
def get_db_connection():
    connection = sqlite3.connect('secure_intelligence_storage.db')
    connection.row_factory = sqlite3.Row  
    return connection

# Create users tables in the SQLite database
# This table stores user information, including email, hashed password, MFA secrets, and roles
def initialize_database():
    connection = get_db_connection()
    with connection:
        connection.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                mfa_secret TEXT,
                role TEXT NOT NULL DEFAULT 'user'
            )
        ''')
    connection.close()

# Insert a new user into the 'users' table with their email, hashed password, and default user role
def insert_user(email, password_hash):
    connection = get_db_connection()
    with connection:
        connection.execute(
            'INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)',
            (email, password_hash, 'user')
        )
    connection.close()

# Find and return a user by their email address from the 'users' table
def find_user_by_email(email):
    connection = get_db_connection()
    user = connection.execute(
        'SELECT id, email, password_hash, mfa_secret, role FROM users WHERE email = ?',
        (email,)
    ).fetchone()
    connection.close()
    return user

# Update the MFA secret for a user, encrypting the secret before storing it in the database
def update_mfa_secret(email, mfa_secret):
    encrypted_secret = encrypt_secret(mfa_secret)
    connection = get_db_connection()
    with connection:
        connection.execute(
            'UPDATE users SET mfa_secret = ? WHERE email = ?',
            (encrypted_secret, email)
        )
    connection.close()

# Encrypt a given string using the encryption cipher (Fernet)
def encrypt_secret(secret):
    return cipher_suite.encrypt(secret.encode())

# Decrypt an encrypted string using the encryption cipher (Fernet)
def decrypt_secret(encrypted_secret):
    return cipher_suite.decrypt(encrypted_secret).decode()

# Delete a user from the 'users' table by their unique ID
def delete_user_by_id(user_id):
    connection = get_db_connection()
    with connection:
        connection.execute('DELETE FROM users WHERE id = ?', (user_id,))
    connection.close()