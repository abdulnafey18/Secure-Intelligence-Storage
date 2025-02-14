import sqlite3  # SQLite for database operations
from cryptography.fernet import Fernet  # Encryption
import os  # Environment variable handling

# Secure Paths Using Environment Variable
KEY_FILE = "/home/ec2-user/Secure-Intelligence-Storage/Secure Intelligence Storage/database/encryption_key.key"
DB_PATH = os.getenv("DB_PATH", "/home/ec2-user/Secure-Intelligence-Storage/Secure Intelligence Storage/database/secure_intelligence_storage.db")

# Load the encryption key securely
if os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as key_file:
        ENCRYPTION_KEY = key_file.read()
else:
    ENCRYPTION_KEY = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(ENCRYPTION_KEY)
    os.chmod(KEY_FILE, 0o600)  # Restrict file access

cipher_suite = Fernet(ENCRYPTION_KEY)

# Secure database connection
def get_db_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row  
    return connection

# Initialize database securely
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

# Insert a new user securely
def insert_user(email, password_hash):
    connection = get_db_connection()
    with connection:
        connection.execute(
            'INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)',
            (email, password_hash, 'user')
        )
    connection.close()

# Fetch user securely
def find_user_by_email(email):
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute(
        'SELECT id, email, password_hash, mfa_secret, role FROM users WHERE email = ?',
        (email,)
    )
    row = cursor.fetchone()
    connection.close()
    return dict(row) if row else None 

# Encrypt and store MFA secret
def update_mfa_secret(email, mfa_secret):
    encrypted_secret = encrypt_secret(mfa_secret)
    connection = get_db_connection()
    with connection:
        connection.execute(
            'UPDATE users SET mfa_secret = ? WHERE email = ?',
            (encrypted_secret, email)
        )
    connection.close()

# Encryption
def encrypt_secret(secret):
    return cipher_suite.encrypt(secret.encode())

# Decryption
def decrypt_secret(encrypted_secret):
    return cipher_suite.decrypt(encrypted_secret).decode()

# Delete user securely
def delete_user_by_id(user_id):
    connection = get_db_connection()
    with connection:
        connection.execute('DELETE FROM users WHERE id = ?', (user_id,))
    connection.close()
