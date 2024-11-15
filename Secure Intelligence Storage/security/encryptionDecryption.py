# Reference for use of advanced encryption using CBC mode:
# https://nitratine.net/blog/post/python-encryption-and-decryption-with-pycryptodome/?_gl=1*18sme64*_gcl_au*MTIwNDYzOTYzMS4xNzI5Mjg4Njgy*_ga*MTk3NDk1OTcyOC4xNzI5Mjg4Njgy*_ga_MBTGG7KX5Y*MTczMTY3OTIwNC40LjEuMTczMTY3OTMyMC4xMS4wLjIxMDE4NjU3Nw..#cbc-example 
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2

# Derive key from password using PBKDF2
def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=32)  # AES key length is 32 bytes (256 bits)

# Encrypt file using AES in CBC mode
def encrypt_file(file_path, file_password):
    # Generate a random salt
    salt = os.urandom(16)

    # Derive key using PBKDF2
    key = derive_key(file_password.encode('utf-8'), salt)

    # Initialize AES cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC)

    # Read plaintext from file
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    # Pad plaintext to be multiple of AES block size
    padded_plaintext = pad(plaintext, AES.block_size)

    # Encrypt plaintext
    ciphertext = cipher.encrypt(padded_plaintext)

    # Write salt and ciphertext to encrypted file
    with open(file_path + '.enc', 'wb') as f:
        f.write(salt)
        f.write(ciphertext)

def decrypt_file(file_path, file_password):
    try:
        # Read salt and ciphertext from encrypted file
        with open(file_path, 'rb') as f:
            salt = f.read(16)
            ciphertext = f.read()

        # Derive key using PBKDF2
        key = derive_key(file_password.encode('utf-8'), salt)

        # Initialize AES cipher in CBC mode
        cipher = AES.new(key, AES.MODE_CBC)

        # Decrypt ciphertext
        plaintext = cipher.decrypt(ciphertext)

        # Unpad decrypted plaintext
        unpadded_plaintext = unpad(plaintext, AES.block_size)

        # Write decrypted plaintext to file
        with open(file_path[:-4], 'wb') as f:  # Remove '.enc' extension from filename
            f.write(unpadded_plaintext)

        print("Decryption successful.")
    except Exception as e:
        print("Decryption failed:", e)