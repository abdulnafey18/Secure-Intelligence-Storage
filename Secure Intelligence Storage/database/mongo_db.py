from pymongo import MongoClient  # Import MongoDB client for interacting with MongoDB.
import os  # Import the `os` module for handling file paths and environment variables.

# Specify the database to be used in MongoDB, named 'secure_intelligence_storage'
client = MongoClient('mongodb://localhost:27017/')
db = client['secure_intelligence_storage']

# Define the folder path where uploaded files will be stored
uploads_folder = os.path.join('Secure Intelligence Storage', 'uploads')

# 'shared_files' to store information about files shared between users
shared_files = db['shared_files']