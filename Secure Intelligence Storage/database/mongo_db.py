from pymongo import MongoClient  # Import MongoDB client for interacting with MongoDB.
import os  # Import the `os` module for handling file paths and environment variables.
from datetime import datetime  # Import datetime for timestamping logs.

# Connect to MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['secure_intelligence_storage']

# Define the folder path where uploaded files will be stored
uploads_folder = os.path.join('Secure Intelligence Storage', 'uploads')

# Collection for storing shared file metadata
shared_files = db['shared_files']

# Collection for storing logs
logs_collection = db['logs']

# Function to add logs to MongoDB
def add_log(log_type, message):
    log_entry = {
        "type": log_type,  
        "message": message,
        "timestamp": datetime.utcnow()
    }
    logs_collection.insert_one(log_entry)  # Insert log into MongoDB