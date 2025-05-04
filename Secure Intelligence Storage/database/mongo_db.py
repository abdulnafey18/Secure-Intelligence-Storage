from pymongo import MongoClient  # Import MongoDB client for interacting with MongoDB.
import os  # Import the `os` module for handling file paths and environment variables.
from datetime import datetime, timezone
datetime.now(timezone.utc)

# Connect to MongoDB
mongo_uri = os.getenv(
    "MONGO_URI",
    "mongodb://admin:ViSiOn%402020@localhost:27017/secure_intelligence_storage?authSource=admin"
)
client = MongoClient(mongo_uri)
db = client['secure_intelligence_storage']

# Define the folder path where uploaded files will be stored
uploads_folder = os.path.join('Secure Intelligence Storage', 'uploads')

# Collection for storing shared file metadata
shared_files = db['shared_files']

# Collection for storing logs
logs_collection = db['logs']

# Function to add logs to MongoDB
def add_log(log_type, message, ip=None):
    log_entry = {
        "type": log_type,
        "message": message,
        "timestamp": datetime.now(timezone.utc)
    }

    if ip:
        log_entry["ip"] = ip

    logs_collection.insert_one(log_entry)

def close_client():
    client.close()
