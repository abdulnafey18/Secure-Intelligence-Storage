from pymongo import MongoClient
import os

# MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client['secure_intelligence_storage']

uploads_folder = os.path.join('Secure Intelligence Storage', 'uploads')

# Iterate through files in uploads folder
for filename in os.listdir(uploads_folder):
    # Find the user associated with this file (assuming you have filename mapping)
    user_record = db.users.find_one({'email': {'$exists': True}})  # Fetch user email from users collection
    
    # Extract email if found
    email = user_record['email'] if user_record else 'unknown'

    # Insert the file record if it does not exist in the uploads collection
    if not db.files.find_one({'filename': filename}):
        db.files.insert_one({
            'filename': filename,
            'email': email
        })

access_requests = db['access_requests']
shared_files = db['shared_files']