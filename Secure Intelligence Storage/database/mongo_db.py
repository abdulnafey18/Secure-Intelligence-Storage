from pymongo import MongoClient

# MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client['secure_intelligence_storage']

access_requests = db['access_requests']
shared_files = db['shared_files']