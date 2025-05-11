import os
os.environ["MONGO_URI"] = "mongodb://localhost:27017/"
import unittest
from database import mongo_db
from datetime import datetime, timezone
datetime.now(timezone.utc)

class TestMongoDB(unittest.TestCase):

    @classmethod
    def tearDownClass(cls):
        mongo_db.close_client()

    def setUp(self):
        mongo_db.logs_collection.delete_many({})
        mongo_db.db.files.delete_many({})

    def test_add_info_log(self):
        mongo_db.add_log("INFO", "Test log entry")
        log = mongo_db.logs_collection.find_one({"message": "Test log entry"})
        self.assertIsNotNone(log)
        self.assertEqual(log["type"], "INFO")

    def test_add_log_with_ip_and_size(self):
        mongo_db.add_log("WARNING", "Suspicious download", ip="127.0.0.1")
        log = mongo_db.logs_collection.find_one({"message": "Suspicious download"})
        self.assertIsNotNone(log)
        self.assertEqual(log["ip"], "127.0.0.1")

    def test_log_has_timestamp(self):
        mongo_db.add_log("INFO", "Timestamp check")
        log = mongo_db.logs_collection.find_one({"message": "Timestamp check"})
        self.assertIn("timestamp", log)

    def test_insert_file_metadata(self):
        test_file = {
            'email': 'user@example.com',
            'filename': 'example_file.enc',
            'upload_time': datetime.now(timezone.utc).isoformat()
        }
        mongo_db.db.files.insert_one(test_file)
        file_entry = mongo_db.db.files.find_one({'filename': 'example_file.enc'})
        self.assertIsNotNone(file_entry)
        self.assertEqual(file_entry['email'], 'user@example.com')

if __name__ == '__main__':
    unittest.main()