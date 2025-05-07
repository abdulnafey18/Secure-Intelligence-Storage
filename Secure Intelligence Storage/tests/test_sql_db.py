import os, sys
os.environ["DB_PATH"] = "tests/test_auth.db"
os.environ["KEY_FILE_PATH"] = "tests/test_key.key"
from database import sql_db
import unittest
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

class TestSQLDatabase(unittest.TestCase):

    def setUp(self):
        self.test_db_path = "tests/test_auth.db"

        # Ensure test directory exists
        os.makedirs("tests", exist_ok=True)

        # Initialize test DB
        sql_db.initialize_database()

    def tearDown(self):
        # Clean up test DB and key file
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        if os.path.exists(os.environ["KEY_FILE_PATH"]):
            os.remove(os.environ["KEY_FILE_PATH"])

    def test_insert_and_find_user(self):
        email = "test@example.com"
        password_hash = "hashedpassword"
        sql_db.insert_user(email, password_hash)
        user = sql_db.find_user_by_email(email)
        self.assertIsNotNone(user)
        self.assertEqual(user['email'], email)

    def test_encrypt_and_decrypt_secret(self):
        secret = "mysecret"
        encrypted = sql_db.encrypt_secret(secret)
        decrypted = sql_db.decrypt_secret(encrypted)
        self.assertEqual(decrypted, secret)

    def test_update_mfa_secret(self):
        email = "test@example.com"
        password_hash = "hashedpassword"
        secret = "mfa123"
        sql_db.insert_user(email, password_hash)
        sql_db.update_mfa_secret(email, secret)
        user = sql_db.find_user_by_email(email)
        decrypted = sql_db.decrypt_secret(user['mfa_secret'])
        self.assertEqual(decrypted, secret)

    def test_delete_user_by_id(self):
        email = "delete@test.com"
        password_hash = "hashedpassword"
        sql_db.insert_user(email, password_hash)
        user = sql_db.find_user_by_email(email)
        sql_db.delete_user_by_id(user['id'])
        deleted_user = sql_db.find_user_by_email(email)
        self.assertIsNone(deleted_user)

if __name__ == '__main__':
    unittest.main()