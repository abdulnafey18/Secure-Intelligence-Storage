from google.cloud import storage  # Import the Google Cloud Storage client library
import os  # Import the module to work with environment variables

# Set the path to the Google Cloud credentials JSON file 
# This file is required to authenticate with Google Cloud Storage-
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = '/home/ec2-user/striking-decker-442010-s7-01f1e626075b.json' 

# Name of the Google Cloud Storage bucket used for storing uploaded files
GCS_BUCKET_NAME = 'secure-intelligence-storage'  

# Function to initialize and return a Google Cloud Storage client
# This client is used to interact with the specified GCS bucket
def get_gcs_client():
    return storage.Client()
