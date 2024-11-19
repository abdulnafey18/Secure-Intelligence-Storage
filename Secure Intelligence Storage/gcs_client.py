from google.cloud import storage 
import os

# Set GCS credentials
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = '/Users/abdul.nafey18/Library/CloudStorage/OneDrive-NationalCollegeofIreland/Computing Project/striking-decker-442010-s7-e3ab11053dc2.json'  

# GCS bucket name
GCS_BUCKET_NAME = 'secure-intelligence-storage'  

# Function to initialize GCS client
def get_gcs_client():
    return storage.Client()