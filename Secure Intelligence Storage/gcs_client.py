from google.cloud import storage  # Import GCS client
import os

# Set GCS credentials
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = '/Users/abdul.nafey18/Library/CloudStorage/OneDrive-NationalCollegeofIreland/Computing Project/Secure-Intelligence-Storage/Secure Intelligence Storage/striking-decker-442010-s7-463ceb9f2989.json'  

# GCS bucket name
GCS_BUCKET_NAME = 'secure-intelligence-storage'  # Replace with your actual bucket name

# Function to initialize GCS client
def get_gcs_client():
    return storage.Client()