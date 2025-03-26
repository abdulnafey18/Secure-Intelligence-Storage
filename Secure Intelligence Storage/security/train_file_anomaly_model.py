import os
import pandas as pd
import joblib
import re
import sys
import ipaddress
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
from datetime import datetime

# Add project root to system path for module imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database.mongo_db import db # MongoDB database connection

# Defining base directory for saving model and encoders
base_dir = os.path.dirname(os.path.abspath(__file__))

# Load last 500 logs from MongoDB
raw_logs = list(db.logs.find({"type": "INFO"}).sort("timestamp", -1).limit(500))

data = []
for log in raw_logs:
    msg = log["message"]
    timestamp = log["timestamp"]
    hour = timestamp.hour
    # Extracting and encoding IP address
    ip_raw = log.get("ip", "0.0.0.0")
    try:
        ip_encoded = int(ipaddress.IPv4Address(ip_raw))
    except:
        ip_encoded = 0
    # Getting file size
    file_size = log.get("file_size", 0)
    # Using regex to identify log action type
    upload = re.match(r"User (.*?) uploaded file: (.+)", msg)
    download = re.match(r"User (.*?) downloaded file: (.+)", msg)
    shared = re.match(r"User (.*?) shared file: (.+?) with (.+)", msg)
    download_shared = re.match(r"User (.*?) downloaded shared file: (.+)", msg)
    # Structuring data based on action type
    if upload:
        user, file = upload.groups()
        data.append({"timestamp": timestamp, "user": user, "action": "Upload", "file_name": file, "recipient": "", "hour": hour, "file_size": file_size, "ip_encoded": ip_encoded})
    elif download:
        user, file = download.groups()
        data.append({"timestamp": timestamp, "user": user, "action": "Download", "file_name": file, "recipient": "", "hour": hour, "file_size": file_size, "ip_encoded": ip_encoded})
    elif shared:
        user, file, recipient = shared.groups()
        data.append({"timestamp": timestamp, "user": user, "action": "Share", "file_name": file, "recipient": recipient, "hour": hour, "file_size": file_size, "ip_encoded": ip_encoded})
    elif download_shared:
        user, file = download_shared.groups()
        data.append({"timestamp": timestamp, "user": user, "action": "DownloadShared", "file_name": file, "recipient": "", "hour": hour, "file_size": file_size, "ip_encoded": ip_encoded})
# Proceeding to training if data is available only
if data:
    df = pd.DataFrame(data)
    df.dropna(inplace=True) # Removing rows with missing values
    # Encode categorical columns for model input    
    le_user = LabelEncoder()
    le_action = LabelEncoder()

    df['user_encoded'] = le_user.fit_transform(df['user'])
    df['action_encoded'] = le_action.fit_transform(df['action'])
    # Selecting features for anomaly detection
    features = df[['user_encoded', 'action_encoded', 'hour', 'file_size', 'ip_encoded']]
    # Training Isolation Forest model (unsupervised anomaly detection)
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(features)
    # Saving model and encoders for future inference
    joblib.dump(model, os.path.join(base_dir, 'file_anomaly_model.pkl'))
    joblib.dump(le_user, os.path.join(base_dir, 'le_user.pkl'))
    joblib.dump(le_action, os.path.join(base_dir, 'le_action.pkl'))

    print("Anomaly detection model retrained and saved from MongoDB logs.")
else:
    print("No data available to train the model.")
