import os
import pandas as pd
import joblib
import re
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
from database.mongo_db import db  # your existing connection

# Get current script directory
base_dir = os.path.dirname(os.path.abspath(__file__))

# Load last 500 file activity logs from MongoDB
raw_logs = list(db.logs.find({"type": "INFO"}).sort("timestamp", -1).limit(500))

data = []
for log in raw_logs:
    msg = log["message"]
    timestamp = log["timestamp"].strftime("%Y-%m-%d %H:%M:%S")

    upload = re.match(r"User (.*?) uploaded file: (.+)", msg)
    download = re.match(r"User (.*?) downloaded file: (.+)", msg)
    shared = re.match(r"User (.*?) shared file: (.+?) with (.+)", msg)
    download_shared = re.match(r"User (.*?) downloaded shared file: (.+)", msg)

    if upload:
        user, file = upload.groups()
        data.append({"timestamp": timestamp, "user": user, "action": "Upload", "file_name": file, "recipient": ""})
    elif download:
        user, file = download.groups()
        data.append({"timestamp": timestamp, "user": user, "action": "Download", "file_name": file, "recipient": ""})
    elif shared:
        user, file, recipient = shared.groups()
        data.append({"timestamp": timestamp, "user": user, "action": "Share", "file_name": file, "recipient": recipient})
    elif download_shared:
        user, file = download_shared.groups()
        data.append({"timestamp": timestamp, "user": user, "action": "DownloadShared", "file_name": file, "recipient": ""})

# Convert to DataFrame
df = pd.DataFrame(data)
df.dropna(inplace=True)

# Encode features
le_user = LabelEncoder()
le_action = LabelEncoder()

df['user_encoded'] = le_user.fit_transform(df['user'])
df['action_encoded'] = le_action.fit_transform(df['action'])

features = df[['user_encoded', 'action_encoded']]

# Train Isolation Forest
model = IsolationForest(contamination=0.1, random_state=42)
model.fit(features)

# Save model and encoders
joblib.dump(model, os.path.join(base_dir, 'file_anomaly_model.pkl'))
joblib.dump(le_user, os.path.join(base_dir, 'le_user.pkl'))
joblib.dump(le_action, os.path.join(base_dir, 'le_action.pkl'))

print("Anomaly detection model retrained and saved from MongoDB logs.")