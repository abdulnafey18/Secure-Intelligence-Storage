import pandas as pd
import joblib
import os
from sklearn.exceptions import NotFittedError

# Get the current script directory
base_dir = os.path.dirname(os.path.abspath(__file__))

# Load structured log file
csv_path = os.path.join(base_dir, "structured_logs.csv")
df = pd.read_csv(csv_path)

# Load model and encoders
model = joblib.load(os.path.join(base_dir, "file_anomaly_model.pkl"))
le_user = joblib.load(os.path.join(base_dir, "le_user.pkl"))
le_action = joblib.load(os.path.join(base_dir, "le_action.pkl"))

# Clean and encode
df.dropna(inplace=True)
df['user_encoded'] = le_user.transform(df['user'].fillna('unknown'))
df['action_encoded'] = le_action.transform(df['action'].fillna('unknown'))

# Prepare features
features = df[['user_encoded', 'action_encoded']]

# Predict anomalies
try:
    df['anomaly'] = model.predict(features)
except NotFittedError:
    print("Model not fitted. Please retrain the model first")
    exit()

# Show anomalies
anomalies = df[df['anomaly'] == -1]
print("Detected Anomalies:")
print(anomalies[['timestamp', 'user', 'action', 'file_name', 'recipient']])