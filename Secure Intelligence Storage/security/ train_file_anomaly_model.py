import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import joblib
import os

# Get the current script directory (i.e. 'security/' folder)
base_dir = os.path.dirname(os.path.abspath(__file__))

# Load the CSV file from the same folder
csv_path = os.path.join(base_dir, "structured_logs.csv")
df = pd.read_csv(csv_path)

# Clean and encode
df.dropna(inplace=True)
le_user = LabelEncoder()
le_action = LabelEncoder()

df['user_encoded'] = le_user.fit_transform(df['user'])
df['action_encoded'] = le_action.fit_transform(df['action'])

features = df[['user_encoded', 'action_encoded']]

# Train Isolation Forest model
model = IsolationForest(contamination=0.1, random_state=42)
model.fit(features)

# Save model and encoders to the same folder
joblib.dump(model, os.path.join(base_dir, 'file_anomaly_model.pkl'))
joblib.dump(le_user, os.path.join(base_dir, 'le_user.pkl'))
joblib.dump(le_action, os.path.join(base_dir, 'le_action.pkl'))

print("Anomaly detection model trained and saved")