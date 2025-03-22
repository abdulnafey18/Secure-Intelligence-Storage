import re
import csv
from datetime import datetime

# log lines
log_lines = [
    "Thu, 20 Mar 2025 14:14:59 GMT - User abdul.nafey18education@gmail.com uploaded file: abdul.nafey18educationmail.com_Abdul_Nafey_x21116261_TABA.pdf",
    "Thu, 20 Mar 2025 14:15:12 GMT - User abdul.nafey18education@gmail.com downloaded file: abdul.nafey18educationmail.com_Abdul_Nafey_x21116261_TABA.pdf.enc",
    "Thu, 20 Mar 2025 14:17:28 GMT - User abdul.nafey18education@gmail.com shared file: abdul.nafey18educationmail.com_Abdul_Nafey_x21116261_TABA.pdf.enc with anafey@dublinport.ie",
    "Thu, 20 Mar 2025 14:18:13 GMT - User anafey@dublinport.ie downloaded shared file: shared_abdul.nafey18educationmail.com_Abdul_Nafey_x21116261_TABA.pdf.enc",
    "Thu, 20 Mar 2025 14:38:38 GMT - User anafey@dublinport.ie uploaded file: anafeydublinport.ie_Cover_Letter.pdf",
    "Thu, 20 Mar 2025 14:38:52 GMT - User anafey@dublinport.ie downloaded file: anafeydublinport.ie_Cover_Letter.pdf.enc",
    "Thu, 20 Mar 2025 14:39:15 GMT - User anafey@dublinport.ie shared file: anafeydublinport.ie_Cover_Letter.pdf.enc with abdul.nafey18education@gmail.com",
    "Thu, 20 Mar 2025 14:39:58 GMT - User abdul.nafey18education@gmail.com downloaded shared file: shared_anafeydublinport.ie_Cover_Letter.pdf.enc"
]

# Output CSV filename
output_file = 'structured_logs.csv'

# Prepare output
structured_data = []

# Regex patterns
upload_pattern = r"User (.*?) uploaded file: (.+)"
download_pattern = r"User (.*?) downloaded file: (.+)"
download_shared_pattern = r"User (.*?) downloaded shared file: (.+)"
share_pattern = r"User (.*?) shared file: (.+?) with (.+)"

for line in log_lines:
    # Split timestamp and message
    if " - " in line:
        timestamp, message = line.split(" - ", 1)
    else:
        continue

    row = {
        'timestamp': timestamp.strip(),
        'user': '',
        'action': '',
        'file_name': '',
        'recipient': ''
    }

    if match := re.match(upload_pattern, message):
        row['user'], row['file_name'] = match.groups()
        row['action'] = 'Upload'
    elif match := re.match(download_pattern, message):
        row['user'], row['file_name'] = match.groups()
        row['action'] = 'Download'
    elif match := re.match(download_shared_pattern, message):
        row['user'], row['file_name'] = match.groups()
        row['action'] = 'DownloadShared'
    elif match := re.match(share_pattern, message):
        row['user'], row['file_name'], row['recipient'] = match.groups()
        row['action'] = 'Share'
    else:
        continue  # unrecognized format

    structured_data.append(row)

# Write to CSV
with open(output_file, 'w', newline='') as csvfile:
    fieldnames = ['timestamp', 'user', 'action', 'file_name', 'recipient']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(structured_data)

print(f"Structured log saved to: {output_file}")