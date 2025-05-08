# Secure-Intelligence-Storage

A secure cloud-based file storage and sharing platform with cybersecurity as its core focus. Designed for small-medium sized buisnesses, this platform integrates advanced file management and security mechanisms such as encryption, intrusion detection, anomaly detection, and automated threat response to protect sensitive files and defend against modern cyber threats.

## Features
1) User Authentication: Secure login system using Flask, SQLite and Multi-Factor Authentication (MFA).
2) Encrypted File Storage: AES Encryption used before uploading files to Google Cloud Storage.
3) Secure Sharing: Share files securely between users with re-encryption and access control.
4) Intrusion Detection System (IDS): Nmap-based IP scanning and real-time threat detection.
5) Anomaly Detection: Isolation Forest ML model to detect unusual file access behavior.
6) Threat Response: IPTables used to block malicious IP addresses in real-time.
7) Admin Dashboard: View logs, blocked IPs, anomaly reports and manage threats.
8) Dockerized MongoDB: Secure and containerized metadata storage.
9) CI/CD Workflow: GitHub Actions used for Continuous Delivery to AWS EC2.

## Technologies Used
1) AWS (EC2) - Cloud hosting platform for secure and scalable application deployment
2) Nmap - Scans network and detects suspicious IPs and open ports
3) Machine Learning (Isolation Forest) - Detects file anomalies for suspicious behaviour
4) AES - Encrypts files for confidentiality before upload or sharing
5) MongoDB (Docker) - Runs in a Docker container on AWS EC2 to store file metadata
6) Google Cloud Storage – Cloud platform for encrypted files to be stored
7) SQLite - Database that stores user credentials and MFA authentication secrets
8) Google Authenticator - Provides MFA via time-based OTPs to enhance login security
9) Visual Studio Code - Main code editor used for development and debugging
10) GitHub - Manages source code with version control and CI/CD during development
11) Python (Flask) - Backend framework powering API routes and handling user operations
12) HTML + CSS - Builds responsive and user-friendly frontend interfaces
13) JavaScript (JS) - Adds interactivity and handles user actions on frontend web pages

## Setup and Deployment
1) Clone the repo
git clone https://github.com/abdulnafey18/Secure-Intelligence-Storage.git
cd Secure-Intelligence-Storage

2) Install dependencies
pip install -r requirements.txt

3) Configure environment variables
export GOOGLE_APPLICATION_CREDENTIALS="path_to_your_gcp_credentials.json"
export DB_PATH="database/auth.db"
export KEY_FILE_PATH="database/key.key"

4) Start Flask server
python3 run.py

## Future Improvements
1) Antivirus-like advanced threat detection and response module
2) Real-time Nmap IP scanning without manual trigger
3) Per-user anomaly detection models
4) AI based recommendations such as suggest file password rotation

## License
This project is for educational purposes (National College of Ireland - Computing Project)