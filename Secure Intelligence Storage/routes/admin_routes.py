import os, joblib, re
import pandas as pd
from flask import request, jsonify, redirect, url_for, flash
from security.nmap_scanner import scan_network
from database.mongo_db import db  # Import MongoDB connection

def admin_routes(app):
    @app.route('/get_logs/<log_type>', methods=['GET'])
    def get_logs(log_type):
        logs = list(db.logs.find({"type": log_type}, {"_id": 0}))  # Fetch logs of selected type
        return jsonify(logs)
    
    @app.route('/scan_network', methods=['POST'])
    def trigger_scan():
        print("[INFO] Scan request received!")

        try:
            scan_data = scan_network()  # Scan EC2 instance

            if scan_data:
                scan_results = scan_data["scan_results"]
                detected_threats = scan_data["threats"]

                print(f"[INFO] Scan Successful! {len(scan_results)} hosts scanned.")

                return jsonify({
                    "status": "success",
                    "results": scan_results,
                    "threats": detected_threats
                })

            else:
                print("[ERROR] Scan failed - No results.")
                return jsonify({"status": "error", "message": "Scan failed"}), 500

        except Exception as e:
            print(f"[ERROR] Exception in scan: {str(e)}")
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route('/get_threat_logs', methods=['GET'])
    def get_threat_logs():
        logs = list(db.nmap_threats.find({}, {"_id": 0}))  
        return jsonify(logs)

    @app.route('/toggle_ip_block', methods=['POST'])
    def toggle_ip_block():
        ip = request.form.get('ip')
        if not ip:
            flash("IP address required!", "error")
            return redirect(url_for('nmap_scanner'))

        # Check current block status
        threat = db.nmap_threats.find_one({"host": ip})
        if not threat:
            flash(f"No record found for {ip}", "error")
            return redirect(url_for('nmap_scanner'))

        if threat["status"] == "Blocked":
            # Unblock IP
            os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")
            db.nmap_threats.update_one({"host": ip}, {"$set": {"status": "Unblocked"}})
            flash(f"IP {ip} has been unblocked!", "success")
        else:
            # Block IP
            os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
            db.nmap_threats.update_one({"host": ip}, {"$set": {"status": "Blocked"}})
            flash(f"IP {ip} has been blocked!", "success")

        return redirect(url_for('nmap_scanner'))
    
    @app.route("/get_file_anomalies", methods=["GET"])
    def get_file_anomalies():
        try:
            # Load model + encoders
            base_dir = os.path.join(os.path.dirname(__file__), "..", "security")
            model = joblib.load(os.path.join(base_dir, "file_anomaly_model.pkl"))
            le_user = joblib.load(os.path.join(base_dir, "le_user.pkl"))
            le_action = joblib.load(os.path.join(base_dir, "le_action.pkl"))

            # Fetch last 100 file activity logs
            raw_logs = list(db.logs.find({"type": "INFO"}).sort("timestamp", -1).limit(100))

            data = []
            for log in raw_logs:
                msg = log["message"]
                timestamp = log["timestamp"].strftime("%Y-%m-%d %H:%M:%S")

                # Match upload/download/shared formats
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

            if not data:
                return jsonify([])

            df = pd.DataFrame(data)
            df['user_encoded'] = le_user.transform(df['user'].fillna('unknown'))
            df['action_encoded'] = le_action.transform(df['action'].fillna('unknown'))

            df['anomaly'] = model.predict(df[['user_encoded', 'action_encoded']])
            anomalies = df[df['anomaly'] == -1]

            results = anomalies[['timestamp', 'user', 'action', 'file_name', 'recipient']].to_dict(orient='records')
            return jsonify(results)

        except Exception as e:
            print("[ERROR in Mongo-based anomaly detection]:", str(e))
            return jsonify({"error": str(e)}), 500
