import os, joblib, re, ipaddress
import pandas as pd
import numpy as np
from flask import request, jsonify, redirect, url_for, flash, send_file
from security.nmap_scanner import scan_network
from database.mongo_db import db 
from security.suspicious_score import calculate_suspicious_score
from fpdf import FPDF
from datetime import datetime

def admin_routes(app):
    # Route for fetching application logs
    @app.route('/get_logs/<log_type>', methods=['GET'])
    def get_logs(log_type):
        logs = list(db.logs.find({"type": log_type}, {"_id": 0}))  # Fetch logs of selected type
        return jsonify(logs)
    # Route for triggering Nmap network vulnerability scan
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
    # Route for fetching threat detection logs
    @app.route('/get_threat_logs', methods=['GET'])
    def get_threat_logs():
        logs = list(db.nmap_threats.find({}, {"_id": 0}))  
        return jsonify(logs)
    # Route to toggle IP block/unblock using iptables firewall
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
    # Route for detecting file activity anomalies using trained ML model
    @app.route("/get_file_anomalies", methods=["GET"])
    def get_file_anomalies():
        try:
            # Load model + encoders
            base_dir = os.path.join(os.path.dirname(__file__), "..", "security")
            model = joblib.load(os.path.join(base_dir, "file_anomaly_model.pkl"))
            le_user = joblib.load(os.path.join(base_dir, "le_user.pkl"))
            le_action = joblib.load(os.path.join(base_dir, "le_action.pkl"))

            # Fetch recent logs
            raw_logs = list(db.logs.find({"type": "INFO"}).sort("timestamp", -1).limit(100))

            data = []
            for log in raw_logs:
                msg = log["message"]
                timestamp_obj = log["timestamp"]
                timestamp = timestamp_obj.strftime("%Y-%m-%d %H:%M:%S")
                hour = timestamp_obj.hour
                file_size = log.get("file_size", 0)
                ip_raw = log.get("ip", "0.0.0.0")

                try:
                    ip_encoded = int(ipaddress.IPv4Address(ip_raw))
                except:
                    ip_encoded = 0

                # Parse logs
                upload = re.match(r"User (.*?) uploaded file: (.+)", msg)
                download = re.match(r"User (.*?) downloaded file: (.+)", msg)
                shared = re.match(r"User (.*?) shared file: (.+?) with (.+)", msg)
                download_shared = re.match(r"User (.*?) downloaded shared file: (.+)", msg)

                if upload:
                    user, file = upload.groups()
                    data.append({"timestamp": timestamp, "user": user, "action": "Upload", "file_name": file, "recipient": "", "hour": hour, "file_size": file_size, "ip_raw": ip_raw, "ip_encoded": ip_encoded})
                elif download:
                    user, file = download.groups()
                    data.append({"timestamp": timestamp, "user": user, "action": "Download", "file_name": file, "recipient": "", "hour": hour, "file_size": file_size, "ip_raw": ip_raw, "ip_encoded": ip_encoded})
                elif shared:
                    user, file, recipient = shared.groups()
                    data.append({"timestamp": timestamp, "user": user, "action": "Share", "file_name": file, "recipient": recipient, "hour": hour, "file_size": file_size, "ip_raw": ip_raw, "ip_encoded": ip_encoded})
                elif download_shared:
                    user, file = download_shared.groups()
                    data.append({"timestamp": timestamp, "user": user, "action": "DownloadShared", "file_name": file, "recipient": "", "hour": hour, "file_size": file_size, "ip_raw": ip_raw, "ip_encoded": ip_encoded})

            if not data:
                return jsonify([])

            # Prepare dataframe
            df = pd.DataFrame(data)

            # Handle unseen labels safely
            df['user'] = df['user'].apply(lambda x: x if x in le_user.classes_ else 'unknown')
            df['action'] = df['action'].apply(lambda x: x if x in le_action.classes_ else 'unknown')

            if 'unknown' not in le_user.classes_:
                le_user.classes_ = np.append(le_user.classes_, 'unknown')
            if 'unknown' not in le_action.classes_:
                le_action.classes_ = np.append(le_action.classes_, 'unknown')

            df['user_encoded'] = le_user.transform(df['user'])
            df['action_encoded'] = le_action.transform(df['action'])

            # Predict anomalies
            df['anomaly'] = model.predict(df[['user_encoded', 'action_encoded', 'hour', 'file_size', 'ip_encoded']])
            anomalies = df[df['anomaly'] == -1]

            anomalies['suspicious_score'] = anomalies.apply(calculate_suspicious_score, axis=1)

            # Format results
            results = anomalies[['timestamp', 'user', 'action', 'file_name', 'recipient', 'suspicious_score']].to_dict(orient='records')
            return jsonify(results)

        except Exception as e:
            print("[ERROR in Mongo-based anomaly detection]:", str(e))
            return jsonify({"error": str(e)}), 500
    # Route to generate and download a PDF report of file anomalies
    @app.route("/generate_anomaly_report")
    def generate_anomaly_report():
        # Loading ML model and encoders from the security directory
        base_dir = os.path.join(os.path.dirname(__file__), "..", "security")
        model = joblib.load(os.path.join(base_dir, "file_anomaly_model.pkl"))
        le_user = joblib.load(os.path.join(base_dir, "le_user.pkl"))
        le_action = joblib.load(os.path.join(base_dir, "le_action.pkl"))

        raw_logs = list(db.logs.find({"type": "INFO"}).sort("timestamp", -1).limit(100))

        data = []
        for log in raw_logs:
            # Extracting key fields from each log
            msg = log["message"]
            timestamp_obj = log["timestamp"]
            timestamp = timestamp_obj.strftime("%Y-%m-%d %H:%M:%S")
            hour = timestamp_obj.hour
            file_size = log.get("file_size", 0)
            ip_raw = log.get("ip", "0.0.0.0")
            # Converting IP to integer format for analysis
            try:
                ip_encoded = int(ipaddress.IPv4Address(ip_raw))
            except:
                ip_encoded = 0
            # Parsing log message to extract user action
            upload = re.match(r"User (.*?) uploaded file: (.+)", msg)
            download = re.match(r"User (.*?) downloaded file: (.+)", msg)
            shared = re.match(r"User (.*?) shared file: (.+?) with (.+)", msg)
            download_shared = re.match(r"User (.*?) downloaded shared file: (.+)", msg)
            # Categorizing action and structure data row accordingly
            if upload:
                user, file = upload.groups()
                data.append({"timestamp": timestamp, "user": user, "action": "Upload", "file_name": file, "recipient": "", "hour": hour, "file_size": file_size, "ip_raw": ip_raw, "ip_encoded": ip_encoded})
            elif download:
                user, file = download.groups()
                data.append({"timestamp": timestamp, "user": user, "action": "Download", "file_name": file, "recipient": "", "hour": hour, "file_size": file_size, "ip_raw": ip_raw, "ip_encoded": ip_encoded})
            elif shared:
                user, file, recipient = shared.groups()
                data.append({"timestamp": timestamp, "user": user, "action": "Share", "file_name": file, "recipient": recipient, "hour": hour, "file_size": file_size, "ip_raw": ip_raw, "ip_encoded": ip_encoded})
            elif download_shared:
                user, file = download_shared.groups()
                data.append({"timestamp": timestamp, "user": user, "action": "DownloadShared", "file_name": file, "recipient": "", "hour": hour, "file_size": file_size, "ip_raw": ip_raw, "ip_encoded": ip_encoded})

        if not data:
            return "No anomalies found."

        df = pd.DataFrame(data)
        df['user'] = df['user'].apply(lambda x: x if x in le_user.classes_ else 'unknown')
        df['action'] = df['action'].apply(lambda x: x if x in le_action.classes_ else 'unknown')
        if 'unknown' not in le_user.classes_:
            le_user.classes_ = np.append(le_user.classes_, 'unknown')
        if 'unknown' not in le_action.classes_:
            le_action.classes_ = np.append(le_action.classes_, 'unknown')
        # Encoding categorical values
        df['user_encoded'] = le_user.transform(df['user'])
        df['action_encoded'] = le_action.transform(df['action'])
        # Applying anomaly detection model
        df['anomaly'] = model.predict(df[['user_encoded', 'action_encoded', 'hour', 'file_size', 'ip_encoded']])
        anomalies = df[df['anomaly'] == -1]
        # Calculating custom suspicious score for each anomaly
        anomalies['suspicious_score'] = anomalies.apply(calculate_suspicious_score, axis=1)
        # Generating PDF report
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", 'B', 16)
        pdf.cell(0, 12, "Secure Intelligence Storage", ln=True, align='C')
        pdf.set_font("Arial", '', 12)
        pdf.cell(0, 10, "Anomaly Detection Report", ln=True, align='C')
        pdf.cell(0, 10, f"Generated On: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align='C')
        pdf.ln(6)

        headers = ["Timestamp", "User", "Action", "File", "Score", "IP", "Size"]
        col_widths = [32, 35, 30, 40, 10, 30, 15]  
        row_height = 6

        pdf.set_fill_color(200, 220, 255)
        pdf.set_font("Arial", 'B', 9)

        # Rendering headers
        for i, header in enumerate(headers):
            pdf.cell(col_widths[i], row_height + 2, header, 1, 0, 'C', True)
        pdf.ln()

        pdf.set_font("Arial", '', 8)
        for _, row in anomalies.iterrows():
            row_data = [
                row['timestamp'],
                row['user'],
                row['action'],
                row['file_name'],
                str(row['suspicious_score']),
                row['ip_raw'],
                str(row['file_size']),
            ]

            x_start = pdf.get_x()
            y_start = pdf.get_y()
            max_y = y_start

            # Tracking height of each cell rendered
            heights = []
            for i, cell in enumerate(row_data):
                pdf.set_xy(x_start + sum(col_widths[:i]), y_start)
                pdf.multi_cell(col_widths[i], row_height, str(cell), 1)
                heights.append(pdf.get_y() - y_start)

            # Move to next line at max height
            pdf.set_y(y_start + max(heights))

        pdf_file = os.path.join(base_dir, "anomaly_report.pdf")
        pdf.output(pdf_file)

        return send_file(pdf_file, as_attachment=True)
