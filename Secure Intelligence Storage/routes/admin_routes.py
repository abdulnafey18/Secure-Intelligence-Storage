import os
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
