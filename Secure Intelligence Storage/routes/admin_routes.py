from flask import request, jsonify
from security.nmap_scanner import scan_network
from database.mongo_db import db  # Import MongoDB connection

def admin_routes(app):
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
