import nmap
from datetime import datetime
from database.mongo_db import db
from bson import ObjectId

# Safe ports
SAFE_PORTS = {5000, 7000, 9000, 27017, 49281, 59928}  

# Initialize Nmap scanner
try:
    nm = nmap.PortScanner()
except Exception as e:
    print(f"ERROR: Nmap is not installed or not in PATH: {e}")

def scan_network(target="127.0.0.1", arguments="-p- -T4"):
    try:
        print(f"Scanning {target} with arguments: {arguments}")
        nm.scan(hosts=target, arguments=arguments)

        if not nm.all_hosts():
            print("No hosts found.")
            return []

        scan_results = []
        detected_threats = []

        for host in nm.all_hosts():
            log_entry = {
                "timestamp": datetime.utcnow().isoformat(),
                "host": host,
                "state": nm[host].state(),
                "ports": []
            }

            for proto in nm[host].all_protocols():
                for port in nm[host][proto]:
                    port_info = {
                        "port": port,
                        "protocol": proto,
                        "state": nm[host][proto][port]['state'],
                        "service": nm[host][proto][port].get('name', 'unknown')
                    }

                    log_entry["ports"].append(port_info)

                    # If port is not in SAFE_PORTS, flag it as suspicious
                    if port not in SAFE_PORTS:
                        detected_threats.append({
                            "timestamp": log_entry["timestamp"],
                            "host": host,
                            "port": port,
                            "service": port_info["service"],
                            "status": "UNAUTHORIZED PORT DETECTED"
                        })

            scan_results.append(log_entry)

        # Store scan results in MongoDB & get inserted ID
        scan_record = {"scan_results": scan_results, "timestamp": datetime.utcnow().isoformat()}
        inserted_id = db.nmap_logs.insert_one(scan_record).inserted_id

        # If threats were detected, store them separately
        if detected_threats:
            for threat in detected_threats:
                threat["_id"] = str(ObjectId())  # Convert ObjectId to string
            db.nmap_threats.insert_many(detected_threats)
            print(f"{len(detected_threats)} THREATS DETECTED! Logged to MongoDB database.")

        return {
            "scan_results": scan_results,
            "threats": detected_threats,
            "_id": str(inserted_id)  # Convert ObjectId to string before returning
        }

    except Exception as e:
        print(f"Nmap Scan Error: {str(e)}")
        return None