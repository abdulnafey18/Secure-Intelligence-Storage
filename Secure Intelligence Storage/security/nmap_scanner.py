import os
import socket
import nmap
from datetime import datetime, timedelta
from database.mongo_db import db
from bson import ObjectId

# Define safe ports (Ports that should NOT be flagged)
SAFE_PORTS = {22, 5000, 27017, 44371}

# Initialize Nmap scanner
try:
    nm = nmap.PortScanner()
except Exception as e:
    print(f"ERROR: Nmap is not installed or not in PATH: {e}")

def detect_external_scans():
    """
    Detects real external scans by checking active TCP connections, ignoring local/EC2 scans.
    """
    print(" Running detect_external_scans()...")

    # Get active TCP connections
    netstat_output = os.popen("sudo netstat -tn").read()
    
    # Get EC2 Private & Public IPs
    instance_ip = socket.gethostbyname(socket.gethostname())  
    instance_public_ip = os.popen("curl -s http://169.254.169.254/latest/meta-data/public-ipv4").read().strip()

    suspicious_ips = {}

    for line in netstat_output.split("\n"):
        parts = line.split()
        if len(parts) > 4 and parts[0].startswith("tcp"):
            ip_port = parts[4]
            if ":" in ip_port:
                ip = ip_port.rsplit(":", 1)[0]  # Extract IP only

                #  Ignore EC2’s own scans & internal traffic
                if ip in {instance_ip, instance_public_ip, "127.0.0.1"} or ip.startswith(("192.168.", "10.", "::1", "172.31.")):
                    print(f" Ignoring local/internal EC2 scan from {ip}")
                    continue  

                #  Prevent logging if the connection is from the same machine
                if ip == instance_ip or ip == instance_public_ip:
                    print(f"Prevented self-scan detection: {ip}")
                    continue  

                #  Initialize count before using it
                suspicious_ips[ip] = suspicious_ips.get(ip, 0) + 1

    detected_threats = []
    for ip, count in suspicious_ips.items():
        if count > 10:  # Increase threshold to reduce false positives
            recent_time_limit = datetime.utcnow() - timedelta(minutes=1)
            recent_threat = db.nmap_threats.find_one(
                {"host": ip, "timestamp": {"$gte": recent_time_limit.isoformat()}}
            )

            if recent_threat:
                print(f"Ignoring past attack from {ip}. Only logging active threats.")
                continue  # Prevent duplicate logs

            threat = {
                "_id": str(ObjectId()),
                "timestamp": datetime.utcnow().isoformat(),
                "host": ip,
                "port": "Multiple",
                "service": "Port Scanning Detected",
                "status": "POTENTIAL ATTACK"
            }
            detected_threats.append(threat)
            print(f" ALERT: Active external scan detected from {ip} (scanned {count} ports)")

    #  Store only new active threats in MongoDB
    if detected_threats:
        db.nmap_threats.insert_many(detected_threats)
        print(f"{len(detected_threats)} external scan attempts logged.")

def scan_network(target=None, arguments="-p- -T4"):
    """
    Runs an Nmap scan on the target and logs unauthorized open ports.
    Also calls detect_external_scans() to detect scanning attacks.
    """
    instance_ip = socket.gethostbyname(socket.gethostname())  
    instance_public_ip = os.popen("curl -s http://169.254.169.254/latest/meta-data/public-ipv4").read().strip()

    if target is None:
        target = instance_ip  # Default to scanning the local instance

    try:
        print(f" Scanning {target} with arguments: {arguments}")
        nm.scan(hosts=target, arguments=arguments)

        if not nm.all_hosts():
            print(" No hosts found.")
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

                    #  Ignore EC2's own scan results but log external threats
                    if host not in {instance_ip, instance_public_ip, "127.0.0.1"} and port not in SAFE_PORTS:
                        detected_threats.append({
                            "_id": str(ObjectId()),
                            "timestamp": log_entry["timestamp"],
                            "host": host,
                            "port": port,
                            "service": port_info["service"],
                            "status": "UNAUTHORIZED PORT DETECTED"
                        })

            scan_results.append(log_entry)

        #  Store scan results in MongoDB & get inserted ID
        scan_record = {"scan_results": scan_results, "timestamp": datetime.utcnow().isoformat()}
        inserted_id = db.nmap_logs.insert_one(scan_record).inserted_id

        #  Store detected threats in MongoDB
        if detected_threats:
            db.nmap_threats.insert_many(detected_threats)
            print(f"{len(detected_threats)} threats detected and logged.")

        # **Detect external scans**
        detect_external_scans()

        return {
            "scan_results": scan_results,
            "threats": detected_threats,
            "_id": str(inserted_id)  # Convert ObjectId to string before returning
        }

    except Exception as e:
        print(f" Nmap Scan Error: {str(e)}")
        return None
