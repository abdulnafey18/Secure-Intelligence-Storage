import os
import socket
import nmap
from datetime import datetime, timedelta
from flask import request
from database.mongo_db import db
from bson import ObjectId

# Set of whitelisted IPs (To be updated dynamically)
WHITELISTED_IPS = set()

# Define safe ports (Ports that should NOT be flagged)
SAFE_PORTS = {22, 5000, 27017, 44371}

# Initialize Nmap scanner
try:
    nm = nmap.PortScanner()
except Exception as e:
    print(f"[ERROR] Nmap is not installed or not in PATH: {e}")

def get_instance_ips():
    """
    Get the EC2 instance's private and public IPs.
    """
    try:
        instance_private_ip = socket.gethostbyname(socket.gethostname())  # Private IP
        instance_public_ip = os.popen("curl -s ifconfig.me").read().strip()  # Fetch external IP
        print(f"[INFO] EC2 Private IP: {instance_private_ip}, Public IP: {instance_public_ip}")
        return instance_private_ip, instance_public_ip
    except Exception as e:
        print(f"[ERROR] Fetching EC2 IPs failed: {e}")
        return None, None

def update_whitelisted_ips():
    """
    Dynamically update the whitelist to include trusted IPs.
    Ensures scan requests & safe connections are not flagged.
    """
    global WHITELISTED_IPS

    # Fetch EC2 instance IPs
    instance_private_ip, instance_public_ip = get_instance_ips()

    # Define known safe IPs
    safe_ips = {
        "127.0.0.1",  # Localhost
        instance_private_ip,
        instance_public_ip,
        "185.134.146.28",  # My Macbook IP
        "34.160.111.145",  # Google CLoud IP
    }

    # Update the global whitelist
    WHITELISTED_IPS.update(safe_ips)

    print(f"[INFO] Updated Whitelist: {WHITELISTED_IPS}")

def detect_external_scans():
    """
    Detects real external scans by checking active TCP connections, 
    even from whitelisted IPs if they show attack-like behavior.
    """
    print("[INFO] Running detect_external_scans()...")

    # Get active TCP connections
    netstat_output = os.popen("sudo netstat -tn").read()

    # Get EC2 Private & Public IPs
    instance_ip = socket.gethostbyname(socket.gethostname())  
    instance_public_ip = os.popen("curl -s ifconfig.me").read().strip()

    print(f"[INFO] EC2 Private IP: {instance_ip}, Public IP: {instance_public_ip}")

    suspicious_ips = {}

    for line in netstat_output.split("\n"):
        parts = line.split()
        if len(parts) > 4 and parts[0].startswith("tcp"):
            ip_port = parts[4]
            if ":" in ip_port:
                ip = ip_port.rsplit(":", 1)[0]  # Extract IP only

                # Ignore local/internal EC2 traffic
                if ip in {instance_ip, instance_public_ip, "127.0.0.1"} or ip.startswith(("192.168.", "10.", "::1", "172.31.")):
                    print(f"[DEBUG] Ignoring local/internal EC2 scan from {ip}")
                    continue  

                # Track connection count for each IP
                suspicious_ips[ip] = suspicious_ips.get(ip, 0) + 1

    detected_threats = []
    for ip, count in suspicious_ips.items():
        #  If an IP scans too many ports in a short time, flag it as an attack!
        ATTACK_THRESHOLD = 15  # You can adjust this based on testing
        if count > ATTACK_THRESHOLD:
            recent_time_limit = datetime.utcnow() - timedelta(minutes=1)
            recent_threat = db.nmap_threats.find_one(
                {"host": ip, "timestamp": {"$gte": recent_time_limit.isoformat()}}
            )

            if recent_threat:
                print(f"[INFO] Ignoring past attack from {ip}. Only logging active threats.")
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
            print(f"[ALERT] External scan detected from {ip} (scanned {count} ports)")

    #  Store only new active threats in MongoDB
    if detected_threats:
        db.nmap_threats.insert_many(detected_threats)
        print(f"[INFO] {len(detected_threats)} external scan attempts logged.")

def scan_network(target=None, arguments="-p- -T4"):
    """
    Runs an Nmap scan on the target and logs unauthorized open ports.
    Also calls detect_external_scans() to detect real scanning attacks.
    """
    update_whitelisted_ips()  # Ensure last scan request IP is whitelisted

    instance_ip, instance_public_ip = get_instance_ips()
    target = target or instance_ip  # Default to scanning EC2

    try:
        print(f"[INFO] Scanning {target} with arguments: {arguments}")
        nm.scan(hosts=target, arguments=arguments)

        if not nm.all_hosts():
            print("[ERROR] No hosts found during scan.")
            return {"status": "error", "message": "No hosts found"}

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

                    # Detect unauthorized open ports
                    if host not in WHITELISTED_IPS and port not in SAFE_PORTS:
                        detected_threats.append({
                            "_id": str(ObjectId()),
                            "timestamp": log_entry["timestamp"],
                            "host": host,
                            "port": port,
                            "service": port_info["service"],
                            "status": "UNAUTHORIZED PORT DETECTED"
                        })

            scan_results.append(log_entry)

        # Store scan results in MongoDB
        scan_record = {"scan_results": scan_results, "timestamp": datetime.utcnow().isoformat()}
        inserted_id = db.nmap_logs.insert_one(scan_record).inserted_id

        # Store detected threats in MongoDB
        if detected_threats:
            db.nmap_threats.insert_many(detected_threats)
            print(f"[INFO] {len(detected_threats)} threats detected and logged.")

        detect_external_scans()  # Detect scanning attacks

        return {
            "status": "success",
            "scan_results": scan_results,
            "threats": detected_threats,
            "_id": str(inserted_id)  # Convert ObjectId to string before returning
        }

    except Exception as e:
        print(f"[ERROR] Nmap Scan Error: {str(e)}")
        return {"status": "error", "message": str(e)}
