import os
import time
from datetime import datetime, timedelta
from database.mongo_db import db
from bson import ObjectId

# Time interval to check for threats (every 30 seconds)
CHECK_INTERVAL = 30

# Blocked IP storage (to prevent duplicate blocks)
BLOCKED_IPS = {}

# Function to execute iptables command
def run_iptables(command):
    try:
        os.system(command)
    except Exception as e:
        print(f"[ERROR] Failed to run iptables command: {e}")

# Function to check and block brute force attackers
def block_brute_force():

    print("[INFO] Checking for brute force attacks...")
    
    recent_time = datetime.utcnow() - timedelta(minutes=5)  # Check last 5 mins
    brute_force_ips = db.nmap_threats.find({
        "service": "Brute Force Attack",
        "timestamp": {"$gte": recent_time.isoformat()}
    })

    for attack in brute_force_ips:
        ip = attack.get("host")
        if ip and ip not in BLOCKED_IPS:
            print(f"[ALERT] Blocking brute force attacker: {ip}")
            run_iptables(f"sudo iptables -A INPUT -s {ip} -j DROP")
            BLOCKED_IPS[ip] = "Brute Force"
            
            # Store blocked IP in MongoDB
            db.blocked_ips.insert_one({
                "ip": ip,
                "reason": "Brute Force",
                "timestamp": datetime.utcnow().isoformat()
            })
            print(f"[INFO] {ip} has been permanently blocked due to brute force attacks.")

# Function to check and block DDoS attackers
def block_ddos():
    print("[INFO] Checking for DDoS attacks...")
    
    recent_time = datetime.utcnow() - timedelta(minutes=5)  # Check last 5 mins
    ddos_ips = db.nmap_threats.find({
        "service": "DDoS Attack",
        "timestamp": {"$gte": recent_time.isoformat()}
    })

    for attack in ddos_ips:
        ip = attack.get("host")
        if ip and ip not in BLOCKED_IPS:
            print(f"[ALERT] Blocking DDoS attacker: {ip}")
            run_iptables(f"sudo iptables -A INPUT -s {ip} -j DROP")
            BLOCKED_IPS[ip] = "DDoS"

            # Store blocked IP in MongoDB
            db.blocked_ips.insert_one({
                "ip": ip,
                "reason": "DDoS",
                "timestamp": datetime.utcnow().isoformat()
            })
            print(f"[INFO] {ip} has been temporarily blocked for 10 minutes.")

            # Schedule unblock after 10 mins
            time.sleep(600)
            run_iptables(f"sudo iptables -D INPUT -s {ip} -j DROP")
            BLOCKED_IPS.pop(ip, None)

            # **Remove IP from MongoDB after unblocking**
            db.blocked_ips.delete_one({"ip": ip})

            print(f"[INFO] Unblocked {ip} after 10 minutes (DDoS).")

# Function to apply rate-limiting on SSH and web traffic
def apply_rate_limiting():

    print("[INFO] Applying rate-limiting rules...")

    # Limit SSH connections (max 3 per minute per IP)
    run_iptables("sudo iptables -A INPUT -p tcp --dport 22 -m limit --limit 3/minute --limit-burst 5 -j ACCEPT")
    run_iptables("sudo iptables -A INPUT -p tcp --dport 22 -j DROP")

    # Limit HTTP(S) connections (max 20 per second per IP)
    run_iptables("sudo iptables -A INPUT -p tcp --dport 80 -m limit --limit 20/second --limit-burst 30 -j ACCEPT")
    run_iptables("sudo iptables -A INPUT -p tcp --dport 80 -j DROP")

    run_iptables("sudo iptables -A INPUT -p tcp --dport 443 -m limit --limit 20/second --limit-burst 30 -j ACCEPT")
    run_iptables("sudo iptables -A INPUT -p tcp --dport 443 -j DROP")

    print("[INFO] Rate-limiting rules applied.")

# Main function to continuously monitor and block threats
def run_ips():
    print("[INFO] Intrusion Prevention System (IPS) is running...")
    
    # Load previously blocked IPs from MongoDB
    for entry in db.blocked_ips.find({}, {"_id": 0}):
        BLOCKED_IPS[entry["ip"]] = entry["reason"]
    
    apply_rate_limiting()  # Apply rate-limiting rules on startup

    while True:
        block_brute_force()
        block_ddos()
        time.sleep(CHECK_INTERVAL)  # Wait before checking again