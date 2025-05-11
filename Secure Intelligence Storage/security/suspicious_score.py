import ipaddress

# Whitelisted IPs
WHITELISTED_IPS = {
    int(ipaddress.IPv4Address("127.0.0.1")),
    int(ipaddress.IPv4Address("34.160.111.145"))
}

# Action risk categories
HIGH_RISK_ACTIONS = ["DownloadShared", "Share"]
MEDIUM_RISK_ACTIONS = ["Upload", "Download"]

# Working hours from 9 AM to 5 PM
WORK_HOUR_START = 9
WORK_HOUR_END = 18

def calculate_suspicious_score(row):
    score = 0
    reasons = []

    # Check for high level risk action
    if row['action'] in HIGH_RISK_ACTIONS:
        score += 3
        reasons.append("High-risk action")

    elif row['action'] in MEDIUM_RISK_ACTIONS:
        score += 1
        reasons.append("Medium-risk action")

    else:
        score += 2
        reasons.append("Uncategorized or unexpected action")

    # Check for outside office hours access
    if row['hour'] < WORK_HOUR_START or row['hour'] > WORK_HOUR_END:
        score += 2
        reasons.append("Accessed outside working hours")

    # IP address check
    if row['ip_encoded'] not in WHITELISTED_IPS:
        score += 3
        reasons.append("Non-whitelisted IP")

    # File size anomalies
    if row['file_size'] > 50000000:
        score += 2
        reasons.append("Very large file size")
    elif row['file_size'] > 10000000:
        score += 1
        reasons.append("Large file size")
    elif row['file_size'] < 5000:
        score += 2
        reasons.append("Suspiciously small file")

    # Unknown user flag
    if row.get('user') == 'unknown':
        score += 2
        reasons.append("Unknown user")

    # Repetition pattern if user repeats unusual action
    if row.get('repetition_flag') is True:
        score += 2
        reasons.append("Unusual repetition pattern")

    # Suspicious filename pattern
    if row.get('file_name', '').lower().endswith(('.exe', '.sh', '.bat')):
        score += 2
        reasons.append("Suspicious file extension")

    # Unusual recipient
    if row.get('recipient') == 'external':
        score += 2
        reasons.append("External file sharing")

    # IP encoded value check is too high and possible spoof
    if row['ip_encoded'] > 4294960000:
        score += 1
        reasons.append("Possibly spoofed IP")

    # Logging reasons for debugging and auditing
    row['suspicion_reasons'] = reasons

    return score
