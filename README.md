# Secure-Intelligence-Storage

###For Intrusion Detection###

To simulate brute force attack run on Machine terminal "nmap --script ssh-brute -p 22 <Ec2 IP>"

To detect logs/Scan the system during the attack or run on Ec2 terminal "sudo journalctl -u sshd --since "10 minutes ago""

To simulate DDOS attack run on Kali Linux terminal "sudo hping3 -S --flood -p 22 <EC2_IP>"

To detect logs/Scan the system after the attack or run on Ec2 terminal "sudo netstat -ntu | grep ':22' | grep SYN_RECV"


###For Intrusion Prevention###


To block/unblock flagged ip press block/unblock in threat table

To manually unblock ip, run on Ec2 terminal "sudo iptables -D INPUT -s <IP> -j DROP" 

To manually view all blocked ip's, run on Ec2 terminal "sudo iptables -L INPUT -n --line-numbers"


###For File Anomaly Detection###


To check anomalies, press Check Anomalies button on the webpage

To retrain the model using the latest file logs from MongoDB run on Ec2 terminal "python3 security/train_file_anomaly_model.py"

After training, verify that the updated model file (file_anomaly_model.pkl, le_action.pkl, le_user.pkl) is present under the security folder, run om Ec2 terminal "ls security"