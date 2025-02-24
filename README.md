# Secure-Intelligence-Storage

###For Intrusion Detection###

#To simulate brute force attack run on Machine terminal "nmap --script ssh-brute -p 22 <Ec2 IP>"

#To detect logs/Scan the system during the attack or run on Ec2 terminal "sudo journalctl -u sshd --since "10 minutes ago""


#To simulate DDOS attack run on Kali Linux terminal "sudo hping3 -S --flood -p 22 <EC2_IP>"

#To detect logs/Scan the system after the attack or run on Ec2 terminal "sudo netstat -ntu | grep ':22' | grep SYN_RECV"


###For Intrusion Prevention###

#To block/unblock flagged ip press block/unblock in threat table

#To manually unblock ip, run on Ec2 terminal "sudo iptables -D INPUT -s <IP> -j DROP" 


#To manually view all blocked ip's, run on Ec2 terminal "sudo iptables -L INPUT -n --line-numbers"
