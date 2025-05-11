import unittest
import ipaddress
from security.suspicious_score import calculate_suspicious_score

class TestSuspiciousScore(unittest.TestCase):

    def test_high_risk_action_off_hours_bad_ip_large_file(self):
        row = {
            'action': 'DownloadShared',
            'hour': 2,
            'ip_encoded': 88888888,
            'file_size': 60000000,
            'user': 'alice',
            'repetition_flag': False,
            'role_escalation': False,
            'file_name': 'backup.zip',
            'recipient': ''
        }
        self.assertGreaterEqual(calculate_suspicious_score(row), 8)

    def test_low_risk_normal_conditions(self):
        row = {
            'action': 'Upload',
            'hour': 11,
            'ip_encoded': int(ipaddress.IPv4Address("127.0.0.1")),
            'file_size': 25000,
            'user': 'bob',
            'repetition_flag': False,
            'role_escalation': False,
            'file_name': 'doc.txt',
            'recipient': ''
        }
        self.assertEqual(calculate_suspicious_score(row), 1)  

    def test_suspicious_file_type_and_external_share(self):
        row = {
            'action': 'Share',
            'hour': 13,
            'ip_encoded': int(ipaddress.IPv4Address("10.0.0.1")),
            'file_size': 30000,
            'user': 'charlie',
            'repetition_flag': False,
            'role_escalation': False,
            'file_name': 'malware.exe',
            'recipient': 'external'
        }
        self.assertGreaterEqual(calculate_suspicious_score(row), 7)

    def test_unknown_user_and_role_escalation(self):
        row = {
            'action': 'Download',
            'hour': 15,
            'ip_encoded': int(ipaddress.IPv4Address("8.8.8.8")),
            'file_size': 50000,
            'user': 'unknown',
            'repetition_flag': False,
            'role_escalation': True,
            'file_name': 'log.txt',
            'recipient': ''
        }
        self.assertGreaterEqual(calculate_suspicious_score(row), 6)

    def test_multiple_flags_combined(self):
        row = {
            'action': 'Share',
            'hour': 22,
            'ip_encoded': int(ipaddress.IPv4Address("172.16.100.100")),
            'file_size': 8000,
            'user': 'unknown',
            'repetition_flag': True,
            'role_escalation': True,
            'file_name': 'export.bat',
            'recipient': 'external'
        }
        score = calculate_suspicious_score(row)
        self.assertGreaterEqual(score, 10)  
    
    def test_unexpected_action_with_spoofed_ip_and_tiny_file(self):
        row = {
            'action': 'Sync',  
            'hour': 4,        
            'ip_encoded': 4294967000,  
            'file_size': 1000,         
            'user': 'internal_user',
            'repetition_flag': True,   
            'role_escalation': False,
            'file_name': 'tool.sh',  
            'recipient': 'internal'
        }
        self.assertGreaterEqual(calculate_suspicious_score(row), 9)

if __name__ == '__main__':
    unittest.main()