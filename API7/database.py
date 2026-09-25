logs = [
    {'server_id': 'SRV-001', 'ssh_port': 2222, 'failed_attempts': 3},   # Normal
    {'server_id': 'SRV-002', 'ssh_port': 22, 'failed_attempts': 12},   # Bahaya: > 5 kali
    {'server_id': 'SRV-003', 'ssh_port': 22},                          # Error: Key hilang
    {'server_id': 'SRV-004', 'ssh_port': 22, 'failed_attempts': 'abc'} # Error: Format salah
]