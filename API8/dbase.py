import sqlite3
from datetime import datetime

DB_NAME = 'security_logs.db'

def init_db():
    '''Membuat tabel jika beluym ada saat aplikasi saat dinyalakan'''
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    #membuat table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            server_id TEXT,
            client_ip TEXT,
            user_agent TEXT,
            failed_attempts INTEGER,
            status TEXT
        )
    ''')

    conn.commit()
    conn.close()

    #fungsi untuk menyimpan data log baru

def save_log(server_id: str, failed_attempts: int, client_ip: str, user_agent: str, status: str):
    '''Menyimpan hasil log hasil analisis ke database'''
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute('''
        INSERT INTO security_logs(timestamp, server_id, client_ip, user_agent, failed_attempts, status)
        VALUES (?, ?, ?, ?, ?, ?)''',
        (timestamp, server_id, client_ip, user_agent, failed_attempts, status))
    conn.commit()
    conn.close()


def get_all_logs(status_filter= None): 
    """Mengambil seluruh data log dari database"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    if status_filter:
        cursor.execute ("SELECT * FROM security_logs WHERE status = ? ORDER BY id DESC", (status_filter,))
    else:
        cursor.execute ("SELECT * FROM security_logs ORDER BY id DESC")

    rows = cursor.fetchall()
    conn.close()

    logs = []
    for row in rows:
        logs.append({
            "id" : row[0],
            "timestamp" : row[1],
            "server_id" : row[2],
            "client_ip" : row[3],
            "user_agent": row[4],
            "failed_attempts" : row[5],
            "status" : row[6]
        })
    return logs

def get_logs_by_status(status_filter : str):
    conn = sqlite3.connect('security_logs.db')
    cursor = conn.cursor()

    cursor.execute('''
        SELECT id, server_id, failed_attempts, client_ip, user_agent, status, created_at 
        FROM security_logs 
        WHERE status = ? 
        ORDER BY id DESC
    ''', (status_filter.upper(),))

    rows = cursor.fetchall()
    conn.close()

    logs = []
    for row in rows:
        logs.append({
            "id": row[0],
            "server_id": row[1],
            "failed_attempts": row[2],
            "client_ip": row[3],
            "user_agent": row[4],
            "status": row[5],
            "created_at": row[6]
        })
    return logs

init_db()

def get_security_stats():
    """Menghitung metriks keamanan"""
    conn = sqlite3.connect('security_logs.db')
    cursor = conn.cursor()

    #total seluruh log
    cursor.execute("SELECT COUNT(*) FROM security_logs")
    total_logs = cursor.fetchone()[0]

    #total log berstatus SAFE
    cursor.execute("SELECT COUNT(*) FROM security_logs WHERE status = 'SAFE' ")
    total_safe = cursor.fetchone()[0]

    #total log berstatus fail
    cursor.execute("SELECT COUNT(*) FROM security_logs WHERE status = 'ALERT' ")
    total_alert = cursor.fetchone()[0]


    #cari IP pengirim ALERT terbanyak (top attacker)
    cursor.execute('''
        SELECT client_ip, COUNT(*) as alert_count
        FROM security_logs
        WHERE status = "ALERT"
        GROUP BY client_ip
        ORDER BY alert_count DESC
        LIMIT 1
    ''')
    top_attacker_row = cursor.fetchone()
    top_attacker = top_attacker_row[0] if top_attacker_row else "None"

    conn.close()

    return {
        "total_request_analyzed" : total_logs,
        "safe_request" : total_safe,
        'alert_request' : total_alert,
        'top_suspicious_ip' : top_attacker
    }