import html
import logging
from database import logs
from exception import SecurityAlertError, InvalidLogFormatError
from dbase import save_log

# Konfigurasi logging
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s'
)


def sanitize_input(text : str) -> str:
    """
    Membersihkan teks dari karakter HTML/Script Berbahaya (XSS Protection).
    Contoh : '<script>' akan diubah menjadi '&lt;script&gt;'
    """
    if isinstance (text, str):
        # 1. hapus spasi berlebih di awal & akhir
        cleaned = text.strip()
        return cleaned
    return text

def inspect_payload(log_data : dict):
    """
    WAF & Validator Payload 
    Mengembalikan: (is_safe: bool, message: str, sanitized_data : dict)
    """

    #kata kunci spesifik untuk perintah SQL berbahaya
    sql_blacklisted = ['DROP TABLE', "UNION SELECT", "DELETE FROM", "--", "OR'1'='1"]
    sanitized_data = {}
    for key, value in log_data.items():
        #jika nilai berupa string lakukan pembersihan

        if isinstance (value, str):
            value_upper = value.upper()

            #1. CEK SQL Injection Berat (jika ada, tetap blokir)
            for pattern in sql_blacklisted:
                if pattern in value_upper:
                    return False, f'Indikasi SQL Injection terdeteksi pada field "{key}"!', {}
                sanitized_data[key] = sanitize_input(value)
            else:
                sanitized_data[key] = value
    return True, "Payload aman & telah dibersihkan", sanitized_data


class serveranalyzer:
    def __init__(self, max_allow_attempts=5):
        self.max_attempts = max_allow_attempts

    def analyze(self, log): 
        server_id = log.get('server_id', 'UNKNOWN')

        # 1. Validasi keberadaan field
        if 'failed_attempts' not in log:
            logging.error(f'Server {server_id}, Key Value tidak ditemukan')
            raise InvalidLogFormatError(f'Field "failed_attempts" tidak ada di {server_id}')

        # 2. Validasi tipe data angka
        attempts = 0
        try:
            attempts = int(log['failed_attempts'])
        except ValueError:
            logging.error(f'server {server_id}, format failed_attempts "{log["failed_attempts"]}" tidak valid')
            raise InvalidLogFormatError(f'format angka tidak valid di {server_id}')


        client_ip = log.get('client_ip', 'UNKNOWN')
        user_agent = log.get('user_agent', 'UNKNOWN')
        # 3. Analisis batas keamanan (Security Alert)
        if attempts > self.max_attempts:
            logging.warning(
                f'Security Alert! : {server_id} dari IP {client_ip}'
                f'mencatat sudah melakukan percobaan{attempts} kali | user-agent: {user_agent}')

            #simpan status alert ke database
            save_log(server_id, attempts, client_ip, user_agent, 'ALERT')
            raise SecurityAlertError(f'Security Alert, {server_id} sudah melakukan {attempts} kali percobaan')

        # 4. Jika kondisi aman
        logging.info(f'server : {server_id} aman. Sudah melakukan {attempts} kali'
                     f'|Client_ip : {client_ip}')

        save_log(server_id, attempts, client_ip, user_agent, "SAFE")
        return f'server {server_id} aman'
