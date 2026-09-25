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

def inspect_payload(payload : dict):
        #blacklist kata kunci yang berbahaya
    bl_pattern = [ '--', 'DROP', 'UNION', '<script>', 'SELECT', "' OR '"]

        #periksa setiap nilai di dalam JSON payload
    for key, value in payload.items():
        value_str = str(value).upper()
        for pattern in bl_pattern:
            if pattern in value_str:
                return False, f'Indikasi serangan terdeteksi pada field "{key}" : pola "{pattern} dilarang!"'

    return True, 'Payload aman'
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
