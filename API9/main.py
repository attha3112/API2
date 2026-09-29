from database import logs
from helper import analyze_server_log
from exception import SecurityAlertError, InvalidLogFormatError

print('MEMULAI ANALISIS LOG SERVER===\n')

for log in logs:
    try:
        result = analyze_server_log(log)
        print(f'[SUCCESS] {result}')
    except SecurityAlertError as e:
        print(f'[ALERT SECURITY] {e}')
    except InvalidLogFormatError as e:
        print(f'[FORMAT ERROR] {e}')

print('\n === ANALISIS SELESAI (Cek file app.log) ====')