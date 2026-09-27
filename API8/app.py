import time
import dbase
from fastapi import FastAPI, HTTPException, Request, Body, status
from helper import serveranalyzer, inspect_payload
from exception import SecurityAlertError, InvalidLogFormatError
from dbase import init_db, get_all_logs, get_logs_by_status,save_log, get_security_stats
from typing import Optional


app = FastAPI(title='Security Analyzer API')

# Inisialisasi analyzer
analyzer = serveranalyzer()
#penyimpanan sementara untuk tracking IP dan waktu req
request_history = {}
#panggil fungsi inisialisasi database
dbase.init_db()

@app.get("/")
def home():
    return {'status': 'online', 'messages': 'Security Log Analyzer API Ready'}

@app.post("/analyze")
def analyze_log(request: Request, log_data: dict = Body(...)):
    # Membaca informasi jaringan dari client
    client_ip = request.client.host
    user_agent = request.headers.get('user-agent', '').lower()
    current_time  = time.time()

    is_safe, message, clean_data = inspect_payload(log_data)
    if not is_safe:
        raise HTTPException(status_code=400, detail=f'WAF Blocked :{message}')

    log_data = clean_data
    log_data['client_ip'] = client_ip
    log_data['user_agent'] = user_agent


    if client_ip not in request_history:
        request_history[client_ip] = []

    #delete timestamp yang sudah lebih dari 60 detik ===

    request_history[client_ip] = [
        t for t in request_history[client_ip] if current_time - t < 60
    ]

    if len(request_history[client_ip]) >= 3:
        raise HTTPException(
            status_code=429,
            detail='[RATE LIMIT EXCEEDED] Terlalu banyak permintaan! Coba lagi setelah 1 menit.'
        )

    request_history[client_ip].append(current_time)
    try : 
        if 'curl' in user_agent or 'python_requests' in user_agent:
            raise HTTPException(
            status_code = status.HTTP_403_FORBIDDEN,
            detail = "[BLOCKED] Akses via otomatisasi/cURL dilarang"
        )

        result = analyzer.analyze(log_data)

        #1. Simpan log aman(safe)
        dbase.save_log(
            server_id = log_data.get('server_id', 'UNKNOWN'),
            failed_attempts = log_data.get('failed_attempts', 0),
            client_ip = client_ip,
            user_agent = user_agent,
            status="SAFE"
        )
        return {'status' : 'success', 'detail' : result}


        #2. Simpan log tidak aman (ALERT)
        dbase.save_log(
            server_id = log_data.get('server_id', 'UNKNOWN'),
            failed_attempts = log_data.get('failed_attempts', 0),
            client_ip = client_ip,
            user_agent = user_agent,
            status="ALERT"
            )
    except SecurityAlertError as e:
        raise HTTPException(status_code=400, detail=f'[ALERT SECURITY] {str(e)}')
    except InvalidLogFormatError as e:
        raise HTTPException(status_code=422, detail=f'[FORMAT ERROR] {str(e)}')
 
     
@app.get('/logs')
def view_all_logs():
    logs  = dbase.get_all_logs()
    return {"total_logs" : len(logs), "data" : logs}

@app.get('/logs/alert')
def view_security_alerts():
    alerts = dbase.get_logs_by_status('ALERT')
    return {'total_alerts' : len(alerts), 'data' :alerts}


@app.get('/stats')
def view_stats():
    """endpoint untuk melihat statistik keamanan server"""
    stats = dbase.get_security_stats()
    return {
        'status' : 'success',
        'metrics' : stats
    }