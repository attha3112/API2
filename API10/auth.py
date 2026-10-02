import datetime
import jwt
from passlib.context import CryptContext
from typing import Optional

# 1. Konfigurasi Rahasia & Algoritma JWT
# Di skala production, SECRET_KEY ini nantinya diambil dari .env file
SECRET_KEY = "SUPER_SECRET_KEY_YANG_SANGAT_RAHASIA_DAN_PANJANG"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# 2. Setup Context untuk Hashing Password menggunakan Bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# --- FUNGSI HASHING PASSWORD ---

def hash_password(password: str) -> str:
    """Mengubah password plaintext menjadi string hash bcrypt yang aman"""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Membandingkan password buatan user dengan hash yang ada di database"""
    return pwd_context.verify(plain_password, hashed_password)


# --- FUNGSI JWT TOKEN ---

def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None) -> str:
    """
    Membuat JWT Access Token baru yang berisi data payload (seperti username)
    dan stempel waktu kadaluarsa.
    """
    to_encode = data.copy()
    
    # Tentukan waktu kadaluarsa token
    if expires_delta:
        expire = datetime.datetime.now(datetime.timezone.utc) + expires_delta
    else:
        expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        
    # Tambahkan claim 'exp' ke dalam payload
    to_encode.update({"exp": expire})
    
    # Encode payload menjadi string JWT menggunakan SECRET_KEY
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[dict]:
    """
    Memverifikasi dan membongkar token JWT.
    Jika token sah dan belum kadaluarsa, kembalikan isi payload-nya.
    Jika palsu/kadaluarsa, kembalikan None.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        # Token sudah melewati batas waktu exp
        return None
    except jwt.InvalidTokenError:
        # Token palsu, rusak, atau SECRET_KEY tidak cocok
        return None