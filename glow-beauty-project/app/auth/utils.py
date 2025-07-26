""" Helper functions for authentication and user management """
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
import secrets
import smtplib
from email.mime.text import MIMEText
from app.auth.models import OtpCode
import redis,os
from fastapi import Request
from app.logger import get_logger
logger = get_logger("auth")

# r = redis.Redis(host="localhost",port=6379,db=0)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)

""" Hash a password using bcrypt """
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

""" verify a plain password against a hashed password """       
def verify_password(plain: str, hashed: str) -> bool:
    """
    Verify a plain password against a hashed password.
    Uses bcrypt for hashing and verification.
    """
    return pwd_context.verify(plain, hashed)

""" Generate a randoms OTP code """
def generate_otp(length: int = 6) -> str:
    return ''.join(secrets.choice('0123456789') for _ in range(length))

def store_otp_email(email:str,otp:str,db,expiry:int=300):
    # r.setex(f"otp:{email}",expiry,otp)
    expiry_time = datetime.now(timezone.utc) + timedelta(seconds=expiry)
    otp_record = OtpCode(email=email,otp_code=otp,
            expires_at=expiry_time,created_at=datetime.now(timezone.utc),method="sinnup_email")
    logger.info(f"================= OK FINE ======================")
    db.add(otp_record)
    db.commit()
    logger.info(f"======== successfuly commit =============")


def get_otp_email(email:str,db:Session):
    # otp = r.get(f"otp:{email}")
    otp_record = db.query(OtpCode).filter(OtpCode.email == email, OtpCode.used == False).first()
    if otp_record and otp_record.expires_at > datetime.now(timezone.utc):
        return otp_record.otp_code
    return None

def mark_otp_as_used(email:str,db:Session):
    # r.delete(f"otp:{email}")
    otp_record = db.query(OtpCode).filter(OtpCode.email == email, OtpCode.used == False).first()
    if otp_record:
        otp_record.used = True
        db.commit()
        return True
    return False



    """
    Verify a plain password against a hashed password.
    Uses bcrypt for hashing and verification.
    """
    return pwd_context.verify(plain, hashed)

def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0]
    return request.client.host


def get_user_agent(request: Request) -> str:
    """Get user agent string from request headers."""
    return request.headers.get("User-Agent", "unknown")


import hashlib

def hash_token(token: str) -> str:
    # Returns hex digest of SHA-256 hash of the token
    return hashlib.sha256(token.encode('utf-8')).hexdigest()
# def generate_token(length: int = 32) -> str:
#     return secrets.token_urlsafe(length)

# def send_email(to_email: str, subject: str, body: str):
#     msg = MIMEText(body)
#     msg["Subject"] = subject
#     msg["From"] = "your@email.com"
#     msg["To"] = to_email

#     with smtplib.SMTP("localhost") as server:
#         server.sendmail(msg["From"], [msg["To"]], msg.as_string())
