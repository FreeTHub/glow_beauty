""" Helper functions for authentication and user management """

from passlib.context import CryptContext
from datetime import datetime, timedelta
import secrets
import smtplib
from email.mime.text import MIMEText

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# def generate_token(length: int = 32) -> str:
#     return secrets.token_urlsafe(length)

# def send_email(to_email: str, subject: str, body: str):
#     msg = MIMEText(body)
#     msg["Subject"] = subject
#     msg["From"] = "your@email.com"
#     msg["To"] = to_email

#     with smtplib.SMTP("localhost") as server:
#         server.sendmail(msg["From"], [msg["To"]], msg.as_string())
