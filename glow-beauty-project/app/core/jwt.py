# # app/utils/token.py
# from pathlib import Path
# from jose import jwt, JWTError
# from datetime import datetime, timedelta
# from app.core.config import settings

# PRIVATE_KEY = Path("keys/private.pem").read_text()
# PUBLIC_KEY = Path("keys/public.pem").read_text()
# ALGORITHM = "RS256"

# import logging
# logger = logging.getLogger("core")

# def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
#     to_encode = data.copy()
#     expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
#     to_encode.update({"exp": expire, "type": "access"})
#     return jwt.encode(to_encode, settings.PRIVATE_KEY, algorithm=settings.ALGORITHM)

# def create_refresh_token(data: dict, expires_delta: timedelta = None) -> str:
#     to_encode = data.copy()
#     expire = datetime.utcnow() + (expires_delta or timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS))
#     to_encode.update({"exp": expire, "type": "refresh"})
#     return jwt.encode(to_encode, settings.PRIVATE_KEY, algorithm=settings.ALGORITHM)

# def verify_token(token: str):
#     try:
#         logger.info(f"Verifying token: {token}")
#         if not token:
#             raise ValueError("Token is missing")
#         payload = jwt.decode(token, settings.PUBLIC_KEY, algorithms=[settings.ALGORITHM])
#         if not isinstance(payload, dict):
#             raise ValueError("Invalid token payload")
        
#         token_type = payload.get("type")
#         if token_type not in ("access", "refresh"):
#             raise JWTError("Invalid token type")

#         return payload
#     except JWTError as e:
#         raise ValueError(f"Token verification failed: {str(e)}")
import jwt
import uuid
from datetime import datetime, timedelta, timezone
from jwt import ExpiredSignatureError, InvalidTokenError
from app.core.config import settings
import logging
logger = logging.getLogger("core")
from jose import jwt, JWTError

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({
        "type": "access",
        "exp": expire  
    })
    logger.info(f"private key: {settings.PRIVATE_KEY}=== algorithm: {settings.ALGORITHM} === data: {to_encode} === expire: {expire}")
    return jwt.encode(to_encode, settings.PRIVATE_KEY, algorithm=settings.ALGORITHM)

def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    logger.info(f"Creating refresh token with data: {to_encode} and expire time: {expire}")
    to_encode.update({
        "type": "refresh",
        "exp": expire  
    })  
    return jwt.encode(to_encode, settings.PRIVATE_KEY, algorithm=settings.ALGORITHM)

def verify_token(token: str):
    try:
        logger.info(f"Verifying token: {token}")
        logger.info(f"Public key: {settings.PUBLIC_KEY} === Algorithm: {settings.ALGORITHM}")
        payload = jwt.decode(
            token,
            settings.PUBLIC_KEY,
            algorithms=[settings.ALGORITHM],
            options={"verify_exp": True}  # ensure token expiry is validated
        )
        logger.info(f"Token payload: {payload}")

        if payload.get("type") not in ["access", "refresh"]:
            raise JWTError("Invalid token type")

        return payload

    except JWTError as e:
        logger.error(f"Token verification failed: {str(e)}")
        return None
    
def is_refresh_token_revoked(token: str) -> bool:
    try:
        payload = jwt.decode(token, settings.PUBLIC_KEY, algorithms=[settings.ALGORITHM])
        return payload.get("revoked", False)
    except ExpiredSignatureError:
        return True
    except InvalidTokenError:
        return True


def is_token_expired(token: str) -> bool:
    try:
        # Decode without verifying the signature
        payload = jwt.get_unverified_claims(token)
        exp = payload.get("exp")

        if not exp:
            raise ValueError("Token has no 'exp' claim")

        # Current UTC time
        now = datetime.now(timezone.utc).timestamp()

        # Check expiry
        return now > exp

    except Exception as e:
        print(f"Error decoding token: {e}")
        return True  # Treat as expired if any error occurs


def revoke_refresh_token(token: str):
    try:
        payload = jwt.decode(token, settings.PUBLIC_KEY, algorithms=[settings.ALGORITHM])
        payload["revoked"] = True
        new_token = jwt.encode(payload, settings.PRIVATE_KEY, algorithm=settings.ALGORITHM)
        logger.info(f"Refresh token revoked: {new_token}")
        return new_token
    except JWTError as e:
        logger.error(f"Failed to revoke refresh token: {str(e)}")
        return None