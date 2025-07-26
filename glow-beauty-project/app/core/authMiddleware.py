# app/middleware/auth_middleware.py
# app/middleware/auth_middleware.py

from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request
from fastapi.responses import JSONResponse
from app.core.jwt import (verify_token, create_access_token, create_refresh_token, is_refresh_token_revoked, revoke_refresh_token,is_token_expired)
from jwt import  ExpiredSignatureError
from app.core.config import settings
from app.logger import get_logger

logger = get_logger("auth")

class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith("/auth/") or request.url.path.startswith("/docs") or request.url.path.startswith("/openapi.json"):
            return await call_next(request)
        logger.info(f"Processing request for path: {request.url.path}")

        access_token = request.headers.get("Authorization")
        logger.info(f"Access token: {access_token}")

        refresh_token = request.headers.get("X-Refresh-Token")
        logger.info(f"Refresh token: {refresh_token}")

        if not access_token or not access_token.startswith("Bearer "):
            return JSONResponse(status_code=401, content={"detail": "Missing access token"})

        token = access_token[7:]

        try:
            is_expired = is_token_expired(token)
            if is_expired:
                raise ExpiredSignatureError("Access token has expired")
            payload = verify_token(token)
            if not payload:
                logger.info("Invalid access token")
                return JSONResponse(status_code=401, content={"detail": "Invalid access token / token expired"})
            logger.info(f"Access token payload: {payload}")
            request.state.user_id = payload.get("sub")
            request.state.roles = payload.get("roles", [])
        except ExpiredSignatureError:
            logger.info("Access token expired. Checking refresh token.")
            
            if is_expired:
                return JSONResponse(status_code=401, content={"detail": "Access token expired"})
            
            if not refresh_token or not is_refresh_token_revoked(refresh_token):
                return JSONResponse(status_code=401, content={"detail": "Invalid or missing refresh token"})

            try:
                refresh_payload = verify_token(refresh_token, settings.JWT_REFRESH_SECRET_KEY)
                # Optional: Revoke the old token and issue a new refresh token (rotation)
                revoke_refresh_token(refresh_token)
                new_access_token = create_access_token({"sub": refresh_payload["sub"], "roles": refresh_payload.get("roles", [])})
                new_refresh_token = create_refresh_token({"sub": refresh_payload["sub"], "roles": refresh_payload.get("roles", [])})
                response = await call_next(request)
                response.headers["X-New-Access-Token"] = new_access_token
                response.headers["X-New-Refresh-Token"] = new_refresh_token
                request.state.user_id = refresh_payload["sub"]
                request.state.roles = refresh_payload.get("roles", [])
                return response
            except Exception as e:
                logger.error(f"Refresh token failed: {str(e)}")
                return JSONResponse(status_code=401, content={"detail": "Refresh token invalid"})

        return await call_next(request)



# app/core/authMiddleware.py

# from app.logger import get_logger
# logger = get_logger("core")

# from fastapi import Request
# from fastapi.responses import JSONResponse
# from starlette.middleware.base import BaseHTTPMiddleware
# from jwt import DecodeError, ExpiredSignatureError
# from .jwt_utils import verify_token

# class AuthMiddleware(BaseHTTPMiddleware):
#     async def dispatch(self, request: Request, call_next):
#         if request.url.path.startswith("/auth/"):
#             return await call_next(request)

#         token = request.headers.get("Authorization")
#         if not token or not token.startswith("Bearer "):
#             return JSONResponse(status_code=401, content={"detail": "Missing or invalid token"})

#         try:
#             payload = verify_token(token[7:])
#             logger.info(f"Token verified for user: {payload.get('sub')}")
#             request.state.user_id = payload.get("sub")
#         except ExpiredSignatureError:
#             return JSONResponse(status_code=401, content={"detail": "Token expired"})
#         except DecodeError:
#             return JSONResponse(status_code=401, content={"detail": "Invalid token"})

#         return await call_next(request)
