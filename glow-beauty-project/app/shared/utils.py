# reusable_error.py
from fastapi import HTTPException, status

def http_error(code: str, message: str, field: str = None, status_code: int = status.HTTP_409_CONFLICT):
    error_payload = {
        "error": {
            "code": code,
            "message": message,
        }
    }
    if field:
        error_payload["error"]["field"] = field

    raise HTTPException(status_code=status_code, detail=error_payload)