""" Router for authentication endpoints. """

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.auth import schemas, service
from app.database import get_db
router = APIRouter()
# router = APIRouter(prefix="/auth", tags=["Auth"])

@router.get("/health", summary="Health Check")
async def health_check_condition():
    """
    Endpoint to verify if the authentication service is running.
    """
    try:
        return service.health_check()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Health check failed: {str(e)}"
        )

@router.post(
    "/signup",
    summary="User Sign Up",
    status_code=status.HTTP_201_CREATED,
    response_model=schemas.SignUpResponse
)
async def sign_up(
    user_data: schemas.SignUpRequest,
    db: Session = Depends(get_db)
):
    """
    Register a new user and trigger email verification.
    """
    try:
        new_user = service.sign_up(user_data, db)
        return {
        "status": "success",
        "message": "User registered. Check your email to verify.",
        "user": new_user
    }
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Sign up failed: {str(e)}"
        )
