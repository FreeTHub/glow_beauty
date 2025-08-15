""" Router for authentication endpoints. """

from fastapi import APIRouter, Depends, HTTPException, status,Request
from sqlalchemy.orm import Session
from app.auth import schemas, service
from app.database import get_db
from fastapi.security import HTTPBearer
from app.core.authMiddleware import AuthMiddleware


router = APIRouter()
bearer_scheme = HTTPBearer(auto_error=False)  

# router = APIRouter(prefix="/auth", tags=["Auth"])

@router.get("/auth/health", summary="Health Check")
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
    "/auth/signup",
    summary="User Sign Up",
    status_code=status.HTTP_202_ACCEPTED,
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
        result = await service.sign_up(user_data, db)
        return result
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Sign up failed: {str(e)}"
        )


@router.post(
    "/auth/final_signup",
    summary="Finalize User Sign Up",
    status_code=status.HTTP_201_CREATED,
    response_model=schemas.SignUpResponse
)
async def final_signup(
    user_data: schemas.SignUpVerifyRequest,
    db: Session = Depends(get_db)
):
    """
    Finalize the user registration after OTP verification.
    """
    try:
        result = await service.final_signup(user_data, db)
        return result
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Final signup failed: {str(e)}"
        )
    
@router.post(
    "/auth/login",
    summary="User Login",
    status_code=status.HTTP_200_OK,
    response_model=schemas.LoginResponse
)
async def login(    
    login_data: schemas.LoginRequest,
    requset: Request, 
    db: Session = Depends(get_db)
):
    """
    Authenticate user and return access and refresh tokens.
    """
    try:
        result = await service.login(login_data,requset, db)
        return result
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Login failed: {str(e)}"
        )

@router.post(
    "/auth/loginotp_request",
    summary="User Login request with OTP",
    status_code=status.HTTP_200_OK,
    # response_model=JSONResponse
)
async def loginotprequest(    
    data: schemas.LogOTPRequest,
    requset: Request, 
    db: Session = Depends(get_db)
):
    """
    Authenticate user and return access and refresh tokens. 
      """
    try:
        result = await service.loginotprequest_service(data,requset, db)
        return result
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Login failed: {str(e)}"
        )


@router.post(
    "/auth/refresh_token",
    summary="Refresh Access Token",
    status_code=status.HTTP_200_OK,
    response_model=schemas.RefreshTokenResponse
)
async def refresh_token(
    token_data: schemas.RefreshTokenRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Refresh the access token using a valid refresh token.
    """
    try:
        # Extract the actual refresh token string from the Pydantic model
        result = await service.refresh_access_token(
            refresh_token= token_data.refresh_token,
            request=request,
            db=db
        )
        return result
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Token refresh failed: {str(e)}"
        )



@router.get("/dashboard")
async def dashboard(request: Request):
   
    return {"message": f"Welcome to Dashboard !"}