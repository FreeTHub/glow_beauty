"""  For Business Logic of Authentication Service  """
from datetime import datetime, timezone, timedelta
from app.core.jwt import  create_access_token, create_refresh_token, verify_token
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from app.auth import models, schemas, utils
from app.auth.models import LoginAttempt, OtpCode, RefreshToken, Role, User, EmailVerification,UserRole
from app.auth.schemas import GoogleLoginRequest, LogOTPRequest, GetLoginResponse, LoginRequest, LoginResponse, SignUpRequest, SignUpVerifyRequest, UserOut ,SignUpResponse,VerifyLoginOTPRequest,ForgetPasswordOTPRequest
from app.auth.utils import generate_otp, get_client_ip, get_user_agent, hash_password, hash_token, store_otp_email, verify_password
from app.core.config import settings
from sqlalchemy.exc import SQLAlchemyError
from fastapi import HTTPException, status,Depends
from fastapi.responses import JSONResponse
import traceback,os
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import Optional
from fastapi import Request, status, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import select
from app.logger import get_logger
logger = get_logger("auth")

LOCK_THRESHOLD = 5
LOCK_DURATION_MINUTES = 15


""" Health Service Check """
def health_check():
    return {
        "status": "ok",
        "message": "Authentication Service is running smoothly"
    }

""" Genereate OTP and store it in the database """
async def sign_up(user_data: SignUpRequest, db: Session) -> SignUpResponse:

    logger.info("Starting user signup process")

    # 1) Uniqueness checks
    if db.query(User).filter_by(email=user_data.email).first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered"
        )
    if db.query(User).filter_by(phone_no=user_data.phone_no).first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Phone number already registered"
        )

    try:
        # OTP verification and other checks can be added her
        existing_otp = db.query(OtpCode).filter(
            OtpCode.email == user_data.email,
            OtpCode.method == "signup_email",
            OtpCode.used == False,
            OtpCode.expires_at > datetime.now(timezone.utc)

        ).first()
        
        if existing_otp:
            logger.info(f"OTP already exists for {user_data.email}. Cannot proceed with signup.")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="OTP already sent to this email. Please verify before signing up."
            ) 
        otp = generate_otp() 
        logger.info(f"Generated OTP for {user_data.email}: {otp}")
        store_otp_email(user_data.email,otp,db,method="signup_email") 
        logger.info("=========== In DB OTP Store Successfully ===========")

        return JSONResponse(
            {
                "status": "otp_sent",
                "message": "OTP sent to your email. Please verify to complete registration."
            })

        # # 2) Create user instance
        # new_user = User(
        #     email=user_data.email,
        #     phone_no=user_data.phone_no,
        #     password=hash_password(user_data.password),
        #     is_active=True,
        #     is_verified_email=False,
        #     is_verified_phone=False
        # )

        # # 3) Persist to database
        # db.add(new_user)
        # db.flush()  
        # # Assign default role to user
        # default_role = UserRole(
        #     user_id=new_user.id,
        #     role_id=1,  # Assuming role_id=1 is the default role  
        #       # or however your UserRole is structured
        #     created_at = datetime.now(timezone.utc)
        # )
        # db.add(default_role)





        # db.commit()
        # db.refresh(new_user)

        # # 4) Optional: Email verification token generation and email sending
        # # raw_token = generate_token()
        # # token_hash = hash_token(raw_token)
        # # verification = EmailVerification(
        # #     user_id=new_user.id,
        # #     token=token_hash,
        # #     expires_at=datetime.utcnow() + timedelta(minutes=15)
        # # )
        # # db.add(verification)
        # # db.commit()
        # #
        # # verify_link = f"{os.getenv('FRONTEND_URL')}/verify-email?token={raw_token}"
        # # send_email(
        # #     to=new_user.email,
        # #     subject="Verify your email",
        # #     body=(
        # #         "Please click the following link to verify your account:\n\n"
        # #         f"{verify_link}"
        # #     )
        # # )

        # # 5) Return wrapped response
        # return SignUpResponse(
        #     status="success",
        #     message="User registered successfully.",
        #     user=new_user  # Pydantic converts via orm_mode
        # )
    

    except SQLAlchemyError as e:
        db.rollback()
        logger.error("Database error during signup: %s", str(e))
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error during signup."
        )

    except HTTPException as http_exc:
        raise http_exc

    except Exception as e:
        db.rollback()
        logger.error("Unexpected error during signup: %s", str(e))
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Signup failed due to unexpected server error."
        )

""" Finalize the signup process after OTP verification """    
async def final_signup(user_data:SignUpVerifyRequest, db: Session) -> SignUpResponse:
    """
    Finalize the signup process after OTP verification.
    """
    try:

        # 1) Uniqueness checks
        if db.query(User).filter_by(email=user_data.email).first():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already registered",
                field="email"
            )
        if db.query(User).filter_by(phone_no=user_data.phone_no).first():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Phone number already registered",
                field ="phone_no"
            )
        logger.info("Starting final signup process")

        # 2) Check if OTP exists and is valid
        check_otp = db.query(OtpCode).filter(
            OtpCode.email == user_data.email,
            OtpCode.method == "signup_email",
            OtpCode.used == False,
            OtpCode.expires_at > datetime.now(timezone.utc)
        ).first()

        if not check_otp:
            logger.info(f"No valid OTP found for {user_data.email}. Cannot proceed with final signup.")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No valid OTP found. Please request a new OTP."
            )
        
        if check_otp.used:
            logger.info(f"OTP already used for {user_data.email}. Cannot proceed with final signup.")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="OTP already used. Please request a new OTP."
            )
        
        if check_otp.otp_code != user_data.otp:
            logger.info(f"Invalid OTP provided for {user_data.email}. Cannot proceed with final signup.")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid OTP provided. Please try again."
            )
        # 3) Mark OTP as used
        check_otp.used = True        

        # 1) Create user instance
        new_user = User(
            email=user_data.email,
            full_name = user_data.full_name,
            phone_no=user_data.phone_no,
            password=hash_password(user_data.password),
            is_active=True,
            is_verified_email=True,
            is_verified_phone=False
        )

        # 2) Persist to database
        db.add(new_user)
        db.flush()  
        
        # Assign default role to user
        default_role = UserRole(
            user_id=new_user.id,
            role_id=1,  # Assuming role_id=1 is the default role  
            created_at=datetime.now(timezone.utc)
        )
        db.add(default_role)

        db.commit()
        db.refresh(new_user)

        return SignUpResponse(
            status="success",
            message="User registered successfully.",
            user=new_user  # Pydantic converts via orm_mode
        )

    except SQLAlchemyError as e:
        db.rollback()
        logger.error("Database error during final signup: %s", str(e))
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error during final signup."
        )

    except HTTPException as http_exc:
        raise http_exc

    except Exception as e:
        db.rollback()
        logger.error("Unexpected error during final signup: %s", str(e))
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Final signup failed due to unexpected server error."
        )
    
# """ Login Service """
# async def login(user_data: LoginRequest, requset : Request, db: Session) -> LoginResponse:
#     """
#     Authenticate user and return access token.
#     """
#     try:
#         logger.info(f"Attempting login for user: {user_data.email}")
#         # Fetch user
#         # result = await db.execute(select(User).filter_by(email=user_data.email))
#         # Fetch user from the result
#         result = db.execute(select(User).filter_by(email=user_data.email))

#         logger.info(f"Query executed to fetch user: {user_data.email}")
#         user: Optional[User] = result.scalars().first()

#         if not user:
#             raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password", headers={"WWW-Authenticate": "Bearer"})
#         logger.info(f"User found: {user.email}")
#         # Check if user locked
#         if user.lock_until and user.lock_until > datetime.now(timezone.utc):
#             raise HTTPException(status_code=status.HTTP_423_LOCKED, detail="Account locked due to multiple failed login attempts. Try later.")

#         # Verify password
#         if not verify_password(user_data.password, user.password):
#             # Increment failed_logins
#             user.failed_logins += 1
#             if user.failed_logins >= LOCK_THRESHOLD:
#                 user.lock_until = datetime.now(timezone.utc) + datetime.timedelta(minutes=LOCK_DURATION_MINUTES)
#                 logger.warning(f"User {user.email} locked due to failed login attempts.")
#                 db.commit()
#             raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password", headers={"WWW-Authenticate": "Bearer"})

#         # Reset failed_logins after successful login
#         user.failed_logins = 0
#         user.lock_until = None
#         db.commit()

#         if not user.is_active:
#             raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is inactive.")

#         # Generate access token
#         access_token = create_access_token(data={"sub": user.email})

#         # Handle refresh tokens:
#         # 1) Check if existing valid refresh token for this user + device
#         result = db.execute(
#             select(RefreshToken)
#             .filter_by(user_id=user.id, revoked=False)
#             .order_by(RefreshToken.expires_at.desc())
#         )
#         existing_token = result.scalars().first()

#         # Revoke old refresh token if any
#         if existing_token:
#             existing_token.revoked = True
#             db.commit()

#         # Generate new refresh token
#         raw_refresh_token = create_refresh_token(data={"sub": user.email})
#         hashed_refresh_token = hash_token(raw_refresh_token)
#         user_agent = get_user_agent(requset)
#         device_id = requset.headers.get("Device-ID", None)
#         ip = get_client_ip(requset)

#         new_refresh_token = RefreshToken(
#             user_id=user.id,
#             token=hashed_refresh_token,
#             expires_at=datetime.now(timezone.utc) + datetime.timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
#             revoked=False,
#             user_agent=user_agent,
#             device_id= device_id,
#             created_at=datetime.now(timezone.utc),
#         )

#         db.add(new_refresh_token)
#         db.commit()
#         db.refresh(new_refresh_token)

#         # Log login attempt
#         login_attempt = LoginAttempt(
#             user_id=user.id,
#             ip_address= ip,
#             user_agent= user_agent,
#             success=True
#         )
#         db.add(login_attempt)
#         db.commit()

#         logger.info(f"User {user.email} logged in successfully from IP {login_attempt.ip_address}")

#         return LoginResponse(
#             status="success",
#             message="Login successful",
#             access_token=access_token,
#             refresh_token=raw_refresh_token,
#             token_type="bearer",
#             user=UserOut.from_orm(user),
#         )

#     except HTTPException as e:
#         raise e

#     except SQLAlchemyError as e:
#         db.rollback()
#         logger.error(f"Database error during login: {e}")
#         traceback.print_exc()
#         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error during login.")

#     except Exception as e:
#         db.rollback()
#         logger.error(f"Unexpected error during login: {e}")
#         traceback.print_exc()
#         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unexpected error during login.")

from sqlalchemy.orm import aliased
async def login(user_data: LoginRequest, request: Request, db: Session) -> LoginResponse:
    """
    Authenticate user and return access + refresh tokens.
    """
    try:
        logger.info(f"Attempting login for user: {user_data.email}")

        result = db.execute(select(User).filter_by(email=user_data.email))
        user: Optional[User] = result.scalars().first()

        if not user:
            logger.warning(f"Login failed: user not found - {user_data.email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        logger.info(f"User found: {user.email}")

        # Check account lock
        if user.lock_until and user.lock_until > datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="Account locked due to multiple failed login attempts. Try later.",
            )

        # Verify password
        if not verify_password(user_data.password, user.password):
            user.failed_logins += 1

            if user.failed_logins >= LOCK_THRESHOLD:
                user.lock_until = datetime.now(timezone.utc) + timedelta(minutes=LOCK_DURATION_MINUTES)
                logger.warning(f"User {user.email} locked due to failed login attempts.")

            # Log failed attempt
            login_attempt = LoginAttempt(
                user_id=user.id,
                ip_address=get_client_ip(request),
                user_agent=get_user_agent(request),
                success=False
            )
            db.add(login_attempt)
            db.commit()

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Successful login — reset counters
        user.failed_logins = 0
        user.lock_until = None
        db.commit()

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is inactive."
            )
        role_row = (
        db.query(Role.name)
        .join(UserRole, Role.id == UserRole.role_id)
        .join(User, User.id == UserRole.user_id)
        .filter(User.email == user_data.email)
        .first()
    )

        role_name = role_row[0] if role_row else None
        logger.info(f"Role==>{role_name}")
        # Generate access token
        access_token = create_access_token(data=
                                           {"sub": user.email,"role":role_name,
                                            "name":user.full_name})

        # Revoke old refresh token if any
        device_id = request.headers.get("Device-ID")
        result = db.execute(
            select(RefreshToken)
            .filter_by(user_id=user.id, revoked=False, device_id=device_id)
            .order_by(RefreshToken.expires_at.desc())
        )
        existing_token = result.scalars().first()
        if existing_token:
            existing_token.revoked = True
            existing_token.replaced_by_token = None  # or set to new token hash if tracking
            db.commit()

        # Create new refresh token
        raw_refresh_token = create_refresh_token(data={"sub": user.email,"role":role_name,
                                            "name":user.full_name})
        hashed_refresh_token = hash_token(raw_refresh_token)
        expired_at = datetime.now(timezone.utc) + timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        logger.info(f"expires_at: {expired_at}")
        new_refresh_token = RefreshToken(
            user_id=user.id,
            token=hashed_refresh_token,
            expires_at=expired_at,
            revoked=False,
            user_agent=get_user_agent(request),
            device_id=device_id,
            created_at=datetime.now(timezone.utc)
        )

        db.add(new_refresh_token)
        db.commit()
        db.refresh(new_refresh_token)

        # Log successful attempt
        login_attempt = LoginAttempt(
            user_id=user.id,
            ip_address=get_client_ip(request),
            user_agent=get_user_agent(request),
            success=True
        )
        db.add(login_attempt)
        db.commit()

        logger.info(f"User {user.email} logged in successfully from IP {login_attempt.ip_address}")

        return LoginResponse(
            status="success",
            message="Login successful",
            access_token=access_token,
            refresh_token=raw_refresh_token,
            token_type="bearer",
            user=UserOut.from_orm(user),
        )

    except HTTPException as e:
        raise e

    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Database error during login: {e}")
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error during login."
        )

    except Exception as e:
        db.rollback()
        logger.error(f"Unexpected error during login: {e}")
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unexpected error during login."
        )

async def loginotprequest_service(user_data: LogOTPRequest, request: Request, db: Session) -> JSONResponse:
    """ OTP request."""
    logger.info("Starting user signup process")

    # 1) Uniqueness checks
    if not  db.query(User).filter_by(email=user_data.email).first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User is not registered"
        )
    # Phone number check is not needed here as we are using email for OTP request 
    # if not db.query(User).filter_by(phone_no=user_data.phone_no,).first():
    #     raise HTTPException(
    #         status_code=status.HTTP_409_CONFLICT,
    #         detail="Phone number is not  registered"
    #     )

    try:
        # OTP verification and other checks can be added her
        existing_otp = db.query(OtpCode).filter(
            OtpCode.email == user_data.email,
            OtpCode.method == "login_email",
            OtpCode.used == False,
            OtpCode.expires_at > datetime.now(timezone.utc)

        ).first()
        
        if existing_otp:
            logger.info(f"OTP already exists for {user_data.email}. Cannot proceed with Log In.")
            raise HTTPException(
                status_code=status.HTTP_200_OK,
                detail="OTP already sent to this email. Please verify before Log In."
            ) 
        otp = generate_otp() 
        logger.info(f"Generated OTP for {user_data.email}: {otp}")
        store_otp_email(user_data.email,otp,db,method="login_email") 
        logger.info("=========== In DB OTP Store Successfully ===========")

        return JSONResponse(
            {
                "status": "otp_sent",
                "message": "OTP sent to your email. Please verify to complete LogIn"
            })

    except SQLAlchemyError as e:
        db.rollback()
        logger.error("Database error during signup: %s", str(e))
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error during signup."
        )

    except HTTPException as http_exc:
        raise http_exc

    except Exception as e:
        db.rollback()
        logger.error("Unexpected error during signup: %s", str(e))
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Signup failed due to unexpected server error."
        )


async def refresh_access_token(refresh_token: str, request: Request, db: Session):
    refresh_token = refresh_token
    logger.info(f"Attempting to refresh token: {refresh_token}")
    payload = verify_token(refresh_token)
    logger.info(f"Token payload: {payload}")
    if not payload:
        logger.error("======== Invalid refresh token============")
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    hashed = hash_token(refresh_token)
   
    stored_token = db.query(RefreshToken).filter_by(token=hashed, revoked=False).first()
    logger.info(f"Stored token: {stored_token}")

    # Use timezone-aware datetime
    if not stored_token or stored_token.expires_at < datetime.now(timezone.utc):
        logger.error("======== Refresh token expired or invalid ============")
        raise HTTPException(status_code=401, detail="Refresh token expired or invalid")

    user = db.query(User).filter_by(id=stored_token.user_id).first()
    logger.info(f"User found: {user.email if user else 'None'}")
    
    if not user or not user.is_active:
        logger.error("======== User not found or inactive ============")
        raise HTTPException(status_code=403, detail="User not found or inactive")
    logger.info(f"User found: {user.email}")
    # Revoke old token
    stored_token.revoked = True
    logger.info(f"Revoking old token: {stored_token.token}")
    # Issue new token
    role_row = (
        db.query(Role.name)
        .join(UserRole, Role.id == UserRole.role_id)
        .join(User, User.id == UserRole.user_id)
        .filter(User.email == user.email)
        .first()
    )

    role_name = role_row[0] if role_row else None
    new_access_token = create_access_token({"sub": user.email,"role":role_name,
                                            "name":user.full_name})
    new_refresh_token_raw = create_refresh_token({"sub": user.email,"role":role_name,
                                            "name":user.full_name})
    new_hashed = hash_token(new_refresh_token_raw)
    logger.info(f"New refresh token created: {new_hashed}")
    new_refresh = RefreshToken(
        user_id=user.id,
        token=new_hashed,
        user_agent=request.headers.get("User-Agent"),
        device_id=get_client_ip(request),
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )
    logger.info(f"New refresh token: {new_refresh.token}")

    db.add(new_refresh)
    db.commit()

    return {
    "status": "success",
    "message": "Token refreshed successfully",
    "access_token": new_access_token,
    "refresh_token": new_refresh_token_raw,
    "token_type": "bearer"
}


async def get_service_logindetails(request: Request,db: Session):
    logger.info("=========== fetch API login details started ===========")
    access_token = request.headers.get("Authorization")
   # original_token = access_token[:7]
    logger.info(access_token[7:])
    payload = verify_token(access_token)
    logger.info(f"Token Payload : {payload}")
    if not payload:
        logger.error("===========Invalid access token===========")
        raise HTTPException(status_code=401,detail="Invalid access token")
    
    logger.info(f"expiry time {payload['exp']}")
    exp_time=datetime.fromtimestamp(payload['exp'],tz=timezone.utc)
    now=datetime.now(timezone.utc)
    logger.info(f"current time {now} and expiry time {exp_time}")

    if now>exp_time :
        logger.error("=========== token expired ===========")
        raise HTTPException(status_code=401,detail="token expired")
    user_data = db.query(User).filter(User.email == payload.get('sub')).first()
    logger.info(user_data)
    if not user_data:
        raise HTTPException(status_code=404,detail='Use not found')
    return GetLoginResponse(
        status="success",
        message="Login details retrieved successfully",
        email=payload.get('sub'),
        name=payload.get('name'),
        role=payload.get('role'),
        phone_no=user_data.phone_no,
        is_active=user_data.is_active,
        is_verified_phone=user_data.is_verified_phone,
        failed_logins=user_data.failed_logins,
        lock_until=user_data.lock_until,
        fingerprint_template=user_data.fingerprint_template
        
        
    )
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
security = HTTPBearer() 
async def logout(
    request: Request,
    db: Session ,
    token: HTTPAuthorizationCredentials = Depends(security)  # extract token from Authorization header
) -> JSONResponse:
    """
    Logout the user by invalidating the refresh token.
    """
    try:
        refresh_token = token.credentials  # get raw token string
        logger.info(f"Attempting logout for token: {refresh_token}")

        if not refresh_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Refresh token is required"
            )

        logger.info("Starting logout process...")

        # Hash the incoming token
        hashed_token = hash_token(refresh_token)
        logger.info(f"Hashed token: {hashed_token}")
        
        # Query the database for this token (only unrevoked tokens)
        stored_token = (
            db.query(RefreshToken)
            .filter_by(token=hashed_token, revoked=False)
            .first()
        )
        logger.info(f"Stored token found: {stored_token}")
        
        # If token is found, revoke it
        if not stored_token or stored_token.revoked:
            logger.warning("No valid refresh token found for logout.")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Refresh token not found or already revoked"
            )

        stored_token.revoked = True
        stored_token.revoked_at = datetime.utcnow()  # store revocation time
        db.commit()
        logger.info(f"Refresh token revoked at {stored_token.revoked_at}")
    

        # Return generic success response
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"status": "success", "message": "Logged out successfully"}
        )

    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        logger.error(f"Logout failed: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )
    
async def verify_loginwithotp_service(request : VerifyLoginOTPRequest,request1:Request,db : Session) :
    try: 
        logger.info("================ verifying login OTP ====================")

        # user=db.query(User).filter(User.email == request.email).first()
        result = db.execute(select(User).filter_by(email=request.email))
        user: Optional[User] = result.scalars().first()

        if not user:
            logger.warning(f"Login failed: user not found - {request.email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        logger.info(f"User found: {user.email}")

        # if not user :
        #     logger.error("============ User Not Found =============")
        #     raise HTTPException(status_code=404,detail="user not found")
        # logger.info("AFTER USER QUERY")
        otp_entry = (
                db.query(OtpCode)
                .filter(
                OtpCode.email == request.email,
                OtpCode.otp_code == request.otp,
                OtpCode.expires_at> datetime.now(timezone.utc),
                OtpCode.used == False,
                OtpCode.method == "login_email"
                )
                .order_by(OtpCode.created_at.desc())  # latest OTP
                .first()
        )
        if not otp_entry :
            logger.error("============ Invalid OTP =============")
            raise HTTPException(status_code=400, detail="Invalid OTP / OTP Already Used ")  
        
        otp_entry.used = True
        logger.info(" BEFORE ACCESSS TOKEN ")
        # access_token=create_access_token(
        #     {"sub": user.email,"name" : user.name,"role" : user.role},)
      
        # role_row=(
        #     db.query(Role.name)
        # .join(UserRole,Role.id==UserRole.user_id)
        # .join(User,User.id==UserRole.user_id)
        # .filter(User.email==request.email)
        # .first()
        # )
        # role_name=role_row[0] if role_row else None
        # logger.info(f"Role==>{role_name}")

        role_row = (
        db.query(Role.name)
        .join(UserRole, Role.id == UserRole.role_id)
        .join(User, User.id == UserRole.user_id)
        .filter(User.email == request.email)
        .first()
    )

        role_name = role_row[0] if role_row else None
        logger.info(f"Role==>{role_name}")
        
        access_token = create_access_token(data=
                                            {"sub": user.email,"role":role_name,
                                                "name":user.full_name})
        logger.info(access_token)

       # Get device ID from headers
        device_id = request1.get("Device-ID")
        logger.info(device_id )
        # Revoke old refresh token
        result=db.execute(
                        select(RefreshToken)
                          .filter_by(user_id=user.id,revoked=False,device_id=device_id)
                          .order_by(RefreshToken.expires_at.desc())
                          )
        existing_token=result.scalars().first()
        if existing_token :
            existing_token.revoked=True
            existing_token.replaced_by_token=None
            db.commit()
        # Create New Refresh Token
        refresh_token=create_refresh_token(data={"sub": user.email,"role":role_name,"name":user.full_name})
        hashed_refresh_token=hash_token(refresh_token)
        expired_at=datetime.now(timezone.utc)+timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        logger.info(f"expires_at:{expired_at}")
        new_refresh_token=RefreshToken(
            user_id=user.id,
            token=hashed_refresh_token,
            expires_at=expired_at,
            revoked=False,
            user_agent=get_user_agent(request1),
            device_id=device_id,
            created_at=datetime.now(timezone.utc)
        )

        db.add(new_refresh_token)
        db.commit()
        db.refresh(new_refresh_token)


        logger.info("================ OTP verified tokens generated ================")
        logger.info(new_refresh_token)

        return LoginResponse(
            status="success",
            message="OTP verified successfully",
            access_token=access_token,
            refresh_token=refresh_token,
            user=UserOut.from_orm(user)

        )
    except HTTPException as e:
            raise e

    except SQLAlchemyError as e:
            db.rollback()
            logger.error(f"Database error during login: {e}")
            traceback.print_exc()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Database error during login."
            )

    except Exception as e:
            db.rollback()
            logger.error(f"Unexpected error during login: {e}")
            traceback.print_exc()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Unexpected error during login."
            )
    
async def forgetpassword_otprequest_service(user_data:ForgetPasswordOTPRequest,request:Request,db:Session) -> JSONResponse:
    if not db.query(User).filter(User.email==user_data.email).first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="user not registered"
        )
    
    try:
        existing_otp=db.query(OtpCode).filter(
            OtpCode.email==user_data.email,
            OtpCode.method=="forget_otp",
            OtpCode.used==False,
            OtpCode.expires_at>datetime.now(timezone.utc)
        ).first()
        if existing_otp:
            logger.info(f"OTP already exist for{user_data.email}.cant proceed")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="OTP already sent to this email. Please verify before Log In."
            ) 
        otp=generate_otp()
        logger.info(f"generated otp for {user_data.email}:{otp}")
        store_otp_email(user_data.email,otp,db,method="forget_otp")
        logger.info("============= OTP stored successfully in DB =============")

        return JSONResponse(
            {
                "status":"otp_sent",
                "message":"otp sent to your mail.please verify to forget password"
            }
        )
    except SQLAlchemyError as e:
        db.rollback()
        logger.error("database error during forget password:%s",str(e))
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="database error during forget password"
        )
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        db.rollback()
        logger.error("Unexpected error during forget password: %s", str(e))
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Forget password failed due to unexpected server error."
        )



# service.py

async def google_login(request, db: AsyncSession):
    email = request.email
    name = request.name
    profile_picture = request.profile_picture
    token = request.token

    if not email or not token:
        raise HTTPException(status_code=400, detail="Email and token required")

    # Fetch user asynchronously
    # result = await db.execute(select(User).where(User.email == email))
    # user = result.scalars().first()
     # 1. Find the user
    user = db.query(User).filter_by(email=email).first()
    phone_no_value = "0000000000"  # Placeholder phone number
    if not user:
        # First-time login → create user
        user = User(
            email=email,
            full_name=name,
            profile_picture=profile_picture,
            google_token=token,
            provider="google",
            is_active=True,
            is_verified_email=True,
            phone_no = phone_no_value, # No phone number since using OAuth
            password = ""  # No password since using OAuth
            
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        # Verify token
        if user.google_token != token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token verification failed"
            )

    # Issue JWT tokens
    access_token = create_access_token({"sub": str(user.id)})
    refresh_token = create_refresh_token({"sub": str(user.id)})

    return {
        "status": "success",
        "message": "Google login successful",
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "profile_picture": user.profile_picture,
            "phone_no": user.phone_no
        },
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }