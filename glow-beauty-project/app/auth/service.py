"""  For Business Logic of Authentication Service  """
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from auth import models, schemas, utils
from auth.models import User, EmailVerification,UserRole
from auth.schemas import SignUpRequest, UserOut ,SignUpResponse
from auth.utils import hash_password
from core.config import settings
import os
import datetime


""" Health Service Check """
def health_check():
    return {
        "status": "ok",
        "message": "Authentication Service is running smoothly"
    }

# """ Signup Service """
# def sign_up(user_data):
#     # Here you would typically hash the password and save the user to a database
#     # For simplicity, we are just returning the user data
#     return {
#         "status": "success",
#         "message": "User signed up successfully",
#         "user": user_data
#     }



from sqlalchemy.exc import SQLAlchemyError
from fastapi import HTTPException, status
from datetime import datetime, timedelta
import os
import traceback
def sign_up(user_data: SignUpRequest, db: Session) -> SignUpResponse:
    # 1) Uniqueness checks
    if db.query(User).filter_by(email=user_data.email).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    if db.query(User).filter_by(phone_no=user_data.phone_no).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Phone number already registered"
        )

    try:
        # 2) Create user instance
        new_user = User(
            email=user_data.email,
            phone_no=user_data.phone_no,
            password=hash_password(user_data.password),
            is_active=True,
            is_verified_email=False,
            is_verified_phone=False
        )

        # 3) Persist to database
        db.add(new_user)
        db.flush()  
         # ✅ Assign default role to user
        default_role = UserRole(
            user_id=new_user.id,
            role_id=1,  # Assuming role_id=1 is the default role  
              # or however your UserRole is structured
            created_at = datetime.utcnow()  
        )
        db.add(default_role)





        db.commit()
        db.refresh(new_user)

        # 4) Optional: Email verification token generation and email sending
        # raw_token = generate_token()
        # token_hash = hash_token(raw_token)
        # verification = EmailVerification(
        #     user_id=new_user.id,
        #     token=token_hash,
        #     expires_at=datetime.utcnow() + timedelta(minutes=15)
        # )
        # db.add(verification)
        # db.commit()
        #
        # verify_link = f"{os.getenv('FRONTEND_URL')}/verify-email?token={raw_token}"
        # send_email(
        #     to=new_user.email,
        #     subject="Verify your email",
        #     body=(
        #         "Please click the following link to verify your account:\n\n"
        #         f"{verify_link}"
        #     )
        # )

        # 5) Return wrapped response
        return SignUpResponse(
            status="success",
            message="User registered successfully.",
            user=new_user  # Pydantic converts via orm_mode
        )

    except SQLAlchemyError as e:
        db.rollback()
        print("Database error during signup:", str(e))
        traceback.print_exc()  # <-- Prints full error stack
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error during signup."
        )
    except Exception:
        db.rollback()
        print("Database error during signup:", str(e))
        traceback.print_exc()  # <-- Prints full error stack
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Signup failed due to server error."
        )