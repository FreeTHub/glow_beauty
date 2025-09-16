""" Pydantic schemas for user authentication and management. / Validation and serialization of user data. """

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, field_validator
import re

# ------------------ Base Schema ------------------
class UserBase(BaseModel):
    email: EmailStr
    phone_no: int

    model_config = {
        "from_attributes": True
    }

# ------------------ Create User ------------------
class UserCreate(UserBase):
    full_name: str
    password: str = Field(..., min_length=8)

    @field_validator("password")
    def validate_password_strength(cls, v):
        if not re.search(r'[A-Z]', v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r'\d', v):
            raise ValueError("Password must contain at least one number")
        if not re.search(r'[!@#$%^&*(),.?\":{}|<>]', v):
            raise ValueError("Password must contain at least one special character")
        return v

# ------------------ Output Schema ------------------
class UserOut(BaseModel):
    id: int
    email: EmailStr
    phone_no: int
    full_name: str
    is_active: bool
    is_verified_email: bool
    is_verified_phone: bool
    created_at: datetime
    updated_at: datetime

    model_config = {
        "from_attributes": True
    }

# ------------------ Signup with OTP ------------------
class SignUpVerifyRequest(UserCreate):
    otp: str = Field(..., min_length=6, max_length=6)

    @field_validator("otp")
    def validate_otp(cls, v):
        if not re.match(r'^\d{6}$', str(v)):
            raise ValueError("OTP must be a 6-digit number")
        return v

    @field_validator("phone_no")
    def validate_phone(cls, v):
        if not re.match(r'^\d{10}$', str(v)):
            raise ValueError("Phone number must be 10 digits")
        return v

# ------------------ Signup (without OTP) ------------------
class SignUpRequest(BaseModel):
    email: EmailStr
    full_name: str
    password: str
    phone_no: int

    @field_validator("phone_no")
    def validate_phone_no(cls, v):
        if not re.match(r'^\d{10}$', str(v)):
            raise ValueError("Phone number must be 10 digits")
        return v

    @field_validator("password")
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not re.search(r'[A-Z]', v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r'\d', v):
            raise ValueError("Password must contain at least one number")
        if not re.search(r'[!@#$%^&*(),.?\":{}|<>]', v):
            raise ValueError("Password must contain at least one special character")
        return v

# ------------------ Login ------------------
class LogOTPRequest(BaseModel):
    email: EmailStr

    @field_validator("email")
    def validate_email(cls, v):
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', str(v)):
            raise ValueError("Invalid email format")
        return v
    
class LoginRequest(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        return v


# ------------------ Login Response ------------------
class LoginResponse(BaseModel):
    status: str
    message: str
    user: UserOut
    access_token: str
    refresh_token: str

    model_config = {
        "from_attributes": True
    }

# ------------------ Logout Response ------------------
class LogoutResponse(BaseModel):
    status: str
    message: str

    model_config = {
        "from_attributes": True
    }

# ------------------ Sign Up Response ------------------
class SignUpResponse(BaseModel):
    status: str
    message: str

    model_config = {
        "from_attributes": True
    }

# ------------------ Refresh Token ------------------
class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class RefreshTokenResponse(BaseModel):
    status: str
    message: str
    access_token: str
    refresh_token: str

    model_config = {
        "from_attributes": True
    }

#------------------ Fingerprint Schema ------------------
class FingerprintRequest(BaseModel):
    fingerprint: str
    email: EmailStr
    # user_agent: Optional[str] = None
    # ip_address: Optional[str] = None
    @field_validator("fingerprint")
    def validate_fingerprint(cls, v):
        if not v:
            raise ValueError("Invalid fingerprint")
        return v
    