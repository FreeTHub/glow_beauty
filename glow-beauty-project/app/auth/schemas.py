""" Pydantic schemas for user authentication and management. / Validation and serialization of user data. """

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, field_validator 
import re

class UserBase(BaseModel):
    email: EmailStr
    phone_no: int
    # is_active: bool = True
    # is_verified_email: bool = False  
    # is_verified_phone: bool = False
    # is_deleted: bool = False
    # failed_logins: int = 0
    # lock_until: Optional[datetime] = None
    # two_factor_enabled: bool = False
    # two_factor_secret: Optional[str] = None
    # fingerprint_template: Optional[str] = None  # Text field
    # # created_at: Optional[datetime] = None
    # updated_at: Optional[datetime] = None

    model_config = {
        "from_attributes": True  # replaces orm_mode in Pydantic v2
    }

class UserCreate(UserBase):
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


class UserOut(BaseModel):
    id: int
    email: EmailStr
    phone_no: int
    is_active: bool
    is_verified_email: bool
    is_verified_phone: bool
    created_at: datetime
    updated_at: datetime

    model_config = {
        "from_attributes": True  # Enables ORM mapping (Pydantic v2+)
    }

class SignUpVerifyRequest(UserCreate): #SignUpRequest
    """Input schema for user signup"""
    otp: str = Field(..., min_length=6, max_length=6, description="One-time password for verification")
    @field_validator("otp")
    def validate_otp(cls, v):
        if not re.match(r'^\d{6}$', str(v)):
            raise ValueError("OTP must be a 6-digit number")
        return v
    
    def validate_phone_no(cls, v):
        if not re.match(r'^\d{10}$', str(v)):
            raise ValueError("Phone number must be a 10-digit number")
        return v
        
    def validate_email(cls, v):
        if not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', v):
            raise ValueError("Invalid email format")
        return v
    
    
class SignUpRequest(BaseModel):  #SignUpVerifyRequest
    email: EmailStr
    name:str
    password: str
    phone_no: int
    @field_validator("phone_no")
    
    def validate_phone_no(cls, v):
        if not re.match(r'^\d{10}$', str(v)):
            raise ValueError("Phone number must be a 10-digit number")
        return v
    
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not re.search(r'[A-Z]', v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r'\d', v):
            raise ValueError("Password must contain at least one number")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError("Password must contain at least one special character")
        return v
        
    def validate_email(cls, v):
        if not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', v):
            raise ValueError("Invalid email format")
        return v

class SignUpResponse(BaseModel):
    status: str
    message: str
    # user: UserOut

    model_config = {
        "from_attributes": True
    }

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        return v
    
class LoginResponse(BaseModel):
    status: str
    message: str
    user: UserOut
    access_token: str
    refresh_token: str

    model_config = {
        "from_attributes": True
    }

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"    

class RefreshTokenRequest(BaseModel):
    refresh_token: str

    # @field_validator("refresh_token")
    # def validate_refresh_token(cls, v):
    #     if not re.match(r'^[a-zA-Z0-9-_.]+$', v):
    #         raise ValueError("Invalid refresh token format")
    #     return v
    
class RefreshTokenResponse(BaseModel):
    status: str
    message: str
    access_token: str
    refresh_token: str

    model_config = {
        "from_attributes": True
    }