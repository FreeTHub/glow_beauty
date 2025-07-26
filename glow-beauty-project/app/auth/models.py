""" Models Declaration Here """

from sqlalchemy import (
    Column, Integer, String, Boolean, ForeignKey, BigInteger, Date, Text, DateTime
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from ..core.base import RWModel,Base

#from core.base import RWModel, Base  # Assuming RWModel is a custom base model


# Import RWModel from the previous step

class User(RWModel):
    __tablename__ = "users"

    email = Column(String(255), unique=True, nullable=False, index=True)
    phone_no = Column(BigInteger, unique=True, nullable=False, index=True)
    password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified_email = Column(Boolean, default=False, nullable=False)
    is_verified_phone = Column(Boolean, default=False, nullable=False)
    failed_logins = Column(Integer, default=0)
    lock_until = Column(DateTime(timezone=True), nullable=True)
    two_factor_enabled = Column(Boolean, default=False)
    two_factor_secret = Column(String(255), nullable=True)
    fingerprint_template = Column(Text, nullable=True)  # bytea in PG = Text here

    roles = relationship("UserRole", back_populates="user", cascade="all, delete-orphan")
    # info = relationship("UserInfo", back_populates="user", uselist=False, cascade="all, delete-orphan")
    email_verifications = relationship("EmailVerification", back_populates="user", cascade="all, delete-orphan")
    password_resets = relationship("PasswordReset", back_populates="user", cascade="all, delete-orphan")
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")
    login_attempts = relationship("LoginAttempt", back_populates="user", cascade="all, delete-orphan")
    otp_codes = relationship("OtpCode", back_populates="user", cascade="all, delete-orphan")
    user_logins = relationship("UserLogin", back_populates="user", cascade="all, delete-orphan")


class Role(RWModel):
    __tablename__ = 'roles'

    name = Column(String(50), unique=True, nullable=False)
    description = Column(Text, nullable=True)

    user_roles = relationship("UserRole", back_populates="role", cascade="all, delete-orphan")


class UserRole(Base):
    __tablename__ = 'user_roles'

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id = Column(BigInteger, ForeignKey('users.id'), primary_key=True)
    role_id = Column(BigInteger, ForeignKey('roles.id'), primary_key=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    user = relationship("User", back_populates="roles")
    role = relationship("Role", back_populates="user_roles")


class EmailVerification(RWModel):
    __tablename__ = 'email_verifications'

    user_id = Column(BigInteger, ForeignKey('users.id'), nullable=False)
    token = Column(String(255), unique=True, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used = Column(Boolean, default=False)


    user = relationship("User", back_populates="email_verifications")


class PasswordReset(RWModel):
    __tablename__ = 'password_resets'

    user_id = Column(BigInteger, ForeignKey('users.id'), nullable=False)
    token = Column(String(255), unique=True, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used = Column(Boolean, default=False)

    user = relationship("User", back_populates="password_resets")


class RefreshToken(RWModel):
    __tablename__ = 'refresh_tokens'

    user_id = Column(BigInteger, ForeignKey('users.id'), nullable=False)
    token = Column(String(512), unique=True, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked = Column(Boolean, default=False)
    replaced_by_token = Column(String(512), nullable=True)
    user_agent = Column(String(255), nullable=True)
    device_id = Column(String(100), nullable=True)

    user = relationship("User", back_populates="refresh_tokens")
    user_logins = relationship("UserLogin", back_populates="refresh_token")


class LoginAttempt(RWModel):
    __tablename__ = 'login_attempts'

    user_id = Column(BigInteger, ForeignKey('users.id'), nullable=False)
    ip_address = Column(String(45), nullable=False)
    user_agent = Column(String(255), nullable=True)
    success = Column(Boolean, nullable=False)

    user = relationship("User", back_populates="login_attempts")


class OtpCode(RWModel):
    __tablename__ = 'otp_codes'

    user_id = Column(BigInteger, ForeignKey('users.id'), nullable=False)
    otp_code = Column(String(10), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used = Column(Boolean, default=False)
    method = Column(String(20), nullable=False)  # e.g., email, sms, app

    user = relationship("User", back_populates="otp_codes")


class UserLogin(RWModel):
    __tablename__ = 'user_logins_activity'

    user_id = Column(BigInteger, ForeignKey('users.id'), nullable=False)
    ip_address = Column(String(45), nullable=False)
    user_agent = Column(String(255), nullable=True)
    device_id = Column(String(100), nullable=True)
    geo_country = Column(String(50), nullable=True)
    geo_city = Column(String(100), nullable=True)
    method = Column(String(20), nullable=True)  # password, otp, google, etc.
    refresh_token_id = Column(BigInteger, ForeignKey('refresh_tokens.id'), nullable=True)

    user = relationship("User", back_populates="user_logins")
    refresh_token = relationship("RefreshToken", back_populates="user_logins")
