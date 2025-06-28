""" RawModel """
# app/core/base.py


from datetime import datetime
from typing import Any
from sqlalchemy import Column, BigInteger, DateTime, Boolean
from sqlalchemy.sql import func
from sqlalchemy.orm import declarative_base, Session
from pydantic import BaseModel

# ========== SQLAlchemy Base ==========
Base = declarative_base()

class RWModel(Base):
    __abstract__ = True

    id = Column(BigInteger, primary_key=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    is_deleted = Column(Boolean, default=False, nullable=False)

    def save(self, session: Session):
        session.add(self)
        session.commit()

    def delete(self, session: Session):
        self.is_deleted = True
        self.save(session)

    def to_dict(self) -> dict[str, Any]:
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

# ========== Utility Functions ==========
def to_camel(string: str) -> str:
    parts = string.split('_')
    return parts[0] + ''.join(word.lower() for word in parts[1:])

def format_datetime(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")

