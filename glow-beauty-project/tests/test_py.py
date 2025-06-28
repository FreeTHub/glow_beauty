from pydantic_settings import BaseSettings
from pathlib import Path

class Settings(BaseSettings):
    DATABASE_URL: str
    SECRET_KEY: str
    DEBUG: bool

    class Config:
        env_file = Path(__file__).resolve().parents[1] / ".env"
        extra = "allow"  # Optional: allows extra env keys if any

settings = Settings()
print("✅ Loaded DB:", settings.DATABASE_URL)
