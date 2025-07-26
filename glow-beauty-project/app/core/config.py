from pydantic_settings import BaseSettings
from pathlib import Path
import os
from dotenv import load_dotenv

load_dotenv()  # Load from .env

class Settings(BaseSettings):
    DATABASE_URL: str
    SECRET_KEY: str
    DEBUG: bool = False
    PROJECT_NAME: str = "FastAPI Project"
    ENV: str = "development"  # or 'production'

    # Application settings
    APP_TITLE: str = os.getenv("APP_TITLE", "")
    APP_DESCRIPTION: str = os.getenv("APP_DESCRIPTION", "")
    APP_VERSION: str = os.getenv("APP_VERSION", "")
    API_VERSION: list = os.getenv("API_VERSION", [])
    DOCS_URL: str = os.getenv("DOCS_URL", "")
    OPENAPI_URL: str = os.getenv("OPENAPI_URL", "")
    APP_TAGS: str = os.getenv("APP_TAGS", "")  # Should be a JSON string

    class Config:
        env_file = Path(__file__).resolve().parent / ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


settings = Settings()
