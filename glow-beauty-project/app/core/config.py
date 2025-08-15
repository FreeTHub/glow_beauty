from pydantic_settings import BaseSettings
from pathlib import Path
from dotenv import load_dotenv
from typing import ClassVar

load_dotenv()


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Basic App Settings
    DATABASE_URL: str
    SECRET_KEY: str
    DEBUG: bool = False
    PROJECT_NAME: str = "FastAPI Project"
    ENV: str = "development"

    APP_TITLE: str = "My FastAPI App"
    APP_DESCRIPTION: str = "FastAPI Project Description"
    APP_VERSION: str = "1.0.0"
    API_VERSION: list = ["v1"]
    DOCS_URL: str = "/docs"
    OPENAPI_URL: str = "/openapi.json"
    APP_TAGS: str = "[]"

    # JWT Expiry Settings
    REFRESH_TOKEN_EXPIRE_DAYS: int = 60
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1

    # Class-level constants
    ALGORITHM: ClassVar[str] = 'RS256'
    PRIVATE_KEY: ClassVar[bytes]
    PUBLIC_KEY: ClassVar[bytes]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # Load RSA keys during app startup
        key_dir = Path(__file__).resolve().parent / "keys"
        try:
            type(self).PRIVATE_KEY = (key_dir / "private.pem").read_bytes()
            type(self).PUBLIC_KEY = (key_dir / "public.pem").read_bytes()
        except FileNotFoundError as e:
            raise RuntimeError(f"RSA Key loading failed: {e}")

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
    }


settings = Settings()
