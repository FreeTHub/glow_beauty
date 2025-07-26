from logging.config import fileConfig
import os

from sqlalchemy import engine_from_config, pool
from alembic import context

# ✅ Load .env for environment variables (before using them)
from dotenv import load_dotenv
load_dotenv(".env")  # Ensure this file exists and has DATABASE_URL

# === Load Alembic config ===
config = context.config

# ✅ Enable logging from Alembic config file
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# ✅ Fetch DATABASE_URL from environment and validate
db_url = os.getenv("DATABASE_URL")
print(f"Using DATABASE_URL: {db_url}")  # Debugging line to check the URL
if not db_url:
    raise RuntimeError("DATABASE_URL is not set in .env or environment variables")

# ✅ Set the database URL for Alembic
config.set_main_option("sqlalchemy.url", db_url)

# === Import models & metadata ===
from app.core.base import Base
from app.auth.models import User, Role, UserRole, EmailVerification
from app.auth.models import PasswordReset, RefreshToken, OtpCode  , UserLogin, LoginAttempt

target_metadata = Base.metadata

# === Offline Migration ===
def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()

# === Online Migration ===
def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )
        with context.begin_transaction():
            context.run_migrations()

# === Choose mode ===
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
