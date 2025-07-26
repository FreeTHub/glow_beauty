""" Database Configuration and Handle From Here  """

# from sqlalchemy.ext.declarative import declarative_base
# from sqlalchemy.orm import sessionmaker
# from sqlalchemy import create_engine
# from app.core.config import settings


# DATABASE_URL = "postgresql+psycopg2://postgres:admin@localhost/post"

# engine = create_engine(DATABASE_URL, echo=True)
# SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# Base = declarative_base()


from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
# from app.core.config import settings
from app.core.config import settings


# Database setup with connection pooling and timeouts
engine = create_engine(
    settings.DATABASE_URL,
    pool_size=20,  # Number of connections to keep open
    max_overflow=10,  # Additional connections allowed during peak
    pool_timeout=30,  # Seconds to wait for a connection
    pool_recycle=3600,  # Recycle connections after 1 hour
    # For SQLite only:
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False  # Optional: control object expiration
)

Base = declarative_base()

#Dependency for getting DB session in FastAPI routes
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()