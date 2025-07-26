from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from fastapi.security import HTTPBearer
from fastapi.middleware.cors import CORSMiddleware

from app.auth import routes
from app.core.config import settings
from app.core.authMiddleware import AuthMiddleware

# Initialize FastAPI
app = FastAPI(
    title=settings.APP_TITLE,
    description=settings.APP_DESCRIPTION,
    version=settings.APP_VERSION,
    docs_url=settings.DOCS_URL,
    openapi_url=settings.OPENAPI_URL,
    openapi_tags=settings.APP_TAGS
)

# Optional: CORS Middleware (adjust as needed)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace with your frontend domains in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Swagger Bearer Token Support ---
bearer_scheme = HTTPBearer(bearerFormat="JWT")

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=settings.APP_TITLE,
        version=settings.APP_VERSION,
        description=settings.APP_DESCRIPTION,
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        }
    }
    for path in openapi_schema["paths"].values():
        for operation in path.values():
            operation["security"] = [{"BearerAuth": []}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# Include your routers (with tags)
app.include_router(routes.router, tags=settings.API_VERSION)

# Add your custom authentication middleware
app.add_middleware(AuthMiddleware)
