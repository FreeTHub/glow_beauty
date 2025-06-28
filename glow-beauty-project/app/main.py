from fastapi import FastAPI
from auth import routes
from core.config import settings

app = FastAPI()

#swagger docs
app.title = settings.APP_TITLE
app.description = settings.APP_DESCRIPTION
app.version = settings.APP_VERSION
app.docs_url = settings.DOCS_URL
app.openapi_url =settings.OPENAPI_URL
app.api_version = settings.API_VERSION

# Include the health router endpoints
app.include_router(routes.router,tags=settings.API_VERSION)


