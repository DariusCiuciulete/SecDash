"""
SecDash v2.0 - Modern FastAPI application with async SQLAlchemy and Celery
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.openapi.utils import get_openapi

# Observability imports
import sentry_sdk
from sentry_sdk.integrations.fastapi import FastApiIntegration
from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration
from opentelemetry import trace
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor

from config import settings
from database import init_db, close_db
from api.v1 import assets, scans, vulnerabilities, dashboard, profiles, health
from middleware.auth import AuthenticationMiddleware
from middleware.error_handling import ErrorHandlingMiddleware


# Initialize observability
if settings.observability.sentry_dsn:
    sentry_sdk.init(
        dsn=settings.observability.sentry_dsn,
        integrations=[
            FastApiIntegration(auto_enabling_instrumentations=False),
            SqlalchemyIntegration(),
        ],
        traces_sample_rate=0.1,
        profiles_sample_rate=0.1,
    )

# Initialize OpenTelemetry
tracer = trace.get_tracer(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    print("Starting SecDash v2.0...")
    
    # Initialize database
    try:
        await init_db()
        print("Database initialized successfully")
    except Exception as e:
        print(f"Database initialization failed: {e}")
        raise
    
    yield
    
    # Shutdown
    print("Shutting down SecDash...")
    await close_db()
    print("Database connections closed")


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    description="Modern Security Dashboard for Vulnerability Management",
    version=settings.app_version,
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    openapi_url="/openapi.json" if settings.debug else None,
    lifespan=lifespan,
)

# Add middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.allowed_hosts,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(AuthenticationMiddleware)
app.add_middleware(ErrorHandlingMiddleware)

# Include API routers
app.include_router(health.router, prefix="/health", tags=["Health"])
app.include_router(assets.router, prefix=f"{settings.api_prefix}/assets", tags=["Assets"])
app.include_router(scans.router, prefix=f"{settings.api_prefix}/scans", tags=["Scans"])
app.include_router(vulnerabilities.router, prefix=f"{settings.api_prefix}/vulnerabilities", tags=["Vulnerabilities"])
app.include_router(dashboard.router, prefix=f"{settings.api_prefix}/dashboard", tags=["Dashboard"])
app.include_router(profiles.router, prefix=f"{settings.api_prefix}/profiles", tags=["Scan Profiles"])

# Custom OpenAPI schema
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    
    # Add security schemes
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        }
    }
    
    # Add global security requirement
    openapi_schema["security"] = [{"BearerAuth": []}]
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

# Initialize OpenTelemetry instrumentation
if settings.observability.jaeger_endpoint:
    FastAPIInstrumentor.instrument_app(app)
    SQLAlchemyInstrumentor().instrument()


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Custom HTTP exception handler"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "timestamp": "2025-07-17T00:00:00Z"  # Use actual timestamp
        }
    )


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "status": "running",
        "docs_url": "/docs" if settings.debug else None,
    }


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
        log_level=settings.observability.log_level.lower(),
        access_log=settings.debug,
    )
