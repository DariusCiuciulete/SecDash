"""
Health check and monitoring endpoints
"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from database import get_db_session
from schemas import BaseSchema

router = APIRouter()


class HealthResponse(BaseSchema):
    """Health check response schema"""
    status: str
    database: str
    redis: str
    version: str


@router.get("/live", summary="Liveness probe")
async def liveness():
    """
    Kubernetes liveness probe endpoint.
    Returns 200 if the application is running.
    """
    return {"status": "alive"}


@router.get("/ready", summary="Readiness probe", response_model=HealthResponse)
async def readiness(db: AsyncSession = Depends(get_db_session)):
    """
    Kubernetes readiness probe endpoint.
    Checks database connectivity and other dependencies.
    """
    # Check database connectivity
    try:
        await db.execute(text("SELECT 1"))
        db_status = "healthy"
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"
    
    # Check Redis connectivity (Celery broker)
    try:
        from celery_app import celery_app
        inspect = celery_app.control.inspect()
        stats = inspect.stats()
        redis_status = "healthy" if stats else "unhealthy"
    except Exception as e:
        redis_status = f"unhealthy: {str(e)}"
    
    overall_status = "ready" if all(
        status == "healthy" 
        for status in [db_status, redis_status]
    ) else "not ready"
    
    return HealthResponse(
        status=overall_status,
        database=db_status,
        redis=redis_status,
        version="2.0.0"
    )


@router.get("/health", summary="Detailed health check", response_model=HealthResponse)
async def health_check(db: AsyncSession = Depends(get_db_session)):
    """
    Detailed health check endpoint with full system status.
    """
    return await readiness(db)
