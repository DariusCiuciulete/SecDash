"""
Error handling middleware
"""
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import traceback
from datetime import datetime


class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    """
    Global error handling middleware
    """
    
    async def dispatch(self, request: Request, call_next):
        try:
            return await call_next(request)
        except Exception as e:
            # Log the error (in production, use proper logging)
            error_traceback = traceback.format_exc()
            print(f"Unhandled error: {error_traceback}")
            
            # Return formatted error response
            return JSONResponse(
                status_code=500,
                content={
                    "error": "Internal server error",
                    "message": str(e) if request.app.debug else "An unexpected error occurred",
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
            )
