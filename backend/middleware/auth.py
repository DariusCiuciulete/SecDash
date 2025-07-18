"""
Authentication middleware for Keycloak JWT validation
"""
from typing import Optional
import jwt
from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from config import settings

# JWT Bearer token extractor
security = HTTPBearer(auto_error=False)


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """
    Middleware to validate Keycloak JWT tokens
    """
    
    def __init__(self, app):
        super().__init__(app)
        self.public_paths = {
            "/", "/health", "/docs", "/redoc", "/openapi.json",
            "/health/live", "/health/ready", "/health/health"
        }
    
    async def dispatch(self, request: Request, call_next):
        # Skip authentication for public paths
        if request.url.path in self.public_paths:
            return await call_next(request)
        
        # For now, skip authentication in debug mode
        if settings.debug:
            request.state.user = {"sub": "debug-user", "preferred_username": "debug"}
            return await call_next(request)
        
        # Extract JWT token from Authorization header
        authorization = request.headers.get("Authorization")
        if not authorization or not authorization.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"error": "Missing or invalid authorization header"}
            )
        
        token = authorization.replace("Bearer ", "")
        
        try:
            # Validate JWT token (simplified - in production use proper Keycloak validation)
            payload = jwt.decode(
                token, 
                options={"verify_signature": False},  # Disabled for demo
                algorithms=[settings.security.jwt_algorithm]
            )
            
            # Store user info in request state
            request.state.user = payload
            
        except jwt.InvalidTokenError as e:
            return JSONResponse(
                status_code=401,
                content={"error": f"Invalid token: {str(e)}"}
            )
        except Exception as e:
            return JSONResponse(
                status_code=500,
                content={"error": f"Authentication error: {str(e)}"}
            )
        
        return await call_next(request)


def get_current_user(request: Request) -> Optional[dict]:
    """Get current user from request state"""
    return getattr(request.state, "user", None)
