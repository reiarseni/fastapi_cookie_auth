"""
Role-based access control decorators for FastAPI Cookie Auth.

This module provides decorators for implementing role-based access control
in FastAPI applications using the fastapi_cookie_auth package.
"""

from functools import wraps
from fastapi import Request, status
from fastapi.responses import JSONResponse


def roles_required(*roles):
    """
    Decorator to allow access only to users with specific roles.
    
    This decorator should be used after the login_required decorator
    to ensure the user is authenticated before checking roles.
    
    Args:
        *roles: List of roles that are allowed access
        
    Returns:
        A decorator that verifies if the user has any of the specified roles
        
    Example:
        @app.get("/admin/users")
        @login_required
        @roles_required("admin", "super_admin")
        async def admin_users(request: Request):
            ...
    """
    def wrapper(func):
        @wraps(func)
        async def decorated_function(request: Request, *args, **kwargs):
            user = request.state.user
            
            # Check if the user has any of the required roles
            if not hasattr(user, 'role') or user.role not in roles:
                # Return a 403 Forbidden error
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"status": "forbidden", "message": "Access denied: Appropriate role required"}
                )
            
            # If the user has the correct role, continue with the original function
            return await func(request, *args, **kwargs)
        return decorated_function
    return wrapper
