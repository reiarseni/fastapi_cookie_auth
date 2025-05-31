"""
Utility functions for FastAPI Cookie Auth.

This module provides core utility functions for authentication and session management,
including user login/logout functionality, request context management, and route protection.
"""

from typing import Any, Callable, Dict, Optional, TypeVar, Set, Union
from contextvars import ContextVar
from fastapi import Request, Response, Depends, HTTPException, status
from fastapi.responses import RedirectResponse
from functools import wraps
import time
from contextlib import contextmanager

# Import session storage from storage module
from .storage import session_store

# Context variable to store current user
current_user_ctx: ContextVar[Any] = ContextVar('current_user', default=None)


def load_user(request: Request) -> Any:
    """
    Get the current user from request state.
    
    Args:
        request: The FastAPI request object
        
    Returns:
        The user object or None if no user is authenticated
    """
    return getattr(request.state, "user", None)


async def current_user(request: Request) -> Any:
    """
    Get the current user from the request.
    
    This function can be used as a dependency in FastAPI routes to
    inject the current user into route handlers.
    
    Args:
        request: The FastAPI request object
        
    Returns:
        The user object or None if no user is authenticated
    """
    user = load_user(request)
    # Set context for this user
    token = current_user_ctx.set(user)
    try:
        # In an async generator, it's important for FastAPI to use yield
        yield user
    finally:
        # Clean up context when finished
        current_user_ctx.reset(token)


def is_authenticated(request: Request) -> bool:
    """
    Check if the current user is authenticated.
    
    Args:
        request: The FastAPI request object
        
    Returns:
        True if the user is authenticated, False otherwise
    """
    user = load_user(request)
    if user is None:
        return False
    # The is_authenticated property should always return True for a normal user in UserMixin
    return getattr(user, "is_authenticated", False)


def login_user(
    request: Request,
    response: Response,
    user: Any,
    remember: bool = False,
    duration: Optional[int] = None,
    force: bool = False,
    extra_session_data: Optional[Dict[str, Any]] = None,
) -> bool:
    """
    Log a user in and set authentication cookie.
    
    This function performs the login process by creating a session for the user
    and setting the necessary authentication cookies. It supports both cookie-based
    and server-side session storage.
    
    Args:
        request: The FastAPI request object
        response: The FastAPI response object
        user: The user object to log in
        remember: Whether to use a long-term cookie
        duration: Optional cookie duration in seconds (overrides remember if provided)
        force: If True, log in even for inactive users
        extra_session_data: Optional additional data to store in the session
    
    Returns:
        True if login is successful, False otherwise
        
    Raises:
        RuntimeError: If LoginManager is not properly initialized
    """
    # Check if user is active (skip if force is True)
    if not force and not getattr(user, "is_active", True):
        return False
    
    # Get user ID, preferably through get_id() method
    if hasattr(user, "get_id") and callable(user.get_id):
        user_id = user.get_id()
    else:
        user_id = str(user.id)
    
    print(f"User ID for session: {user_id}")
    
    # Verify LoginManager access
    login_manager = getattr(request.state, "login_manager", None)
    print(f"Login manager found: {login_manager is not None}")
    
    if not login_manager:
        raise RuntimeError("LoginManager not initialized for this request")
    
    # Get Cookie parameters
    cookie_settings = login_manager.cookie_settings
    secure = cookie_settings.cookie_secure
    httponly = cookie_settings.cookie_httponly
    domain = cookie_settings.cookie_domain
    samesite = cookie_settings.cookie_samesite
    
    # Special case: Chrome requires Secure for SameSite=None
    # Primero verificamos si samesite no es None
    if not cookie_settings.cookie_secure and samesite is not None and samesite.lower() == 'none':
        secure = True
        # If not HTTPS, browsers won't accept SameSite=None
        samesite = 'lax'
        
    # Configure cookie expiration
    max_age = None
    
    if duration:
        max_age = duration
    elif remember:
        max_age = cookie_settings.remember_cookie_duration
    
    # Prepare the value to be stored in the cookie using random token
    from .crypto import generate_session_token, encode_session_data
    from ..utils.config import COOKIE_SECURITY_TOKEN
    
    # Verify we have a secret key
    secret_key = cookie_settings.secret_key
    print(f"Secret key exists: {bool(secret_key)}")
    if not secret_key:
        raise ValueError("A secret key is required to generate session tokens")
    
    # Generate random token
    session_token = generate_session_token()
    cookie_value = session_token
    print(f"Generated session token: {session_token}")
    
    # Encode session data with user ID, request info and extra data
    session_data = encode_session_data(user_id, request, extra_session_data)
    print(f"Session data: {session_data}")
    
    # Store in the session storage with proper max_age
    login_manager._storage.set(session_token, session_data, max_age)
    
    # Set the cookie - with special handling for FastAPI redirect responses
    # Check if this is a redirect response and handle cookies appropriately
    if hasattr(response, "_headers") and "location" in response.headers:
        # For redirects, use raw headers to ensure cookies are set properly
        # This is needed because FastAPI/Starlette handles redirects differently
        cookie_header = f"{cookie_settings.cookie_name}={cookie_value}; Path={cookie_settings.cookie_path}"
        
        # Add expiration if needed
        if max_age is not None:
            cookie_header += f"; Max-Age={max_age}"
        
        # Add domain if specified
        if domain:
            cookie_header += f"; Domain={domain}"
        
        # Add secure flag if needed
        if secure:
            cookie_header += "; Secure"
        
        # Add httponly flag if needed
        if httponly:
            cookie_header += "; HttpOnly"
        
        # Add samesite attribute - manejando None explícitamente
        if samesite is not None:
            cookie_header += f"; SameSite={samesite}"
        
        # Set cookie header directly
        response.headers["Set-Cookie"] = cookie_header
    else:
        # Normal response - use standard set_cookie method
        response.set_cookie(
            key=cookie_settings.cookie_name,
            value=cookie_value,
            max_age=max_age,
            path=cookie_settings.cookie_path,
            domain=domain,
            secure=secure,
            httponly=httponly,
            samesite=samesite,
        )
    
    # Update user in current request context
    request.state.user = user
    current_user_ctx.set(user)
    
    return True


def logout_user(request: Request, response: Response) -> None:
    """
    Log a user out and clear authentication cookie.
    
    Args:
        request: The FastAPI request object
        response: The FastAPI response object to clear the cookie
    """
    # Verify LoginManager access
    login_manager = getattr(request.state, "login_manager", None)
    if not login_manager:
        return
    
    # Get cookie configuration
    cookie_settings = login_manager.cookie_settings
    
    # Get the token from the cookie and remove it from storage
    cookie_value = request.cookies.get(cookie_settings.cookie_name)
    if cookie_value:
        # Delete the session data associated with the token
        login_manager._storage.delete(cookie_value)
    
    # Delete the cookie - with special handling for FastAPI redirect responses
    if hasattr(response, "_headers") and "location" in response.headers:
        # For redirects with FastAPI, we need to set an expired cookie directly in headers
        # This is crucial because delete_cookie doesn't work properly with redirects
        cookie_header = f"{cookie_settings.cookie_name}=; Path={cookie_settings.cookie_path}; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
        
        # Add domain if specified
        if cookie_settings.cookie_domain:
            cookie_header += f"; Domain={cookie_settings.cookie_domain}"
            
        # Set cookie header directly
        response.headers["Set-Cookie"] = cookie_header
    else:
        # Normal response - use standard delete_cookie method
        response.delete_cookie(
            key=cookie_settings.cookie_name,
            path=cookie_settings.cookie_path,
            domain=cookie_settings.cookie_domain
        )
    
    # Update request context
    request.state.user = login_manager._get_anonymous_user()
    current_user_ctx.set(request.state.user)


def login_required(func: Optional[Callable] = None) -> Callable:
    """
    Decorator to protect routes from unauthorized access.
    
    This function can be used either as a standard decorator or as a FastAPI dependency.
    It checks if the user is authenticated before allowing access to protected routes.
    
    Examples:
        # As a standard decorator:
        @app.get("/protected")
        @login_required
        async def protected_route(request: Request):
            # User is already authenticated here
            return {"message": f"Hello {request.state.user.username}"}
            
        # Or as a dependency:
        @app.get("/protected2")
        async def protected_route2(request: Request, _=Depends(login_required())):
            return {"message": f"Hello {request.state.user.username}"}
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(request: Request, *args, **kwargs) -> Any:
            user = request.state.user
            if not user or not getattr(user, "is_authenticated", False):
                login_manager = getattr(request.state, "login_manager", None)
                if login_manager:
                    return login_manager.unauthorized()
                
                # Fallback if login_manager not available
                from fastapi.responses import RedirectResponse
                from fastapi import status
                return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
            
            return await func(request, *args, **kwargs)
        return wrapper
    
    # Allow using the decorator directly or as a dependency
    if func is None:
        # When used as a dependency: @app.get("/route", dependencies=[Depends(login_required())])
        # Or when used with parentheses: @login_required()
        return decorator
    else:
        # When used without parentheses: @login_required
        return decorator(func)
