"""Example FastAPI application using fastapi_cookie_auth.

This example demonstrates how to implement cookie-based authentication
with role-based access control in a FastAPI application.
"""

import os
from typing import Dict, Optional
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response, Form, status, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from functools import wraps
from pathlib import Path

# Import authentication constants and decorators
from auth import ROLE_SUPER_ADMIN, ROLE_ADMIN, ROLE_USER, ROLE_GUEST

# Import fastapi_cookie_auth - for local development
import sys
import os

# Ensure parent directory is in path to import the package
parent_dir = str(Path(__file__).parent.parent.absolute())
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Now we can import the package
from fastapi_cookie_auth import LoginManager, UserMixin, login_user, logout_user, login_required, roles_required

# Load environment variables
load_dotenv()

# Initialize FastAPI app
app = FastAPI(title="FastAPI Cookie Auth Example")

# Set up templates and static files
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")

# Configure uvicorn to show more debug information
import logging
logging.basicConfig(level=logging.DEBUG)

# Initialize login manager with proper configuration
login_manager = LoginManager(app, mode="dev")

# Configure secret key for encryption - use a strong key in production
login_manager.cookie_settings.secret_key = "this-is-a-super-secret-key-for-development-only"

# Make cookie visible in browser dev tools (only for development)
login_manager.cookie_settings.cookie_httponly = False

# Set cookie name explicitly for clarity
login_manager.cookie_settings.cookie_name = "fastapi_auth"

# Adjust SameSite setting for better compatibility
login_manager.cookie_settings.cookie_samesite = None  # Set to None for better compatibility

# Ensure domain is correctly set for local development
login_manager.cookie_settings.cookie_domain = None

# Use memory storage for sessions with expiration and cleanup
login_manager.store_session_in_memory = True

# Configure session expiration - 30 minutes for demo purposes
from fastapi_cookie_auth.utils.config import SESSION_EXPIRY
SESSION_EXPIRY["enabled"] = True
SESSION_EXPIRY["lifetime"] = 1800  # 30 minutes
SESSION_EXPIRY["cleanup_interval"] = 300  # 5 minutes

# Configure token revocation system
from fastapi_cookie_auth.utils.config import REVOCATION_CONFIG
from fastapi_cookie_auth.utils.revocation import configure as configure_revocation
REVOCATION_CONFIG["enabled"] = True
REVOCATION_CONFIG["max_revoked"] = 100
REVOCATION_CONFIG["cleanup_interval"] = 300  # 5 minutes

# Initialize the token revocation system with configured parameters
configure_revocation(
    max_revoked=REVOCATION_CONFIG["max_revoked"],
    cleanup_interval=REVOCATION_CONFIG["cleanup_interval"]
)

# Print configuration for debugging purposes
print(f"Cookie settings: {login_manager.cookie_settings.__dict__}")
print(f"Session expiry: {SESSION_EXPIRY}")
print(f"Token revocation: {REVOCATION_CONFIG}")
print(f"Using memory storage: {login_manager.store_session_in_memory}")
print(f"Storage type: {type(login_manager._storage).__name__}")

# User model implementing UserMixin for authentication
class User(UserMixin):
    """User model implementing UserMixin for authentication.
    
    This class provides user authentication functionality with role-based
    access control support.
    
    Args:
        id: Unique identifier for the user
        username: Username for display and login
        password: User's password (in production, use password hashing)
        role: User's role for access control
    """
    def __init__(self, id: str, username: str, password: str, role: str = ROLE_USER):
        self.id = id
        self.username = username
        self.password = password  # In production, use password hashing
        self.role = role  # Property to determine the user's role
    
    def is_admin(self) -> bool:
        """Check if user has administrator role.
        
        Returns:
            True if user has admin or super_admin role, False otherwise
        """
        return self.role in (ROLE_ADMIN, ROLE_SUPER_ADMIN)
    
    def has_role(self, *roles) -> bool:
        """Check if user has any of the specified roles.
        
        Args:
            *roles: Variable number of role names to check
            
        Returns:
            True if user has any of the specified roles, False otherwise
        """
        return self.role in roles

# Simple in-memory user database for demonstration
users_db: Dict[str, User] = {
    "1": User(id="1", username="superadmin", password="superadmin123", role=ROLE_SUPER_ADMIN),
    "2": User(id="2", username="admin", password="admin123", role=ROLE_ADMIN),
    "3": User(id="3", username="user", password="user123", role=ROLE_USER),
    "4": User(id="4", username="guest", password="guest", role=ROLE_GUEST)
}

@login_manager.user_loader
async def load_user(user_id: str) -> Optional[User]:
    """Load user by ID from the database.
    
    This callback is used by the login manager to retrieve a user
    by their ID during authentication.
    
    Args:
        user_id: The unique identifier of the user to load
        
    Returns:
        User object if found, None otherwise
    """
    return users_db.get(user_id)

@app.get("/")
async def root(request: Request):
    """Render the home page with user information if authenticated.
    
    This route displays the main page of the application, showing different
    content based on authentication status.
    
    Args:
        request: The FastAPI request object
        
    Returns:
        TemplateResponse with the rendered index template
    """
    user = request.state.user if hasattr(request.state, "user") else None
    
    # Check if user is authenticated
    is_authenticated = user is not None and hasattr(user, "is_authenticated") and user.is_authenticated
    
    # Render the template with user info if available
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "user": user,
            "is_authenticated": is_authenticated
        }
    )

@app.get("/login")
async def login_page(request: Request):
    """Render the login page.
    
    This route displays the login form for user authentication.
    
    Args:
        request: The FastAPI request object
        
    Returns:
        TemplateResponse with the rendered login template
    """
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login_post(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
    remember: bool = Form(False)
):
    """Process login form submission."""
    print(f"Login attempt for user: {username} from {request.client.host}")

    # Find user by username
    user = None
    for u in users_db.values():
        if u.username == username:
            user = u
            break
    
    if user is None:
        print(f"Login failed: User {username} not found")
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid username or password"})
        
    # User found, verify password
    
    # Check credentials
    if user.password == password:
        print(f"Login successful for user: {user.username} (ID: {user.id})")
        
        # Solución para el problema de cookies con redirecciones en FastAPI
        # 1. Crear una respuesta normal (no un RedirectResponse)
        response = Response(status_code=status.HTTP_302_FOUND)
        
        # 2. Establecer manualmente la cabecera de redirección
        response.headers["Location"] = "/"
        
        # 3. Aplicar el login_user a esta respuesta (esto establecerá las cookies)
        success = login_user(request, response, user, remember=remember)
        if not success:
            print(f"Login failed for user: {user.username}")
        
        # 4. Retornar la respuesta ya configurada con cookies
        return response
    
    # Invalid credentials
    print(f"Login failed: Invalid password for user {username}")
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": "Invalid credentials"},
    )

@app.get("/logout")
async def logout_route(request: Request, response: Response):
    """Log out the current user and revoke the session token."""
    # Get session token to revoke
    cookie_name = login_manager.cookie_settings.cookie_name
    session_token = request.cookies.get(cookie_name)
    
    # Revoke the token
    if session_token and REVOCATION_CONFIG["enabled"]:
        from fastapi_cookie_auth.utils.revocation import revoke_token
        revoke_token(session_token)
        print(f"Session token revoked: {session_token}")
    
    # Usar el mismo enfoque que para login
    # 1. Crear una respuesta normal
    response = Response(status_code=status.HTTP_302_FOUND)
    
    # 2. Establecer manualmente la cabecera de redirección
    response.headers["Location"] = "/"
    
    # 3. Log out the user con la respuesta normal
    logout_user(request, response)
    
    return response

@app.get("/protected")
@login_required
async def protected_route(request: Request):
    """Protected route that requires authentication."""
    user = request.state.user
    
    return templates.TemplateResponse(
        "protected.html",
        {"request": request, "user": user}
    )

@app.get("/api/profile")
@login_required
async def profile_api(request: Request):
    """API endpoint that returns the current user's profile data."""
    user = request.state.user
    
    return {"id": user.id, "username": user.username}

@app.get("/api/admin")
@login_required
@roles_required(ROLE_ADMIN, ROLE_SUPER_ADMIN)
async def admin_api(request: Request):
    """
    Admin-only API endpoint.
    This route is protected and requires admin or super_admin role.
    """
    user = request.state.user
    
    return {"status": "success", "message": f"Welcome {user.role}!"}


@app.get("/admin/users")
@login_required
@roles_required(ROLE_ADMIN, ROLE_SUPER_ADMIN)
async def admin_users(request: Request):
    """
    Admin users page.
    This route is protected and requires admin or super_admin role.
    """
    user = request.state.user
    
    # In a real application, you would retrieve the user list from the database
    users_list = [{
        "id": u.id,
        "username": u.username,
        "role": u.role
    } for u in users_db.values()]
    
    return templates.TemplateResponse(
        "admin_users.html",
        {"request": request, "user": user, "users": users_list}
    )

@app.get("/admin/superadmin-only")
@login_required
@roles_required(ROLE_SUPER_ADMIN)
async def superadmin_page(request: Request):
    """
    Super admin only page.
    This route is protected and requires super_admin role.
    """
    user = request.state.user
    
    return templates.TemplateResponse(
        "superadmin_only.html",
        {"request": request, "user": user}
    )


@app.get("/sessions")
@login_required
@roles_required(ROLE_ADMIN, ROLE_SUPER_ADMIN)
async def manage_sessions(request: Request):
    """Render the session management page.
    
    This page allows administrators to view and manage active user sessions,
    demonstrating the session storage and revocation features.
    
    Args:
        request: The FastAPI request object
        
    Returns:
        TemplateResponse with the rendered sessions template and session data
    """
    user = request.state.user
    
    # Check if our storage backend supports listing active sessions
    active_sessions = []
    has_storage_listing = hasattr(login_manager._storage, "get_all_sessions")
    
    if has_storage_listing:
        # Get all active sessions
        raw_sessions = login_manager._storage.get_all_sessions()
        
        # Format session data for display
        from fastapi_cookie_auth.utils.crypto import decode_session_data
        for token, data in raw_sessions.items():
            try:
                session = decode_session_data(data)
                if not session:
                    continue
                    
                # Add token to the session data (truncated for security)
                session["token"] = token[:8] + "..." # Show only first 8 chars
                session["raw_token"] = token
                
                # Convert Unix timestamps to human-readable format
                if "created_at" in session:
                    import datetime
                    created = datetime.datetime.fromtimestamp(session["created_at"])
                    session["created_at_str"] = created.strftime("%Y-%m-%d %H:%M:%S")
                
                if "last_activity" in session:
                    import datetime
                    last_active = datetime.datetime.fromtimestamp(session["last_activity"])
                    session["last_activity_str"] = last_active.strftime("%Y-%m-%d %H:%M:%S")
                
                active_sessions.append(session)
            except Exception as e:
                print(f"Error decoding session: {e}")
    
    return templates.TemplateResponse(
        "sessions.html", 
        {
            "request": request, 
            "user": user, 
            "sessions": active_sessions,
            "has_storage_listing": has_storage_listing,
            "session_expiry": SESSION_EXPIRY,
            "revocation_enabled": REVOCATION_CONFIG["enabled"]
        }
    )

@app.post("/revoke-session")
@login_required
@roles_required(ROLE_ADMIN, ROLE_SUPER_ADMIN)
async def revoke_session(request: Request, token: str = Form(...)):
    """Revoke a specific session token.
    
    This endpoint allows administrators to invalidate a user session,
    forcing the user to log in again.
    
    Args:
        request: The FastAPI request object
        token: The session token to revoke
        
    Returns:
        JSON response indicating success or failure
    """
    from fastapi_cookie_auth.utils.revocation import revoke_token
    
    if REVOCATION_CONFIG["enabled"]:
        revoke_token(token)
        return {"success": True, "message": f"Session revoked successfully"}
    else:
        return {"success": False, "message": "Token revocation is not enabled"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
