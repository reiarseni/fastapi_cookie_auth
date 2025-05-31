"""Example FastAPI application using fastapi_cookie_auth."""

import os
from typing import Dict, Optional
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response, Form, status, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from functools import wraps
from pathlib import Path

# Importar constantes y decoradores de autenticación
from auth import ROLE_SUPER_ADMIN, ROLE_ADMIN, ROLE_USER, ROLE_GUEST

# Import fastapi_cookie_auth - for local development
import sys
import os

# Asegurarnos que el directorio padre está en el path para poder importar el paquete
parent_dir = str(Path(__file__).parent.parent.absolute())
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Ahora podemos importar el paquete
from fastapi_cookie_auth import LoginManager, UserMixin, login_user, logout_user, login_required, roles_required

# Load environment variables
load_dotenv()

# Initialize FastAPI app
app = FastAPI(title="FastAPI Cookie Auth Example")

# Set up templates and static files
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")

# Configurar uvicorn para mostrar más información de depuración
import logging
logging.basicConfig(level=logging.DEBUG)

# Initialize login manager with proper configuration
login_manager = LoginManager(app, mode="dev")

# Configure secret key for encryption - use a strong key
login_manager.cookie_settings.secret_key = "this-is-a-super-secret-key-for-development-only"

# Make cookie visible in browser dev tools
login_manager.cookie_settings.cookie_httponly = False

# Set cookie name explicitly
login_manager.cookie_settings.cookie_name = "fastapi_auth"

# Adjust SameSite setting to be more compatible
login_manager.cookie_settings.cookie_samesite = None  # Set to None for better compatibility

# Ensure domain is correctly set for local development
login_manager.cookie_settings.cookie_domain = None

# Use file storage for sessions with expiration and cleanup
login_manager.store_session_in_memory = True

# Configure session expiration - 30 minutes for demo purposes
from fastapi_cookie_auth.utils.config import SESSION_EXPIRY
SESSION_EXPIRY["enabled"] = True
SESSION_EXPIRY["lifetime"] = 1800  # 30 minutes
SESSION_EXPIRY["cleanup_interval"] = 300  # 5 minutes

# Configure token revocation
from fastapi_cookie_auth.utils.config import REVOCATION_CONFIG
from fastapi_cookie_auth.utils.revocation import configure as configure_revocation
REVOCATION_CONFIG["enabled"] = True
REVOCATION_CONFIG["max_revoked"] = 100
REVOCATION_CONFIG["cleanup_interval"] = 300  # 5 minutes

# Initialize the token revocation system
configure_revocation(
    max_revoked=REVOCATION_CONFIG["max_revoked"],
    cleanup_interval=REVOCATION_CONFIG["cleanup_interval"]
)

# Print configuration for debugging
print(f"Cookie settings: {login_manager.cookie_settings.__dict__}")
print(f"Session expiry: {SESSION_EXPIRY}")
print(f"Token revocation: {REVOCATION_CONFIG}")
print(f"Using memory storage: {login_manager.store_session_in_memory}")
print(f"Storage type: {type(login_manager._storage).__name__}")

# User model similar to the one in the tests
class User(UserMixin):
    def __init__(self, id: str, username: str, password: str, role: str = ROLE_USER):
        self.id = id
        self.username = username
        self.password = password  # In production, use password hashing
        self.role = role  # Property to determine the user's role
    
    def is_admin(self) -> bool:
        """Check if user has admin role."""
        return self.role in (ROLE_ADMIN, ROLE_SUPER_ADMIN)
    
    def has_role(self, *roles) -> bool:
        """Check if user has any of the specified roles."""
        return self.role in roles

# Simple in-memory user database
users_db: Dict[str, User] = {
    "1": User(id="1", username="superadmin", password="superadmin123", role=ROLE_SUPER_ADMIN),
    "2": User(id="2", username="admin", password="admin123", role=ROLE_ADMIN),
    "3": User(id="3", username="user", password="user123", role=ROLE_USER),
    "4": User(id="4", username="guest", password="guest", role=ROLE_GUEST)
}

@login_manager.user_loader
async def load_user(user_id: str) -> Optional[User]:
    """Load user by ID."""
    return users_db.get(user_id)

@app.get("/")
async def root(request: Request):
    """Home page route."""
    user = request.state.user
    
    # Customize greeting based on authentication status
    if user and user.is_authenticated:
        greeting = f"Hello {user.username}!"
    else:
        greeting = "Hello anonymous user!"
    
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "user": user, "greeting": greeting}
    )

@app.get("/login")
async def login_page(request: Request):
    """Login page route."""
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
    print(f"\n\n===== LOGIN ATTEMPT =====")
    print(f"Username: {username}")
    print(f"Password: {password}")
    print(f"Remember: {remember}")
    print(f"User IP: {request.client.host}")
    print(f"User Agent: {request.headers.get('user-agent', 'Unknown')}")

    # Find user by username
    user = None
    for u in users_db.values():
        if u.username == username:
            user = u
            break
    
    print(f"Found user: {user is not None}")
    if user:
        print(f"User ID: {user.id}, Username: {user.username}")
    
    # Check credentials
    if user and user.password == password:
        print(f"Password matches! Logging in user...")
        
        # Solución para el problema de cookies con redirecciones en FastAPI
        # 1. Crear una respuesta normal (no un RedirectResponse)
        response = Response(status_code=status.HTTP_302_FOUND)
        
        # 2. Establecer manualmente la cabecera de redirección
        response.headers["Location"] = "/"
        
        # 3. Aplicar el login_user a esta respuesta (esto establecerá las cookies)
        success = login_user(request, response, user, remember=remember)
        print(f"Login successful: {success}")
        
        # 4. Retornar la respuesta ya configurada con cookies
        return response
    
    # Invalid credentials
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
    
    # En una aplicación real, aquí obtendrías la lista de usuarios de la base de datos
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
    """Page to manage active sessions and demonstrate session features."""
    user = request.state.user
    
    # Check if our storage supports listing sessions
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
                    
                # Add token to the session data
                session["token"] = token[:8] + "..." # Show only first 8 chars
                session["raw_token"] = token
                
                # Convert timestamps to readable format
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
    """Revoke a specific session token."""
    from fastapi_cookie_auth.utils.revocation import revoke_token
    
    if REVOCATION_CONFIG["enabled"]:
        revoke_token(token)
        return {"success": True, "message": f"Session revoked successfully"}
    else:
        return {"success": False, "message": "Token revocation is not enabled"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
