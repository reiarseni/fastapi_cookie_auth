# FastAPI Cookie Auth

A lightweight, secure cookie-based authentication implementation for FastAPI, inspired by Flask-Login. This library provides similar functionality to Flask-Login but optimized for the FastAPI ecosystem.

## Features

- HTTP cookie-based authentication with random session tokens (no JWT)
- API similar to Flask-Login (`login_user`, `logout_user`, `current_user`, etc.)
- Route protection using the `login_required` decorator
- Flexible role-based access control with `roles_required` decorator
- Token revocation system for immediate session invalidation
- Support for "remember me" functionality
- Comprehensive cookie security settings (SameSite, Secure, HttpOnly)
- Multiple session storage backends (memory, file-based)
- Easy integration with any user model via UserMixin
- Environment-aware configuration (development/production modes)

## Installation

```bash
pip install fastapi_cookie_auth
```

## Basic Usage

```python
from fastapi import FastAPI, Request, Response, Depends
from fastapi.responses import JSONResponse
from fastapi_cookie_auth import (
    LoginManager, UserMixin, login_required, login_user, logout_user, 
    current_user, roles_required
)

# Initialize FastAPI app
app = FastAPI()

# Initialize login manager with development settings
login_manager = LoginManager(app, mode="dev")

# Configure secret key for encryption (use a strong key in production)
login_manager.cookie_settings.secret_key = "this-is-a-super-secret-key-for-development-only"

# Example user model with role support
class User(UserMixin):
    def __init__(self, id, username, password, role="user"):
        self.id = id
        self.username = username
        self.password = password  # In production, use password hashing
        self.role = role
    
    # Optional: implement a method to return multiple roles if needed
    def get_roles(self):
        # Could return a list of roles from database
        return [self.role]

# Simulated database
users_db = {
    "1": User(id="1", username="admin", password="admin123", role="admin"),
    "2": User(id="2", username="user", password="user123", role="user")
}

# User loader callback function
@login_manager.user_loader
async def load_user(user_id: str):
    return users_db.get(user_id)

# Login endpoint
@app.post("/login")
async def login(request: Request, response: Response, username: str, password: str, remember: bool = False):
    # Find user by username
    user = None
    for u in users_db.values():
        if u.username == username:
            user = u
            break
    
    if user and user.password == password:
        login_user(request, response, user, remember=remember)
        return {"message": "Login successful"}
    
    return JSONResponse(
        status_code=401,
        content={"message": "Invalid credentials"}
    )

# Logout endpoint
@app.post("/logout")
async def logout(request: Request, response: Response):
    logout_user(request, response)
    return {"message": "Logged out"}

# Protected route requiring authentication
@app.get("/profile")
@login_required
async def profile(request: Request, user = Depends(current_user)):
    return {"username": user.username, "id": user.id, "role": user.role}

# Role-protected route
@app.get("/admin")
@login_required
@roles_required("admin")
async def admin_panel(request: Request):
    return {"message": "Welcome to the admin panel"}

# Public route with user awareness
@app.get("/")
async def root(request: Request, user = Depends(current_user)):
    if user and user.is_authenticated:
        return {"message": f"Hello {user.username}!"}
    return {"message": "Hello anonymous user!"}

## UserMixin

The `UserMixin` class is the base for user models, providing standard authentication behaviors. User models should inherit from this class to gain all the necessary properties and methods required for authentication.

### Base Properties and Methods

- `is_active`: Returns `True` by default. Override to implement custom account status logic.
- `is_authenticated`: Returns `True` by default. Determines if the user is logged in.
- `is_anonymous`: Returns `False` by default. Always `False` for authenticated users.
- `get_id()`: Returns the user ID as a string. Uses the `id` attribute by default.

### Example User Model with Roles

```python
class User(UserMixin):
    def __init__(self, id, username, password, role="user", active=True):
        self.id = id
        self.username = username
        self.password = password  # Store hashed passwords only
        self.role = role
        self._active = active
    
    @property
    def is_active(self):
        # Custom implementation to check if account is active
        return self._active
    
    # Method for role-based access control
    def get_roles(self):
        # Return a list of roles - this method is recognized by the
        # roles_required decorator for more flexible role checking
        return [self.role] if self.role else []
```

The `get_roles()` method is particularly useful for role-based access control, as it allows a user to have multiple roles.

## LoginManager Configuration

The `LoginManager` is the core component that handles user authentication, session management, and access control.

### Initialization Modes

```python
# Development mode: Less secure defaults for easier debugging
login_manager = LoginManager(app, mode="dev")

# Production mode: More secure defaults
login_manager = LoginManager(app, mode="prod")

# Custom mode: Configure everything manually
login_manager = LoginManager(app, mode="custom")
```

### Essential Configuration

```python
# Authentication redirection
login_manager.login_view = "/login"  # Where to redirect when auth is required

# Session protection level: None, "basic", or "debug"
login_manager.session_protection = "basic"

# Configure token revocation system
login_manager.configure_revocation(
    max_revoked=5000,          # Maximum number of revoked tokens to store
    cleanup_interval=3600      # Cleanup interval in seconds
)

# Configure session storage backend
login_manager.configure_storage(
    storage_type="file",        # Options: "memory" or "file"
    directory="storage/sessions"  # Directory for file storage
)
```

### User Loader Callback

You must define a user loader function that loads a user from the user ID stored in the session:

```python
@login_manager.user_loader
async def load_user(user_id: str):
    """
    Receives the user ID from the session and returns the corresponding user object.
    Must return None if the user doesn't exist or is no longer valid.
    """
    return await db.get_user(user_id)  # Your implementation
```

### Cookie Security Settings

```python
# Set the secret key for cookie signing/encryption
login_manager.cookie_settings.secret_key = "your-secure-secret-key-here"

# Configure cookie settings
login_manager.cookie_settings.update(
    cookie_name="session",             # Name of the cookie
    cookie_path="/",                  # Path for the cookie
    cookie_domain=None,               # Domain for the cookie (None = current domain)
    cookie_secure=True,               # Require HTTPS (True for production)
    cookie_httponly=True,             # Prevent JavaScript access (True for security)
    cookie_samesite="lax",            # SameSite policy (lax, strict, none)
    remember_cookie_duration=30*86400, # Duration for "remember me" in seconds
    session_cookie_duration=None      # Regular session duration (None = browser session)
)
```

## Role-Based Access Control

FastAPI Cookie Auth includes a flexible role-based access control system that integrates seamlessly with its authentication system.

### Role Implementation in the User Model

There are two main ways to implement roles in your user model:

#### 1. Simple role attribute

```python
class User(UserMixin):
    def __init__(self, id, username, role="user"):
        self.id = id
        self.username = username
        self.role = role  # Single attribute for the role
```

#### 2. get_roles() method (recommended)

```python
class User(UserMixin):
    def __init__(self, id, username, roles=None):
        self.id = id
        self.username = username
        self._roles = roles or ["user"]  # List of roles
    
    def get_roles(self):
        # The roles_required decorator will look for this method first
        return self._roles
```

### Using the roles_required Decorator

```python
from fastapi import FastAPI, Request
from fastapi_cookie_auth import login_required, roles_required

app = FastAPI()

# Role constants definition
ROLE_ADMIN = "admin"
ROLE_MANAGER = "manager"
ROLE_USER = "user"

# Route protected by authentication and role
@app.get("/admin/dashboard")
@login_required  # First verifies authentication
@roles_required(ROLE_ADMIN)  # Then verifies role
async def admin_dashboard(request: Request):
    return {"message": "Welcome to the admin dashboard"}

# Route that accepts multiple roles
@app.get("/reports")
@login_required
@roles_required(ROLE_ADMIN, ROLE_MANAGER)
async def reports(request: Request):
    return {"message": "Access to reports authorized"}
```

### Decorator Behavior

The `roles_required` decorator works as follows:

1. First looks for a `get_roles()` method on the user object
2. If not found, it checks the `role` attribute directly
3. Returns an HTTP 403 (Forbidden) error if the user doesn't have any of the required roles

## Session Storage Options

The library provides multiple session storage backends to fit different use cases:

### In-Memory Storage

Fast but volatile storage that loses all sessions on application restart. Ideal for development or stateless deployments with load balancers.

```python
login_manager.configure_storage(
    storage_type="memory"
)
```

### File-Based Storage

Persistent storage that saves sessions to disk with optimized serialization. Suitable for most production deployments.

```python
login_manager.configure_storage(
    storage_type="file",
    directory="storage/sessions",  # Directory will be created if it doesn't exist
    session_expiry=86400          # Session expiration time in seconds (24 hours default)
)
```

### Storage Performance and Cleanup

The file storage backend includes automatic cleanup of expired sessions to prevent disk space issues. You can configure cleanup behavior:

```python
login_manager.configure_storage(
    storage_type="file",
    directory="storage/sessions",
    session_expiry=86400,        # Session lifetime in seconds
    cleanup_expired=True,        # Enable automatic cleanup
    cleanup_interval=3600        # Cleanup frequency in seconds
)
```

## Session Management

### Token Revocation

The system includes token revocation capabilities, which allows immediately invalidating specific sessions:

```python
from fastapi import Request, Response
from fastapi_cookie_auth import revoke_current_token, logout_user

@app.post("/logout")
async def logout(request: Request, response: Response):
    # Revoke current token to prevent reuse
    revoke_current_token(request)
    # Remove the session cookie
    logout_user(request, response)
    return {"message": "Session closed successfully"}

@app.post("/logout-all-devices")
@login_required
async def logout_all(request: Request, response: Response):
    # Get current user ID
    user_id = request.state.user.get_id()
    # Revoke all tokens for this user (custom implementation)
    await revoke_all_user_tokens(user_id)  # Your implementation
    # Log out from current device
    logout_user(request, response)
    return {"message": "Session closed on all devices"}
```

### Authentication Verification

```python
from fastapi import Request
from fastapi_cookie_auth import is_authenticated

@app.get("/check")
async def check_auth(request: Request):
    if is_authenticated(request):
        return {"authenticated": True}
    return {"authenticated": False}
```

### Current User Access

```python
from fastapi import Depends
from fastapi_cookie_auth import current_user

@app.get("/user-info")
async def user_info(user = Depends(current_user)):
    if user and user.is_authenticated:
        return {
            "username": user.username,
            "id": user.id,
            "roles": user.get_roles() if hasattr(user, 'get_roles') else [user.role],
        }
    return {"message": "No active user session"}
```

## Configuration with Environment Variables

You can configure behavior using environment variables:

```env
# Storage type
STORAGE_TYPE=file
STORAGE_DIR=storage/sessions

# Cookie configuration
COOKIE_NAME=session
COOKIE_SECURE=1
COOKIE_HTTPONLY=1
COOKIE_SAMESITE=lax

# Session duration
REMEMBER_COOKIE_DURATION=2592000  # 30 days in seconds
SESSION_COOKIE_DURATION=86400     # 1 day in seconds

# Token revocation
MAX_REVOKED_TOKENS=1000
CLEANUP_INTERVAL=3600
```

## Security Best Practices

For a secure implementation in production:

1. **Always use HTTPS in production**
   - Configure `cookie_secure=True` in production environments
   - Cookies with the Secure flag are only sent over HTTPS

2. **XSS Protection**
   - Use `cookie_httponly=True` to prevent access from JavaScript
   - Implement the `Content-Security-Policy` header

3. **SameSite Policy**
   - Use `cookie_samesite="lax"` (or "strict" for higher security)
   - Protects against CSRF attacks in most use cases

4. **Never store passwords in plain text**
   ```python
   from passlib.context import CryptContext
   
   # Configure the encryption context
   pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
   
   # Verify a password
   def verify_password(plain_password, hashed_password):
       return pwd_context.verify(plain_password, hashed_password)
   
   # Generate a password hash
   def get_password_hash(password):
       return pwd_context.hash(password)
   ```

5. **Session Management**
   - Implement reasonable expiration times
   - Allow users to view their active sessions
   - Provide functionality to log out from all devices

6. **Input Validation**
   - Validate and sanitize all input data
   - Use Pydantic for data validation in FastAPI

## Contributions

Contributions are welcome. Please send a pull request or open an issue on GitHub.
