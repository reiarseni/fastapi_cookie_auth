# FastAPI Cookie Auth

A cookie-based authentication implementation for FastAPI, inspired by Flask-Login. This library provides similar functionality to Flask-Login but adapted to the FastAPI ecosystem.

## Features

- HTTP cookie-based authentication (no JWT)
- API similar to Flask-Login (`login_user`, `logout_user`, `current_user`, etc.)
- Route protection using the `login_required` decorator
- Integrated role-based access control system
- Support for "remember me" functionality
- Flexible cookie configuration (duration, domain, security flags)
- Multiple session storage options (memory, file, JSON, pickle)
- Easy integration with any user model

## Installation

```bash
pip install fastapi_cookie_auth
```

## Basic Usage

```python
from fastapi import FastAPI, Request, Response, Depends
from fastapi.responses import JSONResponse
from fastapi_cookie_auth import LoginManager, UserMixin, login_required, login_user, logout_user, current_user

app = FastAPI()
login_manager = LoginManager(app)

# Example user model
class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

# Simulated database
users_db = {
    "1": User(id="1", username="admin", password="admin123")
}

@login_manager.user_loader
async def load_user(user_id: str):
    return users_db.get(user_id)

@app.post("/login")
async def login(request: Request, response: Response, username: str, password: str):
    # Find user by username
    user = None
    for u in users_db.values():
        if u.username == username:
            user = u
            break
    
    if user and user.password == password:
        login_user(request, response, user)
        return {"message": "Login successful"}
    
    return JSONResponse(
        status_code=401,
        content={"message": "Invalid credentials"}
    )

@app.post("/logout")
async def logout(request: Request, response: Response):
    logout_user(request, response)
    return {"message": "Logged out"}

@app.get("/profile")
@login_required
async def profile(request: Request, user = Depends(current_user)):
    return {"username": user.username, "id": user.id}

@app.get("/")
async def root(request: Request, user = Depends(current_user)):
    if user and user.is_authenticated:
        return {"message": f"Hello {user.username}!"}
    return {"message": "Hello anonymous user!"}

## UserMixin

The `UserMixin` class is the base for user models. It provides the following properties:

- `is_active`: Returns `True` by default. Defines if the user is active.
- `is_authenticated`: Returns `True` by default. Defines if the user is authenticated.
- `is_anonymous`: Returns `False` by default. Defines if the user is anonymous.
- `get_id()`: Returns the user ID as a string. By default, it uses the `id` attribute.

To extend the functionality:

```python
class User(UserMixin):
    def __init__(self, id, username, password, role="user"):
        self.id = id
        self.username = username
        self.password = password  # In production, use password hashing
        self.role = role
    
    @property
    def is_active(self):
        # Customize logic to determine if the user is active
        return self.active_status
    
    def has_role(self, *roles):
        # Check if the user has any of the specified roles
        return self.role in roles
```

## LoginManager Options

The `LoginManager` is the main component that manages authentication.

### Initialization

```python
login_manager = LoginManager(app)

# Configure login view
login_manager.login_view = "/login"

# Session protection level: None, "basic", or "debug"
login_manager.session_protection = "debug"

# Configure session storage
login_manager.configure_storage(
    storage_type="file",  # Options: "memory", "file"
    directory="/path/to/sessions"
)
```

### User Loader

The `@login_manager.user_loader` decorator is used to define a function that loads a user from their ID:

```python
@login_manager.user_loader
async def load_user(user_id: str):
    """
    This function receives the user ID saved in the cookie
    and must return the corresponding user object or None.
    """
    return await db.get_user(user_id)
```

### Cookie Configuration

```python
login_manager.cookie_settings.update(
    cookie_name="custom_session",          # Nombre de la cookie
    cookie_path="/",                       # Ruta de la cookie
    cookie_domain="",                      # Dominio de la cookie
    cookie_secure=True,                    # Requiere HTTPS
    cookie_httponly=True,                  # No accesible por JavaScript
    cookie_samesite="lax",                 # Política SameSite (lax, strict, none)
    remember_cookie_duration=30*24*60*60,  # Duración para "recordarme" (segundos)
    session_cookie_duration=None           # Duración normal (None = cookie de sesión)
)
```

## Role-Based Access Control

You can implement a role-based system to control access to specific routes:

### 1. Define role constants

```python
# auth/constants.py
ROLE_SUPER_ADMIN = 'super_admin'
ROLE_ADMIN = 'admin'
ROLE_USER = 'user'
ROLE_GUEST = 'guest'
```

### 2. Protect routes with roles

```python
from auth import ROLE_ADMIN, ROLE_SUPER_ADMIN, roles_required
from fastapi_cookie_auth import login_required

@app.get("/admin/dashboard")
@login_required
@roles_required(ROLE_ADMIN, ROLE_SUPER_ADMIN)
async def admin_dashboard(request: Request):
    return {"message": "Welcome to the admin dashboard"}

@app.get("/admin/superadmin-only")
@login_required
@roles_required(ROLE_SUPER_ADMIN)
async def superadmin_page(request: Request):
    return {"message": "This page is for super administrators only"}
```

## Storage Options

The library offers two options for storing session data:

```python
# In-memory storage (non-persistent)
login_manager.configure_storage(storage_type="memory")

# File storage (persistent, with optimized serialization)
login_manager.configure_storage(
    storage_type="file",
    directory="/path/to/sessions"
)
```

The "file" storage type uses optimized serialization for maximum performance while maintaining data persistence.

## Additional Utilities

### Verify Authentication

```python
from fastapi import Request
from fastapi_cookie_auth import is_authenticated

@app.get("/check")
async def check_auth(request: Request):
    if is_authenticated(request):
        return {"authenticated": True}
    return {"authenticated": False}
```

### Get the Current User

```python
from fastapi import Request, Depends
from fastapi_cookie_auth import current_user

@app.get("/user-info")
async def user_info(user = Depends(current_user)):
    if user and user.is_authenticated:
        return {
            "username": user.username,
            "id": user.id,
            # Other user attributes
        }
    return {"message": "No user logged in"}
```

## Environment Variables

You can configure the behavior using environment variables:

```env
STORAGE_TYPE=file
STORAGE_DIR=/path/to/sessions
REMEMBER_COOKIE_DURATION=2592000  # 30 days in seconds
```

## Security

For a secure implementation in production:

1. Make sure to use HTTPS (cookie_secure=True)
2. Set SameSite to "strict" or "lax"
3. Always use HttpOnly (cookie_httponly=True)
4. Never store passwords in plain text, use bcrypt or similar:
    ```python
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    
    def verify_password(plain_password, hashed_password):
        return pwd_context.verify(plain_password, hashed_password)
    
    def get_password_hash(password):
        return pwd_context.hash(password)
    ```

5. Consider implementing additional CSRF protection for sensitive routes
6. For durable storage, use a database instead of file storage

## Contributions

Contributions are welcome. Please send a pull request or open an issue on GitHub.
