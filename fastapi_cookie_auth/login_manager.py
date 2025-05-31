"""
LoginManager class implementation for FastAPI.

This module provides the core authentication functionality for the FastAPI Cookie Auth
package. The LoginManager class is responsible for handling user authentication,
session management, and protecting routes through middleware and decorators.
"""

import time
import hashlib
from typing import Any, Callable, Dict, Literal, Optional, Type, Union

from fastapi import FastAPI, Request, Response, HTTPException, status
from fastapi.responses import RedirectResponse
from starlette.middleware.base import RequestResponseEndpoint

from .utils import current_user_ctx, load_user
from .utils.config import CookieSettings, get_storage_config, REVOCATION_CONFIG, DEV_CONFIG, PROD_CONFIG, DEV_COOKIE_CONFIG, PROD_COOKIE_CONFIG
from .utils.storage import (
    session_store, get_storage, SessionStorageInterface,
    STORAGE_MEMORY, STORAGE_FILE, STORAGE_REDIS
)
from .utils.revocation import configure as configure_revocation, revoke_token, is_token_revoked


class LoginManager:
    """
    Authentication manager for FastAPI applications.

    The LoginManager class provides a Flask-Login style authentication system
    for FastAPI applications. It includes middleware for loading users from
    sessions, decorators for protecting routes, and utilities for managing
    user authentication.

    This implementation allows configuring different session storage types:
    - memory: In-memory storage (volatile)
    - file: Optimized file storage with efficient serialization (persistent)

    Example:
        ```python
        from fastapi import FastAPI
        from fastapi_cookie_auth import LoginManager
        
        app = FastAPI()
        login_manager = LoginManager(app)
        
        # Configure file-based storage
        login_manager.configure_storage("file", directory="/path/to/sessions")
        
        @login_manager.user_loader
        async def load_user(user_id):
            # Load user from database
            return users_db.get(user_id)
        ```
    """

    def __init__(self, app: Optional[FastAPI] = None, mode: Literal["dev", "prod", "custom"] = "dev") -> None:
        """
        Initialize the LoginManager.
        
        Args:
            app: The FastAPI application to initialize. If None, you can initialize
                 later with the init_app method.
            mode: Configuration mode to use ("dev", "prod", or "custom")
        """
        self.app: Optional[FastAPI] = app
        self._user_loader: Optional[Callable] = None
        self._anonymous_user: Optional[Type] = None
        self._unauthorized_callback: Optional[Callable] = None
        self._login_view: str = "/login"
        self._session_protection: str = "basic"
        self._cookie_settings: CookieSettings = CookieSettings()
        self.store_session_in_memory: bool = False
        self._storage: SessionStorageInterface = session_store
        self._storage_type: str = STORAGE_FILE
        self._storage_params: Dict[str, Any] = {}
        
        # Initialize login manager with default configuration
        self._init_config(mode)
        
        # Configure token revocation system
        if REVOCATION_CONFIG["enabled"]:
            configure_revocation(
                max_revoked=REVOCATION_CONFIG["max_revoked"],
                cleanup_interval=REVOCATION_CONFIG["cleanup_interval"]
            )
        
        if app is not None:
            self.init_app(app)
    
    def _init_config(self, mode: Literal["dev", "prod", "custom"] = "dev") -> None:
        """
        Initialize the login manager with default configuration.
        
        Args:
            mode: Configuration mode to use ("dev", "prod", or "custom")
        """
        # Configure cookie settings
        self._cookie_settings.configure(mode)
        
        if mode == "dev":
            if "login_view" in DEV_CONFIG:
                self.login_view = DEV_CONFIG["login_view"]
            if "session_protection" in DEV_CONFIG:
                self.session_protection = DEV_CONFIG["session_protection"]
        elif mode == "prod":
            if "login_view" in PROD_CONFIG:
                self.login_view = PROD_CONFIG["login_view"]
            if "session_protection" in PROD_CONFIG:
                self.session_protection = PROD_CONFIG["session_protection"]
        elif mode == "custom":
            pass
    
    def configure_storage(self, storage_type: str = "file", **kwargs) -> None:
        """
        Configure the session storage type.
        
        This method allows changing the storage backend for sessions. It provides
        options for balancing speed and persistence needs.
        
        Args:
            storage_type: Storage type ("memory" or "file")
            **kwargs: Additional parameters for the storage constructor
                     (e.g., directory="/path/to/sessions")
                     
        Raises:
            ValueError: If the storage type is invalid
        """
        # Validate storage type
        valid_types = (STORAGE_MEMORY, STORAGE_FILE, STORAGE_REDIS)
        if storage_type not in valid_types:
            raise ValueError(
                f"Invalid storage type: {storage_type}. "
                f"Must be one of: {', '.join(valid_types)}"
            )
        
        # Save configuration
        self._storage_type = storage_type
        self._storage_params = kwargs
        
        # Initialize the storage instance
        self._storage = get_storage(storage_type, **kwargs)
    
    def init_app(self, app: FastAPI) -> None:
        """
        Initialize the login manager with a FastAPI application.
        
        This method sets up the middleware for user loading and authentication
        on each request. It should be called once for each FastAPI application
        that needs authentication functionality.
        
        Args:
            app: The FastAPI application to initialize
        """
        self.app = app
        
        # Register middleware to load the user on each request
        @app.middleware("http")
        async def user_loader_middleware(request: Request, call_next: RequestResponseEndpoint) -> Response:
            """Load user information from session and make it available in request context.
            
            This middleware loads the user based on the cookie token and adds it to both the
            request state and the current_user context variable.
            
            Args:
                request: The incoming request
                call_next: Function to call the next middleware or endpoint
                
            Returns:
                The response from the next middleware or endpoint
            """
            
            # Store login_manager in request state for context access
            request.state.login_manager = self
            
            # Default to anonymous user
            request.state.user = self._get_anonymous_user()
            
            # Get the token from the cookie
            cookie_name = self._cookie_settings.cookie_name
            session_token = request.cookies.get(cookie_name)
            user_id = None
            
            if session_token:
                # Check if token has been revoked
                if REVOCATION_CONFIG["enabled"] and is_token_revoked(session_token):
                    # Token is revoked, don't authenticate the user
                    pass  # Silent on revoked tokens
                else:
                    try:
                        # Import necessary functions to decode session data
                        from .utils.crypto import decode_session_data, get_user_id_from_session_data
                        
                        # Get session data from storage using the token
                        session_data_str = self._storage.get(session_token)
                        
                        if session_data_str:
                            # Update last activity timestamp
                            self._storage.update_activity(session_token)
                            
                            # Decode session data and extract user ID
                            session_data = decode_session_data(session_data_str)
                            
                            if session_data:
                                user_id = get_user_id_from_session_data(session_data)
                                if user_id and self._user_loader:
                                    # Load user by ID
                                    user = await self._user_loader(user_id)
                                    if user:
                                        # Set user in request state and context
                                        request.state.user = user
                                        current_user_ctx.set(user)
                    except Exception as e:
                        # Log the error but don't expose details to the client
                        print(f"Authentication error: {e.__class__.__name__}")
                        # Continue with anonymous user
            # No session token - user remains anonymous
            
            # Continue with the request
            response = await call_next(request)
            return response

    def user_loader(self, callback: Callable) -> Callable:
        """
        Decorator to register a user loader function.
        
        This decorator registers a function that will be called to retrieve
        a user object based on a user ID stored in the session. The function
        should accept a user ID string and return a user object or None.
        
        Args:
            callback: Function that receives a user ID and returns a user object
            
        Returns:
            The unmodified callback function
            
        Example:
            ```python
            @login_manager.user_loader
            async def load_user(user_id: str):
                return await User.get(user_id)
            ```
        """
        self._user_loader = callback
        return callback
        
    def anonymous_user(self, user_class: Type) -> Type:
        """
        Decorator to define an anonymous user class.
        
        This decorator registers a class to be used for unauthenticated users.
        The anonymous user class should implement the same interface as your
        regular user class, but represent an unauthenticated state.
        
        Args:
            user_class: Class that defines an anonymous user
            
        Returns:
            The unmodified anonymous user class
            
        Example:
            ```python
            @login_manager.anonymous_user
            class AnonymousUser:
                def is_authenticated(self):
                    return False
            ```
        """
        self._anonymous_user = user_class
        return user_class
    
    def _get_anonymous_user(self) -> Any:
        """
        Get an instance of the anonymous user.
        
        If an anonymous user class has been defined with the @anonymous_user
        decorator, an instance of that class is returned. Otherwise, returns None.
        
        Returns:
            An anonymous user instance or None
        """
        if self._anonymous_user:
            return self._anonymous_user()
        return None
    
    @property
    def login_view(self) -> str:
        """
        Get the login view route.
        
        This is the URL that users will be redirected to when
        they try to access a protected page without authentication.
        """
        return self._login_view
    
    @login_view.setter
    def login_view(self, value: str) -> None:
        """
        Set the login view route.
        
        Args:
            value: URL path for the login page
        """
        self._login_view = value
    
    @property
    def session_protection(self) -> str:
        """
        Get the session protection level.
        
        Session protection helps prevent session hijacking. Available levels are:
        - 'basic': Basic protection against simple hijacking
        - 'strong': Strong protection but may log users out more frequently
        
        Returns:
            The current session protection mode
        """
        return self._session_protection
    
    @session_protection.setter
    def session_protection(self, value: str) -> None:
        """
        Set the session protection level.
        
        Args:
            value: Protection level ('basic' or 'strong')
            
        Raises:
            ValueError: If the value is not a valid protection level
        """
        allowed_values = ["basic", "strong"]
        if value not in allowed_values:
            raise ValueError(
                f"Invalid session_protection mode: {value}. "
                f"Must be one of: 'basic', 'strong'"
            )
        self._session_protection = value
        
        # Activar almacenamiento en memoria
        self.store_session_in_memory = True
    
    @property
    def cookie_settings(self) -> CookieSettings:
        """
        Get the cookie settings configuration.
        
        These settings control how authentication cookies are created and managed,
        including security attributes like HttpOnly, SameSite, and expiration times.
        
        Returns:
            The CookieSettings instance for this login manager
        """
        return self._cookie_settings
        
    def configure(self, mode: Literal["dev", "prod", "custom"] = "dev", **custom_settings) -> None:
        """
        Configure both cookie settings and storage using predefined modes.
        
        This is a convenience method that configures both cookie settings and
        storage settings in one call, using predefined modes.
        
        Args:
            mode: Configuration mode to use ("dev", "prod", or "custom")
            **custom_settings: Custom settings to use when mode is "custom"
            
        Example:
            ```python
            # Configure for development
            login_manager.configure("dev")
            
            # Configure for production
            login_manager.configure("prod")
            
            # Configure with custom settings
            login_manager.configure("custom", cookie_secure=True, cookie_httponly=True)
            ```
        """
        # Configure cookie settings
        self._cookie_settings.configure(mode, **custom_settings)
        
        # Apply general configuration based on mode
        if mode == "dev":
            # Aplicar configuración de desarrollo
            if "login_view" in DEV_CONFIG:
                self.login_view = DEV_CONFIG["login_view"]
            if "session_protection" in DEV_CONFIG:
                self.session_protection = DEV_CONFIG["session_protection"]
        elif mode == "prod":
            # Aplicar configuración de producción
            if "login_view" in PROD_CONFIG:
                self.login_view = PROD_CONFIG["login_view"]
            if "session_protection" in PROD_CONFIG:
                self.session_protection = PROD_CONFIG["session_protection"]
        elif mode == "custom":
            # Apply custom configuration
            # Custom settings are passed directly to CookieSettings.configure()
            pass
        
        # Configure storage with default settings
        storage_config = get_storage_config()
        self.configure_storage(**storage_config)
    
    def _get_session_key(self, request: Request) -> str:
        """
        Generate a unique session key for the user.
        
        This method tries to create a consistent identifier for the user based
        on existing cookies, headers, or client information. It follows a
        fallback strategy to ensure a usable key is always generated.
        
        Args:
            request: The HTTP request object
            
        Returns:
            A unique key to identify the user's session
        """
        # Try to get session ID from our auth cookie first
        session_id = request.cookies.get(self._cookie_settings.cookie_name)
        
        # If no auth cookie exists, try to use other cookies
        if not session_id and request.cookies:
            # Use the first available cookie as a session identifier
            for key, value in request.cookies.items():
                session_id = f"{key}:{value}"
                break
        
        # If no cookies exist, try to use the User-Agent header
        if not session_id:
            headers = dict(request.headers)
            user_agent = headers.get('user-agent', '')
            if user_agent:
                # Truncate long user agents to a reasonable length
                session_id = f"ua:{user_agent[:50]}"
        
        # Last resort: use a combination of IP address and timestamp with hash
        if not session_id:
            client_host = getattr(request.client, 'host', 'unknown')
            timestamp = int(time.time())
            raw_id = f"ip:{client_host}:{timestamp}"
            
            # Generate a hash for a shorter and more secure key
            session_id = hashlib.md5(raw_id.encode()).hexdigest()
        
        # No necesitamos registro aquí
            
        return session_id
    
    def unauthorized(self, next_url: Optional[str] = None) -> Response:
        """
        Handle unauthorized access attempts.
        
        This method is called when a user tries to access a protected resource
        without being authenticated. It can be customized by registering an
        unauthorized_handler callback.
        
        Args:
            next_url: Optional URL to redirect to after successful login.
                      If not provided, the current URL will be used.
        
        Returns:
            A response to handle unauthorized access (default: redirect to login page).
        """
        # Use custom callback if defined
        if self._unauthorized_callback:
            return self._unauthorized_callback(next_url)
        
        # Default behavior: redirect to login page
        login_url = self._login_view
        
        # Add next parameter if provided
        if next_url:
            if "?" in login_url:
                login_url = f"{login_url}&next={next_url}"
            else:
                login_url = f"{login_url}?next={next_url}"
        
        # No necesitamos registro aquí
            
        return RedirectResponse(
            url=login_url, 
            status_code=status.HTTP_302_FOUND
        )
