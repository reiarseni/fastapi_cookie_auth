"""
Configuration settings for FastAPI Cookie Auth.

This module provides the configuration classes for managing cookie settings
and other authentication-related parameters.
"""

import os
import secrets
from typing import Any, Dict, Literal, Optional, Union


# Cookie security mode
COOKIE_SECURITY_TOKEN = "token"     # Random session token (UUID)

# Predefined configuration modes
# Cookie configuration
DEV_COOKIE_CONFIG = {
    "cookie_domain": None,  # None to use current domain (localhost)
    "cookie_secure": False,  # False for development without HTTPS
    "cookie_httponly": False,  # False to allow JavaScript access and DevTools visibility
    "cookie_samesite": "lax",  # Lax is more permissive than Strict
    "remember_cookie_duration": 30 * 24 * 60 * 60,  # 30 days
    "cookie_security_mode": COOKIE_SECURITY_TOKEN,  # Always use random token mode
    "secret_key": "dev-secret-key-not-for-production"  # Key for cryptographic operations
}

PROD_COOKIE_CONFIG = {
    "cookie_domain": None,  # Will use the current domain
    "cookie_secure": True,  # True for production (requires HTTPS)
    "cookie_httponly": True,  # True for security
    "cookie_samesite": "strict",  # Strict for better security
    "remember_cookie_duration": 7 * 24 * 60 * 60,  # 7 days (shorter for security)
    "cookie_security_mode": COOKIE_SECURITY_TOKEN,  # Always use random token mode
    "secret_key": ""  # Must be configured in production with a secure key
}

# General LoginManager configuration
DEV_CONFIG = {
    "login_view": "/login",  # Default login view
    "session_protection": "basic"  # Basic session protection
}

PROD_CONFIG = {
    "login_view": "/login",  # Default login view
    "session_protection": "basic"  # Basic session protection
}

# Storage configuration
STORAGE_CONFIG = {
    "storage_type": "file",
    "directory": "storage/sessions",
    "session_expiry": 3600 * 24,  # Default: 24 hours in seconds
    "cleanup_expired": True      # Auto cleanup expired sessions
}

# Session expiration configuration
SESSION_EXPIRY = {
    "enabled": True,               # Enable session expiration
    "lifetime": 3600 * 24,         # Default session lifetime: 24 hours in seconds
    "cleanup_interval": 3600      # Cleanup interval for expired sessions (seconds)
}

# Revocation configuration
REVOCATION_CONFIG = {
    "enabled": False,              # Enable token revocation tracking
    "max_revoked": 1000,          # Maximum stored revoked tokens
    "cleanup_interval": 3600      # Cleanup interval for revoked tokens (seconds)
}


class CookieSettings:
    """Settings for authentication cookies.
    
    This class manages all cookie-related configuration options used by the
    authentication system. It provides default secure values that can be
    overridden as needed.
    
    Supports three configuration modes:
    - "dev": Development mode with relaxed security for easier debugging
    - "prod": Production mode with strict security settings
    - "custom": Custom settings provided by the user
    
    Supports four security modes for cookies:
    - "signed": User ID signed with HMAC to prevent tampering
    - "encrypted": User ID encrypted for confidentiality
    - "token": Random session token stored instead of User ID
    """
    
    def __init__(self):
        """Initialize cookie settings with secure defaults."""
        # Name of the cookie in the browser
        self.cookie_name: str = "fastapi_auth"
        # Path for which the cookie is valid
        self.cookie_path: str = "/"
        # Domain for which the cookie is valid
        self.cookie_domain: Optional[str] = None
        # Only send cookie over HTTPS
        self.cookie_secure: bool = False
        # Prevent JavaScript access to the cookie
        self.cookie_httponly: bool = True
        # Controls cross-site request policy (None, 'lax', 'strict')
        self.cookie_samesite: str = "lax"
        # Salt for extra security
        self.cookie_salt: str = secrets.token_hex(8)
        # Duration in seconds for persistent cookies
        self.remember_cookie_duration: int = 30 * 24 * 60 * 60  # 30 days
        # Duration for session cookies (None = browser session)
        self.session_cookie_duration: Optional[int] = None
        
        # New security configurations
        # Security mode for cookies (token)
        self.cookie_security_mode: str = COOKIE_SECURITY_TOKEN
        # Secret key for cryptographic operations
        self.secret_key: str = ""
        # No longer necessary to use this flag because we always use tokens
        self.use_session_token: bool = True
        
    def update(self, **kwargs: Any) -> None:
        """
        Update cookie settings with provided values.
        
        Args:
            **kwargs: Key-value pairs of settings to update
            
        Raises:
            ValueError: If an invalid setting name is provided
        """
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
            else:
                raise ValueError(f"Invalid cookie setting: {key}")
                
    def configure(self, mode: Literal["dev", "prod", "custom"] = "dev", **custom_settings) -> None:
        """
        Configure cookie settings using predefined modes or custom settings.
        
        Args:
            mode: Configuration mode to use ("dev", "prod", or "custom")
            **custom_settings: Custom settings to use when mode is "custom"
            
        Raises:
            ValueError: If an invalid mode is provided
        """
        if mode == "dev":
            self.update(**DEV_COOKIE_CONFIG)
        elif mode == "prod":
            self.update(**PROD_COOKIE_CONFIG)
        elif mode == "custom":
            self.update(**custom_settings)
        else:
            raise ValueError(f"Invalid configuration mode: {mode}. Use 'dev', 'prod', or 'custom'")


def get_storage_config() -> Dict[str, str]:
    """
    Get storage configuration with environment variable overrides.
    
    Returns:
        Dictionary with storage configuration
    """
    config = STORAGE_CONFIG.copy()
    
    # Override with environment variables if present
    if os.getenv("SESSION_STORAGE_TYPE"):
        config["storage_type"] = os.getenv("SESSION_STORAGE_TYPE")
    if os.getenv("SESSION_STORAGE_DIRECTORY"):
        config["directory"] = os.getenv("SESSION_STORAGE_DIRECTORY")
        
    return config
