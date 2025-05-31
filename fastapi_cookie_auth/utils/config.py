"""
Configuration settings for FastAPI Cookie Auth.

This module provides the configuration classes for managing cookie settings
and other authentication-related parameters.
"""

import os
import secrets
from typing import Any, Dict, Literal, Optional, Union


# Modo de seguridad de cookies
COOKIE_SECURITY_TOKEN = "token"     # Token de sesión aleatorio (UUID)

# Predefined configuration modes
# Configuración de cookies
DEV_COOKIE_CONFIG = {
    "cookie_domain": None,  # None para usar el dominio actual (localhost)
    "cookie_secure": False,  # False para desarrollo sin HTTPS
    "cookie_httponly": False,  # False para permitir acceso desde JavaScript y ver en DevTools
    "cookie_samesite": "lax",  # Lax es más permisivo que Strict
    "remember_cookie_duration": 30 * 24 * 60 * 60,  # 30 días
    "cookie_security_mode": COOKIE_SECURITY_TOKEN,  # Siempre usar modo token aleatorio
    "secret_key": "dev-secret-key-not-for-production"  # Clave para las operaciones criptográficas
}

PROD_COOKIE_CONFIG = {
    "cookie_domain": None,  # Usará el dominio actual
    "cookie_secure": True,  # True para producción (requiere HTTPS)
    "cookie_httponly": True,  # True para seguridad
    "cookie_samesite": "strict",  # Strict para mejor seguridad
    "remember_cookie_duration": 7 * 24 * 60 * 60,  # 7 días (más corto por seguridad)
    "cookie_security_mode": COOKIE_SECURITY_TOKEN,  # Siempre usar modo token aleatorio
    "secret_key": ""  # Debe configurarse en producción con una clave segura
}

# Configuración general del LoginManager
DEV_CONFIG = {
    "login_view": "/login",  # Vista de login predeterminada
    "session_protection": "basic"  # Protección de sesión básica
}

PROD_CONFIG = {
    "login_view": "/login",  # Vista de login predeterminada
    "session_protection": "basic"  # Protección de sesión básica
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
    - "plain": User ID stored directly in the cookie (least secure)
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
        
        # Nuevas configuraciones de seguridad
        # Modo de seguridad para cookies (token)
        self.cookie_security_mode: str = COOKIE_SECURITY_TOKEN
        # Clave secreta para operaciones criptográficas
        self.secret_key: str = ""
        # Ya no es necesario usar este flag porque siempre usamos tokens
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
