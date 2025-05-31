"""
FastAPI Cookie Auth - A Flask-Login style authentication for FastAPI.
"""

from .login_manager import LoginManager
from .user_mixin import UserMixin
from .decorators import roles_required
from .utils import (
    login_user,
    logout_user,
    login_required,
    current_user,
    is_authenticated
)

__version__ = "0.1.0"
