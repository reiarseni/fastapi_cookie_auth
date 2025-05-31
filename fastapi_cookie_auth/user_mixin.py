"""
UserMixin implementation for FastAPI Cookie Auth.
"""

from typing import Any, Dict, Optional


class UserMixin:
    """
    This provides default implementations for methods that Flask-Login
    expects user objects to have.
    """
    
    @property
    def is_active(self) -> bool:
        """
        Returns True if this is an active user.
        
        This should return True for users unless they are inactive, for example
        because they have been banned or their account is inactive.
        """
        return True
    
    @property
    def is_authenticated(self) -> bool:
        """
        Returns True if the user is authenticated.
        
        This method is required by Flask-Login, and is typically used to
        determine whether a user is logged in or not.
        """
        return True
    
    @property
    def is_anonymous(self) -> bool:
        """
        Returns False as default users are not anonymous.
        
        Anonymous users are not typical in most applications.
        """
        return False
    
    def get_id(self) -> str:
        """
        Return the user ID as a string.
        
        This is required by Flask-Login and is used to restore the user from
        the session cookie.
        """
        try:
            return str(self.id)
        except AttributeError:
            raise NotImplementedError("No `id` attribute. Override get_id()")
