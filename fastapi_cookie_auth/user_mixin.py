"""
UserMixin implementation for FastAPI Cookie Auth.

This module provides a base class that implements common user authentication
methods required for cookie-based authentication in FastAPI applications.
"""

from typing import Any, Dict, Optional


class UserMixin:
    """
    Base class that provides default implementations for authentication methods.
    
    This class is inspired by Flask-Login's UserMixin and provides similar
    functionality for FastAPI applications. User models should inherit from
    this class to gain standard authentication behavior.
    
    Example:
        ```python
        class User(UserMixin):
            def __init__(self, id, username):
                self.id = id
                self.username = username
        ```
    """
    
    @property
    def is_active(self) -> bool:
        """
        Check if this is an active user account.
        
        This property should return True for users unless they are inactive,
        for example because they have been banned or their account has been
        deactivated.
        
        Returns:
            True if the user is active, False otherwise
        """
        return True
    
    @property
    def is_authenticated(self) -> bool:
        """
        Check if the user is authenticated.
        
        This property is used to determine whether a user is logged in.
        By default, all UserMixin instances are considered authenticated.
        Override this property if you need custom authentication logic.
        
        Returns:
            True if the user is authenticated, False otherwise
        """
        return True
    
    @property
    def is_anonymous(self) -> bool:
        """
        Check if the user is anonymous.
        
        This property indicates whether a user is anonymous (not authenticated).
        By default, all UserMixin instances are considered non-anonymous.
        
        Returns:
            False for authenticated users, True for anonymous users
        """
        return False
    
    def get_id(self) -> str:
        """
        Return the user ID as a string.
        
        This method is used to identify the user in the session. It should
        return a unique identifier that can be used to retrieve the user
        from storage.
        
        Returns:
            A string representation of the user's unique identifier
            
        Raises:
            NotImplementedError: If the user object doesn't have an 'id' attribute
                and this method hasn't been overridden
        """
        try:
            return str(self.id)
        except AttributeError:
            raise NotImplementedError("No `id` attribute. Override get_id()")
