"""
Módulo para el almacenamiento de sesiones y datos compartidos.

Proporciona implementaciones de almacenamiento para las sesiones,
incluyendo almacenamiento en memoria y en disco con serialización optimizada.
"""

import os
import pickle
import hashlib
import time
import json
from typing import Dict, Any, Optional, Union
from pathlib import Path
from abc import ABC, abstractmethod

# Constantes para los tipos de almacenamiento disponibles
STORAGE_MEMORY = "memory"  # Almacenamiento en memoria (volátil)
STORAGE_FILE = "file"      # Almacenamiento en archivos con serialización optimizada (persistente)
STORAGE_REDIS = "redis"    # Almacenamiento en Redis (no implementado aún)

class SessionStorageInterface(ABC):
    """Base interface for session storage implementations.
    
    This abstract class defines the common interface that all session storage
    implementations must follow. It ensures a consistent API regardless of the
    underlying storage mechanism.
    """
    
    @abstractmethod
    def get(self, key: str) -> Optional[str]:
        """Retrieve a value from the storage.
        
        Args:
            key: The key to retrieve
            
        Returns:
            The stored value or None if not found
        """
        pass
    
    @abstractmethod
    def set(self, key: str, value: str, max_age: Optional[int] = None) -> None:
        """Store a value in the storage.
        
        Args:
            key: The key to store the value under
            value: The value to store
            max_age: Optional max age in seconds
        """
        pass
    
    @abstractmethod
    def delete(self, key: str) -> None:
        """Delete a value from the storage.
        
        Args:
            key: The key to delete
        """
        pass
    
    @abstractmethod
    def clear(self) -> None:
        """Clear all values from the storage."""
        pass
    
    @abstractmethod
    def cleanup_expired(self) -> int:
        """Clean up expired sessions.
        
        Default implementation does nothing. Subclasses should override.
        
        Returns:
            Number of expired sessions removed
        """
        return 0
    
    def update_activity(self, key: str) -> bool:
        """Update the last activity timestamp for a session.
        
        Args:
            key: Session key
            
        Returns:
            True if update was successful, False otherwise
        """
        # Default implementation - subclasses may override for efficiency
        session_data = self.get(key)
        if not session_data:
            return False
        
        try:
            # Parse existing session data
            data = json.loads(session_data)
            
            # Update last activity timestamp
            data['last_activity'] = int(time.time())
            
            # Save updated data
            self.set(key, json.dumps(data))
            return True
        except (json.JSONDecodeError, TypeError, KeyError):
            return False
    
    def __contains__(self, key: str) -> bool:
        """Check if a key exists in the storage.
        
        This allows using the 'in' operator with storage instances.
        
        Args:
            key: The key to check for existence
            
        Returns:
            True if the key exists, False otherwise
        """
        return self.get(key) is not None

class MemorySessionStorage(SessionStorageInterface):
    """In-memory implementation of session storage.
    
    Stores session data in a dictionary that exists only in memory.
    This implementation is fast but not persistent - data is lost when
    the application restarts.
    """
    
    def __init__(self) -> None:
        """Initialize an empty in-memory storage dictionary."""
        self._store: Dict[str, str] = {}
    
    def get(self, key: str) -> Optional[str]:
        """Retrieve a value from memory storage.
        
        Args:
            key: The key to retrieve
            
        Returns:
            The stored value or None if not found
        """
        print(f"MemorySessionStorage: Attempting to get key {key}")
        print(f"MemorySessionStorage: Available keys: {list(self._store.keys())}")
        value = self._store.get(key)
        print(f"MemorySessionStorage: Found value: {value is not None}")
        return value
    
    def set(self, key: str, value: str, max_age: Optional[int] = None) -> None:
        """Store a value in memory storage.
        
        Args:
            key: The key to store the value under
            value: The value to store
            max_age: Optional max age in seconds (ignored in memory storage)
        """
        # In memory storage we don't use max_age, it would be necessary to implement an expiration mechanism
        print(f"MemorySessionStorage: Storing data with key {key}")
        print(f"MemorySessionStorage: Value type: {type(value)}")
        self._store[key] = value
        print(f"MemorySessionStorage: Storage now has {len(self._store)} items")
    
    def delete(self, key: str) -> None:
        """Delete a value from memory storage.
        
        Args:
            key: The key to delete
        """
        if key in self._store:
            del self._store[key]
    
    def clear(self) -> None:
        """Clear all values from memory storage."""
        self._store.clear()
    
    def cleanup_expired(self) -> int:
        """Clean up expired sessions.
        
        This implementation does nothing since memory storage doesn't support expiration.
        
        Returns:
            0 (no expired sessions removed)
        """
        return 0

class OptimizedFileStorage(SessionStorageInterface):
    """Optimized file storage implementation.
    
    Stores session data in files using pickle for efficient serialization.
    This provides a good balance of performance and persistence while
    maintaining a simple API.
    """
    
    def __init__(self, directory: Union[str, Path] = None, session_expiry: int = 86400, cleanup_expired: bool = True) -> None:
        """Initialize an optimized file storage.
        
        Args:
            directory: Directory to store session files in, defaults to 'storage/sessions'
            session_expiry: Default session expiration time in seconds (24 hours)
            cleanup_expired: Whether to automatically clean up expired sessions
        """
        # Set storage directory with default fallback
        if directory is None:
            directory = "storage/sessions"
            
        self.directory = Path(directory)
        self.session_expiry = session_expiry
        self.cleanup_expired_flag = cleanup_expired
        self.last_cleanup = int(time.time())
        self.cleanup_interval = 3600  # Cleanup once per hour by default
        
        # Create directory if it doesn't exist
        os.makedirs(self.directory, exist_ok=True)
        
        # Initial cleanup of expired sessions
        if self.cleanup_expired_flag:
            self.cleanup_expired()
    
    def _get_file_path(self, key: str) -> Path:
        """Convert a session key to a valid file path.
        
        Creates a safe file name by using a hash of the key to avoid
        issues with invalid characters in filenames.
        
        Args:
            key: The session key
            
        Returns:
            Path object for the session file
        """
        # Use a hash for the filename to handle complex keys
        if key is None:
            raise ValueError("Session key cannot be None")
        
        # Create a hash of the key for a clean, fixed-length filename
        key_hash = hashlib.md5(key.encode('utf-8')).hexdigest()
        return self.directory / f"{key_hash}.session"
    
    def get(self, key: str) -> Optional[str]:
        """Retrieve session data from storage.
        
        Args:
            key: The session key to retrieve
            
        Returns:
            The session data or None if not found, expired, or an error occurs
        """
        # Maybe cleanup expired sessions
        self._maybe_cleanup()
        
        file_path = self._get_file_path(key)
        if file_path.exists():
            try:
                with open(file_path, 'rb') as f:
                    data = pickle.load(f)
                    
                # Check if data has expired
                expiry = data.get('expiry')
                if expiry is not None and int(time.time()) > expiry:
                    # Data has expired, delete it and return None
                    self.delete(key)
                    return None
                    
                return data.get('value')
            except Exception:
                # Fail silently but could log the error in a production system
                return None
        return None
    
    def set(self, key: str, value: str, max_age: Optional[int] = None) -> None:
        """Store session data in storage.
        
        Args:
            key: The session key to store
            value: The session data to store
            max_age: Optional max age in seconds (could be used to set an expiration time)
        """
        file_path = self._get_file_path(key)
        
        # Set expiry based on max_age or default session expiry
        expiry = None
        if max_age is not None:
            expiry = int(time.time()) + max_age
        elif self.session_expiry > 0:
            expiry = int(time.time()) + self.session_expiry
            
        with open(file_path, 'wb') as f:
            pickle.dump({
                'key': key, 
                'value': value,
                'expiry': expiry,
                'created_at': int(time.time())
            }, f, protocol=pickle.HIGHEST_PROTOCOL)
    
    def delete(self, key: str) -> None:
        """Delete a session file if it exists.
        
        Args:
            key: The session key to delete
        """
        file_path = self._get_file_path(key)
        if file_path.exists():
            try:
                file_path.unlink()
            except Exception:
                # Fail silently but could log the error in a production system
                pass
    
    def clear(self) -> None:
        """Delete all session files in the storage directory."""
        for file_path in self.directory.glob("*.session"):
            try:
                file_path.unlink()
            except Exception:
                # Fail silently but could log the error in a production system
                pass
    
    def _maybe_cleanup(self) -> None:
        """Check if we need to clean up expired sessions based on interval."""
        if not self.cleanup_expired_flag:
            return
            
        now = int(time.time())
        if now - self.last_cleanup > self.cleanup_interval:
            self.cleanup_expired()
            self.last_cleanup = now
    
    def cleanup_expired(self) -> int:
        """Clean up expired sessions.
        
        Returns:
            Number of expired sessions removed
        """
        count = 0
        now = int(time.time())
        
        for file_path in self.directory.glob("*.session"):
            try:
                with open(file_path, 'rb') as f:
                    data = pickle.load(f)
                
                # Check if data has expired
                expiry = data.get('expiry')
                if expiry is not None and now > expiry:
                    file_path.unlink()
                    count += 1
            except Exception:
                # Fail silently but could log the error in a production system
                pass
                
        return count

def get_storage(storage_type: str = STORAGE_FILE, **kwargs) -> SessionStorageInterface:
    """
    Create a storage instance based on the specified type.
    
    This factory function creates and returns an appropriate storage implementation
    based on the requested type:
    
    - memory: Fast but volatile (data lost on restart)
    - file: Optimized file storage with efficient serialization (persistent)
    - redis: Redis-based storage (not yet implemented)
    
    Args:
        storage_type: Type of storage to create (memory, file, or redis)
        **kwargs: Additional arguments for the storage constructor (e.g. directory)
    
    Returns:
        An instance of a SessionStorageInterface implementation
    
    Raises:
        ValueError: If the specified storage type is invalid
        NotImplementedError: If the storage type is not yet implemented
    """
    if storage_type == STORAGE_MEMORY:
        return MemorySessionStorage()
    elif storage_type == STORAGE_FILE:
        return OptimizedFileStorage(**kwargs)
    elif storage_type == STORAGE_REDIS:
        raise NotImplementedError(f"Redis storage is not yet implemented.")
    else:
        raise ValueError(f"Invalid storage type: {storage_type}. "
                         f"Valid options are: {STORAGE_MEMORY}, {STORAGE_FILE}, {STORAGE_REDIS}")


# Default storage instance using file storage
session_store = get_storage(STORAGE_FILE)
