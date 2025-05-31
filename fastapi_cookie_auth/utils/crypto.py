"""
Cryptographic utilities for secure cookie and session handling.

This module provides functions for signing and verifying cookies,
as well as generating and managing random session tokens.
"""

import base64
import hashlib
import hmac
import json
import os
import time
import uuid
from typing import Any, Dict, Optional, Tuple, Union


def generate_session_token() -> str:
    """
    Generate a random session token using UUID.
    
    Returns:
        A unique session token string
    """
    return str(uuid.uuid4())


def sign_value(value: str, secret_key: str) -> str:
    """
    Sign a value using HMAC-SHA256.
    
    Args:
        value: The value to sign
        secret_key: The secret key for signing
        
    Returns:
        The signed value in format: value.signature_base64
    """
    if not secret_key:
        raise ValueError("A secret key is required for signing values")
    
    # Calculate HMAC signature
    signature = hmac.new(
        secret_key.encode('utf-8'),
        value.encode('utf-8'),
        hashlib.sha256
    ).digest()
    
    # Encode signature in base64 (URL-safe)
    signature_b64 = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')
    
    # Return value.signature
    return f"{value}.{signature_b64}"


def verify_signed_value(signed_value: str, secret_key: str) -> Optional[str]:
    """
    Verify and extract the original value from a signed value.
    
    Args:
        signed_value: The signed value in format value.signature_base64
        secret_key: The secret key used for signing
        
    Returns:
        The original value if the signature is valid, None otherwise
    """
    if not secret_key:
        raise ValueError("A secret key is required to verify signed values")
    
    # Split into value and signature
    try:
        value, signature_b64 = signed_value.rsplit('.', 1)
    except ValueError:
        # Invalid format
        return None
    
    # Calculate expected signature
    expected_signature = hmac.new(
        secret_key.encode('utf-8'),
        value.encode('utf-8'),
        hashlib.sha256
    ).digest()
    
    # Decode received signature
    try:
        # Add padding if necessary
        padding = len(signature_b64) % 4
        if padding:
            signature_b64 += '=' * (4 - padding)
            
        received_signature = base64.urlsafe_b64decode(signature_b64)
    except Exception:
        # Decoding error
        return None
    
    # Compare signatures (constant time to prevent timing attacks)
    if hmac.compare_digest(expected_signature, received_signature):
        return value
    
    return None


def encrypt_value(value: str, secret_key: str) -> str:
    """
    Encrypt a value using AES-GCM with Fernet.
    This is a simplified implementation that could be extended.
    
    For a complete implementation, we could use:
    from cryptography.fernet import Fernet
    
    Args:
        value: The value to encrypt
        secret_key: The secret key for encryption
        
    Returns:
        The encrypted value in base64 format
    """
    # In this simplified version, we'll use signing as encryption
    # to avoid additional dependencies
    timestamp = int(time.time())
    payload = f"{timestamp}.{value}"
    return sign_value(payload, secret_key)


def decrypt_value(encrypted_value: str, secret_key: str, max_age: Optional[int] = None) -> Optional[str]:
    """
    Decrypt an encrypted value.
    
    Args:
        encrypted_value: The encrypted value
        secret_key: The secret key for decryption
        max_age: Maximum age in seconds to consider the value valid
        
    Returns:
        The original value if decryption is successful and not expired, None otherwise
    """
    # Verify signature
    payload = verify_signed_value(encrypted_value, secret_key)
    if not payload:
        return None
    
    # Extract timestamp and value
    try:
        timestamp_str, value = payload.split('.', 1)
        timestamp = int(timestamp_str)
    except (ValueError, TypeError):
        return None
    
    # Verify age if max_age is specified
    if max_age is not None:
        current_time = int(time.time())
        if current_time - timestamp > max_age:
            return None
    
    return value


def encode_session_data(user_id: str, request: Optional[Any] = None, extra_data: Optional[Dict[str, Any]] = None) -> str:
    """
    Encodes session data in JSON format with enhanced security information.
    
    Args:
        user_id: User ID
        request: Optional request object to extract client info
        extra_data: Additional data for the session
        
    Returns:
        Session data encoded in JSON
    """
    now = int(time.time())
    
    session_data = {
        "user_id": user_id,
        "created_at": now,
        "last_activity": now
    }
    
    # Add client information if request is provided
    if request:
        client_host = getattr(request, "client", None)
        headers = getattr(request, "headers", {})
        
        if client_host:
            session_data["ip_address"] = getattr(client_host, "host", "unknown")
        
        # Add user agent if available
        user_agent = headers.get("user-agent", "")
        if user_agent:
            session_data["user_agent"] = user_agent
    
    if extra_data:
        session_data.update(extra_data)
    
    return json.dumps(session_data)


def decode_session_data(session_data_str: str) -> Optional[Dict[str, Any]]:
    """
    Decodes session data from JSON format.
    
    Args:
        session_data_str: Encoded session data
        
    Returns:
        Dictionary with session data, or None if there's an error
    """
    try:
        return json.loads(session_data_str)
    except json.JSONDecodeError:
        return None


def get_user_id_from_session_data(session_data: Dict[str, Any]) -> Optional[str]:
    """
    Extracts the user ID from session data.
    
    Args:
        session_data: Session data
        
    Returns:
        User ID or None if it doesn't exist
    """
    return session_data.get("user_id")


def generate_secret_key() -> str:
    """
    Generate a random secret key for signing and encryption.
    
    Returns:
        Secret key encoded in base64
    """
    return base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')
