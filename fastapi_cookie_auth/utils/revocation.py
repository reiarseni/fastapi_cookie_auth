"""
Session token revocation and management.

This module provides functionality for token revocation and management,
including invalidation and checking of token validity.
"""

import time
from typing import Dict, List, Optional, Set

# Simple in-memory revocation store
revoked_tokens: Set[str] = set()
revocation_timestamps: Dict[str, int] = {}
last_cleanup: int = int(time.time())

# Maximum number of revoked tokens to store
MAX_REVOKED = 1000
CLEANUP_INTERVAL = 3600  # 1 hour


def revoke_token(token: str, ttl: Optional[int] = None) -> None:
    """
    Revoke a token by adding it to the revoked list.
    
    Args:
        token: The token to revoke
        ttl: Time-to-live in seconds
    """
    # Perform cleanup if needed
    maybe_cleanup()
    
    # Check if we've reached max capacity
    if len(revoked_tokens) >= MAX_REVOKED:
        _remove_oldest_tokens(int(MAX_REVOKED * 0.2))  # Remove 20% oldest
    
    # Add token to revoked list
    revoked_tokens.add(token)
    revocation_timestamps[token] = int(time.time())


def is_token_revoked(token: str) -> bool:
    """
    Check if a token has been revoked.
    
    Args:
        token: Token to check
        
    Returns:
        True if token is revoked, False otherwise
    """
    return token in revoked_tokens


def configure(max_revoked: int = 1000, cleanup_interval: int = 3600) -> None:
    """
    Configure the revocation system.
    
    Args:
        max_revoked: Maximum number of revoked tokens to store
        cleanup_interval: Interval between cleanup operations in seconds
    """
    global MAX_REVOKED, CLEANUP_INTERVAL
    MAX_REVOKED = max_revoked
    CLEANUP_INTERVAL = cleanup_interval


def maybe_cleanup() -> None:
    """Perform cleanup of old revoked tokens if needed."""
    global last_cleanup
    now = int(time.time())
    
    # Check if it's time to do cleanup
    if now - last_cleanup > CLEANUP_INTERVAL:
        _cleanup_expired_tokens()
        last_cleanup = now


def _remove_oldest_tokens(count: int) -> None:
    """
    Remove the oldest tokens from the revocation list.
    
    Args:
        count: Number of tokens to remove
    """
    if not revocation_timestamps:
        return
        
    # Sort by timestamp (oldest first)
    sorted_tokens = sorted(
        revocation_timestamps.items(),
        key=lambda x: x[1]
    )
    
    # Remove oldest tokens
    tokens_to_remove = [token for token, _ in sorted_tokens[:count]]
    
    for token in tokens_to_remove:
        revoked_tokens.discard(token)
        del revocation_timestamps[token]


def _cleanup_expired_tokens() -> None:
    """Remove all expired tokens based on their TTL."""
    # For now this is not implemented as we don't track TTL per token
    # In the future, this could be enhanced to check individual token TTLs
    pass
