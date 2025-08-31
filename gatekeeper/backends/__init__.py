"""
Backends package for the Gatekeeper authentication library.

This package contains backend implementations for user data storage.
"""

from .base import (
    UserBackend,
    BackendError,
    UserNotFoundError,
    UserAlreadyExistsError,
    InvalidCredentialsError,
)

from .memory import MemoryBackend

__all__ = [
    # Base classes
    "UserBackend",
    "BackendError",
    "UserNotFoundError",
    "UserAlreadyExistsError",
    "InvalidCredentialsError",
    
    # Implementations
    "MemoryBackend",
]
