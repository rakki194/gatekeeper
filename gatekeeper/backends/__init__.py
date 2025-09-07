"""
Backends package for the Gatekeeper authentication library.

This package contains backend implementations for user data storage.
"""

from .base import (
    BackendError,
    InvalidCredentialsError,
    UserAlreadyExistsError,
    UserBackend,
    UserNotFoundError,
)
from .memory import MemoryBackend
from .postgresql import PostgreSQLBackend

__all__ = [
    # Base classes
    "UserBackend",
    "BackendError",
    "UserNotFoundError",
    "UserAlreadyExistsError",
    "InvalidCredentialsError",
    # Implementations
    "MemoryBackend",
    "PostgreSQLBackend",
]
