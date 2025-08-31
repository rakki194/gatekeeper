"""
Models package for the Gatekeeper authentication library.

This package contains all the data models used throughout the authentication system.
"""

from .user import (
    User,
    UserRole,
    UserCreate,
    UserPublic,
    UserUpdate,
    UserLogin,
    UserPasswordChange,
)

from .token import (
    TokenData,
    TokenResponse,
    TokenRefreshRequest,
    TokenRefreshResponse,
    TokenValidationResult,
    TokenConfig,
)

__all__ = [
    # User models
    "User",
    "UserRole",
    "UserCreate",
    "UserPublic",
    "UserUpdate",
    "UserLogin",
    "UserPasswordChange",
    
    # Token models
    "TokenData",
    "TokenResponse",
    "TokenRefreshRequest",
    "TokenRefreshResponse",
    "TokenValidationResult",
    "TokenConfig",
]
