"""
Gatekeeper - Authentication and Authorization Library

A comprehensive authentication and authorization library for Python applications,
providing secure user management, JWT token handling, role-based access control,
and flexible backend integration.

Features:
- Secure password hashing with Argon2
- JWT token management with access and refresh tokens
- Role-based access control (RBAC)
- User profile management
- Abstract backend interfaces for easy integration
- FastAPI integration with dependency injection
- Comprehensive security features

Example usage:
    from gatekeeper import AuthManager, User, UserRole
    from gatekeeper.backends.memory import MemoryBackend

    # Initialize authentication manager
    auth_manager = AuthManager(backend=MemoryBackend())

    # Create a user
    user = await auth_manager.create_user(
        username="john_doe",
        password="secure_password",
        role=UserRole.REGULAR
    )

    # Authenticate user
    tokens = await auth_manager.authenticate("john_doe", "secure_password")
"""

__version__ = "0.1.0"
__author__ = "Your Name"
__email__ = "your.email@example.com"

# Core exports
from .core.auth_manager import AuthManager
from .core.token_manager import TokenManager
from .core.password_manager import PasswordManager, SecurityLevel

# Model exports
from .models.user import User, UserRole, UserCreate, UserPublic, UserUpdate
from .models.token import TokenData, TokenResponse, TokenConfig

# Backend exports
from .backends.base import UserBackend, BackendError, UserNotFoundError, UserAlreadyExistsError
from .backends.memory import MemoryBackend
from .backends.postgresql import PostgreSQLBackend

# Utility exports
from .utils.security import SecurityUtils
from .utils.validators import PasswordValidator

# API exports
from .api.dependencies import get_current_user, require_role, require_active_user
from .api.routes import create_auth_router

__all__ = [
    # Core
    "AuthManager",
    "TokenManager", 
    "PasswordManager",
    "SecurityLevel",
    
    # Models
    "User",
    "UserRole",
    "UserCreate",
    "UserPublic",
    "UserUpdate",
    "TokenData",
    "TokenResponse",
    "TokenConfig",
    
    # Backends
    "UserBackend",
    "BackendError",
    "UserNotFoundError",
    "UserAlreadyExistsError",
    "MemoryBackend",
    "PostgreSQLBackend",
    
    # Utils
    "SecurityUtils",
    "PasswordValidator",
    
    # API
    "get_current_user",
    "require_role",
    "require_active_user",
    "create_auth_router",
]
