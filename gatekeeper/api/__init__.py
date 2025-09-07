"""
API modules for the Gatekeeper library.

This package contains FastAPI integration, dependencies, and route handlers.
"""

from .dependencies import get_current_user, require_active_user, require_role
from .routes import create_auth_router

__all__ = [
    "get_current_user",
    "require_role",
    "require_active_user",
    "create_auth_router",
]
