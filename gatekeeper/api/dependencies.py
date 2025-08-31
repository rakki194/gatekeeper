"""
FastAPI dependencies for the Gatekeeper library.

This module provides dependency injection functions for authentication and authorization.
"""

from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from ..core.auth_manager import AuthManager
from ..models.user import User, UserRole

# Security scheme for JWT tokens
security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    auth_manager: Optional[AuthManager] = None,
) -> User:
    """
    Get the current authenticated user from the JWT token.

    Args:
        credentials: HTTP authorization credentials
        auth_manager: Authentication manager instance

    Returns:
        The authenticated user

    Raises:
        HTTPException: If authentication fails
    """
    if auth_manager is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Auth manager not configured",
        )

    token = credentials.credentials
    user = await auth_manager.get_current_user(token)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


async def require_active_user(current_user: User = Depends(get_current_user)) -> User:
    """
    Require that the current user is active.

    Args:
        current_user: The current authenticated user

    Returns:
        The active user

    Raises:
        HTTPException: If user is not active
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user"
        )

    return current_user


async def require_role(
    required_role: UserRole, current_user: User = Depends(require_active_user)
) -> User:
    """
    Require that the current user has a specific role.

    Args:
        required_role: The required role
        current_user: The current authenticated user

    Returns:
        The user with the required role

    Raises:
        HTTPException: If user doesn't have the required role
    """
    if current_user.role < required_role:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role {required_role.value} required",
        )

    return current_user


async def require_admin(current_user: User = Depends(require_active_user)) -> User:
    """
    Require that the current user is an admin.

    Args:
        current_user: The current authenticated user

    Returns:
        The admin user

    Raises:
        HTTPException: If user is not an admin
    """
    return await require_role(UserRole.ADMIN, current_user)
