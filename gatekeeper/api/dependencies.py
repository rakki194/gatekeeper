"""
FastAPI dependencies for Gatekeeper authentication.

This module provides dependency injection functions for authentication,
authorization, and role-based access control.
"""

from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer

from ..core.auth_manager import AuthManager
from ..models.user import User, UserRole

# OAuth2 scheme for token extraction
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Global auth manager instance
_auth_manager: Optional[AuthManager] = None


def get_auth_manager() -> AuthManager:
    """
    Get the authentication manager instance.

    Returns:
        AuthManager: The authentication manager

    Raises:
        HTTPException: If auth manager is not initialized
    """
    global _auth_manager
    if _auth_manager is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service not initialized",
        )
    return _auth_manager


def set_auth_manager(auth_manager: AuthManager) -> None:
    """
    Set the global authentication manager instance.

    Args:
        auth_manager: The authentication manager to set
    """
    global _auth_manager
    _auth_manager = auth_manager


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """
    Dependency to get the current authenticated user from the token.

    Args:
        token (str): The JWT token from the Authorization header.

    Returns:
        User: The User object extracted from the token.

    Raises:
        HTTPException: If the token is invalid or user data is missing.
    """
    auth_manager = get_auth_manager()

    user = await auth_manager.get_current_user(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def require_role(required_role: UserRole):
    """
    Dependency factory to require a specific user role.

    Args:
        required_role: The role required to access the endpoint

    Returns:
        Dependency function that checks the user's role
    """

    async def _require_role(current_user: User = Depends(get_current_user)) -> User:
        """
        Check if the current user has the required role.

        Args:
            current_user: The current authenticated user

        Returns:
            User: The current user if they have the required role

        Raises:
            HTTPException: If the user doesn't have the required role
        """
        if current_user.role != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required role: {required_role.value}",
            )
        return current_user

    return _require_role


def require_roles(required_roles: list[UserRole]):
    """
    Dependency factory to require one of several user roles.

    Args:
        required_roles: List of roles that grant access to the endpoint

    Returns:
        Dependency function that checks if the user has one of the required roles
    """

    async def _require_roles(current_user: User = Depends(get_current_user)) -> User:
        """
        Check if the current user has one of the required roles.

        Args:
            current_user: The current authenticated user

        Returns:
            User: The current user if they have one of the required roles

        Raises:
            HTTPException: If the user doesn't have any of the required roles
        """
        if current_user.role not in required_roles:
            role_names = [role.value for role in required_roles]
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required roles: {', '.join(role_names)}",
            )
        return current_user

    return _require_roles


def require_active_user():
    """
    Dependency factory to require an active (non-guest) user.

    Returns:
        Dependency function that checks if the user is active
    """

    async def _require_active_user(
        current_user: User = Depends(get_current_user),
    ) -> User:
        """
        Check if the current user is active (not a guest).

        Args:
            current_user: The current authenticated user

        Returns:
            User: The current user if they are active

        Raises:
            HTTPException: If the user is a guest
        """
        if current_user.role == UserRole.GUEST:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized for this action as guest",
            )
        return current_user

    return _require_active_user


def require_admin():
    """
    Dependency factory to require an admin user.

    Returns:
        Dependency function that checks if the user is an admin
    """
    return require_role(UserRole.ADMIN)


# Backward-compatible version for tests
def require_admin_legacy():
    """
    Legacy version of require_admin for backward compatibility with tests.

    Returns:
        Dependency function that checks if the user is an admin
    """
    return require_role_legacy(UserRole.ADMIN)


def require_regular_user():
    """
    Dependency factory to require a regular user.

    Returns:
        Dependency function that checks if the user is a regular user
    """
    return require_role(UserRole.REGULAR)


def require_guest():
    """
    Dependency factory to require a guest user.

    Returns:
        Dependency function that checks if the user is a guest
    """
    return require_role(UserRole.GUEST)


# Backward-compatible version for tests
def require_active_user_legacy():
    """
    Legacy version of require_active_user for backward compatibility with tests.

    Returns:
        Dependency function that checks if the user is active
    """

    async def _require_active_user_legacy(current_user: User) -> User:
        """
        Check if the current user is active (not a guest).

        Args:
            current_user: The current authenticated user

        Returns:
            User: The current user if they are active

        Raises:
            HTTPException: If the user is a guest
        """
        if current_user.role == UserRole.GUEST:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized for this action as guest",
            )
        return current_user

    return _require_active_user_legacy


async def get_current_user_optional(request: Request) -> Optional[User]:
    """
    Optional dependency to get the current user if a token is provided.

    Args:
        request: The FastAPI request object

    Returns:
        Optional[User]: The user if a valid token is provided, None otherwise
    """
    # Try to get token from Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.lower().startswith("bearer "):
        return None

    token = auth_header.split(" ", 1)[1].strip()
    if not token:
        return None

    try:
        auth_manager = get_auth_manager()
        user = await auth_manager.get_current_user(token)
        return user
    except HTTPException:
        return None


async def get_current_user_sse(request: Request) -> User:
    """
    Resolve the current user for SSE endpoints where browsers cannot set
    Authorization headers on EventSource. Supports:
      - Authorization: Bearer <token>
      - Query params: ?token=<access_token> or ?access_token=<access_token>
    """
    # Try Authorization header first
    token: Optional[str] = None
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1].strip()

    # Fallback to query parameter
    if not token:
        qp = request.query_params
        token = qp.get("token") or qp.get("access_token")

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Use gatekeeper to get current user
    auth_manager = get_auth_manager()
    user = await auth_manager.get_current_user(token)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def get_current_active_user_sse():
    """
    Active-user variant for SSE routes.

    Returns:
        Dependency function that checks if the user is active for SSE
    """

    async def _get_current_active_user_sse(
        current_user: User = Depends(get_current_user_sse),
    ) -> User:
        """
        Active-user variant for SSE routes.
        """
        if current_user.role == UserRole.GUEST:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized for this action as guest",
            )
        return current_user

    return _get_current_active_user_sse


async def validate_token(token: str, required_role: Optional[UserRole] = None) -> bool:
    """
    Validate a token and optionally check role requirements.

    Args:
        token: The JWT token to validate
        required_role: Optional role requirement

    Returns:
        bool: True if token is valid and meets role requirements
    """
    try:
        auth_manager = get_auth_manager()
        return await auth_manager.validate_token(
            token, required_role.value if required_role else None
        )
    except Exception:
        return False
