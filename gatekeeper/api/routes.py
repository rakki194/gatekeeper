"""
Authentication API routes for Gatekeeper.

This module provides FastAPI routes for authentication operations including
login, logout, token refresh, and user management.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from typing import Optional

from ..core.auth_manager import AuthManager
from ..models.user import UserCreate, UserPublic, UserUpdate
from ..models.token import TokenResponse
from ..api.dependencies import get_auth_manager, get_current_user, require_role
from ..models.user import User, UserRole

# Create the main auth router
auth_router = APIRouter(prefix="/auth", tags=["authentication"])


@auth_router.post("/login", response_model=TokenResponse)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    request: Request = None,
    auth_manager: AuthManager = Depends(get_auth_manager)
):
    """
    Authenticate user and return access/refresh tokens.
    
    Args:
        form_data: OAuth2 form data containing username and password
        request: FastAPI request object for IP address extraction
        auth_manager: Authentication manager instance
        
    Returns:
        TokenResponse: Access and refresh tokens
        
    Raises:
        HTTPException: If authentication fails
    """
    # Extract client IP for rate limiting
    client_ip = None
    if request:
        client_ip = request.client.host if request.client else None
    
    # Authenticate user
    tokens = await auth_manager.authenticate(
        username=form_data.username,
        password=form_data.password,
        client_ip=client_ip
    )
    
    if not tokens:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return tokens


@auth_router.post("/refresh", response_model=TokenResponse)
async def refresh_tokens(
    refresh_token: str,
    request: Request = None,
    auth_manager: AuthManager = Depends(get_auth_manager)
):
    """
    Refresh access token using a valid refresh token.
    
    Args:
        refresh_token: The refresh token
        request: FastAPI request object for IP address extraction
        auth_manager: Authentication manager instance
        
    Returns:
        TokenResponse: New access and refresh tokens
        
    Raises:
        HTTPException: If refresh token is invalid
    """
    # Extract client IP for rate limiting
    client_ip = None
    if request:
        client_ip = request.client.host if request.client else None
    
    # Refresh tokens
    tokens = await auth_manager.refresh_tokens(
        refresh_token=refresh_token,
        client_ip=client_ip
    )
    
    if not tokens:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return tokens


@auth_router.post("/logout")
async def logout(
    token: str,
    auth_manager: AuthManager = Depends(get_auth_manager)
):
    """
    Logout user by revoking their token.
    
    Args:
        token: The access token to revoke
        auth_manager: Authentication manager instance
        
    Returns:
        dict: Success message
    """
    success = await auth_manager.logout(token)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to logout"
        )
    
    return {"message": "Successfully logged out"}


@auth_router.post("/register", response_model=UserPublic)
async def register(
    user_data: UserCreate,
    auth_manager: AuthManager = Depends(get_auth_manager)
):
    """
    Register a new user.
    
    Args:
        user_data: User creation data
        auth_manager: Authentication manager instance
        
    Returns:
        UserPublic: The created user (without sensitive data)
        
    Raises:
        HTTPException: If user creation fails
    """
    try:
        user = await auth_manager.create_user(user_data)
        return UserPublic.from_user(user)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@auth_router.get("/me", response_model=UserPublic)
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
):
    """
    Get current user information.
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        UserPublic: Current user information
    """
    return UserPublic.from_user(current_user)


@auth_router.put("/me", response_model=UserPublic)
async def update_current_user(
    user_update: UserUpdate,
    current_user: User = Depends(get_current_user),
    auth_manager: AuthManager = Depends(get_auth_manager)
):
    """
    Update current user information.
    
    Args:
        user_update: User update data
        current_user: Current authenticated user
        auth_manager: Authentication manager instance
        
    Returns:
        UserPublic: Updated user information
    """
    try:
        updated_user = await auth_manager.update_user(current_user.username, user_update)
        return UserPublic.from_user(updated_user)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@auth_router.post("/change-password")
async def change_password(
    current_password: str,
    new_password: str,
    current_user: User = Depends(get_current_user),
    auth_manager: AuthManager = Depends(get_auth_manager)
):
    """
    Change current user's password.
    
    Args:
        current_password: Current password
        new_password: New password
        current_user: Current authenticated user
        auth_manager: Authentication manager instance
        
    Returns:
        dict: Success message
        
    Raises:
        HTTPException: If password change fails
    """
    success = await auth_manager.change_password(
        username=current_user.username,
        current_password=current_password,
        new_password=new_password
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to change password"
        )
    
    return {"message": "Password changed successfully"}


# Admin-only endpoints
@auth_router.get("/users", response_model=list[UserPublic])
async def list_users(
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    auth_manager: AuthManager = Depends(get_auth_manager)
):
    """
    List all users (admin only).
    
    Args:
        current_user: Current authenticated user (must be admin)
        auth_manager: Authentication manager instance
        
    Returns:
        list[UserPublic]: List of all users
    """
    users = await auth_manager.list_users()
    return [UserPublic.from_user(user) for user in users]


@auth_router.get("/users/{username}", response_model=UserPublic)
async def get_user(
    username: str,
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    auth_manager: AuthManager = Depends(get_auth_manager)
):
    """
    Get user by username (admin only).
    
    Args:
        username: Username to look up
        current_user: Current authenticated user (must be admin)
        auth_manager: Authentication manager instance
        
    Returns:
        UserPublic: User information
        
    Raises:
        HTTPException: If user not found
    """
    user = await auth_manager.get_user_by_username(username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return UserPublic.from_user(user)


@auth_router.put("/users/{username}", response_model=UserPublic)
async def update_user(
    username: str,
    user_update: UserUpdate,
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    auth_manager: AuthManager = Depends(get_auth_manager)
):
    """
    Update user by username (admin only).
    
    Args:
        username: Username to update
        user_update: User update data
        current_user: Current authenticated user (must be admin)
        auth_manager: Authentication manager instance
        
    Returns:
        UserPublic: Updated user information
        
    Raises:
        HTTPException: If user not found or update fails
    """
    try:
        updated_user = await auth_manager.update_user(username, user_update)
        return UserPublic.from_user(updated_user)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@auth_router.delete("/users/{username}")
async def delete_user(
    username: str,
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    auth_manager: AuthManager = Depends(get_auth_manager)
):
    """
    Delete user by username (admin only).
    
    Args:
        username: Username to delete
        current_user: Current authenticated user (must be admin)
        auth_manager: Authentication manager instance
        
    Returns:
        dict: Success message
        
    Raises:
        HTTPException: If user not found or deletion fails
    """
    try:
        success = await auth_manager.delete_user(username)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to delete user"
            )
        
        return {"message": f"User '{username}' deleted successfully"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@auth_router.post("/users/{username}/revoke-tokens")
async def revoke_user_tokens(
    username: str,
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    auth_manager: AuthManager = Depends(get_auth_manager)
):
    """
    Revoke all tokens for a user (admin only).
    
    Args:
        username: Username whose tokens should be revoked
        current_user: Current authenticated user (must be admin)
        auth_manager: Authentication manager instance
        
    Returns:
        dict: Success message
    """
    success = await auth_manager.revoke_tokens(username)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to revoke tokens"
        )
    
    return {"message": f"All tokens revoked for user '{username}'"}


@auth_router.get("/stats")
async def get_auth_stats(
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    auth_manager: AuthManager = Depends(get_auth_manager)
):
    """
    Get authentication statistics (admin only).
    
    Args:
        current_user: Current authenticated user (must be admin)
        auth_manager: Authentication manager instance
        
    Returns:
        dict: Authentication statistics
    """
    stats = await auth_manager.get_token_stats()
    return stats


@auth_router.post("/cleanup")
async def cleanup_expired_tokens(
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    auth_manager: AuthManager = Depends(get_auth_manager)
):
    """
    Clean up expired tokens (admin only).
    
    Args:
        current_user: Current authenticated user (must be admin)
        auth_manager: Authentication manager instance
        
    Returns:
        dict: Success message
    """
    await auth_manager.cleanup_expired_tokens()
    return {"message": "Expired tokens cleaned up successfully"}


def create_auth_router() -> APIRouter:
    """
    Create and return the authentication router.
    
    Returns:
        APIRouter: Configured authentication router
    """
    return auth_router
