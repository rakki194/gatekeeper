"""
FastAPI routes for the Gatekeeper library.

This module provides route handlers for authentication and user management endpoints.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer

from ..core.auth_manager import AuthManager
from ..models.user import User, UserCreate, UserPublic, UserUpdate, UserRole
from ..models.token import TokenResponse
from .dependencies import get_current_user, require_active_user, require_admin

# Security scheme for JWT tokens
security = HTTPBearer()


def create_auth_router(auth_manager: AuthManager) -> APIRouter:
    """
    Create an authentication router with all auth-related endpoints.
    
    Args:
        auth_manager: Authentication manager instance
        
    Returns:
        FastAPI router with auth endpoints
    """
    router = APIRouter(prefix="/auth", tags=["authentication"])
    
    @router.post("/register", response_model=UserPublic)
    async def register(user_data: UserCreate):
        """Register a new user."""
        try:
            user = await auth_manager.create_user(user_data)
            return UserPublic.from_user(user)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )
    
    @router.post("/login", response_model=TokenResponse)
    async def login(username: str, password: str):
        """Authenticate user and return tokens."""
        tokens = await auth_manager.authenticate(username, password)
        
        if tokens is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        return tokens
    
    @router.post("/refresh", response_model=TokenResponse)
    async def refresh_token(refresh_token: str):
        """Refresh access token using refresh token."""
        tokens = await auth_manager.refresh_token(refresh_token)
        
        if tokens is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        return tokens
    
    @router.get("/me", response_model=UserPublic)
    async def get_current_user_info(current_user: User = Depends(get_current_user)):
        """Get current user information."""
        return UserPublic.from_user(current_user)
    
    @router.put("/me", response_model=UserPublic)
    async def update_current_user(
        user_update: UserUpdate,
        current_user: User = Depends(require_active_user)
    ):
        """Update current user information."""
        try:
            updated_user = await auth_manager.update_user(current_user.username, user_update)
            return UserPublic.from_user(updated_user)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )
    
    @router.post("/change-password")
    async def change_password(
        current_password: str,
        new_password: str,
        current_user: User = Depends(require_active_user)
    ):
        """Change current user's password."""
        success = await auth_manager.change_password(
            current_user.username, current_password, new_password
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid current password"
            )
        
        return {"message": "Password changed successfully"}
    
    @router.get("/users", response_model=list[UserPublic])
    async def list_users(current_user: User = Depends(require_admin)):
        """List all users (admin only)."""
        users = await auth_manager.list_users()
        return [UserPublic.from_user(user) for user in users]
    
    @router.get("/users/{username}", response_model=UserPublic)
    async def get_user(
        username: str,
        current_user: User = Depends(require_admin)
    ):
        """Get user by username (admin only)."""
        user = await auth_manager.get_user_by_username(username)
        
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        return UserPublic.from_user(user)
    
    @router.put("/users/{username}", response_model=UserPublic)
    async def update_user(
        username: str,
        user_update: UserUpdate,
        current_user: User = Depends(require_admin)
    ):
        """Update user by username (admin only)."""
        try:
            updated_user = await auth_manager.update_user(username, user_update)
            return UserPublic.from_user(updated_user)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )
    
    @router.delete("/users/{username}")
    async def delete_user(
        username: str,
        current_user: User = Depends(require_admin)
    ):
        """Delete user by username (admin only)."""
        try:
            await auth_manager.delete_user(username)
            return {"message": "User deleted successfully"}
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )
    
    @router.get("/health")
    async def health_check():
        """Health check endpoint."""
        is_healthy = await auth_manager.health_check()
        
        if not is_healthy:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Service unhealthy"
            )
        
        return {"status": "healthy"}
    
    return router
