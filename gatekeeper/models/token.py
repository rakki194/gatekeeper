"""
Token models for the Gatekeeper authentication library.

This module defines Pydantic models for JWT token data structures used
throughout the authentication system.
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field


class TokenData(BaseModel):
    """
    Token data model for JWT payload.

    Contains the data that will be encoded in JWT tokens.

    Attributes:
        sub (str): Subject (usually username)
        role (str): User role
        type (str): Token type (access or refresh)
        exp (Optional[datetime]): Expiration time
        iat (Optional[datetime]): Issued at time
        jti (Optional[str]): JWT ID for token uniqueness
        metadata (Dict[str, Any]): Additional token metadata
    """

    sub: str = Field(..., description="Subject (usually username)")
    role: str = Field(..., description="User role")
    type: str = Field(..., description="Token type (access or refresh)")
    exp: Optional[datetime] = Field(default=None, description="Expiration time")
    iat: Optional[datetime] = Field(default=None, description="Issued at time")
    jti: Optional[str] = Field(default=None, description="JWT ID for token uniqueness")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

    @property
    def username(self) -> str:
        """Get username from subject field for backward compatibility."""
        return self.sub

    def update(self, **kwargs) -> "TokenData":
        """Update token data for backward compatibility with tests."""
        return self.model_copy(update=kwargs)


class TokenResponse(BaseModel):
    """
    Token response model for authentication endpoints.

    Contains the tokens returned after successful authentication.

    Attributes:
        access_token (str): JWT access token
        refresh_token (str): JWT refresh token
        token_type (str): Token type (usually "bearer")
        expires_in (int): Access token expiration time in seconds
        refresh_expires_in (int): Refresh token expiration time in seconds
    """

    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Access token expiration time in seconds")
    refresh_expires_in: int = Field(..., description="Refresh token expiration time in seconds")


class TokenRefreshRequest(BaseModel):
    """
    Token refresh request model.

    Attributes:
        refresh_token (str): The refresh token to use for getting a new access token
    """

    refresh_token: str = Field(..., description="Refresh token")


class TokenRefreshResponse(BaseModel):
    """
    Token refresh response model.

    Contains the new access token after successful refresh.

    Attributes:
        access_token (str): New JWT access token
        token_type (str): Token type (usually "bearer")
        expires_in (int): Access token expiration time in seconds
    """

    access_token: str = Field(..., description="New JWT access token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Access token expiration time in seconds")


class TokenValidationResult(BaseModel):
    """
    Token validation result model.

    Contains the result of token validation.

    Attributes:
        is_valid (bool): Whether the token is valid
        payload (Optional[TokenData]): Token payload if valid
        error (Optional[str]): Error message if invalid
        is_expired (bool): Whether the token is expired
        is_refresh_token (bool): Whether this is a refresh token
    """

    is_valid: bool = Field(..., description="Whether the token is valid")
    payload: Optional[TokenData] = Field(default=None, description="Token payload if valid")
    error: Optional[str] = Field(default=None, description="Error message if invalid")
    is_expired: bool = Field(default=False, description="Whether the token is expired")
    is_refresh_token: bool = Field(default=False, description="Whether this is a refresh token")


class TokenConfig(BaseModel):
    """
    Token configuration model.

    Contains configuration for JWT token generation and validation.

    Attributes:
        secret_key (str): Secret key for JWT signing
        algorithm (str): JWT algorithm (default: HS256)
        access_token_expire_minutes (int): Access token expiration time in minutes
        refresh_token_expire_days (int): Refresh token expiration time in days
        issuer (Optional[str]): Token issuer
        audience (Optional[str]): Token audience
    """

    secret_key: str = Field(..., description="Secret key for JWT signing")
    algorithm: str = Field(default="HS256", description="JWT algorithm")
    access_token_expire_minutes: int = Field(default=30, description="Access token expiration time in minutes")
    refresh_token_expire_days: int = Field(default=7, description="Refresh token expiration time in days")
    issuer: Optional[str] = Field(default=None, description="Token issuer")
    audience: Optional[str] = Field(default=None, description="Token audience")

    @property
    def access_token_expire_timedelta(self) -> timedelta:
        """Get access token expiration as timedelta."""
        return timedelta(minutes=self.access_token_expire_minutes)

    @property
    def refresh_token_expire_timedelta(self) -> timedelta:
        """Get refresh token expiration as timedelta."""
        return timedelta(days=self.refresh_token_expire_days)
