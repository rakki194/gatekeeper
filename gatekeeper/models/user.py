"""
User models for the Gatekeeper authentication library.

This module defines Pydantic models for user data structures used throughout
the authentication system. These models ensure type safety and provide
automatic validation for data passing between components.
"""

import re
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, field_validator


class UserRole(str, Enum):
    """
    User role options for access control.

    Defines the different roles a user can have within the application:
    - admin: Full administrative privileges
    - regular: Standard user with view and edit permissions for own content
    - guest: Limited view-only access
    """

    ADMIN = "admin"
    REGULAR = "regular"
    GUEST = "guest"


class User(BaseModel):
    """
    User model for authentication and authorization.

    Stores user credentials, role, and optional profile information.

    Attributes:
        id (Optional[str]): Unique identifier for the user (backend-specific)
        username (str): Unique username for the user
        password_hash (str): Hashed password for security
        role (UserRole): The role of the user (admin, regular, guest)
        email (Optional[str]): User's email address
        profile_picture_url (Optional[str]): URL pointing to the user's profile picture
        is_active (bool): Whether the user account is active
        created_at (Optional[datetime]): When the user was created
        updated_at (Optional[datetime]): When the user was last updated
        metadata (Dict[str, Any]): Additional user metadata
        permissions (Dict[str, Any]): User permissions for backward compatibility
    """

    id: Optional[str] = Field(default=None)
    username: str = Field(..., min_length=3, max_length=50)
    password_hash: str
    role: UserRole = Field(UserRole.REGULAR)
    email: Optional[str] = Field(default=None)
    profile_picture_url: Optional[str] = Field(default=None)
    yapcoin_balance: Optional[int] = Field(default=0)
    is_active: bool = Field(default=True)
    created_at: Optional[datetime] = Field(default=None)
    updated_at: Optional[datetime] = Field(default=None)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    permissions: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        """Validate username format."""
        if not re.match(r"^[a-zA-Z0-9_-]+$", value):
            raise ValueError(
                "Username must contain only alphanumeric characters, underscores, and hyphens"
            )
        return value

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: Optional[str]) -> Optional[str]:
        """Validate email format if provided."""
        if value is not None:
            email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
            if not re.match(email_pattern, value):
                raise ValueError("Invalid email format")
        return value


class UserPublic(BaseModel):
    """
    Public User model, containing only non-sensitive information.

    Used for API responses where sensitive data like password_hash should not be exposed.
    """

    id: Optional[str] = None
    username: str
    role: UserRole
    email: Optional[str] = None
    profile_picture_url: Optional[str] = None
    yapcoin_balance: Optional[int] = Field(default=0)
    is_active: bool
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_user(cls, user: "User") -> "UserPublic":
        """
        Create a UserPublic instance from a User instance.

        Args:
            user: User instance to convert

        Returns:
            UserPublic instance with public data only
        """
        return cls(
            id=user.id,
            username=user.username,
            role=user.role,
            email=user.email,
            profile_picture_url=user.profile_picture_url,
            yapcoin_balance=user.yapcoin_balance or 0,
            is_active=user.is_active,
            created_at=user.created_at,
            updated_at=user.updated_at,
            metadata=user.metadata or {},
        )


class UserCreate(BaseModel):
    """
    User model for registration requests.

    Accepts a plain password which will be hashed by the server.

    Attributes:
        username (str): Unique username for the user
        password (str): Plain text password for registration
        email (Optional[str]): User's email address
        role (UserRole): The role of the user (admin, regular, guest). Defaults to regular.
    """

    username: str = Field(
        ...,
        min_length=3,
        max_length=50,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Unique username for the user. Alphanumeric, underscores, and hyphens only.",
    )
    password: str = Field(
        ...,
        min_length=8,
        description="Plain text password for registration. Must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.",
    )
    email: Optional[str] = Field(default=None)
    role: UserRole = Field(UserRole.REGULAR)

    @field_validator("password")
    @classmethod
    def validate_password_complexity(cls, value: str) -> str:
        """
        Validate password complexity requirements.

        Ensures password contains at least:
        - One uppercase letter
        - One lowercase letter
        - One digit
        - One special character
        """
        if not re.search(r"[A-Z]", value):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", value):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", value):
            raise ValueError("Password must contain at least one digit")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            raise ValueError("Password must contain at least one special character")
        return value

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: Optional[str]) -> Optional[str]:
        """Validate email format if provided."""
        if value is not None:
            email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
            if not re.match(email_pattern, value):
                raise ValueError("Invalid email format")
        return value


class UserUpdate(BaseModel):
    """
    User model for update requests.

    Allows updating user information without exposing sensitive data.

    Attributes:
        username (Optional[str]): New username
        email (Optional[str]): New email address
        role (Optional[UserRole]): New role
        is_active (Optional[bool]): Whether the user account is active
        profile_picture_url (Optional[str]): New profile picture URL
        metadata (Optional[Dict[str, Any]]): Additional user metadata
    """

    username: Optional[str] = Field(
        default=None,
        min_length=3,
        max_length=50,
        pattern=r"^[a-zA-Z0-9_-]+$",
    )
    email: Optional[str] = Field(default=None)
    role: Optional[UserRole] = Field(default=None)
    is_active: Optional[bool] = Field(default=None)
    profile_picture_url: Optional[str] = Field(default=None)
    metadata: Optional[Dict[str, Any]] = Field(default=None)

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: Optional[str]) -> Optional[str]:
        """Validate username format if provided."""
        if value is not None and not re.match(r"^[a-zA-Z0-9_-]+$", value):
            raise ValueError(
                "Username must contain only alphanumeric characters, underscores, and hyphens"
            )
        return value

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: Optional[str]) -> Optional[str]:
        """Validate email format if provided."""
        if value is not None:
            email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
            if not re.match(email_pattern, value):
                raise ValueError("Invalid email format")
        return value


class UserLogin(BaseModel):
    """
    User login model for authentication requests.

    Attributes:
        username (str): Username for authentication
        password (str): Plain text password for authentication
    """

    username: str = Field(..., min_length=1, description="Username for authentication")
    password: str = Field(..., min_length=1, description="Password for authentication")


class UserPasswordChange(BaseModel):
    """
    User password change model.

    Attributes:
        current_password (str): Current password for verification
        new_password (str): New password
    """

    current_password: str = Field(..., min_length=1, description="Current password")
    new_password: str = Field(
        ...,
        min_length=8,
        description="New password. Must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.",
    )

    @field_validator("new_password")
    @classmethod
    def validate_password_complexity(cls, value: str) -> str:
        """
        Validate password complexity requirements.

        Ensures password contains at least:
        - One uppercase letter
        - One lowercase letter
        - One digit
        - One special character
        """
        if not re.search(r"[A-Z]", value):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", value):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", value):
            raise ValueError("Password must contain at least one digit")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            raise ValueError("Password must contain at least one special character")
        return value


class PasswordResetRequest(BaseModel):
    """
    Password reset request model.

    Attributes:
        email (str): Email address to send reset link to
    """

    email: str = Field(..., description="Email address for password reset")


class PasswordResetToken(BaseModel):
    """
    Password reset token model.

    Attributes:
        token (str): The reset token
        new_password (str): New password
    """

    token: str = Field(..., description="Password reset token")
    new_password: str = Field(
        ...,
        min_length=8,
        description="New password. Must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.",
    )

    @field_validator("new_password")
    @classmethod
    def validate_password_complexity(cls, value: str) -> str:
        """
        Validate password complexity requirements.

        Ensures password contains at least:
        - One uppercase letter
        - One lowercase letter
        - One digit
        - One special character
        """
        if not re.search(r"[A-Z]", value):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", value):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", value):
            raise ValueError("Password must contain at least one digit")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            raise ValueError("Password must contain at least one special character")
        return value


class PasswordResetResponse(BaseModel):
    """
    Password reset response model.

    Attributes:
        message (str): Success message
        token (Optional[str]): Reset token (for development/testing)
    """

    message: str = Field(..., description="Success message")
    token: Optional[str] = Field(
        None, description="Reset token (for development/testing)"
    )
