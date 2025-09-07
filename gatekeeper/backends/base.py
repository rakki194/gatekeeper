"""
Abstract backend interfaces for the Gatekeeper authentication library.

This module defines the abstract base classes that all user backends must implement.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from ..models.user import User, UserCreate, UserPublic, UserUpdate


class BackendError(Exception):
    """Base exception for backend operations."""

    pass


class UserNotFoundError(BackendError):
    """Raised when a user is not found in the backend."""

    pass


class UserAlreadyExistsError(BackendError):
    """Raised when trying to create a user that already exists."""

    pass


class InvalidCredentialsError(BackendError):
    """Raised when authentication credentials are invalid."""

    pass


class UserBackend(ABC):
    """
    Abstract base class for user data backends.

    All user storage backends must implement this interface to provide
    consistent user management functionality across different storage systems.
    """

    @abstractmethod
    async def create_user(self, user: UserCreate) -> User:
        """
        Create a new user in the backend.

        Args:
            user: User creation data

        Returns:
            User: The created user object

        Raises:
            UserAlreadyExistsError: If a user with the same username already exists
            BackendError: For other backend-specific errors
        """
        pass

    @abstractmethod
    async def get_user_by_username(self, username: str) -> Optional[User]:
        """
        Retrieve a user by username.

        Args:
            username: The username to search for

        Returns:
            Optional[User]: The user if found, None otherwise
        """
        pass

    @abstractmethod
    async def get_user_by_id(self, user_id: str) -> Optional[User]:
        """
        Retrieve a user by ID.

        Args:
            user_id: The user ID to search for

        Returns:
            Optional[User]: The user if found, None otherwise
        """
        pass

    @abstractmethod
    async def get_user_by_email(self, email: str) -> Optional[User]:
        """
        Retrieve a user by email address.

        Args:
            email: The email address to search for

        Returns:
            Optional[User]: The user if found, None otherwise
        """
        pass

    @abstractmethod
    async def update_user(self, username: str, user_update: UserUpdate) -> User:
        """
        Update an existing user.

        Args:
            username: The username of the user to update
            user_update: The update data

        Returns:
            User: The updated user object

        Raises:
            UserNotFoundError: If the user is not found
            BackendError: For other backend-specific errors
        """
        pass

    @abstractmethod
    async def delete_user(self, username: str) -> bool:
        """
        Delete a user from the backend.

        Args:
            username: The username of the user to delete

        Returns:
            bool: True if the user was deleted, False if not found
        """
        pass

    @abstractmethod
    async def list_users(self, skip: int = 0, limit: int = 100) -> List[UserPublic]:
        """
        List users in the backend.

        Args:
            skip: Number of users to skip (for pagination)
            limit: Maximum number of users to return

        Returns:
            List[UserPublic]: List of users (public data only)
        """
        pass

    @abstractmethod
    async def count_users(self) -> int:
        """
        Get the total number of users in the backend.

        Returns:
            int: Total number of users
        """
        pass

    @abstractmethod
    async def update_user_password(self, username: str, new_password_hash: str) -> bool:
        """
        Update a user's password hash.

        Args:
            username: The username of the user
            new_password_hash: The new password hash

        Returns:
            bool: True if the password was updated, False if user not found

        Raises:
            BackendError: For backend-specific errors
        """
        pass

    @abstractmethod
    async def update_user_role(self, username: str, new_role: str) -> bool:
        """
        Update a user's role.

        Args:
            username: The username of the user
            new_role: The new role

        Returns:
            bool: True if the role was updated, False if user not found

        Raises:
            BackendError: For backend-specific errors
        """
        pass

    @abstractmethod
    async def update_user_profile_picture(
        self, username: str, profile_picture_url: Optional[str]
    ) -> bool:
        """
        Update a user's profile picture URL.

        Args:
            username: The username of the user
            profile_picture_url: The new profile picture URL or None to remove

        Returns:
            bool: True if the profile picture was updated, False if user not found

        Raises:
            BackendError: For backend-specific errors
        """
        pass

    @abstractmethod
    async def update_user_metadata(
        self, username: str, metadata: Dict[str, Any]
    ) -> bool:
        """
        Update a user's metadata.

        Args:
            username: The username of the user
            metadata: The new metadata dictionary

        Returns:
            bool: True if the metadata was updated, False if user not found

        Raises:
            BackendError: For backend-specific errors
        """
        pass

    @abstractmethod
    async def search_users(
        self, query: str, skip: int = 0, limit: int = 100
    ) -> List[UserPublic]:
        """
        Search for users by username or email.

        Args:
            query: Search query string
            skip: Number of users to skip (for pagination)
            limit: Maximum number of users to return

        Returns:
            List[UserPublic]: List of matching users (public data only)
        """
        pass

    @abstractmethod
    async def get_users_by_role(
        self, role: str, skip: int = 0, limit: int = 100
    ) -> List[UserPublic]:
        """
        Get users by role.

        Args:
            role: The role to filter by
            skip: Number of users to skip (for pagination)
            limit: Maximum number of users to return

        Returns:
            List[UserPublic]: List of users with the specified role
        """
        pass

    @abstractmethod
    async def is_username_taken(self, username: str) -> bool:
        """
        Check if a username is already taken.

        Args:
            username: The username to check

        Returns:
            bool: True if the username is taken, False otherwise
        """
        pass

    @abstractmethod
    async def is_email_taken(self, email: str) -> bool:
        """
        Check if an email is already taken.

        Args:
            email: The email to check

        Returns:
            bool: True if the email is taken, False otherwise
        """
        pass

    @abstractmethod
    async def get_user_settings(self, username: str) -> Dict[str, Any]:
        """
        Get user settings.

        Args:
            username: The username of the user

        Returns:
            Dict[str, Any]: User settings dictionary

        Raises:
            UserNotFoundError: If the user is not found
        """
        pass

    @abstractmethod
    async def update_user_settings(
        self, username: str, settings: Dict[str, Any]
    ) -> bool:
        """
        Update user settings.

        Args:
            username: The username of the user
            settings: The settings to update

        Returns:
            bool: True if the settings were updated, False if user not found

        Raises:
            BackendError: For backend-specific errors
        """
        pass

    @abstractmethod
    async def update_user_username(self, old_username: str, new_username: str) -> bool:
        """
        Update a user's username.

        Args:
            old_username: The current username
            new_username: The new username

        Returns:
            bool: True if the username was updated, False if user not found or new username taken

        Raises:
            BackendError: For backend-specific errors
        """
        pass

    @abstractmethod
    async def get_all_users(self) -> List[UserPublic]:
        """
        Get all users in the backend.

        Returns:
            List[UserPublic]: List of all users (public data only)
        """
        pass

    async def update_user_yapcoin_balance(self, username: str, amount: int) -> bool:
        """
        Update a user's YapCoin balance.

        This method is optional and may not be implemented by all backends.
        Default implementation returns False.

        Args:
            username: The username of the user
            amount: The amount to add/subtract from the balance

        Returns:
            bool: True if the balance was updated, False if user not found or not supported
        """
        return False

    @abstractmethod
    async def close(self) -> None:
        """
        Close the backend connection and clean up resources.

        This method should be called when the backend is no longer needed.
        """
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """
        Perform a health check on the backend.

        Returns:
            bool: True if the backend is healthy, False otherwise
        """
        pass
