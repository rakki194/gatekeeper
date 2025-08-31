"""
In-memory backend implementation for the Gatekeeper authentication library.

This module provides a simple in-memory user storage backend suitable for
testing, development, and small-scale applications.
"""

import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
import uuid

from .base import UserBackend, BackendError, UserNotFoundError, UserAlreadyExistsError
from ..models.user import User, UserCreate, UserUpdate, UserPublic

logger = logging.getLogger(__name__)


class MemoryBackend(UserBackend):
    """
    In-memory user storage backend.

    This backend stores user data in memory and is suitable for testing,
    development, and small-scale applications. Data is lost when the
    application restarts.
    """

    def __init__(self):
        """Initialize the in-memory backend."""
        self._users: Dict[str, User] = {}
        self._usernames: Dict[str, str] = {}  # username -> user_id mapping
        self._emails: Dict[str, str] = {}  # email -> user_id mapping
        self._settings: Dict[str, Dict[str, Any]] = {}  # user_id -> settings mapping
        self._closed = False

    async def create_user(self, user: UserCreate) -> User:
        """
        Create a new user in the in-memory storage.

        Args:
            user: User creation data

        Returns:
            User: The created user object

        Raises:
            UserAlreadyExistsError: If a user with the same username already exists
        """
        if self._closed:
            raise BackendError("Backend is closed")

        # Check if username already exists
        if user.username in self._usernames:
            raise UserAlreadyExistsError(
                f"User with username '{user.username}' already exists"
            )

        # Check if email already exists (if provided)
        if user.email and user.email in self._emails:
            raise UserAlreadyExistsError(
                f"User with email '{user.email}' already exists"
            )

        # Generate user ID
        user_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)

        # Create user object
        new_user = User(
            id=user_id,
            username=user.username,
            password_hash="",  # Will be set by auth manager
            role=user.role,
            email=user.email,
            is_active=True,
            created_at=now,
            updated_at=now,
            metadata={},
        )

        # Store user
        self._users[user_id] = new_user
        self._usernames[user.username] = user_id
        if user.email:
            self._emails[user.email] = user_id

        logger.info(f"Created user '{user.username}' with ID '{user_id}'")
        return new_user

    async def get_user_by_username(self, username: str) -> Optional[User]:
        """
        Retrieve a user by username.

        Args:
            username: The username to search for

        Returns:
            Optional[User]: The user if found, None otherwise
        """
        if self._closed:
            raise BackendError("Backend is closed")

        user_id = self._usernames.get(username)
        if user_id:
            return self._users.get(user_id)
        return None

    async def get_user_by_id(self, user_id: str) -> Optional[User]:
        """
        Retrieve a user by ID.

        Args:
            user_id: The user ID to search for

        Returns:
            Optional[User]: The user if found, None otherwise
        """
        if self._closed:
            raise BackendError("Backend is closed")

        return self._users.get(user_id)

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
        """
        if self._closed:
            raise BackendError("Backend is closed")

        user = await self.get_user_by_username(username)
        if not user:
            raise UserNotFoundError(f"User '{username}' not found")

        # Update fields if provided
        if user_update.username is not None and user_update.username != username:
            # Check if new username is already taken
            if user_update.username in self._usernames:
                raise UserAlreadyExistsError(
                    f"Username '{user_update.username}' is already taken"
                )

            # Update username mapping
            del self._usernames[username]
            self._usernames[user_update.username] = user.id
            user.username = user_update.username

        if user_update.email is not None and user_update.email != user.email:
            # Check if new email is already taken
            if user_update.email in self._emails:
                raise UserAlreadyExistsError(
                    f"Email '{user_update.email}' is already taken"
                )

            # Update email mapping
            if user.email:
                del self._emails[user.email]
            if user_update.email:
                self._emails[user_update.email] = user.id
            user.email = user_update.email

        if user_update.role is not None:
            user.role = user_update.role

        if user_update.is_active is not None:
            user.is_active = user_update.is_active

        if user_update.profile_picture_url is not None:
            user.profile_picture_url = user_update.profile_picture_url

        if user_update.metadata is not None:
            user.metadata.update(user_update.metadata)

        user.updated_at = datetime.now(timezone.utc)

        logger.info(f"Updated user '{user.username}'")
        return user

    async def delete_user(self, username: str) -> bool:
        """
        Delete a user from the in-memory storage.

        Args:
            username: The username of the user to delete

        Returns:
            bool: True if the user was deleted, False if not found
        """
        if self._closed:
            raise BackendError("Backend is closed")

        user = await self.get_user_by_username(username)
        if not user:
            return False

        # Remove from all mappings
        del self._users[user.id]
        del self._usernames[username]
        if user.email:
            del self._emails[user.email]
        if user.id in self._settings:
            del self._settings[user.id]

        logger.info(f"Deleted user '{username}'")
        return True

    async def list_users(self, skip: int = 0, limit: int = 100) -> List[UserPublic]:
        """
        List users in the in-memory storage.

        Args:
            skip: Number of users to skip (for pagination)
            limit: Maximum number of users to return

        Returns:
            List[UserPublic]: List of users (public data only)
        """
        if self._closed:
            raise BackendError("Backend is closed")

        users = list(self._users.values())
        users.sort(
            key=lambda u: u.created_at or datetime.min.replace(tzinfo=timezone.utc)
        )

        paginated_users = users[skip : skip + limit]
        return [UserPublic.from_user(user) for user in paginated_users]

    async def count_users(self) -> int:
        """
        Get the total number of users in the in-memory storage.

        Returns:
            int: Total number of users
        """
        if self._closed:
            raise BackendError("Backend is closed")

        return len(self._users)

    async def update_user_password(self, username: str, new_password_hash: str) -> bool:
        """
        Update a user's password hash.

        Args:
            username: The username of the user
            new_password_hash: The new password hash

        Returns:
            bool: True if the password was updated, False if user not found
        """
        if self._closed:
            raise BackendError("Backend is closed")

        user = await self.get_user_by_username(username)
        if not user:
            return False

        user.password_hash = new_password_hash
        user.updated_at = datetime.now(timezone.utc)

        logger.info(f"Updated password for user '{username}'")
        return True

    async def update_user_role(self, username: str, new_role: str) -> bool:
        """
        Update a user's role.

        Args:
            username: The username of the user
            new_role: The new role

        Returns:
            bool: True if the role was updated, False if user not found
        """
        if self._closed:
            raise BackendError("Backend is closed")

        user = await self.get_user_by_username(username)
        if not user:
            return False

        user.role = new_role
        user.updated_at = datetime.now(timezone.utc)

        logger.info(f"Updated role for user '{username}' to '{new_role}'")
        return True

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
        """
        if self._closed:
            raise BackendError("Backend is closed")

        user = await self.get_user_by_username(username)
        if not user:
            return False

        user.profile_picture_url = profile_picture_url
        user.updated_at = datetime.now(timezone.utc)

        logger.info(f"Updated profile picture for user '{username}'")
        return True

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
        """
        if self._closed:
            raise BackendError("Backend is closed")

        user = await self.get_user_by_username(username)
        if not user:
            return False

        user.metadata.update(metadata)
        user.updated_at = datetime.now(timezone.utc)

        logger.info(f"Updated metadata for user '{username}'")
        return True

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
        if self._closed:
            raise BackendError("Backend is closed")

        query_lower = query.lower()
        matching_users = []

        for user in self._users.values():
            if query_lower in user.username.lower() or (
                user.email and query_lower in user.email.lower()
            ):
                matching_users.append(user)

        matching_users.sort(
            key=lambda u: u.created_at or datetime.min.replace(tzinfo=timezone.utc)
        )
        paginated_users = matching_users[skip : skip + limit]

        return [UserPublic.from_user(user) for user in paginated_users]

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
        if self._closed:
            raise BackendError("Backend is closed")

        matching_users = [user for user in self._users.values() if user.role == role]
        matching_users.sort(
            key=lambda u: u.created_at or datetime.min.replace(tzinfo=timezone.utc)
        )

        paginated_users = matching_users[skip : skip + limit]
        return [UserPublic.from_user(user) for user in paginated_users]

    async def is_username_taken(self, username: str) -> bool:
        """
        Check if a username is already taken.

        Args:
            username: The username to check

        Returns:
            bool: True if the username is taken, False otherwise
        """
        if self._closed:
            raise BackendError("Backend is closed")

        return username in self._usernames

    async def is_email_taken(self, email: str) -> bool:
        """
        Check if an email is already taken.

        Args:
            email: The email to check

        Returns:
            bool: True if the email is taken, False otherwise
        """
        if self._closed:
            raise BackendError("Backend is closed")

        return email in self._emails

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
        if self._closed:
            raise BackendError("Backend is closed")

        user = await self.get_user_by_username(username)
        if not user:
            raise UserNotFoundError(f"User '{username}' not found")

        return self._settings.get(user.id, {})

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
        """
        if self._closed:
            raise BackendError("Backend is closed")

        user = await self.get_user_by_username(username)
        if not user:
            return False

        if user.id not in self._settings:
            self._settings[user.id] = {}

        self._settings[user.id].update(settings)

        logger.info(f"Updated settings for user '{username}'")
        return True

    async def update_user_username(self, old_username: str, new_username: str) -> bool:
        """
        Update a user's username.

        Args:
            old_username: The current username
            new_username: The new username

        Returns:
            bool: True if the username was updated, False if user not found or new username taken
        """
        if self._closed:
            raise BackendError("Backend is closed")

        # Check if old user exists
        if old_username not in self._usernames:
            return False

        # Check if new username is already taken
        if new_username in self._usernames:
            return False

        # Get user ID
        user_id = self._usernames[old_username]
        user = self._users[user_id]

        # Update username in user object
        user.username = new_username

        # Update username mappings
        del self._usernames[old_username]
        self._usernames[new_username] = user_id

        logger.info(f"Updated username from '{old_username}' to '{new_username}'")
        return True

    async def get_all_users(self) -> List[UserPublic]:
        """
        Get all users in the backend.

        Returns:
            List[UserPublic]: List of all users (public data only)
        """
        if self._closed:
            raise BackendError("Backend is closed")

        return [
            UserPublic(
                username=user.username,
                role=user.role,
                yapcoin_balance=user.yapcoin_balance or 0,
                profile_picture_url=user.profile_picture_url,
            )
            for user in self._users.values()
        ]

    async def update_user_yapcoin_balance(self, username: str, amount: int) -> bool:
        """
        Update a user's YapCoin balance.

        Args:
            username: The username of the user
            amount: The amount to add/subtract from the balance

        Returns:
            bool: True if the balance was updated, False if user not found
        """
        if self._closed:
            raise BackendError("Backend is closed")

        if username not in self._usernames:
            return False

        user_id = self._usernames[username]
        user = self._users[user_id]

        # Initialize balance if None
        if user.yapcoin_balance is None:
            user.yapcoin_balance = 0

        # Update the balance
        user.yapcoin_balance += amount

        # Ensure balance doesn't go negative
        if user.yapcoin_balance < 0:
            user.yapcoin_balance = 0

        logger.info(
            f"Updated YapCoin balance for user '{username}' by {amount} (new balance: {user.yapcoin_balance})"
        )
        return True

    async def close(self) -> None:
        """
        Close the in-memory backend and clean up resources.
        """
        self._users.clear()
        self._usernames.clear()
        self._emails.clear()
        self._settings.clear()
        self._closed = True
        logger.info("Memory backend closed")

    async def health_check(self) -> bool:
        """
        Perform a health check on the in-memory backend.

        Returns:
            bool: True if the backend is healthy, False otherwise
        """
        return not self._closed

    def clear(self) -> None:
        """
        Clear all data from the in-memory backend.

        This method is useful for testing purposes.
        """
        self._users.clear()
        self._usernames.clear()
        self._emails.clear()
        self._settings.clear()
        logger.info("Memory backend data cleared")
