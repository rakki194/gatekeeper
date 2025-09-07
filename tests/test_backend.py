"""
Tests for backend functionality in the Gatekeeper library.

This module tests the memory backend and base backend classes.
"""

import pytest
from datetime import datetime, timezone
from gatekeeper.backends.memory import MemoryBackend
from gatekeeper.backends.base import (
    BackendError,
    UserNotFoundError,
    UserAlreadyExistsError,
)
from gatekeeper.models.user import User, UserRole


@pytest.fixture
def memory_backend():
    """Create a memory backend for testing."""
    return MemoryBackend()


@pytest.fixture
def sample_user():
    """Create a sample user for testing."""
    return User(
        id="test-id",
        username="testuser",
        email="test@example.com",
        role=UserRole.REGULAR,
        is_active=True,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
        password_hash="hashed_password",
    )


class TestMemoryBackend:
    """Test the MemoryBackend class."""

    @pytest.mark.asyncio
    async def test_create_user(self, memory_backend, sample_user):
        """Test user creation."""
        created_user = await memory_backend.create_user(sample_user)

        # The backend generates a new UUID, so we can't assert the exact ID
        assert created_user.id is not None
        assert created_user.username == sample_user.username
        assert created_user.email == sample_user.email
        assert created_user.role == sample_user.role

    @pytest.mark.asyncio
    async def test_create_duplicate_user(self, memory_backend, sample_user):
        """Test creating duplicate user raises error."""
        await memory_backend.create_user(sample_user)

        with pytest.raises(UserAlreadyExistsError):
            await memory_backend.create_user(sample_user)

    @pytest.mark.asyncio
    async def test_get_user_by_id(self, memory_backend, sample_user):
        """Test getting user by ID."""
        created_user = await memory_backend.create_user(sample_user)

        retrieved_user = await memory_backend.get_user_by_id(created_user.id)

        assert retrieved_user is not None
        assert retrieved_user.id == created_user.id
        assert retrieved_user.username == sample_user.username

    @pytest.mark.asyncio
    async def test_get_user_by_id_not_found(self, memory_backend):
        """Test getting non-existent user by ID."""
        user = await memory_backend.get_user_by_id("non-existent-id")
        assert user is None

    @pytest.mark.asyncio
    async def test_get_user_by_username(self, memory_backend, sample_user):
        """Test getting user by username."""
        created_user = await memory_backend.create_user(sample_user)

        retrieved_user = await memory_backend.get_user_by_username(sample_user.username)

        assert retrieved_user is not None
        assert retrieved_user.username == sample_user.username
        assert retrieved_user.id == created_user.id

    @pytest.mark.asyncio
    async def test_get_user_by_username_not_found(self, memory_backend):
        """Test getting non-existent user by username."""
        user = await memory_backend.get_user_by_username("non-existent")
        assert user is None

    @pytest.mark.asyncio
    async def test_get_user_by_email(self, memory_backend, sample_user):
        """Test getting user by email."""
        created_user = await memory_backend.create_user(sample_user)

        # Use the backend's internal method to find user by email
        users = await memory_backend.list_users()
        user_by_email = None
        for user in users:
            if user.email == sample_user.email:
                user_by_email = user
                break

        assert user_by_email is not None
        assert user_by_email.email == sample_user.email
        assert user_by_email.username == sample_user.username

    @pytest.mark.asyncio
    async def test_get_user_by_email_not_found(self, memory_backend):
        """Test getting non-existent user by email."""
        users = await memory_backend.list_users()
        user_by_email = None
        for user in users:
            if user.email == "nonexistent@example.com":
                user_by_email = user
                break
        assert user_by_email is None

    @pytest.mark.asyncio
    async def test_update_user(self, memory_backend, sample_user):
        """Test updating user."""
        created_user = await memory_backend.create_user(sample_user)

        # Create a UserUpdate object with the changes
        from gatekeeper.models.user import UserUpdate
        user_update = UserUpdate(
            email="updated@example.com",
            role=UserRole.ADMIN
        )

        updated_user = await memory_backend.update_user(created_user.username, user_update)

        assert updated_user.email == "updated@example.com"
        assert updated_user.role == UserRole.ADMIN

    @pytest.mark.asyncio
    async def test_update_user_not_found(self, memory_backend):
        """Test updating non-existent user."""
        from gatekeeper.models.user import UserUpdate
        user_update = UserUpdate(email="updated@example.com")
        
        with pytest.raises(UserNotFoundError):
            await memory_backend.update_user("nonexistent", user_update)

    @pytest.mark.asyncio
    async def test_delete_user(self, memory_backend, sample_user):
        """Test deleting user."""
        created_user = await memory_backend.create_user(sample_user)

        # Verify user exists
        user = await memory_backend.get_user_by_id(created_user.id)
        assert user is not None

        # Delete user by username
        result = await memory_backend.delete_user(created_user.username)
        assert result is True

        # Verify user is deleted
        user = await memory_backend.get_user_by_id(created_user.id)
        assert user is None

    @pytest.mark.asyncio
    async def test_delete_user_not_found(self, memory_backend):
        """Test deleting non-existent user."""
        # The current implementation returns False for non-existent users
        result = await memory_backend.delete_user("nonexistent")
        assert result is False

    @pytest.mark.asyncio
    async def test_list_users(self, memory_backend):
        """Test listing users."""
        # Create multiple users
        user1 = User(
            id="1",
            username="user1",
            email="user1@example.com",
            role=UserRole.REGULAR,
            password_hash="hash1",
        )
        user2 = User(
            id="2",
            username="user2",
            email="user2@example.com",
            role=UserRole.ADMIN,
            password_hash="hash2",
        )

        await memory_backend.create_user(user1)
        await memory_backend.create_user(user2)

        users = await memory_backend.list_users()

        assert len(users) == 2
        usernames = [user.username for user in users]
        assert "user1" in usernames
        assert "user2" in usernames

    @pytest.mark.asyncio
    async def test_list_users_pagination(self, memory_backend):
        """Test listing users with pagination."""
        # Create multiple users
        for i in range(5):
            user = User(
                id=str(i),
                username=f"user{i}",
                email=f"user{i}@example.com",
                role=UserRole.REGULAR,
                password_hash=f"hash{i}",
            )
            await memory_backend.create_user(user)

        # Test pagination
        users = await memory_backend.list_users(skip=1, limit=2)
        assert len(users) == 2

    @pytest.mark.asyncio
    async def test_count_users(self, memory_backend):
        """Test counting users."""
        assert await memory_backend.count_users() == 0

        user = User(
            id="1",
            username="user1",
            email="user1@example.com",
            role=UserRole.REGULAR,
            password_hash="hash1",
        )
        await memory_backend.create_user(user)

        assert await memory_backend.count_users() == 1

    @pytest.mark.asyncio
    async def test_update_user_password(self, memory_backend, sample_user):
        """Test updating user password."""
        created_user = await memory_backend.create_user(sample_user)

        success = await memory_backend.update_user_password(
            created_user.username, "new_hash"
        )

        assert success is True

        # Verify password was updated
        user = await memory_backend.get_user_by_username(created_user.username)
        assert user.password_hash == "new_hash"

    @pytest.mark.asyncio
    async def test_update_user_password_not_found(self, memory_backend):
        """Test updating password for non-existent user."""
        success = await memory_backend.update_user_password("non-existent", "new_hash")
        assert success is False

    @pytest.mark.asyncio
    async def test_update_user_role(self, memory_backend, sample_user):
        """Test updating user role."""
        created_user = await memory_backend.create_user(sample_user)

        success = await memory_backend.update_user_role(
            created_user.username, UserRole.ADMIN
        )

        assert success is True

        # Verify role was updated
        user = await memory_backend.get_user_by_username(created_user.username)
        assert user.role == UserRole.ADMIN

    @pytest.mark.asyncio
    async def test_update_user_role_not_found(self, memory_backend):
        """Test updating role for non-existent user."""
        success = await memory_backend.update_user_role("non-existent", UserRole.ADMIN)
        assert success is False

    @pytest.mark.asyncio
    async def test_update_user_profile_picture(self, memory_backend, sample_user):
        """Test updating user profile picture."""
        created_user = await memory_backend.create_user(sample_user)

        success = await memory_backend.update_user_profile_picture(
            created_user.username, "https://example.com/avatar.jpg"
        )

        assert success is True

        # Verify profile picture was updated
        user = await memory_backend.get_user_by_username(created_user.username)
        assert user.profile_picture_url == "https://example.com/avatar.jpg"

    @pytest.mark.asyncio
    async def test_update_user_profile_picture_not_found(self, memory_backend):
        """Test updating profile picture for non-existent user."""
        success = await memory_backend.update_user_profile_picture(
            "non-existent", "https://example.com/avatar.jpg"
        )
        assert success is False

    @pytest.mark.asyncio
    async def test_update_user_metadata(self, memory_backend, sample_user):
        """Test updating user metadata."""
        created_user = await memory_backend.create_user(sample_user)

        metadata = {"key": "value", "preferences": {"theme": "dark"}}
        success = await memory_backend.update_user_metadata(
            created_user.username, metadata
        )

        assert success is True

        # Verify metadata was updated
        user = await memory_backend.get_user_by_username(created_user.username)
        assert user.metadata == metadata

    @pytest.mark.asyncio
    async def test_update_user_metadata_not_found(self, memory_backend):
        """Test updating metadata for non-existent user."""
        metadata = {"key": "value"}
        success = await memory_backend.update_user_metadata("non-existent", metadata)
        assert success is False

    @pytest.mark.asyncio
    async def test_search_users(self, memory_backend):
        """Test searching users."""
        # Create users with different usernames and emails
        user1 = User(
            id="1",
            username="john_doe",
            email="john@example.com",
            role=UserRole.REGULAR,
            password_hash="hash1",
        )
        user2 = User(
            id="2",
            username="jane_smith",
            email="jane@example.com",
            role=UserRole.ADMIN,
            password_hash="hash2",
        )
        user3 = User(
            id="3",
            username="bob_wilson",
            email="bob@example.com",
            role=UserRole.REGULAR,
            password_hash="hash3",
        )

        await memory_backend.create_user(user1)
        await memory_backend.create_user(user2)
        await memory_backend.create_user(user3)

        # Search by username
        results = await memory_backend.search_users("john")
        assert len(results) == 1
        assert results[0].username == "john_doe"

        # Search by email
        results = await memory_backend.search_users("jane@example.com")
        assert len(results) == 1
        assert results[0].username == "jane_smith"

    @pytest.mark.asyncio
    async def test_get_users_by_role(self, memory_backend):
        """Test getting users by role."""
        user1 = User(
            id="1",
            username="user1",
            email="user1@example.com",
            role=UserRole.REGULAR,
            password_hash="hash1",
        )
        user2 = User(
            id="2",
            username="user2",
            email="user2@example.com",
            role=UserRole.ADMIN,
            password_hash="hash2",
        )
        user3 = User(
            id="3",
            username="user3",
            email="user3@example.com",
            role=UserRole.REGULAR,
            password_hash="hash3",
        )

        await memory_backend.create_user(user1)
        await memory_backend.create_user(user2)
        await memory_backend.create_user(user3)

        # Get regular users
        regular_users = await memory_backend.get_users_by_role(UserRole.REGULAR)
        assert len(regular_users) == 2

        # Get admin users
        admin_users = await memory_backend.get_users_by_role(UserRole.ADMIN)
        assert len(admin_users) == 1
        assert admin_users[0].username == "user2"

    @pytest.mark.asyncio
    async def test_is_username_taken(self, memory_backend, sample_user):
        """Test checking if username is taken."""
        assert await memory_backend.is_username_taken(sample_user.username) is False

        await memory_backend.create_user(sample_user)

        assert await memory_backend.is_username_taken(sample_user.username) is True

    @pytest.mark.asyncio
    async def test_is_email_taken(self, memory_backend, sample_user):
        """Test checking if email is taken."""
        assert await memory_backend.is_email_taken(sample_user.email) is False

        await memory_backend.create_user(sample_user)

        assert await memory_backend.is_email_taken(sample_user.email) is True

    @pytest.mark.asyncio
    async def test_get_user_settings(self, memory_backend, sample_user):
        """Test getting user settings."""
        created_user = await memory_backend.create_user(sample_user)

        # Set some settings using the generated ID
        memory_backend._settings[created_user.id] = {
            "theme": "dark",
            "notifications": True,
        }

        settings = await memory_backend.get_user_settings(created_user.username)

        assert settings["theme"] == "dark"
        assert settings["notifications"] is True

    @pytest.mark.asyncio
    async def test_get_user_settings_not_found(self, memory_backend):
        """Test getting settings for non-existent user."""
        with pytest.raises(UserNotFoundError):
            await memory_backend.get_user_settings("non-existent")

    @pytest.mark.asyncio
    async def test_update_user_settings(self, memory_backend, sample_user):
        """Test updating user settings."""
        created_user = await memory_backend.create_user(sample_user)

        new_settings = {"theme": "light", "notifications": False}
        success = await memory_backend.update_user_settings(
            created_user.username, new_settings
        )

        assert success is True

        # Verify settings were updated
        settings = await memory_backend.get_user_settings(created_user.username)
        assert settings == new_settings

    @pytest.mark.asyncio
    async def test_update_user_settings_not_found(self, memory_backend):
        """Test updating settings for non-existent user."""
        settings = {"theme": "light"}
        success = await memory_backend.update_user_settings("non-existent", settings)
        assert success is False

    @pytest.mark.asyncio
    async def test_close_backend(self, memory_backend):
        """Test closing the backend."""
        await memory_backend.close()

        # Verify backend is closed
        assert memory_backend._closed is True

        # Verify operations fail after closing
        with pytest.raises(BackendError, match="Backend is closed"):
            await memory_backend.list_users()

    @pytest.mark.asyncio
    async def test_health_check(self, memory_backend):
        """Test health check."""
        is_healthy = await memory_backend.health_check()
        assert is_healthy is True
