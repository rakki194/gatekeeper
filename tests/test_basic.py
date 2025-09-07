"""
Basic tests for the Gatekeeper authentication library.

These tests verify the core functionality of the library.
"""

import asyncio
from datetime import datetime

import pytest

from gatekeeper import (
    AuthManager,
    SecurityLevel,
    TokenConfig,
    UserAlreadyExistsError,
    UserCreate,
    UserNotFoundError,
    UserRole,
)
from gatekeeper.backends.memory import MemoryBackend


@pytest.fixture
def token_config():
    """Create a test token configuration."""
    return TokenConfig(
        secret_key="test-secret-key-for-testing-only-not-for-production",
        access_token_expire_minutes=30,
        refresh_token_expire_days=7,
    )


@pytest.fixture
def auth_manager(token_config):
    """Create an authentication manager for testing."""
    backend = MemoryBackend()
    return AuthManager(
        backend=backend,
        token_config=token_config,
        password_security_level=SecurityLevel.LOW,  # Use low security for faster tests
    )


@pytest.fixture
def sample_user_data():
    """Create sample user data for testing."""
    return UserCreate(
        username="testuser",
        password="TestPassword123!",
        email="test@example.com",
        role=UserRole.REGULAR,
    )


@pytest.mark.asyncio
async def test_create_user(auth_manager, sample_user_data):
    """Test user creation."""
    user = await auth_manager.create_user(sample_user_data)

    assert user.username == "testuser"
    assert user.email == "test@example.com"
    assert user.role == UserRole.REGULAR
    assert user.is_active is True
    assert user.password_hash != "TestPassword123!"  # Password should be hashed


@pytest.mark.asyncio
async def test_create_duplicate_user(auth_manager, sample_user_data):
    """Test that creating a duplicate user raises an error."""
    await auth_manager.create_user(sample_user_data)

    with pytest.raises(UserAlreadyExistsError):
        await auth_manager.create_user(sample_user_data)


@pytest.mark.asyncio
async def test_authenticate_user(auth_manager, sample_user_data):
    """Test user authentication."""
    await auth_manager.create_user(sample_user_data)

    tokens = await auth_manager.authenticate("testuser", "TestPassword123!")

    assert tokens is not None
    assert tokens.access_token is not None
    assert tokens.refresh_token is not None
    assert tokens.token_type == "bearer"


@pytest.mark.asyncio
async def test_authenticate_invalid_credentials(auth_manager, sample_user_data):
    """Test authentication with invalid credentials."""
    await auth_manager.create_user(sample_user_data)

    # Wrong password
    tokens = await auth_manager.authenticate("testuser", "WrongPassword123!")
    assert tokens is None

    # Non-existent user
    tokens = await auth_manager.authenticate("nonexistent", "TestPassword123!")
    assert tokens is None


@pytest.mark.asyncio
async def test_get_current_user(auth_manager, sample_user_data):
    """Test getting current user from token."""
    await auth_manager.create_user(sample_user_data)
    tokens = await auth_manager.authenticate("testuser", "TestPassword123!")

    current_user = await auth_manager.get_current_user(tokens.access_token)

    assert current_user is not None
    assert current_user.username == "testuser"
    assert current_user.role == UserRole.REGULAR


@pytest.mark.asyncio
async def test_get_current_user_invalid_token(auth_manager):
    """Test getting current user with invalid token."""
    current_user = await auth_manager.get_current_user("invalid-token")
    assert current_user is None


@pytest.mark.asyncio
async def test_change_password(auth_manager, sample_user_data):
    """Test password change."""
    await auth_manager.create_user(sample_user_data)

    # Change password
    success = await auth_manager.change_password(
        "testuser", "TestPassword123!", "NewPassword456!"
    )
    assert success is True

    # Verify old password doesn't work
    tokens = await auth_manager.authenticate("testuser", "TestPassword123!")
    assert tokens is None

    # Verify new password works
    tokens = await auth_manager.authenticate("testuser", "NewPassword456!")
    assert tokens is not None


@pytest.mark.asyncio
async def test_change_password_wrong_current_password(auth_manager, sample_user_data):
    """Test password change with wrong current password."""
    await auth_manager.create_user(sample_user_data)

    success = await auth_manager.change_password(
        "testuser", "WrongPassword123!", "NewPassword456!"
    )
    assert success is False


@pytest.mark.asyncio
async def test_list_users(auth_manager, sample_user_data):
    """Test listing users."""
    await auth_manager.create_user(sample_user_data)

    # Create another user
    user2_data = UserCreate(
        username="testuser2",
        password="TestPassword123!",
        email="test2@example.com",
        role=UserRole.ADMIN,
    )
    await auth_manager.create_user(user2_data)

    users = await auth_manager.list_users()

    assert len(users) == 2
    usernames = [user.username for user in users]
    assert "testuser" in usernames
    assert "testuser2" in usernames


@pytest.mark.asyncio
async def test_count_users(auth_manager, sample_user_data):
    """Test counting users."""
    assert await auth_manager.count_users() == 0

    await auth_manager.create_user(sample_user_data)
    assert await auth_manager.count_users() == 1


@pytest.mark.asyncio
async def test_is_username_taken(auth_manager, sample_user_data):
    """Test username availability checking."""
    assert await auth_manager.is_username_taken("testuser") is False

    await auth_manager.create_user(sample_user_data)
    assert await auth_manager.is_username_taken("testuser") is True


@pytest.mark.asyncio
async def test_is_email_taken(auth_manager, sample_user_data):
    """Test email availability checking."""
    assert await auth_manager.is_email_taken("test@example.com") is False

    await auth_manager.create_user(sample_user_data)
    assert await auth_manager.is_email_taken("test@example.com") is True


@pytest.mark.asyncio
async def test_validate_password_strength(auth_manager):
    """Test password strength validation."""
    # Strong password
    is_strong, reason = auth_manager.validate_password_strength("StrongPass123!")
    assert is_strong is True

    # Weak password - too short
    is_strong, reason = auth_manager.validate_password_strength("weak")
    assert is_strong is False
    assert "at least 8 characters" in reason

    # Weak password - no uppercase
    is_strong, reason = auth_manager.validate_password_strength("weakpass123!")
    assert is_strong is False
    assert "uppercase" in reason


@pytest.mark.asyncio
async def test_verify_token(auth_manager, sample_user_data):
    """Test token verification."""
    await auth_manager.create_user(sample_user_data)
    tokens = await auth_manager.authenticate("testuser", "TestPassword123!")

    assert auth_manager.verify_token(tokens.access_token) is True
    assert auth_manager.verify_token("invalid-token") is False


@pytest.mark.asyncio
async def test_health_check(auth_manager):
    """Test health check."""
    assert await auth_manager.health_check() is True


@pytest.mark.asyncio
async def test_close(auth_manager):
    """Test closing the auth manager."""
    await auth_manager.close()
    # Should not raise any exceptions


if __name__ == "__main__":
    # Run tests directly
    asyncio.run(pytest.main([__file__, "-v"]))
