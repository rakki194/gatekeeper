"""
Tests for API functionality in the Gatekeeper library.

This module tests the FastAPI integration, dependencies, and routes.
"""

import pytest
from fastapi import HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials

from gatekeeper.api.dependencies import (
    get_current_user,
    require_active_user,
    require_role,
    require_admin,
)
from gatekeeper import AuthManager, TokenConfig, UserCreate, UserRole, SecurityLevel
from gatekeeper.backends.memory import MemoryBackend
from gatekeeper.models.user import User


@pytest.fixture
def auth_manager():
    """Create an authentication manager for testing."""
    token_config = TokenConfig(
        secret_key="test-secret-key-for-testing-only-not-for-production",
        access_token_expire_minutes=30,
        refresh_token_expire_days=7,
    )
    backend = MemoryBackend()
    return AuthManager(
        backend=backend,
        token_config=token_config,
        password_security_level=SecurityLevel.LOW,
    )


@pytest.fixture
def sample_user():
    """Create a sample user for testing."""
    return User(
        id="test-id",
        username="testuser",
        email="test@example.com",
        role=UserRole.REGULAR,
        is_active=True,
        password_hash="hashed_password",
    )


class TestDependencies:
    """Test the API dependencies."""

    @pytest.mark.asyncio
    async def test_get_current_user_success(self, auth_manager, sample_user):
        """Test getting current user with valid token."""
        # Create user and get token
        user_data = UserCreate(
            username="testuser", password="TestPassword123!", email="test@example.com"
        )
        await auth_manager.create_user(user_data)
        tokens = await auth_manager.authenticate("testuser", "TestPassword123!")

        # Mock credentials
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer", credentials=tokens.access_token
        )

        # Test dependency
        current_user = await get_current_user(credentials, auth_manager)

        assert current_user is not None
        assert current_user.username == "testuser"

    @pytest.mark.asyncio
    async def test_get_current_user_no_auth_manager(self):
        """Test getting current user without auth manager."""
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer", credentials="invalid-token"
        )

        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(credentials, None)

        assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR

    @pytest.mark.asyncio
    async def test_get_current_user_invalid_token(self, auth_manager):
        """Test getting current user with invalid token."""
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer", credentials="invalid-token"
        )

        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(credentials, auth_manager)

        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_require_active_user_active(self, sample_user):
        """Test requiring active user with active user."""
        current_user = await require_active_user(sample_user)
        assert current_user == sample_user

    @pytest.mark.asyncio
    async def test_require_active_user_inactive(self):
        """Test requiring active user with inactive user."""
        inactive_user = User(
            id="test-id",
            username="testuser",
            email="test@example.com",
            role=UserRole.REGULAR,
            is_active=False,
            password_hash="hashed_password",
        )

        with pytest.raises(HTTPException) as exc_info:
            await require_active_user(inactive_user)

        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.asyncio
    async def test_require_role_sufficient(self, sample_user):
        """Test requiring role with sufficient permissions."""
        current_user = await require_role(UserRole.REGULAR, sample_user)
        assert current_user == sample_user

    @pytest.mark.asyncio
    async def test_require_role_insufficient(self, sample_user):
        """Test requiring role with insufficient permissions."""
        with pytest.raises(HTTPException) as exc_info:
            await require_role(UserRole.ADMIN, sample_user)

        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.asyncio
    async def test_require_admin_admin_user(self):
        """Test requiring admin with admin user."""
        admin_user = User(
            id="test-id",
            username="admin",
            email="admin@example.com",
            role=UserRole.ADMIN,
            is_active=True,
            password_hash="hashed_password",
        )

        current_user = await require_admin(admin_user)
        assert current_user == admin_user

    @pytest.mark.asyncio
    async def test_require_admin_regular_user(self, sample_user):
        """Test requiring admin with regular user."""
        with pytest.raises(HTTPException) as exc_info:
            await require_admin(sample_user)

        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN


class TestAPIIntegration:
    """Test API integration scenarios."""

    @pytest.mark.asyncio
    async def test_dependency_chain(self, auth_manager):
        """Test that dependencies work together correctly."""
        # Create user and get token
        user_data = UserCreate(
            username="testuser", password="TestPassword123!", email="test@example.com"
        )
        await auth_manager.create_user(user_data)
        tokens = await auth_manager.authenticate("testuser", "TestPassword123!")

        # Mock credentials
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer", credentials=tokens.access_token
        )

        # Test the full chain
        current_user = await get_current_user(credentials, auth_manager)
        active_user = await require_active_user(current_user)
        role_user = await require_role(UserRole.REGULAR, active_user)

        assert role_user.username == "testuser"
        assert role_user.is_active is True
        assert role_user.role == UserRole.REGULAR
