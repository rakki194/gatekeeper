"""
Tests for API functionality in the Gatekeeper library.

This module tests the FastAPI integration, dependencies, and routes.
"""

from unittest.mock import patch

import pytest
from fastapi import HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials

from gatekeeper import AuthManager, SecurityLevel, TokenConfig, UserCreate, UserRole
from gatekeeper.api.dependencies import (
    get_current_active_user_sse,
    get_current_user,
    get_current_user_sse,
    require_active_user,
    require_admin,
    require_role,
    set_auth_manager,
)
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
        # Set the auth manager globally
        set_auth_manager(auth_manager)

        # Create user and get token
        user_data = UserCreate(
            username="testuser", password="TestPassword123!", email="test@example.com"
        )
        await auth_manager.create_user(user_data)
        tokens = await auth_manager.authenticate("testuser", "TestPassword123!")

        # Test dependency
        current_user = await get_current_user(tokens.access_token)

        assert current_user is not None
        assert current_user.username == "testuser"

    @pytest.mark.asyncio
    async def test_get_current_user_no_auth_manager(self):
        """Test getting current user without auth manager."""
        # Clear the auth manager
        set_auth_manager(None)

        with pytest.raises(HTTPException) as exc_info:
            await get_current_user("invalid-token")

        assert exc_info.value.status_code == status.HTTP_503_SERVICE_UNAVAILABLE

    @pytest.mark.asyncio
    async def test_get_current_user_invalid_token(self, auth_manager):
        """Test getting current user with invalid token."""
        # Set the auth manager globally
        set_auth_manager(auth_manager)

        with pytest.raises(HTTPException) as exc_info:
            await get_current_user("invalid-token")

        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_require_active_user_active(self, sample_user):
        """Test require_active_user with active user."""
        # Create a dependency function
        require_active_dep = require_active_user()

        # Call the returned function directly with our sample user
        result = await require_active_dep(sample_user)
        assert result == sample_user

    @pytest.mark.asyncio
    async def test_require_active_user_inactive(self):
        """Test require_active_user with inactive user."""
        # Create an inactive user
        inactive_user = User(
            id="test-id",
            username="testuser",
            email="test@example.com",
            role=UserRole.GUEST,
            is_active=True,
            password_hash="hashed_password",
        )

        # Create a dependency function
        require_active_dep = require_active_user()

        # Call the returned function directly with our inactive user
        with pytest.raises(HTTPException) as exc_info:
            await require_active_dep(inactive_user)
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.asyncio
    async def test_require_role_sufficient(self, sample_user):
        """Test require_role with sufficient role."""
        # Create a dependency function
        require_role_dep = require_role(UserRole.REGULAR)

        # Call the returned function directly with our sample user
        result = await require_role_dep(sample_user)
        assert result == sample_user

    @pytest.mark.asyncio
    async def test_require_role_insufficient(self, sample_user):
        """Test require_role with insufficient role."""
        # Create a dependency function
        require_role_dep = require_role(UserRole.ADMIN)

        # Call the returned function directly with our sample user
        with pytest.raises(HTTPException) as exc_info:
            await require_role_dep(sample_user)
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.asyncio
    async def test_require_admin_admin_user(self):
        """Test require_admin with admin user."""
        # Create an admin user
        admin_user = User(
            id="admin-id",
            username="admin",
            email="admin@example.com",
            role=UserRole.ADMIN,
            is_active=True,
            password_hash="hashed_password",
        )

        # Create a dependency function
        require_admin_dep = require_admin()

        # Call the returned function directly with our admin user
        result = await require_admin_dep(admin_user)
        assert result == admin_user

    @pytest.mark.asyncio
    async def test_require_admin_regular_user(self, sample_user):
        """Test require_admin with regular user."""
        # Create a dependency function
        require_admin_dep = require_admin()

        # Call the returned function directly with our sample user
        with pytest.raises(HTTPException) as exc_info:
            await require_admin_dep(sample_user)
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.asyncio
    async def test_dependency_chain(self, auth_manager):
        """Test dependency chain execution."""
        # Set the auth manager globally
        set_auth_manager(auth_manager)

        # Create user and get token
        user_data = UserCreate(
            username="testuser", password="TestPassword123!", email="test@example.com"
        )
        await auth_manager.create_user(user_data)
        tokens = await auth_manager.authenticate("testuser", "TestPassword123!")

        # Test the full dependency chain
        current_user = await get_current_user(tokens.access_token)
        assert current_user is not None

        # Test role requirement
        require_role_dep = require_role(UserRole.REGULAR)
        result = await require_role_dep(current_user)
        assert result == current_user

    @pytest.mark.asyncio
    async def test_get_current_active_user_sse_active(self, auth_manager):
        """Test get_current_active_user_sse with active user."""
        # Set the auth manager globally
        set_auth_manager(auth_manager)

        # Create user and get token
        user_data = UserCreate(
            username="testuser", password="TestPassword123!", email="test@example.com"
        )
        await auth_manager.create_user(user_data)
        tokens = await auth_manager.authenticate("testuser", "TestPassword123!")

        # Mock request with token
        from fastapi import Request

        mock_request = Request(
            scope={
                "type": "http",
                "headers": [],
                "query_string": f"token={tokens.access_token}".encode(),
            }
        )

        # Test the dependency chain: first get the user, then check if active
        current_user = await get_current_user_sse(mock_request)
        assert current_user is not None
        assert current_user.username == "testuser"

        # Now test the active user check
        get_active_user_sse_dep = get_current_active_user_sse()
        # We need to mock the dependency injection for testing
        from unittest.mock import patch

        with patch(
            "gatekeeper.api.dependencies.get_current_user_sse",
            return_value=current_user,
        ):
            result = await get_active_user_sse_dep(mock_request)
            assert result == current_user

    @pytest.mark.asyncio
    async def test_get_current_active_user_sse_guest(self, auth_manager):
        """Test get_current_active_user_sse with guest user."""
        # Set the auth manager globally
        set_auth_manager(auth_manager)

        # Create guest user and get token
        user_data = UserCreate(
            username="guestuser",
            password="TestPassword123!",
            email="guest@example.com",
            role=UserRole.GUEST,
        )
        await auth_manager.create_user(user_data)
        tokens = await auth_manager.authenticate("guestuser", "TestPassword123!")

        # Mock request with token
        from fastapi import Request

        mock_request = Request(
            scope={
                "type": "http",
                "headers": [],
                "query_string": f"token={tokens.access_token}".encode(),
            }
        )

        # Test the dependency chain: first get the user, then check if active
        current_user = await get_current_user_sse(mock_request)
        assert current_user is not None
        assert current_user.username == "guestuser"
        assert current_user.role == UserRole.GUEST

        # Now test the active user check - should fail for guest
        get_active_user_sse_dep = get_current_active_user_sse()
        # We need to mock the dependency injection for testing
        from unittest.mock import patch

        with patch(
            "gatekeeper.api.dependencies.get_current_user_sse",
            return_value=current_user,
        ):
            with pytest.raises(HTTPException) as exc_info:
                await get_active_user_sse_dep(mock_request)
            assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN


class TestAPIIntegration:
    """Test API integration scenarios."""

    @pytest.mark.asyncio
    async def test_dependency_chain(self, auth_manager):
        """Test dependency chain execution."""
        # Set the auth manager globally
        set_auth_manager(auth_manager)

        # Create user and get token
        user_data = UserCreate(
            username="testuser", password="TestPassword123!", email="test@example.com"
        )
        await auth_manager.create_user(user_data)
        tokens = await auth_manager.authenticate("testuser", "TestPassword123!")

        # Test the full dependency chain
        current_user = await get_current_user(tokens.access_token)
        assert current_user is not None

        # Test role requirement
        require_role_dep = require_role(UserRole.REGULAR)
        result = await require_role_dep(current_user)
        assert result == current_user
