"""
Tests for core functionality in the Gatekeeper library.

This module tests the auth manager, password manager, and token manager.
"""

import pytest
from datetime import datetime, timezone, timedelta
from gatekeeper import AuthManager, TokenConfig, UserCreate, UserRole, SecurityLevel
from gatekeeper.backends.memory import MemoryBackend
from gatekeeper.core.password_manager import PasswordManager
from gatekeeper.core.token_manager import TokenManager
from gatekeeper.models.user import User, UserUpdate
from gatekeeper.models.token import TokenData


@pytest.fixture
def token_config():
    """Create a test token configuration."""
    return TokenConfig(
        secret_key="test-secret-key-for-testing-only-not-for-production",
        access_token_expire_minutes=30,
        refresh_token_expire_days=7
    )


@pytest.fixture
def auth_manager(token_config):
    """Create an authentication manager for testing."""
    backend = MemoryBackend()
    return AuthManager(
        backend=backend,
        token_config=token_config,
        password_security_level=SecurityLevel.LOW
    )


@pytest.fixture
def password_manager():
    """Create a password manager for testing."""
    return PasswordManager(security_level=SecurityLevel.LOW)


@pytest.fixture
def token_manager(token_config):
    """Create a token manager for testing."""
    return TokenManager(token_config)


class TestPasswordManager:
    """Test the PasswordManager class."""
    
    def test_hash_password_argon2(self, password_manager):
        """Test password hashing with Argon2."""
        password = "TestPassword123!"
        hash_result = password_manager.hash_password(password)
        
        assert hash_result.startswith("$argon2")
        assert password_manager.verify_password(password, hash_result) is True
    
    def test_verify_password_wrong_password(self, password_manager):
        """Test password verification with wrong password."""
        password = "TestPassword123!"
        hash_result = password_manager.hash_password(password)
        
        assert password_manager.verify_password("WrongPassword123!", hash_result) is False
    
    def test_validate_password_strength_strong(self, password_manager):
        """Test strong password validation."""
        is_strong, reason = password_manager.validate_password_strength("StrongPass123!")
        assert is_strong is True
        assert "meets strength requirements" in reason
    
    def test_validate_password_strength_weak(self, password_manager):
        """Test weak password validation."""
        is_strong, reason = password_manager.validate_password_strength("weak")
        assert is_strong is False
        assert "at least 8 characters" in reason
    
    def test_validate_password_strength_common_password(self, password_manager):
        """Test common password validation."""
        is_strong, reason = password_manager.validate_password_strength("password123")
        assert is_strong is False
        assert "too common" in reason
    
    def test_get_password_hasher(self, password_manager):
        """Test getting password hasher."""
        argon2_hasher = password_manager.get_password_hasher()
        assert argon2_hasher is not None


class TestTokenManager:
    """Test the TokenManager class."""
    
    def test_create_access_token(self, token_manager):
        """Test creating access token."""
        token_data = TokenData(
            sub="testuser",
            type="access",
            username="testuser",
            role=UserRole.REGULAR,
            exp=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        
        token = token_manager.create_access_token(token_data)
        
        assert token is not None
        assert len(token) > 0
    
    def test_create_refresh_token(self, token_manager):
        """Test creating refresh token."""
        token_data = TokenData(
            sub="testuser",
            type="refresh",
            username="testuser",
            role=UserRole.REGULAR,
            exp=datetime.now(timezone.utc) + timedelta(days=7)
        )
        
        token = token_manager.create_refresh_token(token_data)
        
        assert token is not None
        assert len(token) > 0
    
    def test_verify_token_valid(self, token_manager):
        """Test verifying valid token."""
        token_data = TokenData(
            sub="testuser",
            type="access",
            username="testuser",
            role=UserRole.REGULAR,
            exp=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        
        token = token_manager.create_access_token(token_data)
        result = token_manager.verify_token(token)
        
        assert result.is_valid is True
        assert result.payload is not None
        assert result.payload.username == "testuser"
    
    def test_verify_token_invalid(self, token_manager):
        """Test verifying invalid token."""
        result = token_manager.verify_token("invalid-token")
        
        assert result.is_valid is False
        assert result.error is not None
    
    def test_verify_token_expired(self, token_manager):
        """Test verifying expired token."""
        token_data = TokenData(
            sub="testuser",
            type="access",
            username="testuser",
            role=UserRole.REGULAR,
            exp=datetime.now(timezone.utc) - timedelta(hours=1)  # Expired
        )
        
        token = token_manager.create_access_token(token_data)
        result = token_manager.verify_token(token)
        
        assert result.is_valid is False
        assert result.is_expired is True
    
    def test_refresh_access_token(self, token_manager):
        """Test refreshing access token."""
        token_data = TokenData(
            sub="testuser",
            type="refresh",
            username="testuser",
            role=UserRole.REGULAR,
            exp=datetime.now(timezone.utc) + timedelta(days=7)
        )
        
        refresh_token = token_manager.create_refresh_token(token_data)
        new_token = token_manager.refresh_access_token(refresh_token)
        
        assert new_token is not None
        assert len(new_token) > 0
    
    def test_refresh_access_token_invalid(self, token_manager):
        """Test refreshing invalid token."""
        new_token = token_manager.refresh_access_token("invalid-refresh-token")
        assert new_token is None


class TestAuthManager:
    """Test the AuthManager class."""
    
    @pytest.mark.asyncio
    async def test_create_user_success(self, auth_manager):
        """Test successful user creation."""
        user_data = UserCreate(
            username="testuser",
            password="TestPassword123!",
            email="test@example.com",
            role=UserRole.REGULAR
        )
        
        user = await auth_manager.create_user(user_data)
        
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.role == UserRole.REGULAR
        assert user.is_active is True
        assert user.password_hash != "TestPassword123!"  # Should be hashed
    
    @pytest.mark.asyncio
    async def test_create_user_duplicate_username(self, auth_manager):
        """Test creating user with duplicate username."""
        user_data = UserCreate(
            username="testuser",
            password="TestPassword123!",
            email="test@example.com"
        )
        
        await auth_manager.create_user(user_data)
        
        # Try to create another user with same username
        user_data2 = UserCreate(
            username="testuser",
            password="AnotherPassword123!",
            email="test2@example.com"
        )
        
        with pytest.raises(Exception):  # Should raise UserAlreadyExistsError
            await auth_manager.create_user(user_data2)
    
    @pytest.mark.asyncio
    async def test_authenticate_success(self, auth_manager):
        """Test successful authentication."""
        user_data = UserCreate(
            username="testuser",
            password="TestPassword123!",
            email="test@example.com"
        )
        
        await auth_manager.create_user(user_data)
        tokens = await auth_manager.authenticate("testuser", "TestPassword123!")
        
        assert tokens is not None
        assert tokens.access_token is not None
        assert tokens.refresh_token is not None
        assert tokens.token_type == "bearer"
    
    @pytest.mark.asyncio
    async def test_authenticate_wrong_password(self, auth_manager):
        """Test authentication with wrong password."""
        user_data = UserCreate(
            username="testuser",
            password="TestPassword123!",
            email="test@example.com"
        )
        
        await auth_manager.create_user(user_data)
        tokens = await auth_manager.authenticate("testuser", "WrongPassword123!")
        
        assert tokens is None
    
    @pytest.mark.asyncio
    async def test_authenticate_nonexistent_user(self, auth_manager):
        """Test authentication with non-existent user."""
        tokens = await auth_manager.authenticate("nonexistent", "TestPassword123!")
        assert tokens is None
    
    @pytest.mark.asyncio
    async def test_get_current_user_success(self, auth_manager):
        """Test getting current user from valid token."""
        user_data = UserCreate(
            username="testuser",
            password="TestPassword123!",
            email="test@example.com"
        )
        
        await auth_manager.create_user(user_data)
        tokens = await auth_manager.authenticate("testuser", "TestPassword123!")
        
        current_user = await auth_manager.get_current_user(tokens.access_token)
        
        assert current_user is not None
        assert current_user.username == "testuser"
    
    @pytest.mark.asyncio
    async def test_get_current_user_invalid_token(self, auth_manager):
        """Test getting current user from invalid token."""
        current_user = await auth_manager.get_current_user("invalid-token")
        assert current_user is None
    
    @pytest.mark.asyncio
    async def test_change_password_success(self, auth_manager):
        """Test successful password change."""
        user_data = UserCreate(
            username="testuser",
            password="OldPassword123!",
            email="test@example.com"
        )
        
        await auth_manager.create_user(user_data)
        
        success = await auth_manager.change_password(
            "testuser", "OldPassword123!", "NewPassword456!"
        )
        
        assert success is True
        
        # Verify old password doesn't work
        tokens = await auth_manager.authenticate("testuser", "OldPassword123!")
        assert tokens is None
        
        # Verify new password works
        tokens = await auth_manager.authenticate("testuser", "NewPassword456!")
        assert tokens is not None
    
    @pytest.mark.asyncio
    async def test_change_password_wrong_current(self, auth_manager):
        """Test password change with wrong current password."""
        user_data = UserCreate(
            username="testuser",
            password="OldPassword123!",
            email="test@example.com"
        )
        
        await auth_manager.create_user(user_data)
        
        success = await auth_manager.change_password(
            "testuser", "WrongPassword123!", "NewPassword456!"
        )
        
        assert success is False
    
    @pytest.mark.asyncio
    async def test_update_user_success(self, auth_manager):
        """Test successful user update."""
        user_data = UserCreate(
            username="testuser",
            password="TestPassword123!",
            email="test@example.com"
        )
        
        await auth_manager.create_user(user_data)
        
        user_update = UserUpdate(
            email="updated@example.com",
            role=UserRole.ADMIN
        )
        
        updated_user = await auth_manager.update_user("testuser", user_update)
        
        assert updated_user.email == "updated@example.com"
        assert updated_user.role == UserRole.ADMIN
    
    @pytest.mark.asyncio
    async def test_update_user_not_found(self, auth_manager):
        """Test updating non-existent user."""
        user_update = UserUpdate(email="updated@example.com")
        
        # The current implementation logs an error but doesn't raise an exception
        # So we test that it returns None
        result = await auth_manager.update_user("nonexistent", user_update)
        assert result is None
    
    @pytest.mark.asyncio
    async def test_delete_user_success(self, auth_manager):
        """Test successful user deletion."""
        user_data = UserCreate(
            username="testuser",
            password="TestPassword123!",
            email="test@example.com"
        )
        
        await auth_manager.create_user(user_data)
        
        # Verify user exists
        user = await auth_manager.get_user_by_username("testuser")
        assert user is not None
        
        # Delete user
        await auth_manager.delete_user("testuser")
        
        # Verify user is deleted
        user = await auth_manager.get_user_by_username("testuser")
        assert user is None
    
    @pytest.mark.asyncio
    async def test_delete_user_not_found(self, auth_manager):
        """Test deleting non-existent user."""
        # The current implementation doesn't raise an exception for non-existent users
        # So we test that it doesn't raise an exception
        await auth_manager.delete_user("nonexistent")
    
    @pytest.mark.asyncio
    async def test_get_user_by_username_success(self, auth_manager):
        """Test getting user by username."""
        user_data = UserCreate(
            username="testuser",
            password="TestPassword123!",
            email="test@example.com"
        )
        
        await auth_manager.create_user(user_data)
        
        user = await auth_manager.get_user_by_username("testuser")
        
        assert user is not None
        assert user.username == "testuser"
        assert user.email == "test@example.com"
    
    @pytest.mark.asyncio
    async def test_get_user_by_username_not_found(self, auth_manager):
        """Test getting non-existent user by username."""
        user = await auth_manager.get_user_by_username("nonexistent")
        assert user is None
    
    @pytest.mark.asyncio
    async def test_search_users(self, auth_manager):
        """Test searching users."""
        # Create multiple users
        user1 = UserCreate(username="john_doe", password="TestPass123!", email="john@example.com")
        user2 = UserCreate(username="jane_smith", password="TestPass123!", email="jane@example.com")
        
        await auth_manager.create_user(user1)
        await auth_manager.create_user(user2)
        
        # Search by username
        results = await auth_manager.search_users("john")
        assert len(results) == 1
        assert results[0].username == "john_doe"
    
    @pytest.mark.asyncio
    async def test_get_users_by_role(self, auth_manager):
        """Test getting users by role."""
        user1 = UserCreate(username="user1", password="TestPass123!", email="user1@example.com", role=UserRole.REGULAR)
        user2 = UserCreate(username="user2", password="TestPass123!", email="user2@example.com", role=UserRole.ADMIN)
        
        await auth_manager.create_user(user1)
        await auth_manager.create_user(user2)
        
        # Get regular users
        regular_users = await auth_manager.get_users_by_role(UserRole.REGULAR)
        assert len(regular_users) == 1
        assert regular_users[0].username == "user1"
    
    @pytest.mark.asyncio
    async def test_refresh_token_success(self, auth_manager):
        """Test successful token refresh."""
        user_data = UserCreate(
            username="testuser",
            password="TestPassword123!",
            email="test@example.com"
        )
        
        await auth_manager.create_user(user_data)
        tokens = await auth_manager.authenticate("testuser", "TestPassword123!")
        
        new_tokens = await auth_manager.refresh_token(tokens.refresh_token)
        
        assert new_tokens is not None
        assert new_tokens.access_token is not None
        assert new_tokens.access_token != tokens.access_token  # Should be different
    
    @pytest.mark.asyncio
    async def test_refresh_token_invalid(self, auth_manager):
        """Test refreshing invalid token."""
        new_tokens = await auth_manager.refresh_token("invalid-refresh-token")
        assert new_tokens is None
    
    @pytest.mark.asyncio
    async def test_verify_token_valid(self, auth_manager):
        """Test verifying valid token."""
        user_data = UserCreate(
            username="testuser",
            password="TestPassword123!",
            email="test@example.com"
        )
        
        await auth_manager.create_user(user_data)
        tokens = await auth_manager.authenticate("testuser", "TestPassword123!")
        
        is_valid = auth_manager.verify_token(tokens.access_token)
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_verify_token_invalid(self, auth_manager):
        """Test verifying invalid token."""
        is_valid = auth_manager.verify_token("invalid-token")
        assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_validate_password_strength(self, auth_manager):
        """Test password strength validation."""
        is_strong, reason = auth_manager.validate_password_strength("StrongPass123!")
        assert is_strong is True
        
        is_strong, reason = auth_manager.validate_password_strength("weak")
        assert is_strong is False
    
    @pytest.mark.asyncio
    async def test_health_check(self, auth_manager):
        """Test health check."""
        is_healthy = await auth_manager.health_check()
        assert is_healthy is True
    
    @pytest.mark.asyncio
    async def test_close(self, auth_manager):
        """Test closing the auth manager."""
        await auth_manager.close()
        # Should not raise any exceptions
