"""
Tests for edge cases and additional coverage in the Gatekeeper library.

This module tests edge cases and scenarios that might not be covered by the main tests.
"""

import pytest
from datetime import datetime, timezone, timedelta
from gatekeeper import AuthManager, TokenConfig, UserCreate, UserRole, SecurityLevel
from gatekeeper.backends.memory import MemoryBackend
from gatekeeper.core.password_manager import PasswordManager
from gatekeeper.core.token_manager import TokenManager
from gatekeeper.models.user import User, UserUpdate
from gatekeeper.models.token import TokenData
from gatekeeper.utils.security import SecurityUtils
from gatekeeper.utils.validators import PasswordValidator


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


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    def test_password_manager_high_security(self):
        """Test password manager with high security level."""
        pm = PasswordManager(security_level=SecurityLevel.HIGH)
        is_strong, reason = pm.validate_password_strength("WeakPass123!")
        # High security should be more strict
        assert "meets strength requirements" in reason or "too common" in reason
    
    def test_password_manager_medium_security(self):
        """Test password manager with medium security level."""
        pm = PasswordManager(security_level=SecurityLevel.MEDIUM)
        is_strong, reason = pm.validate_password_strength("StrongPass123!")
        assert is_strong is True
    
    def test_password_manager_very_high_security(self):
        """Test password manager with very high security level."""
        pm = PasswordManager(security_level=SecurityLevel.VERY_HIGH)
        is_strong, reason = pm.validate_password_strength("WeakPass123!")
        # Very high security should be very strict
        assert "meets strength requirements" in reason or "too common" in reason
    
    def test_password_manager_unknown_security(self):
        """Test password manager with unknown security level."""
        pm = PasswordManager(security_level="UNKNOWN")
        is_strong, reason = pm.validate_password_strength("StrongPass123!")
        # Should default to LOW security
        assert is_strong is True
    
    def test_password_verification_edge_cases(self, password_manager):
        """Test password verification edge cases."""
        # Test with empty password
        assert password_manager.verify_password("", "some_hash") is False
        
        # Test with None password
        assert password_manager.verify_password(None, "some_hash") is False
        
        # Test with empty hash
        assert password_manager.verify_password("password", "") is False
        
        # Test with None hash
        assert password_manager.verify_password("password", None) is False
    
    def test_password_hash_edge_cases(self, password_manager):
        """Test password hashing edge cases."""
        # Test with empty password
        with pytest.raises(ValueError):
            password_manager.hash_password("")
        
        # Test with None password
        with pytest.raises(ValueError):
            password_manager.hash_password(None)
    
    def test_token_manager_edge_cases(self, token_manager):
        """Test token manager edge cases."""
        # Test with None token data
        with pytest.raises(AttributeError):
            token_manager.create_access_token(None)
        
        # Test with invalid token
        result = token_manager.verify_token("")
        assert result.is_valid is False
        
        result = token_manager.verify_token(None)
        assert result.is_valid is False
    
    @pytest.mark.asyncio
    async def test_auth_manager_edge_cases(self, auth_manager):
        """Test auth manager edge cases."""
        # Test creating user with empty username
        with pytest.raises(ValueError):
            user_data = UserCreate(
                username="",
                password="TestPass123!",
                email="test@example.com"
            )
            await auth_manager.create_user(user_data)
        
        # Test creating user with None username
        with pytest.raises(ValueError):
            user_data = UserCreate(
                username=None,
                password="TestPass123!",
                email="test@example.com"
            )
            await auth_manager.create_user(user_data)
        
        # Test authenticating with empty credentials
        tokens = await auth_manager.authenticate("", "password")
        assert tokens is None
        
        tokens = await auth_manager.authenticate("username", "")
        assert tokens is None
        
        # Test getting current user with empty token
        user = await auth_manager.get_current_user("")
        assert user is None
        
        user = await auth_manager.get_current_user(None)
        assert user is None
    
    def test_security_utils_edge_cases(self):
        """Test security utils edge cases."""
        # Test token generation with zero length
        token = SecurityUtils.generate_secure_token(0)
        assert token == ""
        
        # Test password generation with zero length
        with pytest.raises(ValueError):
            SecurityUtils.generate_secure_password(0)
        
        # Test password generation with negative length
        with pytest.raises(ValueError):
            SecurityUtils.generate_secure_password(-1)
        
        # Test API key generation with empty prefix
        key = SecurityUtils.generate_api_key("")
        assert key.startswith("_")
        
        # Test constant time compare with None values
        assert SecurityUtils.constant_time_compare(None, None) is True
        assert SecurityUtils.constant_time_compare("test", None) is False
        assert SecurityUtils.constant_time_compare(None, "test") is False
    
    def test_validator_edge_cases(self):
        """Test validator edge cases."""
        # Test email validation with None
        is_valid, reason = PasswordValidator.validate_email(None)
        assert is_valid is False
        assert "cannot be empty" in reason
        
        # Test username validation with None
        is_valid, reason = PasswordValidator.validate_username(None)
        assert is_valid is False
        assert "cannot be empty" in reason
        
        # Test password validation with None
        is_valid, reason = PasswordValidator.validate_password_strength(None)
        assert is_valid is False
        assert "cannot be empty" in reason
        
        # Test password validation with empty string
        is_valid, reason = PasswordValidator.validate_password_strength("")
        assert is_valid is False
        assert "at least 8 characters" in reason


class TestBackendEdgeCases:
    """Test backend edge cases."""
    
    @pytest.fixture
    def memory_backend(self):
        """Create a memory backend for testing."""
        return MemoryBackend()
    
    @pytest.mark.asyncio
    async def test_backend_edge_cases(self, memory_backend):
        """Test backend edge cases."""
        # Test creating user with None
        with pytest.raises(AttributeError):
            await memory_backend.create_user(None)
        
        # Test getting user by None ID
        user = await memory_backend.get_user_by_id(None)
        assert user is None
        
        # Test getting user by None username
        user = await memory_backend.get_user_by_username(None)
        assert user is None
        
        # Test updating user with None
        with pytest.raises(AttributeError):
            await memory_backend.update_user(None, UserUpdate())
        
        # Test deleting user with None ID
        result = await memory_backend.delete_user(None)
        assert result is False
        
        # Test updating password with None values
        success = await memory_backend.update_user_password(None, "new_hash")
        assert success is False
        
        success = await memory_backend.update_user_password("username", None)
        assert success is False
        
        # Test updating role with None values
        success = await memory_backend.update_user_role(None, UserRole.ADMIN)
        assert success is False
        
        # Test updating profile picture with None values
        success = await memory_backend.update_user_profile_picture(None, "url")
        assert success is False
        
        success = await memory_backend.update_user_profile_picture("username", None)
        assert success is False
        
        # Test updating metadata with None values
        success = await memory_backend.update_user_metadata(None, {"key": "value"})
        assert success is False
        
        success = await memory_backend.update_user_metadata("username", None)
        assert success is False
        
        # Test checking username taken with None
        is_taken = await memory_backend.is_username_taken(None)
        assert is_taken is False
        
        # Test checking email taken with None
        is_taken = await memory_backend.is_email_taken(None)
        assert is_taken is False
        
        # Test search users with None
        results = await memory_backend.search_users(None)
        assert results == []
        
        # Test get users by role with None
        results = await memory_backend.get_users_by_role(None)
        assert results == []
        
        # Test list users with negative values
        results = await memory_backend.list_users(skip=-1, limit=-1)
        assert results == []
        
        # Test update user settings with None values
        success = await memory_backend.update_user_settings(None, {"key": "value"})
        assert success is False
        
        success = await memory_backend.update_user_settings("username", None)
        assert success is False
    
    @pytest.mark.asyncio
    async def test_backend_closed_operations(self, memory_backend):
        """Test operations on closed backend."""
        await memory_backend.close()
        
        # All operations should fail
        with pytest.raises(Exception):
            await memory_backend.list_users()
        
        with pytest.raises(Exception):
            await memory_backend.count_users()
        
        with pytest.raises(Exception):
            await memory_backend.create_user(User(
                id="test",
                username="test",
                email="test@example.com",
                role=UserRole.REGULAR,
                password_hash="hash"
            ))
        
        with pytest.raises(Exception):
            await memory_backend.get_user_by_id("test")
        
        with pytest.raises(Exception):
            await memory_backend.get_user_by_username("test")
        
        with pytest.raises(Exception):
            await memory_backend.update_user("test", UserUpdate())
        
        with pytest.raises(Exception):
            await memory_backend.delete_user("test")
        
        with pytest.raises(Exception):
            await memory_backend.update_user_password("test", "hash")
        
        with pytest.raises(Exception):
            await memory_backend.update_user_role("test", UserRole.ADMIN)
        
        with pytest.raises(Exception):
            await memory_backend.update_user_profile_picture("test", "url")
        
        with pytest.raises(Exception):
            await memory_backend.update_user_metadata("test", {"key": "value"})
        
        with pytest.raises(Exception):
            await memory_backend.search_users("test")
        
        with pytest.raises(Exception):
            await memory_backend.get_users_by_role(UserRole.REGULAR)
        
        with pytest.raises(Exception):
            await memory_backend.is_username_taken("test")
        
        with pytest.raises(Exception):
            await memory_backend.is_email_taken("test")
        
        with pytest.raises(Exception):
            await memory_backend.get_user_settings("test")
        
        with pytest.raises(Exception):
            await memory_backend.update_user_settings("test", {"key": "value"})
        
        with pytest.raises(Exception):
            await memory_backend.health_check()


class TestModelEdgeCases:
    """Test model edge cases."""
    
    def test_user_model_edge_cases(self):
        """Test user model edge cases."""
        # Test user with minimal required fields
        user = User(
            username="testuser",
            password_hash="hash"
        )
        assert user.username == "testuser"
        assert user.password_hash == "hash"
        assert user.role == UserRole.REGULAR  # Default value
        assert user.is_active is True  # Default value
        
        # Test user with all fields
        user = User(
            id="test-id",
            username="testuser",
            email="test@example.com",
            role=UserRole.ADMIN,
            is_active=False,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            password_hash="hash",
            profile_picture_url="https://example.com/avatar.jpg",
            yapcoin_balance=100,
            metadata={"key": "value"}
        )
        assert user.id == "test-id"
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.role == UserRole.ADMIN
        assert user.is_active is False
        assert user.password_hash == "hash"
        assert user.profile_picture_url == "https://example.com/avatar.jpg"
        assert user.yapcoin_balance == 100
        assert user.metadata == {"key": "value"}
    
    def test_token_model_edge_cases(self):
        """Test token model edge cases."""
        # Test token data with minimal fields
        token_data = TokenData(
            sub="testuser",
            type="access"
        )
        assert token_data.sub == "testuser"
        assert token_data.type == "access"
        
        # Test token data with all fields
        exp = datetime.now(timezone.utc) + timedelta(hours=1)
        iat = datetime.now(timezone.utc)
        token_data = TokenData(
            sub="testuser",
            type="access",
            exp=exp,
            iat=iat,
            jti="unique-id",
            metadata={"key": "value"}
        )
        assert token_data.sub == "testuser"
        assert token_data.type == "access"
        assert token_data.exp == exp
        assert token_data.iat == iat
        assert token_data.jti == "unique-id"
        assert token_data.metadata == {"key": "value"}
    
    def test_user_create_edge_cases(self):
        """Test user create model edge cases."""
        # Test with minimal required fields
        user_create = UserCreate(
            username="testuser",
            password="TestPass123!"
        )
        assert user_create.username == "testuser"
        assert user_create.password == "TestPass123!"
        assert user_create.role == UserRole.REGULAR  # Default value
        
        # Test with all fields
        user_create = UserCreate(
            username="testuser",
            password="TestPass123!",
            email="test@example.com",
            role=UserRole.ADMIN
        )
        assert user_create.username == "testuser"
        assert user_create.password == "TestPass123!"
        assert user_create.email == "test@example.com"
        assert user_create.role == UserRole.ADMIN
    
    def test_user_update_edge_cases(self):
        """Test user update model edge cases."""
        # Test with no fields (all optional)
        user_update = UserUpdate()
        assert user_update.email is None
        assert user_update.role is None
        assert user_update.is_active is None
        assert user_update.profile_picture_url is None
        assert user_update.metadata is None
        
        # Test with all fields
        user_update = UserUpdate(
            email="new@example.com",
            role=UserRole.ADMIN,
            is_active=False,
            profile_picture_url="https://example.com/new-avatar.jpg",
            metadata={"new_key": "new_value"}
        )
        assert user_update.email == "new@example.com"
        assert user_update.role == UserRole.ADMIN
        assert user_update.is_active is False
        assert user_update.profile_picture_url == "https://example.com/new-avatar.jpg"
        assert user_update.metadata == {"new_key": "new_value"}
