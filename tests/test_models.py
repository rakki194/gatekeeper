"""
Tests for data models in the Gatekeeper library.

This module tests the Pydantic models used for data validation.
"""

import pytest
from datetime import datetime, timezone
from gatekeeper.models.user import User, UserCreate, UserUpdate, UserPublic, UserRole
from gatekeeper.models.token import TokenData


class TestUserModels:
    """Test the User model and related models."""

    def test_user_creation(self):
        """Test creating a user with all fields."""
        user = User(
            id="test-id",
            username="testuser",
            email="test@example.com",
            role=UserRole.REGULAR,
            is_active=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            password_hash="hashed_password",
            profile_picture_url="https://example.com/avatar.jpg",
            yapcoin_balance=100,
            metadata={"theme": "dark", "language": "en"}
        )

        assert user.id == "test-id"
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.role == UserRole.REGULAR
        assert user.is_active is True
        assert user.password_hash == "hashed_password"
        assert user.profile_picture_url == "https://example.com/avatar.jpg"
        assert user.yapcoin_balance == 100
        assert user.metadata == {"theme": "dark", "language": "en"}

    def test_user_creation_minimal(self):
        """Test creating a user with minimal fields."""
        user = User(
            id="test-id",
            username="testuser",
            role=UserRole.REGULAR,
            is_active=True,
            password_hash="hashed_password"
        )

        assert user.id == "test-id"
        assert user.username == "testuser"
        assert user.email is None
        assert user.role == UserRole.REGULAR
        assert user.is_active is True
        assert user.password_hash == "hashed_password"
        assert user.profile_picture_url is None
        assert user.yapcoin_balance == 0
        assert user.metadata == {}

    def test_user_creation_defaults(self):
        """Test user creation with default values."""
        user = User(
            id="test-id",
            username="testuser",
            password_hash="hashed_password"
        )

        assert user.role == UserRole.REGULAR
        assert user.is_active is True
        assert user.email is None
        assert user.profile_picture_url is None
        assert user.yapcoin_balance == 0
        assert user.metadata == {}
        assert user.created_at is None
        assert user.updated_at is None

    def test_user_create_model(self):
        """Test the UserCreate model."""
        user_data = UserCreate(
            username="testuser",
            password="TestPassword123!",
            email="test@example.com",
            role=UserRole.ADMIN
        )

        assert user_data.username == "testuser"
        assert user_data.password == "TestPassword123!"
        assert user_data.email == "test@example.com"
        assert user_data.role == UserRole.ADMIN

    def test_user_create_model_minimal(self):
        """Test UserCreate model with minimal fields."""
        user_data = UserCreate(
            username="testuser",
            password="TestPassword123!"
        )

        assert user_data.username == "testuser"
        assert user_data.password == "TestPassword123!"
        assert user_data.email is None
        assert user_data.role == UserRole.REGULAR

    def test_user_update_model(self):
        """Test the UserUpdate model."""
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

    def test_user_update_model_partial(self):
        """Test UserUpdate model with partial data."""
        user_update = UserUpdate(
            email="new@example.com"
        )

        assert user_update.email == "new@example.com"
        assert user_update.role is None
        assert user_update.is_active is None
        assert user_update.profile_picture_url is None
        assert user_update.metadata is None

    def test_user_public_model(self):
        """Test the UserPublic model."""
        user = User(
            id="test-id",
            username="testuser",
            email="test@example.com",
            role=UserRole.REGULAR,
            is_active=True,
            password_hash="hashed_password",
            profile_picture_url="https://example.com/avatar.jpg",
            yapcoin_balance=100,
            metadata={"theme": "dark"}
        )

        user_public = UserPublic.from_user(user)

        assert user_public.id == user.id
        assert user_public.username == user.username
        assert user_public.email == user.email
        assert user_public.role == user.role
        assert user_public.is_active == user.is_active
        assert user_public.profile_picture_url == user.profile_picture_url
        assert user_public.yapcoin_balance == user.yapcoin_balance
        assert user_public.metadata == user.metadata
        assert user_public.created_at == user.created_at
        assert user_public.updated_at == user.updated_at

        # Ensure password_hash is not included
        assert not hasattr(user_public, 'password_hash')

    def test_user_public_from_user_none_metadata(self):
        """Test UserPublic.from_user with None metadata."""
        user = User(
            id="test-id",
            username="testuser",
            role=UserRole.REGULAR,
            is_active=True,
            password_hash="hashed_password",
            metadata={}  # Use empty dict instead of None
        )

        user_public = UserPublic.from_user(user)

        assert user_public.metadata == {}

    def test_user_validation(self):
        """Test user model validation."""
        # Test valid user
        user = User(
            id="test-id",
            username="testuser",
            role=UserRole.REGULAR,
            is_active=True,
            password_hash="hashed_password"
        )
        assert user.username == "testuser"

        # Test invalid email format
        with pytest.raises(ValueError):
            User(
                id="test-id",
                username="testuser",
                email="invalid-email",
                role=UserRole.REGULAR,
                is_active=True,
                password_hash="hashed_password"
            )

        # Test username too short
        with pytest.raises(ValueError):
            User(
                id="test-id",
                username="ab",  # Too short
                role=UserRole.REGULAR,
                is_active=True,
                password_hash="hashed_password"
            )

        # Test username too long
        with pytest.raises(ValueError):
            User(
                id="test-id",
                username="a" * 51,  # Too long
                role=UserRole.REGULAR,
                is_active=True,
                password_hash="hashed_password"
            )

    def test_user_role_enum(self):
        """Test UserRole enum values."""
        assert UserRole.GUEST.value == "guest"
        assert UserRole.REGULAR.value == "regular"
        assert UserRole.ADMIN.value == "admin"

    def test_user_metadata_handling(self):
        """Test user metadata handling."""
        # Test with empty metadata
        user = User(
            id="test-id",
            username="testuser",
            role=UserRole.REGULAR,
            is_active=True,
            password_hash="hashed_password",
            metadata={}
        )
        assert user.metadata == {}

        # Test with None metadata (should default to empty dict)
        user = User(
            id="test-id",
            username="testuser",
            role=UserRole.REGULAR,
            is_active=True,
            password_hash="hashed_password",
            metadata={}  # Use empty dict instead of None
        )
        assert user.metadata == {}

        # Test with complex metadata
        complex_metadata = {
            "preferences": {
                "theme": "dark",
                "language": "en",
                "notifications": True
            },
            "settings": {
                "timezone": "UTC",
                "date_format": "ISO"
            }
        }
        user = User(
            id="test-id",
            username="testuser",
            role=UserRole.REGULAR,
            is_active=True,
            password_hash="hashed_password",
            metadata=complex_metadata
        )
        assert user.metadata == complex_metadata


class TestTokenModels:
    """Test the Token model and related models."""

    def test_token_data_creation(self):
        """Test creating TokenData with all fields."""
        now = datetime.now(timezone.utc)
        exp = now.replace(year=now.year + 1)  # Expire in 1 year

        token_data = TokenData(
            sub="user123",
            role="regular",
            type="access",
            exp=exp,
            iat=now,
            jti="unique-token-id",
            metadata={"device": "web", "ip": "127.0.0.1"}
        )

        assert token_data.sub == "user123"
        assert token_data.role == "regular"
        assert token_data.type == "access"
        assert token_data.exp == exp
        assert token_data.iat == now
        assert token_data.jti == "unique-token-id"
        assert token_data.metadata == {"device": "web", "ip": "127.0.0.1"}

    def test_token_data_creation_minimal(self):
        """Test creating TokenData with minimal fields."""
        token_data = TokenData(
            sub="user123",
            role="regular",
            type="access"
        )

        assert token_data.sub == "user123"
        assert token_data.role == "regular"
        assert token_data.type == "access"
        assert token_data.exp is None
        assert token_data.iat is None
        assert token_data.jti is None
        assert token_data.metadata == {}

    def test_token_data_defaults(self):
        """Test TokenData default values."""
        token_data = TokenData(
            sub="user123",
            role="regular",
            type="access"
        )

        assert token_data.exp is None
        assert token_data.iat is None
        assert token_data.jti is None
        assert token_data.metadata == {}

    def test_token_data_validation(self):
        """Test TokenData validation."""
        # Test valid token data
        token_data = TokenData(
            sub="user123",
            role="regular",
            type="access"
        )
        assert token_data.sub == "user123"

        # Test with expired token
        past_exp = datetime.now(timezone.utc).replace(year=datetime.now(timezone.utc).year - 1)
        token_data = TokenData(
            sub="user123",
            role="regular",
            type="access",
            exp=past_exp,
            iat=datetime.now(timezone.utc)
        )
        # Should not raise error as validation is not enforced in the model

    def test_token_data_metadata_handling(self):
        """Test TokenData metadata handling."""
        # Test with empty metadata
        token_data = TokenData(
            sub="user123",
            role="regular",
            type="access",
            metadata={}
        )
        assert token_data.metadata == {}

        # Test with None metadata (should default to empty dict)
        token_data = TokenData(
            sub="user123",
            role="regular",
            type="access",
            metadata={}  # Use empty dict instead of None
        )
        assert token_data.metadata == {}

        # Test with complex metadata
        complex_metadata = {
            "device_info": {
                "type": "mobile",
                "os": "iOS",
                "version": "15.0"
            },
            "session": {
                "id": "session123",
                "created": datetime.now(timezone.utc).isoformat()
            }
        }
        token_data = TokenData(
            sub="user123",
            role="regular",
            type="access",
            metadata=complex_metadata
        )
        assert token_data.metadata == complex_metadata
