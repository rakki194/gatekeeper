"""
Tests for model classes in the Gatekeeper library.

This module tests the user and token models.
"""

import pytest
from datetime import datetime, timezone, timedelta
from gatekeeper.models.user import (
    User, UserCreate, UserUpdate, UserPublic, UserLogin, UserPasswordChange, UserRole
)
from gatekeeper.models.token import (
    TokenData, TokenResponse, TokenConfig, TokenRefreshRequest, 
    TokenRefreshResponse, TokenValidationResult
)


class TestUserModels:
    """Test user-related models."""
    
    def test_user_creation(self):
        """Test User model creation."""
        user = User(
            id="test-id",
            username="testuser",
            email="test@example.com",
            role=UserRole.REGULAR,
            is_active=True,
            password_hash="hashed_password"
        )
        
        assert user.id == "test-id"
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.role == UserRole.REGULAR
        assert user.is_active is True
    
    def test_user_create_validation(self):
        """Test UserCreate validation."""
        user_data = UserCreate(
            username="testuser",
            password="TestPass123!",
            email="test@example.com",
            role=UserRole.ADMIN
        )
        
        assert user_data.username == "testuser"
        assert user_data.password == "TestPass123!"
        assert user_data.email == "test@example.com"
        assert user_data.role == UserRole.ADMIN
    
    def test_user_create_invalid_username(self):
        """Test UserCreate with invalid username."""
        with pytest.raises(ValueError):
            UserCreate(
                username="test@user",
                password="TestPass123!",
                email="test@example.com"
            )
    
    def test_user_create_invalid_password(self):
        """Test UserCreate with invalid password."""
        with pytest.raises(ValueError):
            UserCreate(
                username="testuser",
                password="weakpass",
                email="test@example.com"
            )
    
    def test_user_create_invalid_email(self):
        """Test UserCreate with invalid email."""
        with pytest.raises(ValueError):
            UserCreate(
                username="testuser",
                password="TestPass123!",
                email="invalid-email"
            )
    
    def test_user_update(self):
        """Test UserUpdate model."""
        user_update = UserUpdate(
            email="new@example.com",
            role=UserRole.ADMIN,
            is_active=False
        )
        
        assert user_update.email == "new@example.com"
        assert user_update.role == UserRole.ADMIN
        assert user_update.is_active is False
    
    def test_user_public_from_user(self):
        """Test UserPublic.from_user method."""
        user = User(
            id="test-id",
            username="testuser",
            email="test@example.com",
            role=UserRole.REGULAR,
            is_active=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            metadata={"key": "value"},
            password_hash="hashed_password"
        )
        
        user_public = UserPublic.from_user(user)
        
        assert user_public.id == user.id
        assert user_public.username == user.username
        assert user_public.email == user.email
        assert user_public.role == user.role
        assert user_public.is_active == user.is_active
        assert user_public.created_at == user.created_at
        assert user_public.updated_at == user.updated_at
        assert user_public.metadata == user.metadata
    
    def test_user_public_from_user_none_metadata(self):
        """Test UserPublic.from_user with None metadata."""
        user = User(
            id="test-id",
            username="testuser",
            email="test@example.com",
            role=UserRole.REGULAR,
            is_active=True,
            metadata=None,
            password_hash="hashed_password"
        )
        
        user_public = UserPublic.from_user(user)
        assert user_public.metadata == {}
    
    def test_user_login(self):
        """Test UserLogin model."""
        login = UserLogin(username="testuser", password="password123")
        
        assert login.username == "testuser"
        assert login.password == "password123"
    
    def test_user_password_change(self):
        """Test UserPasswordChange model."""
        password_change = UserPasswordChange(
            current_password="oldpass123!",
            new_password="NewPass456!"
        )
        
        assert password_change.current_password == "oldpass123!"
        assert password_change.new_password == "NewPass456!"
    
    def test_user_password_change_invalid_new_password(self):
        """Test UserPasswordChange with invalid new password."""
        with pytest.raises(ValueError):
            UserPasswordChange(
                current_password="oldpass123!",
                new_password="weak"
            )


class TestTokenModels:
    """Test token-related models."""
    
    def test_token_data(self):
        """Test TokenData model."""
        token_data = TokenData(
            sub="testuser",
            type="access",
            username="testuser",
            role=UserRole.REGULAR,
            exp=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        
        assert token_data.username == "testuser"
        assert token_data.role == UserRole.REGULAR
        assert token_data.exp > datetime.now(timezone.utc)
    
    def test_token_response(self):
        """Test TokenResponse model."""
        token_response = TokenResponse(
            access_token="access_token_123",
            refresh_token="refresh_token_456",
            token_type="bearer",
            expires_in=1800,
            refresh_expires_in=604800
        )
        
        assert token_response.access_token == "access_token_123"
        assert token_response.refresh_token == "refresh_token_456"
        assert token_response.token_type == "bearer"
        assert token_response.expires_in == 1800
        assert token_response.refresh_expires_in == 604800
    
    def test_token_config(self):
        """Test TokenConfig model."""
        token_config = TokenConfig(
            secret_key="test-secret-key",
            algorithm="HS256",
            access_token_expire_minutes=30,
            refresh_token_expire_days=7,
            issuer="test-issuer",
            audience="test-audience"
        )
        
        assert token_config.secret_key == "test-secret-key"
        assert token_config.algorithm == "HS256"
        assert token_config.access_token_expire_minutes == 30
        assert token_config.refresh_token_expire_days == 7
        assert token_config.issuer == "test-issuer"
        assert token_config.audience == "test-audience"
    
    def test_token_config_defaults(self):
        """Test TokenConfig with default values."""
        token_config = TokenConfig(secret_key="test-secret-key")
        
        assert token_config.algorithm == "HS256"
        assert token_config.access_token_expire_minutes == 30
        assert token_config.refresh_token_expire_days == 7
        assert token_config.issuer is None
        assert token_config.audience is None
    
    def test_token_config_timedelta_properties(self):
        """Test TokenConfig timedelta properties."""
        token_config = TokenConfig(
            secret_key="test-secret-key",
            access_token_expire_minutes=60,
            refresh_token_expire_days=14
        )
        
        assert token_config.access_token_expire_timedelta == timedelta(minutes=60)
        assert token_config.refresh_token_expire_timedelta == timedelta(days=14)
    
    def test_token_refresh_request(self):
        """Test TokenRefreshRequest model."""
        refresh_request = TokenRefreshRequest(refresh_token="refresh_token_123")
        
        assert refresh_request.refresh_token == "refresh_token_123"
    
    def test_token_refresh_response(self):
        """Test TokenRefreshResponse model."""
        refresh_response = TokenRefreshResponse(
            access_token="new_access_token_123",
            token_type="bearer",
            expires_in=1800
        )
        
        assert refresh_response.access_token == "new_access_token_123"
        assert refresh_response.token_type == "bearer"
        assert refresh_response.expires_in == 1800
    
    def test_token_validation_result(self):
        """Test TokenValidationResult model."""
        token_data = TokenData(
            sub="testuser",
            type="access",
            username="testuser",
            role=UserRole.REGULAR
        )
        
        validation_result = TokenValidationResult(
            is_valid=True,
            payload=token_data,
            error=None,
            is_expired=False,
            is_refresh_token=False
        )
        
        assert validation_result.is_valid is True
        assert validation_result.payload == token_data
        assert validation_result.error is None
        assert validation_result.is_expired is False
        assert validation_result.is_refresh_token is False
    
    def test_token_validation_result_invalid(self):
        """Test TokenValidationResult for invalid token."""
        validation_result = TokenValidationResult(
            is_valid=False,
            payload=None,
            error="Token expired",
            is_expired=True,
            is_refresh_token=False
        )
        
        assert validation_result.is_valid is False
        assert validation_result.payload is None
        assert validation_result.error == "Token expired"
        assert validation_result.is_expired is True
        assert validation_result.is_refresh_token is False
