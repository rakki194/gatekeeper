"""
Tests for utility modules in the Gatekeeper library.

This module tests the security and validation utilities.
"""

import re

from gatekeeper.utils.security import SecurityUtils
from gatekeeper.utils.validators import PasswordValidator


class TestSecurityUtils:
    """Test the SecurityUtils class."""

    def test_generate_secure_token(self):
        """Test secure token generation."""
        token1 = SecurityUtils.generate_secure_token(32)
        token2 = SecurityUtils.generate_secure_token(64)

        assert len(token1) > 0
        assert len(token2) > len(token1)
        assert token1 != token2  # Should be different each time

    def test_generate_secure_password(self):
        """Test secure password generation."""
        password = SecurityUtils.generate_secure_password(16)

        assert len(password) == 16
        assert re.search(r"[a-z]", password)  # lowercase
        assert re.search(r"[A-Z]", password)  # uppercase
        assert re.search(r"\d", password)  # digit
        assert re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]", password)  # special char

    def test_generate_secure_password_custom_length(self):
        """Test secure password generation with custom length."""
        password = SecurityUtils.generate_secure_password(20)
        assert len(password) == 20

    def test_generate_api_key(self):
        """Test API key generation."""
        key1 = SecurityUtils.generate_api_key()
        key2 = SecurityUtils.generate_api_key("test")

        assert len(key1) > 0
        assert key2.startswith("test_")
        assert key1 != key2

    def test_constant_time_compare(self):
        """Test constant time comparison."""
        # Equal strings
        assert SecurityUtils.constant_time_compare("test", "test") is True
        assert SecurityUtils.constant_time_compare("", "") is True

        # Different strings
        assert SecurityUtils.constant_time_compare("test", "other") is False
        assert SecurityUtils.constant_time_compare("test", "TEST") is False
        assert SecurityUtils.constant_time_compare("", "test") is False


class TestPasswordValidator:
    """Test the PasswordValidator class."""

    def test_validate_password_strength_strong(self):
        """Test strong password validation."""
        is_strong, reason = PasswordValidator.validate_password_strength(
            "StrongPass123!"
        )
        assert is_strong is True
        assert "meets strength requirements" in reason

    def test_validate_password_strength_too_short(self):
        """Test password too short."""
        is_strong, reason = PasswordValidator.validate_password_strength("weak")
        assert is_strong is False
        assert "at least 8 characters" in reason

    def test_validate_password_strength_no_uppercase(self):
        """Test password without uppercase."""
        is_strong, reason = PasswordValidator.validate_password_strength("weakpass123!")
        assert is_strong is False
        assert "uppercase" in reason

    def test_validate_password_strength_no_lowercase(self):
        """Test password without lowercase."""
        is_strong, reason = PasswordValidator.validate_password_strength("WEAKPASS123!")
        assert is_strong is False
        assert "lowercase" in reason

    def test_validate_password_strength_no_digit(self):
        """Test password without digit."""
        is_strong, reason = PasswordValidator.validate_password_strength("WeakPass!")
        assert is_strong is False
        assert "digit" in reason

    def test_validate_password_strength_no_special(self):
        """Test password without special character."""
        is_strong, reason = PasswordValidator.validate_password_strength("WeakPass123")
        assert is_strong is False
        assert "special character" in reason

    def test_validate_email_valid(self):
        """Test valid email validation."""
        is_valid, reason = PasswordValidator.validate_email("test@example.com")
        assert is_valid is True
        assert "valid" in reason

    def test_validate_email_invalid_format(self):
        """Test invalid email format."""
        is_valid, reason = PasswordValidator.validate_email("invalid-email")
        assert is_valid is False
        assert "Invalid email format" in reason

    def test_validate_email_empty(self):
        """Test empty email."""
        is_valid, reason = PasswordValidator.validate_email("")
        assert is_valid is False
        assert "cannot be empty" in reason

    def test_validate_email_none(self):
        """Test None email."""
        is_valid, reason = PasswordValidator.validate_email(None)
        assert is_valid is False
        assert "cannot be empty" in reason

    def test_validate_username_valid(self):
        """Test valid username validation."""
        is_valid, reason = PasswordValidator.validate_username("testuser")
        assert is_valid is True
        assert "valid" in reason

    def test_validate_username_too_short(self):
        """Test username too short."""
        is_valid, reason = PasswordValidator.validate_username("ab")
        assert is_valid is False
        assert "at least 3 characters" in reason

    def test_validate_username_too_long(self):
        """Test username too long."""
        long_username = "a" * 31
        is_valid, reason = PasswordValidator.validate_username(long_username)
        assert is_valid is False
        assert "no more than 30 characters" in reason

    def test_validate_username_invalid_chars(self):
        """Test username with invalid characters."""
        is_valid, reason = PasswordValidator.validate_username("test@user")
        assert is_valid is False
        assert "letters, numbers, underscores, and hyphens" in reason

    def test_validate_username_starts_with_invalid(self):
        """Test username starting with invalid character."""
        is_valid, reason = PasswordValidator.validate_username("_testuser")
        assert is_valid is False
        assert "start with a letter or number" in reason

    def test_validate_username_empty(self):
        """Test empty username."""
        is_valid, reason = PasswordValidator.validate_username("")
        assert is_valid is False
        assert "cannot be empty" in reason

    def test_validate_username_none(self):
        """Test None username."""
        is_valid, reason = PasswordValidator.validate_username(None)
        assert is_valid is False
        assert "cannot be empty" in reason
