"""
Token management for the Gatekeeper authentication library.

This module provides JWT token creation, validation, and management functionality
for the authentication system.
"""

import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

from jose import JWTError, jwt

from ..models.token import TokenData, TokenResponse, TokenValidationResult, TokenConfig

logger = logging.getLogger(__name__)


class TokenManager:
    """
    Token management class for JWT operations.
    
    Provides methods for creating, validating, and managing JWT tokens
    for authentication and authorization.
    """

    def __init__(self, config: TokenConfig):
        """
        Initialize the token manager.
        
        Args:
            config: Token configuration containing secret key and other settings
        """
        self.config = config
        self._validate_config()

    def _validate_config(self) -> None:
        """Validate the token configuration."""
        if not self.config.secret_key:
            raise ValueError("Secret key is required for token management")
        
        if self.config.secret_key == "test-secret-key-for-testing-only-not-for-production":
            logger.warning("Using test secret key - not suitable for production")

    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """
        Creates a JWT access token.

        Args:
            data: The data to encode into the token (e.g., {"sub": username, "role": role})
            expires_delta: The timedelta for token expiration

        Returns:
            str: The encoded JWT token
        """
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + self.config.access_token_expire_timedelta
        
        to_encode.update({
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "type": "access",
            "jti": secrets.token_urlsafe(32)
        })
        
        # Add optional claims
        if self.config.issuer:
            to_encode["iss"] = self.config.issuer
        if self.config.audience:
            to_encode["aud"] = self.config.audience
            
        encoded_jwt = jwt.encode(to_encode, self.config.secret_key, algorithm=self.config.algorithm)
        return encoded_jwt

    def create_refresh_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """
        Creates a JWT refresh token.

        Args:
            data: The data to encode into the token (e.g., {"sub": username, "role": role})
            expires_delta: The timedelta for token expiration

        Returns:
            str: The encoded JWT refresh token
        """
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + self.config.refresh_token_expire_timedelta
        
        to_encode.update({
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "type": "refresh",
            "jti": secrets.token_urlsafe(32)
        })
        
        # Add optional claims
        if self.config.issuer:
            to_encode["iss"] = self.config.issuer
        if self.config.audience:
            to_encode["aud"] = self.config.audience
            
        encoded_jwt = jwt.encode(to_encode, self.config.secret_key, algorithm=self.config.algorithm)
        return encoded_jwt

    def create_token_pair(self, username: str, role: str) -> TokenResponse:
        """
        Create both access and refresh tokens for a user.

        Args:
            username: The username to include in the tokens
            role: The user's role to include in the tokens

        Returns:
            TokenResponse: Object containing both tokens and metadata
        """
        token_data = {"sub": username, "role": role}
        
        access_token = self.create_access_token(token_data)
        refresh_token = self.create_refresh_token(token_data)
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=int(self.config.access_token_expire_timedelta.total_seconds()),
            refresh_expires_in=int(self.config.refresh_token_expire_timedelta.total_seconds())
        )

    def verify_token(self, token: str) -> TokenValidationResult:
        """
        Verifies a JWT token and returns validation result.

        Args:
            token: The JWT token to verify

        Returns:
            TokenValidationResult: Validation result with payload and status
        """
        try:
            # Decode the token
            payload = jwt.decode(
                token, 
                self.config.secret_key, 
                algorithms=[self.config.algorithm],
                issuer=self.config.issuer,
                audience=self.config.audience
            )
            
            # Extract key fields
            username: str = payload.get("sub")
            token_type: str = payload.get("type")
            role: str = payload.get("role")
            
            # Validate required fields (role is not required for reset tokens)
            if not username:
                return TokenValidationResult(
                    is_valid=False,
                    error="Missing required token fields",
                    is_expired=False,
                    is_refresh_token=False
                )
            
            # For non-reset tokens, role is required
            if token_type != "reset" and not role:
                return TokenValidationResult(
                    is_valid=False,
                    error="Missing required token fields",
                    is_expired=False,
                    is_refresh_token=False
                )
            
            # Check token type
            is_refresh_token = token_type == "refresh"
            
            # Create token data object
            token_data = TokenData(
                sub=username,
                role=role or "",  # Default to empty string for reset tokens
                type=token_type or "access",
                exp=datetime.fromtimestamp(payload.get("exp", 0), tz=timezone.utc) if payload.get("exp") else None,
                iat=datetime.fromtimestamp(payload.get("iat", 0), tz=timezone.utc) if payload.get("iat") else None,
                jti=payload.get("jti"),
                metadata={k: v for k, v in payload.items() if k not in ["sub", "role", "type", "exp", "iat", "jti", "iss", "aud"]}
            )
            
            return TokenValidationResult(
                is_valid=True,
                payload=token_data,
                is_expired=False,
                is_refresh_token=is_refresh_token
            )
            
        except JWTError as e:
            logger.error(f"JWTError during token verification: {e}")
            return TokenValidationResult(
                is_valid=False,
                error=f"Invalid token: {str(e)}",
                is_expired=False,
                is_refresh_token=False
            )
        except Exception as e:
            logger.error(f"Unexpected error during token verification: {e}")
            return TokenValidationResult(
                is_valid=False,
                error=f"Token verification failed: {str(e)}",
                is_expired=False,
                is_refresh_token=False
            )

    def verify_access_token(self, token: str) -> TokenValidationResult:
        """
        Verifies a JWT access token specifically.

        Args:
            token: The JWT access token to verify

        Returns:
            TokenValidationResult: Validation result
        """
        result = self.verify_token(token)
        
        if result.is_valid and result.payload and result.payload.type != "access":
            return TokenValidationResult(
                is_valid=False,
                error="Token is not an access token",
                is_expired=False,
                is_refresh_token=False
            )
        
        return result

    def verify_refresh_token(self, token: str) -> TokenValidationResult:
        """
        Verifies a JWT refresh token specifically.

        Args:
            token: The JWT refresh token to verify

        Returns:
            TokenValidationResult: Validation result
        """
        result = self.verify_token(token)
        
        if result.is_valid and result.payload and result.payload.type != "refresh":
            return TokenValidationResult(
                is_valid=False,
                error="Token is not a refresh token",
                is_expired=False,
                is_refresh_token=False
            )
        
        return result

    def refresh_access_token(self, refresh_token: str) -> Optional[str]:
        """
        Create a new access token using a valid refresh token.

        Args:
            refresh_token: The refresh token to use

        Returns:
            Optional[str]: New access token if refresh token is valid, None otherwise
        """
        result = self.verify_refresh_token(refresh_token)
        
        if not result.is_valid or not result.payload:
            return None
        
        # Create new access token with same user data
        token_data = {
            "sub": result.payload.sub,
            "role": result.payload.role
        }
        
        return self.create_access_token(token_data)

    def decode_token_payload(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Decode a JWT token without verification (for debugging/testing).

        Args:
            token: The JWT token to decode

        Returns:
            Optional[Dict[str, Any]]: Decoded payload or None if invalid
        """
        try:
            # Decode without verification
            payload = jwt.decode(token, options={"verify_signature": False})
            return payload
        except JWTError:
            return None

    def get_token_expiration(self, token: str) -> Optional[datetime]:
        """
        Get the expiration time of a token.

        Args:
            token: The JWT token

        Returns:
            Optional[datetime]: Expiration time or None if invalid
        """
        result = self.verify_token(token)
        if result.is_valid and result.payload:
            return result.payload.exp
        return None

    def is_token_expired(self, token: str) -> bool:
        """
        Check if a token is expired.

        Args:
            token: The JWT token

        Returns:
            bool: True if token is expired, False otherwise
        """
        exp_time = self.get_token_expiration(token)
        if exp_time is None:
            return True
        return datetime.now(timezone.utc) > exp_time

    def create_reset_token(self, email: str) -> str:
        """
        Create a password reset token.

        Args:
            email: The email address for the reset token

        Returns:
            str: The encoded JWT reset token
        """
        to_encode = {
            "sub": email,
            "type": "reset",
            "jti": secrets.token_urlsafe(32)
        }
        
        # Reset tokens expire in 24 hours
        expire = datetime.now(timezone.utc) + timedelta(hours=24)
        to_encode.update({
            "exp": expire,
            "iat": datetime.now(timezone.utc)
        })
        
        # Add optional claims
        if self.config.issuer:
            to_encode["iss"] = self.config.issuer
        if self.config.audience:
            to_encode["aud"] = self.config.audience
            
        encoded_jwt = jwt.encode(to_encode, self.config.secret_key, algorithm=self.config.algorithm)
        return encoded_jwt

    def verify_reset_token(self, token: str) -> TokenValidationResult:
        """
        Verifies a JWT reset token specifically.

        Args:
            token: The JWT reset token to verify

        Returns:
            TokenValidationResult: Validation result
        """
        result = self.verify_token(token)
        
        if result.is_valid and result.payload and result.payload.type != "reset":
            return TokenValidationResult(
                is_valid=False,
                error="Token is not a reset token",
                is_expired=False,
                is_refresh_token=False
            )
        
        return result

    def get_token_info(self, token: str) -> Dict[str, Any]:
        """
        Get comprehensive information about a token.

        Args:
            token: The JWT token

        Returns:
            Dict[str, Any]: Token information including validity, type, expiration, etc.
        """
        result = self.verify_token(token)
        
        info = {
            "is_valid": result.is_valid,
            "is_expired": result.is_expired,
            "is_refresh_token": result.is_refresh_token,
            "error": result.error,
        }
        
        if result.payload:
            info.update({
                "username": result.payload.sub,
                "role": result.payload.role,
                "type": result.payload.type,
                "expires_at": result.payload.exp,
                "issued_at": result.payload.iat,
                "jti": result.payload.jti,
                "metadata": result.payload.metadata,
            })
        
        return info
