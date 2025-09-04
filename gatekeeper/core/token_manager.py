"""
Token management for the Gatekeeper authentication library.

This module provides JWT token creation, validation, and management functionality
for the authentication system.
"""

import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Set
from collections import defaultdict
import time

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
        
        # Token blacklist for revoked tokens
        self._blacklisted_tokens: Set[str] = set()
        
        # Rate limiting tracking
        self._rate_limit_tracker: Dict[str, list] = defaultdict(list)
        self._max_requests_per_minute = 60
        
        # Cleanup old rate limit entries periodically
        self._last_cleanup = time.time()

    def _validate_config(self) -> None:
        """Validate the token configuration."""
        if not self.config.secret_key:
            raise ValueError("Secret key is required for token management")
        
        if self.config.secret_key == "test-secret-key-for-testing-only-not-for-production":
            logger.warning("Using test secret key - not suitable for production")

    def _cleanup_rate_limits(self) -> None:
        """Clean up old rate limit entries."""
        current_time = time.time()
        if current_time - self._last_cleanup > 300:  # Clean up every 5 minutes
            cutoff_time = current_time - 60  # Keep only last minute
            
            for ip_address in list(self._rate_limit_tracker.keys()):
                self._rate_limit_tracker[ip_address] = [
                    timestamp for timestamp in self._rate_limit_tracker[ip_address]
                    if timestamp > cutoff_time
                ]
                
                # Remove empty entries
                if not self._rate_limit_tracker[ip_address]:
                    del self._rate_limit_tracker[ip_address]
            
            self._last_cleanup = current_time

    def check_rate_limit(self, identifier: str) -> bool:
        """
        Check if the request is within rate limits.
        
        Args:
            identifier: IP address or user identifier
            
        Returns:
            bool: True if within limits, False if rate limited
        """
        self._cleanup_rate_limits()
        
        current_time = time.time()
        cutoff_time = current_time - 60  # 1 minute window
        
        # Filter recent requests
        recent_requests = [
            timestamp for timestamp in self._rate_limit_tracker[identifier]
            if timestamp > cutoff_time
        ]
        
        # Check if within limit
        if len(recent_requests) >= self._max_requests_per_minute:
            return False
        
        # Add current request
        self._rate_limit_tracker[identifier].append(current_time)
        return True

    def blacklist_token(self, token: str) -> None:
        """
        Add a token to the blacklist (revoke it).
        
        Args:
            token: The JWT token to blacklist
        """
        self._blacklisted_tokens.add(token)
        logger.info(f"Token blacklisted (length: {len(token)})")

    def is_token_blacklisted(self, token: str) -> bool:
        """
        Check if a token is blacklisted.
        
        Args:
            token: The JWT token to check
            
        Returns:
            bool: True if token is blacklisted
        """
        return token in self._blacklisted_tokens

    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """
        Creates a JWT access token.

        Args:
            data: The data to encode into the token (e.g., {"sub": username, "role": role})
            expires_delta: The timedelta for token expiration

        Returns:
            str: The encoded JWT token
        """
        # Convert TokenData to dict if needed
        if hasattr(data, 'model_dump'):
            to_encode = data.model_dump()
        else:
            to_encode = data.copy()
            
        # Only set expiration if not already provided or if expires_delta is specified
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
            to_encode.update({
                "exp": expire,
                "iat": datetime.now(timezone.utc),
                "type": "access",
                "jti": secrets.token_urlsafe(32)
            })
        elif "exp" not in to_encode:
            # Only set default expiration if not already provided
            expire = datetime.now(timezone.utc) + self.config.access_token_expire_timedelta
            to_encode.update({
                "exp": expire,
                "iat": datetime.now(timezone.utc),
                "type": "access",
                "jti": secrets.token_urlsafe(32)
            })
        else:
            # Keep existing exp, just add other fields
            to_encode.update({
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
        # Convert TokenData to dict if needed
        if hasattr(data, 'model_dump'):
            to_encode = data.model_dump()
        else:
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

    def create_tokens(self, data: Dict[str, Any]) -> TokenResponse:
        """
        Create both access and refresh tokens.
        
        Args:
            data: The data to encode into the tokens
            
        Returns:
            TokenResponse: Object containing both tokens and metadata
        """
        access_token = self.create_access_token(data)
        refresh_token = self.create_refresh_token(data)
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=self.config.access_token_expire_minutes * 60,
            refresh_expires_in=self.config.refresh_token_expire_days * 24 * 60 * 60
        )

    def verify_token(self, token: str, token_type: str = "access") -> TokenValidationResult:
        """
        Verify and decode a JWT token.
        
        Args:
            token: The JWT token to verify
            token_type: Expected token type ("access" or "refresh")
            
        Returns:
            TokenValidationResult: Result of token validation
        """
        try:
            # Check if token is blacklisted
            if self.is_token_blacklisted(token):
                return TokenValidationResult(
                    is_valid=False,
                    error="Token has been revoked",
                    error_code="TOKEN_REVOKED"
                )
            
            # Decode and verify token
            payload = jwt.decode(
                token, 
                self.config.secret_key, 
                algorithms=[self.config.algorithm],
                issuer=self.config.issuer,
                audience=self.config.audience
            )
            
            # Validate token type
            if payload.get("type") != token_type:
                return TokenValidationResult(
                    is_valid=False,
                    error=f"Invalid token type. Expected {token_type}",
                    error_code="INVALID_TOKEN_TYPE"
                )
            
            # Check expiration
            exp = payload.get("exp")
            if exp and datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc):
                return TokenValidationResult(
                    is_valid=False,
                    error="Token has expired",
                    error_code="TOKEN_EXPIRED"
                )
            
            return TokenValidationResult(
                is_valid=True,
                payload=payload,
                token_data=TokenData(
                    sub=payload.get("sub"),
                    role=payload.get("role"),
                    type=payload.get("type"),
                    exp=exp
                )
            )
            
        except JWTError as e:
            error_msg = str(e)
            is_expired = "expired" in error_msg.lower() or "exp" in error_msg.lower()
            return TokenValidationResult(
                is_valid=False,
                error=error_msg,
                error_code="JWT_ERROR",
                is_expired=is_expired
            )
        except Exception as e:
            logger.error(f"Unexpected error during token verification: {e}")
            return TokenValidationResult(
                is_valid=False,
                error="Token verification failed",
                error_code="VERIFICATION_ERROR"
            )

    def refresh_access_token(self, refresh_token: str) -> Optional[str]:
        """
        Create a new access token using a valid refresh token.
        
        Args:
            refresh_token: The refresh token
            
        Returns:
            Optional[str]: New access token if refresh token is valid
        """
        result = self.verify_token(refresh_token, "refresh")
        if not result.is_valid:
            return None
        
        # Create new access token with same user data
        payload = result.payload
        if hasattr(payload, 'sub'):
            # TokenData object
            user_data = {
                "sub": payload.sub,
                "role": payload.role
            }
        else:
            # Dictionary payload
            user_data = {
                "sub": payload.get("sub"),
                "role": payload.get("role")
            }
        
        return self.create_access_token(user_data)

    def get_token_info(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a token without verifying it.
        
        Args:
            token: The JWT token
            
        Returns:
            Optional[Dict[str, Any]]: Token payload if valid format
        """
        try:
            # Decode without verification to get payload
            payload = jwt.decode(
                token, 
                options={"verify_signature": False}
            )
            return payload
        except JWTError:
            return None

    def revoke_user_tokens(self, username: str) -> None:
        """
        Revoke all tokens for a specific user.
        Note: This is a simple implementation. In production, you might want
        to track tokens by user and revoke them individually.
        
        Args:
            username: The username whose tokens should be revoked
        """
        # In a production system, you would track tokens by user
        # and revoke them individually. This is a placeholder.
        logger.info(f"All tokens for user '{username}' marked for revocation")

    def cleanup_expired_blacklist(self) -> None:
        """Clean up expired tokens from blacklist to save memory."""
        current_time = time.time()
        expired_tokens = set()
        
        for token in self._blacklisted_tokens:
            try:
                payload = jwt.decode(
                    token,
                    options={"verify_signature": False}
                )
                exp = payload.get("exp")
                if exp and exp < current_time:
                    expired_tokens.add(token)
            except JWTError:
                # Invalid token format, remove it
                expired_tokens.add(token)
        
        # Remove expired tokens
        self._blacklisted_tokens -= expired_tokens
        if expired_tokens:
            logger.info(f"Cleaned up {len(expired_tokens)} expired blacklisted tokens")

    def get_blacklist_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the token blacklist.
        
        Returns:
            Dict[str, Any]: Statistics about blacklisted tokens
        """
        return {
            "total_blacklisted": len(self._blacklisted_tokens),
            "rate_limit_entries": len(self._rate_limit_tracker),
            "last_cleanup": self._last_cleanup
        }
