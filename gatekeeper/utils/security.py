"""
Security utilities for the Gatekeeper library.

This module provides security-related utilities and helper functions.
"""

import secrets
import string
from typing import Optional


class SecurityUtils:
    """Security utilities for authentication and authorization."""
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """
        Generate a cryptographically secure random token.
        
        Args:
            length: Length of the token to generate
            
        Returns:
            A secure random token
        """
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def generate_secure_password(length: int = 16) -> str:
        """
        Generate a cryptographically secure random password.
        
        Args:
            length: Length of the password to generate
            
        Returns:
            A secure random password
        """
        # Define character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Ensure at least one character from each set
        password = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(symbols)
        ]
        
        # Fill the rest with random characters from all sets
        all_chars = lowercase + uppercase + digits + symbols
        for _ in range(length - 4):
            password.append(secrets.choice(all_chars))
        
        # Shuffle the password
        password_list = list(password)
        secrets.SystemRandom().shuffle(password_list)
        
        return ''.join(password_list)
    
    @staticmethod
    def generate_api_key(prefix: Optional[str] = None) -> str:
        """
        Generate a secure API key.
        
        Args:
            prefix: Optional prefix for the API key
            
        Returns:
            A secure API key
        """
        key = secrets.token_urlsafe(32)
        if prefix:
            return f"{prefix}_{key}"
        return key
    
    @staticmethod
    def constant_time_compare(a: str, b: str) -> bool:
        """
        Compare two strings in constant time to prevent timing attacks.
        
        Args:
            a: First string to compare
            b: Second string to compare
            
        Returns:
            True if strings are equal, False otherwise
        """
        return secrets.compare_digest(a, b)
