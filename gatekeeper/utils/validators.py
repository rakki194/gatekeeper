"""
Validation utilities for the Gatekeeper library.

This module provides validation utilities for passwords, emails, and other data.
"""

import re
from typing import Tuple


class PasswordValidator:
    """Password validation utilities."""
    
    @staticmethod
    def validate_password_strength(password: str) -> Tuple[bool, str]:
        """
        Validate password strength.
        
        Args:
            password: Password to validate
            
        Returns:
            Tuple of (is_strong, reason)
        """
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        
        if not re.search(r'\d', password):
            return False, "Password must contain at least one digit"
        
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
            return False, "Password must contain at least one special character"
        
        return True, "Password meets strength requirements"
    
    @staticmethod
    def validate_email(email: str) -> Tuple[bool, str]:
        """
        Validate email format.
        
        Args:
            email: Email to validate
            
        Returns:
            Tuple of (is_valid, reason)
        """
        if not email:
            return False, "Email cannot be empty"
        
        # Basic email regex pattern
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not re.match(pattern, email):
            return False, "Invalid email format"
        
        return True, "Email format is valid"
    
    @staticmethod
    def validate_username(username: str) -> Tuple[bool, str]:
        """
        Validate username format.
        
        Args:
            username: Username to validate
            
        Returns:
            Tuple of (is_valid, reason)
        """
        if not username:
            return False, "Username cannot be empty"
        
        if len(username) < 3:
            return False, "Username must be at least 3 characters long"
        
        if len(username) > 30:
            return False, "Username must be no more than 30 characters long"
        
        # Only allow alphanumeric characters, underscores, and hyphens
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            return False, "Username can only contain letters, numbers, underscores, and hyphens"
        
        # Must start with a letter or number
        if not re.match(r'^[a-zA-Z0-9]', username):
            return False, "Username must start with a letter or number"
        
        return True, "Username format is valid"
