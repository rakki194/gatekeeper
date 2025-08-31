"""
Password management for the Gatekeeper authentication library.

This module provides a centralized interface for password hashing operations,
supporting modern Argon2 hashing with optimal security parameters and
migration from legacy bcrypt hashes.
"""

import logging
import re
import os
import secrets
from typing import Optional, Tuple, Dict, Any
from enum import Enum

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerificationError
except ImportError:
    raise ImportError(
        "argon2-cffi is required for password hashing. "
        "Install with: pip install argon2-cffi"
    )

try:
    import bcrypt
except ImportError:
    bcrypt = None

logger = logging.getLogger(__name__)


class Argon2Variant(Enum):
    """Argon2 variants available for password hashing."""

    ARGON2ID = "argon2id"  # Recommended for password hashing
    ARGON2I = "argon2i"  # Data-independent memory access
    ARGON2D = "argon2d"  # Data-dependent memory access


class SecurityLevel(Enum):
    """Predefined security levels for Argon2 parameters."""

    LOW = "low"  # For development/testing
    MEDIUM = "medium"  # For general use
    HIGH = "high"  # For high-security applications
    PARANOID = "paranoid"  # For maximum security


# Security parameter presets based on OWASP recommendations and modern best practices
SECURITY_PARAMS = {
    SecurityLevel.LOW: {
        "time_cost": 2,
        "memory_cost": 2**16,  # 64 MiB
        "parallelism": 1,
        "hash_len": 32,
        "salt_len": 16,
    },
    SecurityLevel.MEDIUM: {
        "time_cost": 3,
        "memory_cost": 2**17,  # 128 MiB
        "parallelism": 2,
        "hash_len": 32,
        "salt_len": 16,
    },
    SecurityLevel.HIGH: {
        "time_cost": 4,
        "memory_cost": 2**18,  # 256 MiB
        "parallelism": 4,
        "hash_len": 32,
        "salt_len": 16,
    },
    SecurityLevel.PARANOID: {
        "time_cost": 6,
        "memory_cost": 2**19,  # 512 MiB
        "parallelism": 8,
        "hash_len": 32,
        "salt_len": 16,
    },
}


class PasswordManager:
    """
    Password management class for secure password operations.
    
    Provides methods for hashing, verifying, and validating passwords using
    modern cryptographic algorithms with automatic migration from legacy formats.
    """

    def __init__(self, security_level: SecurityLevel = SecurityLevel.MEDIUM):
        """
        Initialize the password manager.
        
        Args:
            security_level: The security level to use for password hashing
        """
        self.security_level = security_level
        self._password_hasher: Optional[PasswordHasher] = None

    def get_security_level(self) -> SecurityLevel:
        """
        Get the current security level.

        Returns:
            SecurityLevel: The configured security level
        """
        return self.security_level

    def get_argon2_params(self) -> Dict[str, Any]:
        """
        Get Argon2 parameters based on the current security level.

        Returns:
            Dict[str, Any]: Argon2 parameters dictionary
        """
        return SECURITY_PARAMS[self.security_level].copy()

    def get_password_hasher(self) -> PasswordHasher:
        """
        Get the password hasher instance.

        Creates a password hasher with optimal Argon2 parameters based on
        the configured security level.

        Returns:
            PasswordHasher: Configured password hasher instance
        """
        if self._password_hasher is None:
            params = self.get_argon2_params()

            self._password_hasher = PasswordHasher(
                time_cost=params["time_cost"],
                memory_cost=params["memory_cost"],
                parallelism=params["parallelism"],
                hash_len=params["hash_len"],
                salt_len=params["salt_len"],
            )

            logger.info(
                f"Initialized Argon2 password hasher with {self.security_level.value} "
                f"security level (t={params['time_cost']}, m={params['memory_cost']}, "
                f"p={params['parallelism']})"
            )

        return self._password_hasher

    def hash_password(self, password: str) -> str:
        """
        Hash a password using Argon2 with optimal security parameters.

        Args:
            password: Plain text password to hash

        Returns:
            str: Hashed password string

        Raises:
            ValueError: If password is empty
        """
        if not password:
            raise ValueError("Password cannot be empty")

        password_hasher = self.get_password_hasher()
        return password_hasher.hash(password)

    def verify_password(self, password: str, hashed_password: str) -> bool:
        """
        Verify a password against a hash.

        Supports Argon2 hashes and legacy bcrypt hashes for backward compatibility.

        Args:
            password: Plain text password to verify
            hashed_password: Stored password hash

        Returns:
            bool: True if password matches, False otherwise
        """
        if not password or not hashed_password:
            return False

        # Try Argon2 first (modern hashes)
        if self.is_argon2_hash(hashed_password):
            try:
                password_hasher = self.get_password_hasher()
                password_hasher.verify(hashed_password, password)
                return True
            except VerificationError:
                return False
            except Exception as e:
                logger.warning(f"Error verifying Argon2 hash: {e}")
                return False

        # Try bcrypt (legacy hashes)
        elif self.is_bcrypt_hash(hashed_password):
            if bcrypt is None:
                logger.warning("bcrypt not available, cannot verify legacy hash")
                return False

            try:
                return bcrypt.checkpw(
                    password.encode("utf-8"), hashed_password.encode("utf-8")
                )
            except Exception as e:
                logger.warning(f"Error verifying bcrypt hash: {e}")
                return False

        # Unknown hash format
        else:
            logger.warning(f"Unknown hash format encountered: {hashed_password[:20]}...")
            return False

    def verify_and_update_password(
        self, password: str, hashed_password: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify a password and return updated hash if needed.

        This method will:
        1. Verify the password against the current hash
        2. Return a new hash if the current hash is using an outdated algorithm
           or parameters (e.g., bcrypt instead of Argon2, or old Argon2 parameters)

        Args:
            password: Plain text password to verify
            hashed_password: Stored password hash

        Returns:
            Tuple[bool, Optional[str]]: (is_valid, new_hash_if_needed)
        """
        if not password or not hashed_password:
            return False, None

        # Try Argon2 first
        if self.is_argon2_hash(hashed_password):
            try:
                password_hasher = self.get_password_hasher()
                password_hasher.verify(hashed_password, password)

                # Check if hash needs updating (different parameters)
                if self._needs_argon2_update(hashed_password):
                    new_hash = password_hasher.hash(password)
                    logger.info("Argon2 hash updated to current parameters")
                    return True, new_hash

                return True, None

            except VerificationError:
                return False, None
            except Exception as e:
                logger.warning(f"Error verifying Argon2 hash: {e}")
                return False, None

        # Try bcrypt (legacy hashes)
        elif self.is_bcrypt_hash(hashed_password):
            if bcrypt is None:
                logger.warning("bcrypt not available, cannot verify legacy hash")
                return False, None

            try:
                if bcrypt.checkpw(
                    password.encode("utf-8"), hashed_password.encode("utf-8")
                ):
                    # Migrate to Argon2
                    new_hash = self.hash_password(password)
                    logger.info("Migrated bcrypt hash to Argon2")
                    return True, new_hash
                return False, None
            except Exception as e:
                logger.warning(f"Error verifying bcrypt hash: {e}")
                return False, None

        # Unknown hash format
        else:
            logger.warning(f"Unknown hash format encountered: {hashed_password[:20]}...")
            return False, None

    def _needs_argon2_update(self, hashed_password: str) -> bool:
        """
        Check if an Argon2 hash needs updating due to parameter changes.

        Args:
            hashed_password: Argon2 hash to check

        Returns:
            bool: True if hash should be updated
        """
        try:
            # Parse the hash to extract parameters
            parts = hashed_password.split("$")
            if len(parts) < 5:
                return True

            # Extract parameters from hash
            variant = parts[1]
            version = parts[2]
            params_str = parts[3]

            # Parse memory, time, and parallelism from params
            param_parts = params_str.split(",")
            if len(param_parts) != 3:
                return True

            try:
                memory_cost = int(param_parts[0].split("=")[1])
                time_cost = int(param_parts[1].split("=")[1])
                parallelism = int(param_parts[2].split("=")[1])
            except (ValueError, IndexError):
                return True

            # Get current recommended parameters
            current_params = self.get_argon2_params()

            # Check if any parameters need updating
            if (
                memory_cost != current_params["memory_cost"]
                or time_cost != current_params["time_cost"]
                or parallelism != current_params["parallelism"]
            ):
                return True

            return False

        except Exception as e:
            logger.warning(f"Error parsing Argon2 hash parameters: {e}")
            return True

    def is_bcrypt_hash(self, hashed_password: str) -> bool:
        """
        Check if a hash is in bcrypt format.

        Args:
            hashed_password: Password hash to check

        Returns:
            bool: True if the hash is in bcrypt format
        """
        # bcrypt hash pattern: $2a$ or $2b$ followed by rounds and salt/hash
        bcrypt_pattern = r"^\$2[abxy]\$\d{2}\$[A-Za-z0-9+/.]{22}[A-Za-z0-9+/.]{31}$"
        return bool(re.match(bcrypt_pattern, hashed_password))

    def is_argon2_hash(self, hashed_password: str) -> bool:
        """
        Check if a hash is in Argon2 format.

        Args:
            hashed_password: Password hash to check

        Returns:
            bool: True if the hash is in Argon2 format
        """
        return hashed_password.startswith("$argon2")

    def get_hash_algorithm(self, hashed_password: str) -> str:
        """
        Determine the algorithm used for a password hash.

        Args:
            hashed_password: Password hash to analyze

        Returns:
            str: Algorithm name ('argon2', 'bcrypt', or 'unknown')
        """
        if self.is_argon2_hash(hashed_password):
            return "argon2"
        elif self.is_bcrypt_hash(hashed_password):
            return "bcrypt"
        else:
            return "unknown"

    def get_hash_variant(self, hashed_password: str) -> Optional[str]:
        """
        Get the specific Argon2 variant used in a hash.

        Args:
            hashed_password: Argon2 hash to analyze

        Returns:
            Optional[str]: Variant name ('argon2id', 'argon2i', 'argon2d') or None
        """
        if not self.is_argon2_hash(hashed_password):
            return None

        try:
            parts = hashed_password.split("$")
            if len(parts) >= 2:
                return parts[1]
        except Exception:
            pass

        return None

    def generate_secure_salt(self, length: int = 16) -> bytes:
        """
        Generate a cryptographically secure salt.

        Args:
            length: Length of the salt in bytes

        Returns:
            bytes: Random salt
        """
        return secrets.token_bytes(length)

    def benchmark_hash_time(self, password: str, iterations: int = 10) -> Dict[str, float]:
        """
        Benchmark hash performance for different security levels.

        Args:
            password: Password to hash for benchmarking
            iterations: Number of iterations to run

        Returns:
            Dict[str, float]: Average time per hash for each security level
        """
        results = {}

        for level in SecurityLevel:
            params = SECURITY_PARAMS[level]
            hasher = PasswordHasher(
                time_cost=params["time_cost"],
                memory_cost=params["memory_cost"],
                parallelism=params["parallelism"],
                hash_len=params["hash_len"],
                salt_len=params["salt_len"],
            )

            import time

            start_time = time.time()

            for _ in range(iterations):
                hasher.hash(password)

            end_time = time.time()
            avg_time = (end_time - start_time) / iterations
            results[level.value] = avg_time

        return results

    def validate_password_strength(self, password: str) -> Tuple[bool, str]:
        """
        Validate password strength according to modern security standards.

        Args:
            password: Password to validate

        Returns:
            Tuple[bool, str]: (is_strong, reason)
        """
        if not password:
            return False, "Password cannot be empty"

        if len(password) < 8:
            return False, "Password must be at least 8 characters long"

        if len(password) > 128:
            return False, "Password must be no more than 128 characters long"

        # Check for common weak patterns
        common_passwords = {
            "password",
            "123456",
            "123456789",
            "qwerty",
            "abc123",
            "password123",
            "admin",
            "letmein",
            "welcome",
            "monkey",
        }

        if password.lower() in common_passwords:
            return False, "Password is too common"

        # Check character diversity
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

        if not (has_lower and has_upper and has_digit):
            return (
                False,
                "Password must contain lowercase, uppercase, and numeric characters",
            )

        return True, "Password meets strength requirements"

    def get_hash_info(self, hashed_password: str) -> Dict[str, Any]:
        """
        Get detailed information about a password hash.

        Args:
            hashed_password: Password hash to analyze

        Returns:
            Dict[str, Any]: Hash information including algorithm, parameters, etc.
        """
        info = {
            "algorithm": self.get_hash_algorithm(hashed_password),
            "variant": None,
            "parameters": {},
            "needs_update": False,
        }

        if info["algorithm"] == "argon2":
            info["variant"] = self.get_hash_variant(hashed_password)
            info["needs_update"] = self._needs_argon2_update(hashed_password)

            # Parse Argon2 parameters
            try:
                parts = hashed_password.split("$")
                if len(parts) >= 5:
                    params_str = parts[3]
                    param_parts = params_str.split(",")
                    if len(param_parts) == 3:
                        info["parameters"] = {
                            "memory_cost": int(param_parts[0].split("=")[1]),
                            "time_cost": int(param_parts[1].split("=")[1]),
                            "parallelism": int(param_parts[2].split("=")[1]),
                        }
            except Exception:
                pass

        elif info["algorithm"] == "bcrypt":
            # Parse bcrypt parameters
            try:
                parts = hashed_password.split("$")
                if len(parts) == 4:
                    info["parameters"] = {"rounds": int(parts[2])}
            except Exception:
                pass

        return info
