"""
Authentication manager for the Gatekeeper authentication library.

This module provides the main authentication manager that orchestrates
user authentication, authorization, and management operations.
"""

import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta

from ..models.user import User, UserCreate, UserUpdate, UserPublic, UserLogin, UserPasswordChange
from ..models.token import TokenResponse, TokenConfig
from ..backends.base import UserBackend, BackendError, UserNotFoundError, UserAlreadyExistsError, InvalidCredentialsError
from .password_manager import PasswordManager, SecurityLevel
from .token_manager import TokenManager

logger = logging.getLogger(__name__)


class AuthManager:
    """
    Main authentication manager for the Gatekeeper library.
    
    This class orchestrates all authentication and authorization operations,
    including user management, password handling, and token management.
    """

    def __init__(
        self,
        backend: UserBackend,
        token_config: TokenConfig,
        password_security_level: SecurityLevel = SecurityLevel.MEDIUM
    ):
        """
        Initialize the authentication manager.
        
        Args:
            backend: User data storage backend
            token_config: JWT token configuration
            password_security_level: Security level for password hashing
        """
        self.backend = backend
        self.token_config = token_config
        self.password_manager = PasswordManager(security_level=password_security_level)
        self.token_manager = TokenManager(token_config)

    async def create_user(self, user: UserCreate) -> User:
        """
        Create a new user with hashed password.
        
        Args:
            user: User creation data
            
        Returns:
            User: The created user object
            
        Raises:
            UserAlreadyExistsError: If a user with the same username already exists
            BackendError: For other backend-specific errors
        """
        # Hash the password
        password_hash = self.password_manager.hash_password(user.password)
        
        # Create user in backend
        created_user = await self.backend.create_user(user)
        
        # Update the password hash
        await self.backend.update_user_password(created_user.username, password_hash)
        
        # Return user with hashed password
        created_user.password_hash = password_hash
        
        logger.info(f"Created user '{user.username}' with role '{user.role}'")
        return created_user

    async def authenticate(self, username: str, password: str, client_ip: str = None) -> Optional[TokenResponse]:
        """
        Authenticate a user with username and password.
        
        Args:
            username: The username
            password: The plain text password
            client_ip: Client IP address for rate limiting
            
        Returns:
            Optional[TokenResponse]: Token response if authentication successful, None otherwise
        """
        # Rate limiting check
        if client_ip and not self.token_manager.check_rate_limit(client_ip):
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            return None
        
        # Get user from backend
        user = await self.backend.get_user_by_username(username)
        if not user:
            logger.warning(f"Authentication failed: user '{username}' not found")
            return None

        # Check if user is active
        if not user.is_active:
            logger.warning(f"Authentication failed: user '{username}' is inactive")
            return None

        # Verify password
        is_valid, updated_hash = self.password_manager.verify_and_update_password(
            password, user.password_hash
        )
        
        if not is_valid:
            logger.warning(f"Authentication failed: invalid password for user '{username}'")
            return None
        
        # Update password hash if needed
        if updated_hash:
            await self.backend.update_user_password(username, updated_hash)
            logger.info(f"Password hash updated for user '{username}'")
        
        # Create tokens
        token_data = {
            "sub": user.username,
            "role": user.role.value,
            "permissions": user.permissions or [],
            "user_id": str(user.id)
        }
        
        tokens = self.token_manager.create_tokens(token_data)
        
        # Log successful authentication
        logger.info(f"User '{username}' authenticated successfully")
        
        return tokens

    async def authenticate_by_email(self, email: str, password: str) -> Optional[TokenResponse]:
        """
        Authenticate a user with email and password.
        
        Args:
            email: The email address
            password: The plain text password
            
        Returns:
            Optional[TokenResponse]: Token response if authentication successful, None otherwise
        """
        try:
            # Get user from backend by email
            user = await self.backend.get_user_by_email(email)
            if not user:
                logger.warning(f"Authentication failed: user with email '{email}' not found")
                return None

            # Check if user is active
            if not user.is_active:
                logger.warning(f"Authentication failed: user with email '{email}' is inactive")
                return None

            # Verify password
            is_valid, updated_hash = self.password_manager.verify_and_update_password(
                password, user.password_hash
            )
            
            if not is_valid:
                logger.warning(f"Authentication failed: invalid password for user with email '{email}'")
                return None

            # Update password hash if needed (e.g., migration to new Argon2 parameters)
            if updated_hash:
                await self.backend.update_user_password(user.username, updated_hash)
                logger.info(f"Updated password hash for user '{user.username}'")

            # Create token pair
            tokens = self.token_manager.create_token_pair(user.username, user.role.value)
            
            logger.info(f"User with email '{email}' authenticated successfully")
            return tokens
            
        except Exception as e:
            logger.error(f"Error during email authentication: {e}")
            return None

    async def refresh_tokens(self, refresh_token: str, client_ip: str = None) -> Optional[TokenResponse]:
        """
        Refresh access token using a valid refresh token.
        
        Args:
            refresh_token: The refresh token
            client_ip: Client IP address for rate limiting
            
        Returns:
            Optional[TokenResponse]: New tokens if refresh successful, None otherwise
        """
        # Rate limiting check
        if client_ip and not self.token_manager.check_rate_limit(client_ip):
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            return None
        
        # Verify refresh token
        result = self.token_manager.verify_token(refresh_token, "refresh")
        if not result.is_valid:
            logger.warning("Token refresh failed: invalid refresh token")
            return None
        
        # Get user data from token
        username = result.payload.sub if result.payload else None
        if not username:
            logger.warning("Token refresh failed: missing username in token")
            return None
        
        # Get user from backend to ensure they still exist and are active
        user = await self.backend.get_user_by_username(username)
        if not user or not user.is_active:
            logger.warning(f"Token refresh failed: user '{username}' not found or inactive")
            return None
        
        # Create new tokens
        token_data = {
            "sub": user.username,
            "role": user.role.value,
            "permissions": user.permissions or [],
            "user_id": str(user.id)
        }
        
        tokens = self.token_manager.create_tokens(token_data)
        
        logger.info(f"Tokens refreshed successfully for user '{username}'")
        return tokens

    # Backward-compatible alias for tests
    async def refresh_token(self, refresh_token: str) -> Optional[TokenResponse]:
        """
        Backward-compatible alias for refresh_tokens.
        
        Args:
            refresh_token: The refresh token
            
        Returns:
            Optional[TokenResponse]: New tokens if refresh successful, None otherwise
        """
        return await self.refresh_tokens(refresh_token)

    async def revoke_tokens(self, username: str, token: str = None) -> bool:
        """
        Revoke tokens for a user.
        
        Args:
            username: The username whose tokens should be revoked
            token: Specific token to revoke (if None, revokes all user tokens)
            
        Returns:
            bool: True if tokens were revoked successfully
        """
        if token:
            # Revoke specific token
            self.token_manager.blacklist_token(token)
            logger.info(f"Token revoked for user '{username}'")
        else:
            # Revoke all user tokens
            self.token_manager.revoke_user_tokens(username)
            logger.info(f"All tokens revoked for user '{username}'")
        
        return True

    async def logout(self, token: str) -> bool:
        """
        Logout a user by revoking their token.
        
        Args:
            token: The token to revoke
            
        Returns:
            bool: True if logout successful
        """
        # Get token info to log the logout
        token_info = self.token_manager.get_token_info(token)
        username = token_info.get("sub") if token_info else "unknown"
        
        # Revoke the token
        self.token_manager.blacklist_token(token)
        
        logger.info(f"User '{username}' logged out successfully")
        return True

    async def get_current_user(self, token: str) -> Optional[User]:
        """
        Get the current user from a valid token.
        
        Args:
            token: The JWT token
            
        Returns:
            Optional[User]: The user if token is valid, None otherwise
        """
        # Verify the token
        result = self.token_manager.verify_token(token, "access")
        if not result.is_valid:
            logger.warning("Failed to get current user: invalid token")
            return None
        
        # Extract username from token
        username = result.payload.sub if result.payload else None
        if not username:
            logger.warning("Failed to get current user: missing username in token")
            return None
        
        # Get user from backend
        user = await self.backend.get_user_by_username(username)
        if not user or not user.is_active:
            logger.warning(f"Failed to get current user: user '{username}' not found or inactive")
            return None
        
        return user

    async def validate_token(self, token: str, required_role: str = None) -> bool:
        """
        Validate a token and optionally check role requirements.
        
        Args:
            token: The JWT token to validate
            required_role: Optional role requirement
            
        Returns:
            bool: True if token is valid and meets role requirements
        """
        # Verify the token
        result = self.token_manager.verify_token(token, "access")
        if not result.is_valid:
            return False
        
        # Check role requirement if specified
        if required_role:
            user_role = result.payload.role if result.payload else None
            if user_role != required_role:
                return False
        
        return True

    async def get_token_stats(self) -> Dict[str, Any]:
        """
        Get statistics about token usage and blacklist.
        
        Returns:
            Dict[str, Any]: Token statistics
        """
        return self.token_manager.get_blacklist_stats()

    async def cleanup_expired_tokens(self) -> None:
        """Clean up expired tokens from blacklist."""
        self.token_manager.cleanup_expired_blacklist()

    async def change_password(self, username: str, current_password: str, new_password: str) -> bool:
        """
        Change a user's password.
        
        Args:
            username: The username
            current_password: The current password for verification
            new_password: The new password
            
        Returns:
            bool: True if password was changed successfully, False otherwise
        """
        # Get user
        user = await self.backend.get_user_by_username(username)
        if not user:
            return False

        # Verify current password
        is_valid, _ = self.password_manager.verify_and_update_password(
            current_password, user.password_hash
        )
        
        if not is_valid:
            return False

        # Hash new password
        new_password_hash = self.password_manager.hash_password(new_password)
        
        # Update password in backend
        success = await self.backend.update_user_password(username, new_password_hash)
        
        if success:
            logger.info(f"Password changed for user '{username}'")
        
        return success

    async def update_user(self, username: str, user_update: UserUpdate) -> Optional[User]:
        """
        Update user information.
        
        Args:
            username: The username of the user to update
            user_update: The update data
            
        Returns:
            Optional[User]: The updated user if successful, None otherwise
        """
        try:
            updated_user = await self.backend.update_user(username, user_update)
            logger.info(f"Updated user '{username}'")
            return updated_user
        except (UserNotFoundError, UserAlreadyExistsError) as e:
            logger.warning(f"Failed to update user '{username}': {e}")
            return None

    async def delete_user(self, username: str) -> bool:
        """
        Delete a user.
        
        Args:
            username: The username of the user to delete
            
        Returns:
            bool: True if user was deleted, False otherwise
        """
        success = await self.backend.delete_user(username)
        
        if success:
            logger.info(f"Deleted user '{username}'")
        
        return success

    async def list_users(self, skip: int = 0, limit: int = 100) -> List[UserPublic]:
        """
        List users in the system.
        
        Args:
            skip: Number of users to skip (for pagination)
            limit: Maximum number of users to return
            
        Returns:
            List[UserPublic]: List of users (public data only)
        """
        return await self.backend.list_users(skip=skip, limit=limit)

    async def get_user_by_username(self, username: str) -> Optional[User]:
        """
        Get a user by username.
        
        Args:
            username: The username to search for
            
        Returns:
            Optional[User]: The user if found, None otherwise
        """
        return await self.backend.get_user_by_username(username)

    async def search_users(self, query: str, skip: int = 0, limit: int = 100) -> List[UserPublic]:
        """
        Search for users.
        
        Args:
            query: Search query string
            skip: Number of users to skip (for pagination)
            limit: Maximum number of users to return
            
        Returns:
            List[UserPublic]: List of matching users
        """
        return await self.backend.search_users(query, skip=skip, limit=limit)

    async def get_users_by_role(self, role: str, skip: int = 0, limit: int = 100) -> List[UserPublic]:
        """
        Get users by role.
        
        Args:
            role: The role to filter by
            skip: Number of users to skip (for pagination)
            limit: Maximum number of users to return
            
        Returns:
            List[UserPublic]: List of users with the specified role
        """
        return await self.backend.get_users_by_role(role, skip=skip, limit=limit)

    async def update_user_role(self, username: str, new_role: str) -> bool:
        """
        Update a user's role.
        
        Args:
            username: The username of the user
            new_role: The new role
            
        Returns:
            bool: True if role was updated, False otherwise
        """
        success = await self.backend.update_user_role(username, new_role)
        
        if success:
            logger.info(f"Updated role for user '{username}' to '{new_role}'")
        
        return success

    async def update_user_profile_picture(self, username: str, profile_picture_url: Optional[str]) -> bool:
        """
        Update a user's profile picture.
        
        Args:
            username: The username of the user
            profile_picture_url: The new profile picture URL or None to remove
            
        Returns:
            bool: True if profile picture was updated, False otherwise
        """
        return await self.backend.update_user_profile_picture(username, profile_picture_url)

    async def get_user_settings(self, username: str) -> Dict[str, Any]:
        """
        Get user settings.
        
        Args:
            username: The username of the user
            
        Returns:
            Dict[str, Any]: User settings dictionary
        """
        return await self.backend.get_user_settings(username)

    async def update_user_settings(self, username: str, settings: Dict[str, Any]) -> bool:
        """
        Update user settings.
        
        Args:
            username: The username of the user
            settings: The settings to update
            
        Returns:
            bool: True if settings were updated, False otherwise
        """
        return await self.backend.update_user_settings(username, settings)

    async def update_user_username(self, old_username: str, new_username: str) -> bool:
        """
        Update a user's username.
        
        Args:
            old_username: The current username
            new_username: The new username
            
        Returns:
            bool: True if username was updated, False otherwise
        """
        success = await self.backend.update_user_username(old_username, new_username)
        
        if success:
            logger.info(f"Updated username from '{old_username}' to '{new_username}'")
        
        return success

    async def get_all_users(self) -> List[UserPublic]:
        """
        Get all users in the system.
        
        Returns:
            List[UserPublic]: List of all users (public data only)
        """
        return await self.backend.get_all_users()

    async def update_user_yapcoin_balance(self, username: str, amount: int) -> bool:
        """
        Update a user's YapCoin balance.
        
        This method is optional and may not be supported by all backends.
        
        Args:
            username: The username of the user
            amount: The amount to add/subtract from the balance
            
        Returns:
            bool: True if balance was updated, False otherwise or if not supported
        """
        try:
            success = await self.backend.update_user_yapcoin_balance(username, amount)
            
            if success:
                logger.info(f"Updated YapCoin balance for user '{username}' by {amount}")
            else:
                logger.warning(f"YapCoin balance update failed for user '{username}' or not supported by backend")
            
            return success
        except Exception as e:
            logger.warning(f"YapCoin balance update not supported by backend: {e}")
            return False

    async def is_username_taken(self, username: str) -> bool:
        """
        Check if a username is already taken.
        
        Args:
            username: The username to check
            
        Returns:
            bool: True if the username is taken, False otherwise
        """
        return await self.backend.is_username_taken(username)

    async def is_email_taken(self, email: str) -> bool:
        """
        Check if an email is already taken.
        
        Args:
            email: The email to check
            
        Returns:
            bool: True if the email is taken, False otherwise
        """
        return await self.backend.is_email_taken(email)

    async def count_users(self) -> int:
        """
        Get the total number of users.
        
        Returns:
            int: Total number of users
        """
        return await self.backend.count_users()

    def validate_password_strength(self, password: str) -> tuple[bool, str]:
        """
        Validate password strength.
        
        Args:
            password: The password to validate
            
        Returns:
            tuple[bool, str]: (is_strong, reason)
        """
        return self.password_manager.validate_password_strength(password)

    def verify_token(self, token: str) -> bool:
        """
        Verify if a token is valid.
        
        Args:
            token: The JWT token to verify
            
        Returns:
            bool: True if token is valid, False otherwise
        """
        result = self.token_manager.verify_token(token, "access")
        return result.is_valid

    async def request_password_reset(self, email: str) -> Optional[str]:
        """
        Request a password reset for a user.
        
        This method generates a secure reset token and stores it temporarily.
        In a production environment, this token would be sent via email.
        
        Args:
            email: The email address of the user requesting password reset
            
        Returns:
            Optional[str]: Reset token if successful, None if user not found
        """
        try:
            # Find user by email
            user = await self.backend.get_user_by_email(email)
            if not user:
                logger.warning(f"Password reset requested for non-existent email: {email}")
                return None

            if not user.is_active:
                logger.warning(f"Password reset requested for inactive user: {email}")
                return None

            # Generate a secure reset token
            reset_token = self.token_manager.create_reset_token(email)
            
            # Store the reset token in user metadata (in production, this would be in a separate table)
            if not user.metadata:
                user.metadata = {}
            
            user.metadata["reset_token"] = reset_token
            user.metadata["reset_token_expires"] = (datetime.now() + timedelta(hours=24)).isoformat()
            
            # Update user with reset token
            from ..models.user import UserUpdate
            user_update = UserUpdate(metadata=user.metadata)
            await self.backend.update_user(user.username, user_update)
            
            logger.info(f"Password reset token generated for user: {user.username}")
            return reset_token
            
        except Exception as e:
            logger.error(f"Error requesting password reset for {email}: {e}")
            return None

    async def reset_password_with_token(self, reset_token: str, new_password: str) -> bool:
        """
        Reset a user's password using a valid reset token.
        
        Args:
            reset_token: The reset token from request_password_reset
            new_password: The new password
            
        Returns:
            bool: True if password was reset successfully, False otherwise
        """
        try:
            # Verify the reset token
            token_data = self.token_manager.verify_reset_token(reset_token)
            if not token_data or not token_data.is_valid:
                logger.warning("Invalid reset token used")
                return False

            email = token_data.payload.sub if token_data.payload else None
            if not email:
                logger.warning("Reset token missing email payload")
                return False

            # Find user by email
            user = await self.backend.get_user_by_email(email)
            if not user:
                logger.warning(f"User not found for reset token: {email}")
                return False

            if not user.is_active:
                logger.warning(f"Password reset attempted for inactive user: {email}")
                return False

            # Verify the token matches what's stored in user metadata
            if not user.metadata or user.metadata.get("reset_token") != reset_token:
                logger.warning(f"Reset token mismatch for user: {user.username}")
                return False

            # Check if token has expired (24 hours)
            token_expires = user.metadata.get("reset_token_expires")
            if token_expires:
                try:
                    expires_dt = datetime.fromisoformat(token_expires)
                    if datetime.now() > expires_dt:
                        logger.warning(f"Reset token expired for user: {user.username}")
                        return False
                except Exception as e:
                    logger.warning(f"Error parsing token expiration: {e}")
                    return False

            # Validate new password strength
            is_strong, reason = self.password_manager.validate_password_strength(new_password)
            if not is_strong:
                logger.warning(f"Password reset failed - weak password: {reason}")
                return False

            # Hash the new password
            new_password_hash = self.password_manager.hash_password(new_password)
            
            # Update the password
            success = await self.backend.update_user_password(user.username, new_password_hash)
            if not success:
                logger.error(f"Failed to update password for user: {user.username}")
                return False

            # Clear the reset token from metadata
            if user.metadata:
                user.metadata.pop("reset_token", None)
                user.metadata.pop("reset_token_expires", None)
                user_update = UserUpdate(metadata=user.metadata)
                await self.backend.update_user(user.username, user_update)

            logger.info(f"Password reset successful for user: {user.username}")
            return True
            
        except Exception as e:
            logger.error(f"Error resetting password with token: {e}")
            return False

    async def close(self) -> None:
        """
        Close the authentication manager and clean up resources.
        """
        await self.backend.close()
        logger.info("Authentication manager closed")

    async def health_check(self) -> bool:
        """
        Perform a health check on the authentication system.
        
        Returns:
            bool: True if the system is healthy, False otherwise
        """
        try:
            return await self.backend.health_check()
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False
