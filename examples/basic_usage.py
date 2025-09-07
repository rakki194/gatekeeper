#!/usr/bin/env python3
"""
Basic usage example for the Gatekeeper authentication library.

This example demonstrates the core functionality of the library.
"""

import asyncio
import os
import sys

# Add the parent directory to the path so we can import gatekeeper
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gatekeeper import (
    AuthManager,
    SecurityLevel,
    TokenConfig,
    UserCreate,
    UserRole,
    UserUpdate,
)
from gatekeeper.backends.memory import MemoryBackend


async def main():
    """Main example function."""
    print("🚀 Gatekeeper Authentication Library - Basic Usage Example")
    print("=" * 60)

    # Initialize the authentication manager
    print("\n1. Initializing authentication manager...")
    token_config = TokenConfig(
        secret_key="your-secret-key-here-change-in-production",
        access_token_expire_minutes=30,
        refresh_token_expire_days=7,
    )

    auth_manager = AuthManager(
        backend=MemoryBackend(),
        token_config=token_config,
        password_security_level=SecurityLevel.MEDIUM,
    )

    print("✅ Authentication manager initialized")

    # Create a user
    print("\n2. Creating a new user...")
    user_data = UserCreate(
        username="john_doe",
        password="SecurePassword123!",
        email="john@example.com",
        role=UserRole.REGULAR,
    )

    try:
        user = await auth_manager.create_user(user_data)
        print(f"✅ User created: {user.username} (ID: {user.id})")
        print(f"   Role: {user.role}")
        print(f"   Email: {user.email}")
        print(f"   Active: {user.is_active}")
    except Exception as e:
        print(f"❌ Failed to create user: {e}")
        return

    # Create an admin user
    print("\n3. Creating an admin user...")
    admin_data = UserCreate(
        username="admin",
        password="AdminPassword456!",
        email="admin@example.com",
        role=UserRole.ADMIN,
    )

    try:
        admin_user = await auth_manager.create_user(admin_data)
        print(f"✅ Admin user created: {admin_user.username}")
    except Exception as e:
        print(f"❌ Failed to create admin user: {e}")

    # Authenticate the regular user
    print("\n4. Authenticating user...")
    tokens = await auth_manager.authenticate("john_doe", "SecurePassword123!")

    if tokens:
        print("✅ Authentication successful!")
        print(f"   Access token: {tokens.access_token[:50]}...")
        print(f"   Refresh token: {tokens.refresh_token[:50]}...")
        print(f"   Token type: {tokens.token_type}")
        print(f"   Expires in: {tokens.expires_in} seconds")
    else:
        print("❌ Authentication failed!")
        return

    # Get current user from token
    print("\n5. Getting current user from token...")
    current_user = await auth_manager.get_current_user(tokens.access_token)

    if current_user:
        print(f"✅ Current user: {current_user.username}")
        print(f"   Role: {current_user.role}")
        print(f"   Email: {current_user.email}")
    else:
        print("❌ Failed to get current user")

    # Test token verification
    print("\n6. Testing token verification...")
    is_valid = auth_manager.verify_token(tokens.access_token)
    print(f"✅ Token is valid: {is_valid}")

    # Test invalid token
    is_valid = auth_manager.verify_token("invalid-token")
    print(f"❌ Invalid token is valid: {is_valid}")

    # Change password
    print("\n7. Changing user password...")
    success = await auth_manager.change_password(
        "john_doe", "SecurePassword123!", "NewSecurePassword789!"
    )

    if success:
        print("✅ Password changed successfully")

        # Try to authenticate with old password
        old_tokens = await auth_manager.authenticate("john_doe", "SecurePassword123!")
        print(f"❌ Old password still works: {old_tokens is not None}")

        # Try to authenticate with new password
        new_tokens = await auth_manager.authenticate(
            "john_doe", "NewSecurePassword789!"
        )
        print(f"✅ New password works: {new_tokens is not None}")
    else:
        print("❌ Failed to change password")

    # List users
    print("\n8. Listing all users...")
    users = await auth_manager.list_users()
    print(f"✅ Found {len(users)} users:")
    for user in users:
        print(f"   - {user.username} ({user.role})")

    # Search users
    print("\n9. Searching users...")
    search_results = await auth_manager.search_users("john")
    print(f"✅ Search for 'john' found {len(search_results)} users:")
    for user in search_results:
        print(f"   - {user.username}")

    # Get users by role
    print("\n10. Getting users by role...")
    admin_users = await auth_manager.get_users_by_role(UserRole.ADMIN)
    print(f"✅ Found {len(admin_users)} admin users:")
    for user in admin_users:
        print(f"   - {user.username}")

    # Update user
    print("\n11. Updating user...")
    user_update = UserUpdate(
        email="john.updated@example.com",
        profile_picture_url="https://example.com/avatar.jpg",
    )

    updated_user = await auth_manager.update_user("john_doe", user_update)
    if updated_user:
        print(f"✅ User updated: {updated_user.username}")
        print(f"   New email: {updated_user.email}")
        print(f"   Profile picture: {updated_user.profile_picture_url}")
    else:
        print("❌ Failed to update user")

    # Test password strength validation
    print("\n12. Testing password strength validation...")
    test_passwords = [
        "weak",
        "weakpass",
        "WeakPass",
        "WeakPass123",
        "StrongPassword123!",
        "password123",
    ]

    for password in test_passwords:
        is_strong, reason = auth_manager.validate_password_strength(password)
        status = "✅" if is_strong else "❌"
        print(f"{status} '{password}': {reason}")

    # Health check
    print("\n13. Performing health check...")
    is_healthy = await auth_manager.health_check()
    print(f"✅ System health: {is_healthy}")

    # Close the auth manager
    print("\n14. Closing authentication manager...")
    await auth_manager.close()
    print("✅ Authentication manager closed")

    print("\n🎉 Example completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
