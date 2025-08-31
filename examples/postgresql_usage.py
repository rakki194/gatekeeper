#!/usr/bin/env python3
"""
PostgreSQL backend usage example for the Gatekeeper authentication library.

This example demonstrates how to use the PostgreSQL backend for persistent user storage.
"""

import asyncio
import os
import sys
from pathlib import Path

# Add the parent directory to the path so we can import gatekeeper
sys.path.insert(0, str(Path(__file__).parent.parent))

from gatekeeper import (
    AuthManager,
    TokenConfig,
    UserCreate,
    UserRole,
)
from gatekeeper.backends.postgresql import PostgreSQLBackend


async def main():
    """Main example function."""
    print("🚀 Gatekeeper Authentication Library - PostgreSQL Backend Example")
    print("=" * 70)

    # Configure database connection
    database_url = os.getenv(
        "DATABASE_URL", "postgresql://yipyap:yipyap@localhost:5432/yipyap"
    )

    print(f"📊 Using database: {database_url}")

    # Initialize PostgreSQL backend
    print("\n🔧 Initializing PostgreSQL backend...")
    backend = PostgreSQLBackend(
        database_url=database_url, echo=True  # Enable SQL logging for demonstration
    )

    # Configure token settings
    token_config = TokenConfig(
        secret_key="your-secret-key-here-change-in-production",
        algorithm="HS256",
        access_token_expire_minutes=30,
        refresh_token_expire_days=7,
    )

    # Initialize authentication manager
    print("🔐 Initializing authentication manager...")
    auth_manager = AuthManager(backend=backend, token_config=token_config)

    try:
        # Test database connection
        print("\n🏥 Testing database connection...")
        is_healthy = await backend.health_check()
        if is_healthy:
            print("✅ Database connection successful!")
        else:
            print("❌ Database connection failed!")
            return

        # Create a test user
        print("\n👤 Creating test user...")
        user_create = UserCreate(
            username="postgres_user",
            password="SecurePass123!",
            email="postgres@example.com",
            role=UserRole.REGULAR,
        )

        user = await auth_manager.create_user(user_create)
        print(f"✅ User created: {user.username} (ID: {user.id})")

        # Authenticate the user
        print("\n🔑 Authenticating user...")
        tokens = await auth_manager.authenticate("postgres_user", "SecurePass123!")
        print(f"✅ Authentication successful!")
        print(f"   Access token: {tokens.access_token[:20]}...")
        print(f"   Refresh token: {tokens.refresh_token[:20]}...")

        # Get current user from token
        print("\n👤 Getting current user from token...")
        current_user = await auth_manager.get_current_user(tokens.access_token)
        print(f"✅ Current user: {current_user.username} (Role: {current_user.role})")

        # List all users
        print("\n📋 Listing all users...")
        users = await auth_manager.list_users()
        print(f"✅ Found {len(users)} users:")
        for user in users:
            print(f"   - {user.username} ({user.role}) - {user.email}")

        # Update user
        print("\n✏️  Updating user...")
        from gatekeeper.models.user import UserUpdate

        user_update = UserUpdate(
            email="updated@example.com", metadata={"preferences": {"theme": "dark"}}
        )
        updated_user = await auth_manager.update_user("postgres_user", user_update)
        print(f"✅ User updated: {updated_user.email}")

        # Search users
        print("\n🔍 Searching users...")
        search_results = await auth_manager.search_users("postgres")
        print(f"✅ Search results: {len(search_results)} users found")

        # Get user count
        print("\n📊 Getting user count...")
        count = await auth_manager.count_users()
        print(f"✅ Total users: {count}")

        # Test YapCoin balance update
        print("\n💰 Testing YapCoin balance update...")
        success = await auth_manager.update_user_yapcoin_balance("postgres_user", 100)
        if success:
            print("✅ YapCoin balance updated!")
            user = await auth_manager.get_user_by_username("postgres_user")
            print(f"   New balance: {user.yapcoin_balance}")

        print("\n🎉 PostgreSQL backend example completed successfully!")
        print("\n💡 Key benefits of PostgreSQL backend:")
        print("   - Users persist across application restarts")
        print("   - Scalable for production use")
        print("   - ACID compliance for data integrity")
        print("   - Built-in connection pooling")
        print("   - Support for complex queries and indexing")

    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("\n💡 Make sure PostgreSQL is running and accessible.")
        print("   You can use the provided Docker Compose file:")
        print("   docker-compose -f docker-compose.postgres.yml up -d")

    finally:
        # Clean up
        print("\n🧹 Cleaning up...")
        await auth_manager.close()
        print("✅ Cleanup completed")


if __name__ == "__main__":
    # Run the example
    asyncio.run(main())
