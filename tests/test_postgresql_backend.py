"""
Tests for PostgreSQL backend functionality in the Gatekeeper library.
"""

import pytest
import asyncio
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

from gatekeeper.backends.postgresql import PostgreSQLBackend
from gatekeeper.models.user import User, UserCreate, UserUpdate, UserPublic, UserRole


class TestPostgreSQLBackend:
    """Test cases for PostgreSQL backend."""
    
    @pytest.fixture
    def backend(self):
        """Create a PostgreSQL backend instance for testing."""
        # Use a test database URL
        database_url = "postgresql://test:test@localhost:5432/test_db"
        backend = PostgreSQLBackend(database_url=database_url, echo=False)
        # Mock the _initialize_database method to prevent actual DB operations
        with patch.object(backend, '_initialize_database'):
            yield backend
    
    def _create_mock_user(self, **kwargs):
        """Helper to create a properly structured mock user."""
        mock_user = MagicMock()
        mock_user.id = kwargs.get('id', "test-uuid")
        mock_user.username = kwargs.get('username', "testuser")
        mock_user.password_hash = kwargs.get('password_hash', "hashed_password")
        mock_user.role = kwargs.get('role', "regular")
        mock_user.email = kwargs.get('email', "test@example.com")
        mock_user.profile_picture_url = kwargs.get('profile_picture_url', None)
        mock_user.yapcoin_balance = kwargs.get('yapcoin_balance', 0)
        mock_user.is_active = kwargs.get('is_active', True)
        mock_user.created_at = kwargs.get('created_at', datetime.now(timezone.utc))
        mock_user.updated_at = kwargs.get('updated_at', datetime.now(timezone.utc))
        mock_user.user_metadata = kwargs.get('user_metadata', {})
        return mock_user
    
    @pytest.mark.asyncio
    async def test_create_user(self, backend):
        """Test creating a user."""
        user_create = UserCreate(
            username="testuser",
            password="TestPass123!",
            email="test@example.com",
            role=UserRole.REGULAR
        )
        
        with patch.object(backend, '_get_session') as mock_session:
            # Mock the session and database operations
            mock_db = MagicMock()
            mock_session.return_value.__enter__.return_value = mock_db
            
            # Mock user creation - first check returns None (no existing user)
            mock_db.query.return_value.filter.return_value.first.return_value = None
            mock_db.add.return_value = None
            mock_db.commit.return_value = None
            mock_db.refresh.return_value = None
            
            # Mock the UserModel creation and its attributes
            with patch('gatekeeper.backends.postgresql.UserModel') as mock_user_model:
                mock_db_user = self._create_mock_user()
                mock_user_model.return_value = mock_db_user
                
                # Test user creation
                user = await backend.create_user(user_create)
                
                assert user.username == "testuser"
                assert user.email == "test@example.com"
                assert user.role == UserRole.REGULAR
                assert user.is_active is True
    
    @pytest.mark.asyncio
    async def test_get_user_by_username(self, backend):
        """Test retrieving a user by username."""
        with patch.object(backend, '_get_session') as mock_session:
            mock_db = MagicMock()
            mock_session.return_value.__enter__.return_value = mock_db
            
            # Mock user retrieval
            mock_user = self._create_mock_user()
            
            mock_db.query.return_value.filter.return_value.first.return_value = mock_user
            
            # Test user retrieval
            user = await backend.get_user_by_username("testuser")
            
            assert user is not None
            assert user.username == "testuser"
            assert user.email == "test@example.com"
    
    @pytest.mark.asyncio
    async def test_get_user_by_username_not_found(self, backend):
        """Test retrieving a non-existent user."""
        with patch.object(backend, '_get_session') as mock_session:
            mock_db = MagicMock()
            mock_session.return_value.__enter__.return_value = mock_db
            
            # Mock user not found
            mock_db.query.return_value.filter.return_value.first.return_value = None
            
            # Test user retrieval
            user = await backend.get_user_by_username("nonexistent")
            
            assert user is None
    
    @pytest.mark.asyncio
    async def test_update_user(self, backend):
        """Test updating a user."""
        user_update = UserUpdate(
            email="newemail@example.com",
            role=UserRole.ADMIN
        )
        
        with patch.object(backend, '_get_session') as mock_session:
            mock_db = MagicMock()
            mock_session.return_value.__enter__.return_value = mock_db
            
            # Mock existing user
            mock_user = self._create_mock_user()
            
            # Mock the email conflict check to return None (no conflict)
            mock_db.query.return_value.filter.return_value.first.side_effect = [
                mock_user,  # First call for existing user
                None        # Second call for email conflict check
            ]
            
            mock_db.commit.return_value = None
            mock_db.refresh.return_value = None
            
            # Test user update
            user = await backend.update_user("testuser", user_update)
            
            assert user.email == "newemail@example.com"
            assert user.role == UserRole.ADMIN
    
    @pytest.mark.asyncio
    async def test_delete_user(self, backend):
        """Test deleting a user."""
        with patch.object(backend, '_get_session') as mock_session:
            mock_db = MagicMock()
            mock_session.return_value.__enter__.return_value = mock_db
            
            # Mock existing user
            mock_user = self._create_mock_user()
            mock_db.query.return_value.filter.return_value.first.return_value = mock_user
            mock_db.delete.return_value = None
            mock_db.commit.return_value = None
            
            # Test user deletion
            result = await backend.delete_user("testuser")
            
            assert result is True
    
    @pytest.mark.asyncio
    async def test_list_users(self, backend):
        """Test listing users."""
        with patch.object(backend, '_get_session') as mock_session:
            mock_db = MagicMock()
            mock_session.return_value.__enter__.return_value = mock_db
            
            # Mock users list
            mock_users = []
            for i in range(3):
                mock_user = self._create_mock_user(
                    id=f"user-{i}-uuid",
                    username=f"user{i}",
                    email=f"user{i}@example.com"
                )
                mock_users.append(mock_user)
            
            mock_db.query.return_value.offset.return_value.limit.return_value.all.return_value = mock_users
            
            # Test listing users
            users = await backend.list_users(skip=0, limit=10)
            
            assert len(users) == 3
            assert all(isinstance(user, UserPublic) for user in users)
    
    @pytest.mark.asyncio
    async def test_count_users(self, backend):
        """Test counting users."""
        with patch.object(backend, '_get_session') as mock_session:
            mock_db = MagicMock()
            mock_session.return_value.__enter__.return_value = mock_db
            
            # Mock count
            mock_db.query.return_value.count.return_value = 5
            
            # Test counting users
            count = await backend.count_users()
            
            assert count == 5
    
    @pytest.mark.asyncio
    async def test_health_check(self, backend):
        """Test health check."""
        with patch.object(backend, '_get_session') as mock_session:
            mock_db = MagicMock()
            mock_session.return_value.__enter__.return_value = mock_db
            
            # Mock successful health check
            mock_db.execute.return_value = None
            
            # Test health check
            is_healthy = await backend.health_check()
            
            assert is_healthy is True
    
    @pytest.mark.asyncio
    async def test_close(self, backend):
        """Test closing the backend."""
        with patch.object(backend, 'engine') as mock_engine:
            mock_engine.dispose.return_value = None
            
            # Test closing
            await backend.close()
            
            mock_engine.dispose.assert_called_once()
