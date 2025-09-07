"""
SQLite backend implementation for the Gatekeeper authentication library.

This module provides a SQLite-based user storage backend using SQLAlchemy.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import (
    create_engine,
    Column,
    String,
    Integer,
    Boolean,
    DateTime,
    JSON,
    text,
)
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from .base import UserBackend, BackendError, UserNotFoundError, UserAlreadyExistsError
from ..models.user import User, UserCreate, UserUpdate, UserPublic, UserRole

logger = logging.getLogger(__name__)

# SQLAlchemy base class
Base = declarative_base()


class UserModel(Base):
    """SQLAlchemy model for users table."""

    __tablename__ = "gatekeeper_users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(50), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default=UserRole.REGULAR)
    email = Column(String(255), unique=True, nullable=True, index=True)
    profile_picture_url = Column(String(500), nullable=True)
    yapcoin_balance = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    user_metadata = Column(JSON, default=dict)


class SQLiteBackend(UserBackend):
    """
    SQLite backend implementation for user storage.

    This backend uses SQLAlchemy with SQLite to provide persistent user storage
    with full support for all user management operations.
    """

    def __init__(
        self,
        database_url: str = "sqlite:///./gatekeeper.db",
        pool_size: int = 5,
        max_overflow: int = 10,
        echo: bool = False,
    ):
        """
        Initialize the SQLite backend.

        Args:
            database_url: SQLite database URL
            pool_size: Connection pool size
            max_overflow: Maximum overflow connections
            echo: Enable SQLAlchemy echo for debugging
        """
        self.database_url = database_url
        self.pool_size = pool_size
        self.max_overflow = max_overflow
        self.echo = echo
        
        # Convert SQLite URL to async format if needed
        if database_url.startswith("sqlite://"):
            self.async_database_url = database_url.replace("sqlite://", "sqlite+aiosqlite://")
        else:
            self.async_database_url = database_url
        
        self.engine = None
        self.session_factory = None
        self._initialized = False

    async def _initialize(self) -> None:
        """Initialize the database connection and create tables."""
        if self._initialized:
            return
        
        try:
            # Create engine
            self.engine = create_engine(
                self.database_url,
                echo=self.echo,
                pool_size=self.pool_size,
                max_overflow=self.max_overflow,
                pool_pre_ping=True,
            )
            
            # Create session factory
            self.session_factory = sessionmaker(
                bind=self.engine,
                class_=Session,
                expire_on_commit=False
            )
            
            # Create tables
            Base.metadata.create_all(bind=self.engine)
            
            self._initialized = True
            logger.info("SQLite backend initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize SQLite backend: {e}")
            raise BackendError(f"Failed to initialize SQLite backend: {e}")

    def _get_session(self) -> Session:
        """Get a database session."""
        if not self._initialized:
            raise BackendError("Backend not initialized")
        return self.session_factory()

    def _model_to_user(self, model: UserModel) -> User:
        """Convert SQLAlchemy model to User object."""
        return User(
            id=model.id,
            username=model.username,
            password_hash=model.password_hash,
            role=UserRole(model.role),
            email=model.email,
            profile_picture_url=model.profile_picture_url,
            yapcoin_balance=model.yapcoin_balance,
            is_active=model.is_active,
            created_at=model.created_at,
            updated_at=model.updated_at,
            metadata=model.user_metadata or {},
        )

    def _model_to_user_public(self, model: UserModel) -> UserPublic:
        """Convert SQLAlchemy model to UserPublic object."""
        return UserPublic(
            id=model.id,
            username=model.username,
            role=UserRole(model.role),
            email=model.email,
            profile_picture_url=model.profile_picture_url,
            yapcoin_balance=model.yapcoin_balance,
            is_active=model.is_active,
            created_at=model.created_at,
            updated_at=model.updated_at,
            metadata=model.user_metadata or {},
        )

    async def create_user(self, user: UserCreate) -> User:
        """Create a new user in the backend."""
        await self._initialize()
        
        session = self._get_session()
        try:
            # Check if username already exists
            existing_user = session.query(UserModel).filter(
                UserModel.username == user.username
            ).first()
            if existing_user:
                raise UserAlreadyExistsError(f"Username '{user.username}' already exists")
            
            # Check if email already exists (if provided)
            if user.email:
                existing_email = session.query(UserModel).filter(
                    UserModel.email == user.email
                ).first()
                if existing_email:
                    raise UserAlreadyExistsError(f"Email '{user.email}' already exists")
            
            # Create new user
            user_model = UserModel(
                username=user.username,
                password_hash="",  # Will be set by auth manager
                role=user.role.value,
                email=user.email,
                profile_picture_url=None,  # UserCreate doesn't have this field
                yapcoin_balance=0,  # Default value
                is_active=True,  # Default value
                user_metadata={},  # Default value
            )
            
            session.add(user_model)
            session.commit()
            session.refresh(user_model)
            
            logger.info(f"Created user: {user.username}")
            return self._model_to_user(user_model)
            
        except UserAlreadyExistsError:
            session.rollback()
            raise
        except IntegrityError as e:
            session.rollback()
            if "UNIQUE constraint failed" in str(e):
                if "username" in str(e):
                    raise UserAlreadyExistsError(f"Username '{user.username}' already exists")
                elif "email" in str(e):
                    raise UserAlreadyExistsError(f"Email '{user.email}' already exists")
            raise BackendError(f"Database integrity error: {e}")
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to create user {user.username}: {e}")
            raise BackendError(f"Failed to create user: {e}")
        finally:
            session.close()

    async def get_user_by_username(self, username: str) -> Optional[User]:
        """Retrieve a user by username."""
        await self._initialize()
        
        session = self._get_session()
        try:
            user_model = session.query(UserModel).filter(
                UserModel.username == username
            ).first()
            
            if user_model:
                return self._model_to_user(user_model)
            return None
            
        except Exception as e:
            logger.error(f"Failed to get user by username {username}: {e}")
            raise BackendError(f"Failed to get user by username: {e}")
        finally:
            session.close()

    async def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Retrieve a user by ID."""
        await self._initialize()
        
        session = self._get_session()
        try:
            user_model = session.query(UserModel).filter(
                UserModel.id == user_id
            ).first()
            
            if user_model:
                return self._model_to_user(user_model)
            return None
            
        except Exception as e:
            logger.error(f"Failed to get user by ID {user_id}: {e}")
            raise BackendError(f"Failed to get user by ID: {e}")
        finally:
            session.close()

    async def get_user_by_email(self, email: str) -> Optional[User]:
        """Retrieve a user by email address."""
        await self._initialize()
        
        session = self._get_session()
        try:
            user_model = session.query(UserModel).filter(
                UserModel.email == email
            ).first()
            
            if user_model:
                return self._model_to_user(user_model)
            return None
            
        except Exception as e:
            logger.error(f"Failed to get user by email {email}: {e}")
            raise BackendError(f"Failed to get user by email: {e}")
        finally:
            session.close()

    async def update_user(self, username: str, user_update: UserUpdate) -> User:
        """Update an existing user."""
        await self._initialize()
        
        session = self._get_session()
        try:
            user_model = session.query(UserModel).filter(
                UserModel.username == username
            ).first()
            
            if not user_model:
                raise UserNotFoundError(f"User '{username}' not found")
            
            # Update fields if provided
            if user_update.email is not None:
                user_model.email = user_update.email
            if user_update.profile_picture_url is not None:
                user_model.profile_picture_url = user_update.profile_picture_url
            if user_update.is_active is not None:
                user_model.is_active = user_update.is_active
            if user_update.metadata is not None:
                user_model.user_metadata = user_update.metadata
            
            user_model.updated_at = datetime.now(timezone.utc)
            
            session.commit()
            session.refresh(user_model)
            
            logger.info(f"Updated user: {username}")
            return self._model_to_user(user_model)
            
        except UserNotFoundError:
            session.rollback()
            raise
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to update user {username}: {e}")
            raise BackendError(f"Failed to update user: {e}")
        finally:
            session.close()

    async def delete_user(self, username: str) -> bool:
        """Delete a user from the backend."""
        await self._initialize()
        
        session = self._get_session()
        try:
            user_model = session.query(UserModel).filter(
                UserModel.username == username
            ).first()
            
            if not user_model:
                return False
            
            session.delete(user_model)
            session.commit()
            
            logger.info(f"Deleted user: {username}")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to delete user {username}: {e}")
            raise BackendError(f"Failed to delete user: {e}")
        finally:
            session.close()

    async def list_users(self, skip: int = 0, limit: int = 100) -> List[UserPublic]:
        """List users in the backend."""
        await self._initialize()
        
        session = self._get_session()
        try:
            user_models = session.query(UserModel).offset(skip).limit(limit).all()
            return [self._model_to_user_public(model) for model in user_models]
            
        except Exception as e:
            logger.error(f"Failed to list users: {e}")
            raise BackendError(f"Failed to list users: {e}")
        finally:
            session.close()

    async def count_users(self) -> int:
        """Get the total number of users in the backend."""
        await self._initialize()
        
        session = self._get_session()
        try:
            count = session.query(UserModel).count()
            return count
            
        except Exception as e:
            logger.error(f"Failed to count users: {e}")
            raise BackendError(f"Failed to count users: {e}")
        finally:
            session.close()

    async def update_user_password(self, username: str, new_password_hash: str) -> bool:
        """Update a user's password hash."""
        await self._initialize()
        
        session = self._get_session()
        try:
            user_model = session.query(UserModel).filter(
                UserModel.username == username
            ).first()
            
            if not user_model:
                return False
            
            user_model.password_hash = new_password_hash
            user_model.updated_at = datetime.now(timezone.utc)
            
            session.commit()
            
            logger.info(f"Updated password for user: {username}")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to update password for user {username}: {e}")
            raise BackendError(f"Failed to update password: {e}")
        finally:
            session.close()

    async def update_user_role(self, username: str, new_role: str) -> bool:
        """Update a user's role."""
        await self._initialize()
        
        session = self._get_session()
        try:
            user_model = session.query(UserModel).filter(
                UserModel.username == username
            ).first()
            
            if not user_model:
                return False
            
            user_model.role = new_role
            user_model.updated_at = datetime.now(timezone.utc)
            
            session.commit()
            
            logger.info(f"Updated role for user {username} to {new_role}")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to update role for user {username}: {e}")
            raise BackendError(f"Failed to update role: {e}")
        finally:
            session.close()

    async def update_user_profile_picture(
        self, username: str, profile_picture_url: Optional[str]
    ) -> bool:
        """Update a user's profile picture URL."""
        await self._initialize()
        
        session = self._get_session()
        try:
            user_model = session.query(UserModel).filter(
                UserModel.username == username
            ).first()
            
            if not user_model:
                return False
            
            user_model.profile_picture_url = profile_picture_url
            user_model.updated_at = datetime.now(timezone.utc)
            
            session.commit()
            
            logger.info(f"Updated profile picture for user: {username}")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to update profile picture for user {username}: {e}")
            raise BackendError(f"Failed to update profile picture: {e}")
        finally:
            session.close()

    async def update_user_metadata(
        self, username: str, metadata: Dict[str, Any]
    ) -> bool:
        """Update a user's metadata."""
        await self._initialize()
        
        session = self._get_session()
        try:
            user_model = session.query(UserModel).filter(
                UserModel.username == username
            ).first()
            
            if not user_model:
                return False
            
            user_model.user_metadata = metadata
            user_model.updated_at = datetime.now(timezone.utc)
            
            session.commit()
            
            logger.info(f"Updated metadata for user: {username}")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to update metadata for user {username}: {e}")
            raise BackendError(f"Failed to update metadata: {e}")
        finally:
            session.close()

    async def search_users(
        self, query: str, skip: int = 0, limit: int = 100
    ) -> List[UserPublic]:
        """Search for users by username or email."""
        await self._initialize()
        
        session = self._get_session()
        try:
            user_models = session.query(UserModel).filter(
                (UserModel.username.ilike(f"%{query}%")) |
                (UserModel.email.ilike(f"%{query}%"))
            ).offset(skip).limit(limit).all()
            
            return [self._model_to_user_public(model) for model in user_models]
            
        except Exception as e:
            logger.error(f"Failed to search users with query '{query}': {e}")
            raise BackendError(f"Failed to search users: {e}")
        finally:
            session.close()

    async def get_users_by_role(
        self, role: str, skip: int = 0, limit: int = 100
    ) -> List[UserPublic]:
        """Get users by role."""
        await self._initialize()
        
        session = self._get_session()
        try:
            user_models = session.query(UserModel).filter(
                UserModel.role == role
            ).offset(skip).limit(limit).all()
            
            return [self._model_to_user_public(model) for model in user_models]
            
        except Exception as e:
            logger.error(f"Failed to get users by role {role}: {e}")
            raise BackendError(f"Failed to get users by role: {e}")
        finally:
            session.close()

    async def is_username_taken(self, username: str) -> bool:
        """Check if a username is already taken."""
        await self._initialize()
        
        session = self._get_session()
        try:
            user_model = session.query(UserModel).filter(
                UserModel.username == username
            ).first()
            
            return user_model is not None
            
        except Exception as e:
            logger.error(f"Failed to check if username {username} is taken: {e}")
            raise BackendError(f"Failed to check username availability: {e}")
        finally:
            session.close()

    async def is_email_taken(self, email: str) -> bool:
        """Check if an email is already taken."""
        await self._initialize()
        
        session = self._get_session()
        try:
            user_model = session.query(UserModel).filter(
                UserModel.email == email
            ).first()
            
            return user_model is not None
            
        except Exception as e:
            logger.error(f"Failed to check if email {email} is taken: {e}")
            raise BackendError(f"Failed to check email availability: {e}")
        finally:
            session.close()

    async def get_user_settings(self, username: str) -> Dict[str, Any]:
        """Get user settings."""
        await self._initialize()
        
        session = self._get_session()
        try:
            user_model = session.query(UserModel).filter(
                UserModel.username == username
            ).first()
            
            if not user_model:
                raise UserNotFoundError(f"User '{username}' not found")
            
            return user_model.user_metadata or {}
            
        except UserNotFoundError:
            raise
        except Exception as e:
            logger.error(f"Failed to get user settings for {username}: {e}")
            raise BackendError(f"Failed to get user settings: {e}")
        finally:
            session.close()

    async def update_user_settings(
        self, username: str, settings: Dict[str, Any]
    ) -> bool:
        """Update user settings."""
        await self._initialize()
        
        session = self._get_session()
        try:
            user_model = session.query(UserModel).filter(
                UserModel.username == username
            ).first()
            
            if not user_model:
                return False
            
            user_model.user_metadata = settings
            user_model.updated_at = datetime.now(timezone.utc)
            
            session.commit()
            
            logger.info(f"Updated settings for user: {username}")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to update settings for user {username}: {e}")
            raise BackendError(f"Failed to update settings: {e}")
        finally:
            session.close()

    async def update_user_username(self, old_username: str, new_username: str) -> bool:
        """Update a user's username."""
        await self._initialize()
        
        session = self._get_session()
        try:
            # Check if new username is already taken
            existing_user = session.query(UserModel).filter(
                UserModel.username == new_username
            ).first()
            if existing_user:
                return False
            
            user_model = session.query(UserModel).filter(
                UserModel.username == old_username
            ).first()
            
            if not user_model:
                return False
            
            user_model.username = new_username
            user_model.updated_at = datetime.now(timezone.utc)
            
            session.commit()
            
            logger.info(f"Updated username from {old_username} to {new_username}")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to update username from {old_username} to {new_username}: {e}")
            raise BackendError(f"Failed to update username: {e}")
        finally:
            session.close()

    async def get_all_users(self) -> List[UserPublic]:
        """Get all users in the backend."""
        await self._initialize()
        
        session = self._get_session()
        try:
            user_models = session.query(UserModel).all()
            return [self._model_to_user_public(model) for model in user_models]
            
        except Exception as e:
            logger.error(f"Failed to get all users: {e}")
            raise BackendError(f"Failed to get all users: {e}")
        finally:
            session.close()

    async def update_user_yapcoin_balance(self, username: str, amount: int) -> bool:
        """Update a user's YapCoin balance."""
        await self._initialize()
        
        session = self._get_session()
        try:
            user_model = session.query(UserModel).filter(
                UserModel.username == username
            ).first()
            
            if not user_model:
                return False
            
            user_model.yapcoin_balance = amount
            user_model.updated_at = datetime.now(timezone.utc)
            
            session.commit()
            
            logger.info(f"Updated YapCoin balance for user {username} to {amount}")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to update YapCoin balance for user {username}: {e}")
            raise BackendError(f"Failed to update YapCoin balance: {e}")
        finally:
            session.close()

    async def close(self) -> None:
        """Close the backend connection and clean up resources."""
        if self.engine:
            self.engine.dispose()
            self._initialized = False
            logger.info("SQLite backend closed")

    async def health_check(self) -> bool:
        """Perform a health check on the backend."""
        try:
            await self._initialize()
            session = self._get_session()
            session.execute(text("SELECT 1"))
            session.close()
            return True
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False
