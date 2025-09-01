"""
PostgreSQL backend implementation for the Gatekeeper authentication library.

This module provides a PostgreSQL-based user storage backend using SQLAlchemy.
"""

import logging
import uuid
from datetime import datetime
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
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.dialects.postgresql import UUID

from .base import UserBackend, BackendError, UserNotFoundError, UserAlreadyExistsError
from ..models.user import User, UserCreate, UserUpdate, UserPublic, UserRole

logger = logging.getLogger(__name__)

# SQLAlchemy base class
Base = declarative_base()


class UserModel(Base):
    """SQLAlchemy model for users table."""

    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default=UserRole.REGULAR)
    email = Column(String(255), unique=True, nullable=True, index=True)
    profile_picture_url = Column(String(500), nullable=True)
    yapcoin_balance = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_metadata = Column(JSON, default=dict)


class PostgreSQLBackend(UserBackend):
    """
    PostgreSQL backend implementation for user storage.

    Uses SQLAlchemy ORM to interact with a PostgreSQL database for user management.
    """

    def __init__(self, database_url: str, echo: bool = False):
        """
        Initialize the PostgreSQL backend.

        Args:
            database_url: PostgreSQL connection URL
            echo: Whether to echo SQL statements (for debugging)
        """
        self.database_url = database_url
        self.engine = create_engine(database_url, echo=echo)
        self.SessionLocal = sessionmaker(
            autocommit=False, autoflush=False, bind=self.engine
        )
        self._initialized = False

    def _get_session(self) -> Session:
        """Get a database session."""
        return self.SessionLocal()

    def _initialize_database(self):
        """Initialize the database by creating tables."""
        if not self._initialized:
            Base.metadata.create_all(bind=self.engine)
            self._initialized = True
            logger.info("PostgreSQL backend initialized")

    async def create_user(self, user: UserCreate) -> User:
        """Create a new user in the database."""
        self._initialize_database()

        with self._get_session() as session:
            try:
                # Check if username already exists
                existing_user = (
                    session.query(UserModel)
                    .filter(UserModel.username == user.username)
                    .first()
                )
                if existing_user:
                    raise UserAlreadyExistsError(
                        f"Username '{user.username}' already exists"
                    )

                # Check if email already exists (if provided)
                if user.email:
                    existing_email = (
                        session.query(UserModel)
                        .filter(UserModel.email == user.email)
                        .first()
                    )
                    if existing_email:
                        raise UserAlreadyExistsError(
                            f"Email '{user.email}' already exists"
                        )

                # Create new user
                db_user = UserModel(
                    username=user.username,
                    password_hash=user.password,  # This should be hashed by the auth manager
                    role=user.role,
                    email=user.email,
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow(),
                )

                session.add(db_user)
                session.commit()
                session.refresh(db_user)

                # Convert to User model
                return User(
                    id=str(db_user.id),
                    username=db_user.username,
                    password_hash=db_user.password_hash,
                    role=UserRole(db_user.role),
                    email=db_user.email,
                    profile_picture_url=db_user.profile_picture_url,
                    yapcoin_balance=db_user.yapcoin_balance,
                    is_active=db_user.is_active,
                    created_at=db_user.created_at,
                    updated_at=db_user.updated_at,
                    metadata=db_user.user_metadata or {},
                )

            except IntegrityError as e:
                session.rollback()
                if "username" in str(e).lower():
                    raise UserAlreadyExistsError(
                        f"Username '{user.username}' already exists"
                    )
                elif "email" in str(e).lower():
                    raise UserAlreadyExistsError(f"Email '{user.email}' already exists")
                else:
                    raise BackendError(f"Database integrity error: {e}")
            except SQLAlchemyError as e:
                session.rollback()
                raise BackendError(f"Database error: {e}")

    async def get_user_by_username(self, username: str) -> Optional[User]:
        """Retrieve a user by username."""
        self._initialize_database()

        with self._get_session() as session:
            try:
                db_user = (
                    session.query(UserModel)
                    .filter(UserModel.username == username)
                    .first()
                )

                if not db_user:
                    return None

                return User(
                    id=str(db_user.id),
                    username=db_user.username,
                    password_hash=db_user.password_hash,
                    role=UserRole(db_user.role),
                    email=db_user.email,
                    profile_picture_url=db_user.profile_picture_url,
                    yapcoin_balance=db_user.yapcoin_balance,
                    is_active=db_user.is_active,
                    created_at=db_user.created_at,
                    updated_at=db_user.updated_at,
                    metadata=db_user.user_metadata or {},
                )

            except SQLAlchemyError as e:
                raise BackendError(f"Database error: {e}")

    async def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Retrieve a user by ID."""
        self._initialize_database()

        with self._get_session() as session:
            try:
                db_user = (
                    session.query(UserModel).filter(UserModel.id == user_id).first()
                )

                if not db_user:
                    return None

                return User(
                    id=str(db_user.id),
                    username=db_user.username,
                    password_hash=db_user.password_hash,
                    role=UserRole(db_user.role),
                    email=db_user.email,
                    profile_picture_url=db_user.profile_picture_url,
                    yapcoin_balance=db_user.yapcoin_balance,
                    is_active=db_user.is_active,
                    created_at=db_user.created_at,
                    updated_at=db_user.updated_at,
                    metadata=db_user.user_metadata or {},
                )

            except SQLAlchemyError as e:
                raise BackendError(f"Database error: {e}")

    async def get_user_by_email(self, email: str) -> Optional[User]:
        """Retrieve a user by email address."""
        self._initialize_database()

        with self._get_session() as session:
            try:
                db_user = (
                    session.query(UserModel)
                    .filter(UserModel.email == email)
                    .first()
                )

                if not db_user:
                    return None

                return User(
                    id=str(db_user.id),
                    username=db_user.username,
                    password_hash=db_user.password_hash,
                    role=UserRole(db_user.role),
                    email=db_user.email,
                    profile_picture_url=db_user.profile_picture_url,
                    yapcoin_balance=db_user.yapcoin_balance,
                    is_active=db_user.is_active,
                    created_at=db_user.created_at,
                    updated_at=db_user.updated_at,
                    metadata=db_user.user_metadata or {},
                )

            except SQLAlchemyError as e:
                raise BackendError(f"Database error: {e}")

    async def update_user(self, username: str, user_update: UserUpdate) -> User:
        """Update an existing user."""
        self._initialize_database()

        with self._get_session() as session:
            try:
                db_user = (
                    session.query(UserModel)
                    .filter(UserModel.username == username)
                    .first()
                )

                if not db_user:
                    raise UserNotFoundError(f"User '{username}' not found")

                # Update fields if provided
                if user_update.username is not None:
                    # Check if new username is already taken
                    existing = (
                        session.query(UserModel)
                        .filter(
                            UserModel.username == user_update.username,
                            UserModel.id != db_user.id,
                        )
                        .first()
                    )
                    if existing:
                        raise UserAlreadyExistsError(
                            f"Username '{user_update.username}' already exists"
                        )
                    db_user.username = user_update.username

                if user_update.email is not None:
                    # Check if new email is already taken
                    if user_update.email:
                        existing = (
                            session.query(UserModel)
                            .filter(
                                UserModel.email == user_update.email,
                                UserModel.id != db_user.id,
                            )
                            .first()
                        )
                        if existing:
                            raise UserAlreadyExistsError(
                                f"Email '{user_update.email}' already exists"
                            )
                    db_user.email = user_update.email

                if user_update.role is not None:
                    db_user.role = user_update.role

                if user_update.is_active is not None:
                    db_user.is_active = user_update.is_active

                if user_update.profile_picture_url is not None:
                    db_user.profile_picture_url = user_update.profile_picture_url

                if user_update.metadata is not None:
                    db_user.user_metadata = user_update.metadata

                db_user.updated_at = datetime.utcnow()

                session.commit()
                session.refresh(db_user)

                return User(
                    id=str(db_user.id),
                    username=db_user.username,
                    password_hash=db_user.password_hash,
                    role=UserRole(db_user.role),
                    email=db_user.email,
                    profile_picture_url=db_user.profile_picture_url,
                    yapcoin_balance=db_user.yapcoin_balance,
                    is_active=db_user.is_active,
                    created_at=db_user.created_at,
                    updated_at=db_user.updated_at,
                    metadata=db_user.user_metadata or {},
                )

            except SQLAlchemyError as e:
                session.rollback()
                raise BackendError(f"Database error: {e}")

    async def delete_user(self, username: str) -> bool:
        """Delete a user from the database."""
        self._initialize_database()

        with self._get_session() as session:
            try:
                db_user = (
                    session.query(UserModel)
                    .filter(UserModel.username == username)
                    .first()
                )

                if not db_user:
                    return False

                session.delete(db_user)
                session.commit()
                return True

            except SQLAlchemyError as e:
                session.rollback()
                raise BackendError(f"Database error: {e}")

    async def list_users(self, skip: int = 0, limit: int = 100) -> List[UserPublic]:
        """List users in the database."""
        self._initialize_database()

        with self._get_session() as session:
            try:
                db_users = session.query(UserModel).offset(skip).limit(limit).all()

                return [
                    UserPublic.from_user(
                        User(
                            id=str(db_user.id),
                            username=db_user.username,
                            password_hash=db_user.password_hash,
                            role=UserRole(db_user.role),
                            email=db_user.email,
                            profile_picture_url=db_user.profile_picture_url,
                            yapcoin_balance=db_user.yapcoin_balance,
                            is_active=db_user.is_active,
                            created_at=db_user.created_at,
                            updated_at=db_user.updated_at,
                            metadata=db_user.user_metadata or {},
                        )
                    )
                    for db_user in db_users
                ]

            except SQLAlchemyError as e:
                raise BackendError(f"Database error: {e}")

    async def count_users(self) -> int:
        """Get the total number of users in the database."""
        self._initialize_database()

        with self._get_session() as session:
            try:
                return session.query(UserModel).count()
            except SQLAlchemyError as e:
                raise BackendError(f"Database error: {e}")

    async def update_user_password(self, username: str, new_password_hash: str) -> bool:
        """Update a user's password hash."""
        self._initialize_database()

        with self._get_session() as session:
            try:
                db_user = (
                    session.query(UserModel)
                    .filter(UserModel.username == username)
                    .first()
                )

                if not db_user:
                    return False

                db_user.password_hash = new_password_hash
                db_user.updated_at = datetime.utcnow()
                session.commit()
                return True

            except SQLAlchemyError as e:
                session.rollback()
                raise BackendError(f"Database error: {e}")

    async def update_user_role(self, username: str, new_role: str) -> bool:
        """Update a user's role."""
        self._initialize_database()

        with self._get_session() as session:
            try:
                db_user = (
                    session.query(UserModel)
                    .filter(UserModel.username == username)
                    .first()
                )

                if not db_user:
                    return False

                db_user.role = new_role
                db_user.updated_at = datetime.utcnow()
                session.commit()
                return True

            except SQLAlchemyError as e:
                session.rollback()
                raise BackendError(f"Database error: {e}")

    async def update_user_profile_picture(
        self, username: str, profile_picture_url: Optional[str]
    ) -> bool:
        """Update a user's profile picture URL."""
        self._initialize_database()

        with self._get_session() as session:
            try:
                db_user = (
                    session.query(UserModel)
                    .filter(UserModel.username == username)
                    .first()
                )

                if not db_user:
                    return False

                db_user.profile_picture_url = profile_picture_url
                db_user.updated_at = datetime.utcnow()
                session.commit()
                return True

            except SQLAlchemyError as e:
                session.rollback()
                raise BackendError(f"Database error: {e}")

    async def update_user_metadata(
        self, username: str, metadata: Dict[str, Any]
    ) -> bool:
        """Update a user's metadata."""
        self._initialize_database()

        with self._get_session() as session:
            try:
                db_user = (
                    session.query(UserModel)
                    .filter(UserModel.username == username)
                    .first()
                )

                if not db_user:
                    return False

                db_user.user_metadata = metadata
                db_user.updated_at = datetime.utcnow()
                session.commit()
                return True

            except SQLAlchemyError as e:
                session.rollback()
                raise BackendError(f"Database error: {e}")

    async def search_users(
        self, query: str, skip: int = 0, limit: int = 100
    ) -> List[UserPublic]:
        """Search for users by username or email."""
        self._initialize_database()

        with self._get_session() as session:
            try:
                db_users = (
                    session.query(UserModel)
                    .filter(
                        (UserModel.username.ilike(f"%{query}%"))
                        | (UserModel.email.ilike(f"%{query}%"))
                    )
                    .offset(skip)
                    .limit(limit)
                    .all()
                )

                return [
                    UserPublic.from_user(
                        User(
                            id=str(db_user.id),
                            username=db_user.username,
                            password_hash=db_user.password_hash,
                            role=UserRole(db_user.role),
                            email=db_user.email,
                            profile_picture_url=db_user.profile_picture_url,
                            yapcoin_balance=db_user.yapcoin_balance,
                            is_active=db_user.is_active,
                            created_at=db_user.created_at,
                            updated_at=db_user.updated_at,
                            metadata=db_user.user_metadata or {},
                        )
                    )
                    for db_user in db_users
                ]

            except SQLAlchemyError as e:
                raise BackendError(f"Database error: {e}")

    async def get_users_by_role(
        self, role: str, skip: int = 0, limit: int = 100
    ) -> List[UserPublic]:
        """Get users by role."""
        self._initialize_database()

        with self._get_session() as session:
            try:
                db_users = (
                    session.query(UserModel)
                    .filter(UserModel.role == role)
                    .offset(skip)
                    .limit(limit)
                    .all()
                )

                return [
                    UserPublic.from_user(
                        User(
                            id=str(db_user.id),
                            username=db_user.username,
                            password_hash=db_user.password_hash,
                            role=UserRole(db_user.role),
                            email=db_user.email,
                            profile_picture_url=db_user.profile_picture_url,
                            yapcoin_balance=db_user.yapcoin_balance,
                            is_active=db_user.is_active,
                            created_at=db_user.created_at,
                            updated_at=db_user.updated_at,
                            metadata=db_user.user_metadata or {},
                        )
                    )
                    for db_user in db_users
                ]

            except SQLAlchemyError as e:
                raise BackendError(f"Database error: {e}")

    async def is_username_taken(self, username: str) -> bool:
        """Check if a username is already taken."""
        self._initialize_database()

        with self._get_session() as session:
            try:
                return (
                    session.query(UserModel)
                    .filter(UserModel.username == username)
                    .first()
                    is not None
                )
            except SQLAlchemyError as e:
                raise BackendError(f"Database error: {e}")

    async def is_email_taken(self, email: str) -> bool:
        """Check if an email is already taken."""
        self._initialize_database()

        with self._get_session() as session:
            try:
                return (
                    session.query(UserModel).filter(UserModel.email == email).first()
                    is not None
                )
            except SQLAlchemyError as e:
                raise BackendError(f"Database error: {e}")

    async def get_user_settings(self, username: str) -> Dict[str, Any]:
        """Get user settings."""
        self._initialize_database()

        with self._get_session() as session:
            try:
                db_user = (
                    session.query(UserModel)
                    .filter(UserModel.username == username)
                    .first()
                )

                if not db_user:
                    raise UserNotFoundError(f"User '{username}' not found")

                return db_user.user_metadata or {}

            except SQLAlchemyError as e:
                raise BackendError(f"Database error: {e}")

    async def update_user_settings(
        self, username: str, settings: Dict[str, Any]
    ) -> bool:
        """Update user settings."""
        self._initialize_database()

        with self._get_session() as session:
            try:
                db_user = (
                    session.query(UserModel)
                    .filter(UserModel.username == username)
                    .first()
                )

                if not db_user:
                    return False

                db_user.user_metadata = settings
                db_user.updated_at = datetime.utcnow()
                session.commit()
                return True

            except SQLAlchemyError as e:
                session.rollback()
                raise BackendError(f"Database error: {e}")

    async def update_user_username(self, old_username: str, new_username: str) -> bool:
        """Update a user's username."""
        self._initialize_database()

        with self._get_session() as session:
            try:
                # Check if new username is already taken
                existing = (
                    session.query(UserModel)
                    .filter(UserModel.username == new_username)
                    .first()
                )
                if existing:
                    return False

                db_user = (
                    session.query(UserModel)
                    .filter(UserModel.username == old_username)
                    .first()
                )

                if not db_user:
                    return False

                db_user.username = new_username
                db_user.updated_at = datetime.utcnow()
                session.commit()
                return True

            except SQLAlchemyError as e:
                session.rollback()
                raise BackendError(f"Database error: {e}")

    async def get_all_users(self) -> List[UserPublic]:
        """Get all users in the database."""
        self._initialize_database()

        with self._get_session() as session:
            try:
                db_users = session.query(UserModel).all()

                return [
                    UserPublic.from_user(
                        User(
                            id=str(db_user.id),
                            username=db_user.username,
                            password_hash=db_user.password_hash,
                            role=UserRole(db_user.role),
                            email=db_user.email,
                            profile_picture_url=db_user.profile_picture_url,
                            yapcoin_balance=db_user.yapcoin_balance,
                            is_active=db_user.is_active,
                            created_at=db_user.created_at,
                            updated_at=db_user.updated_at,
                            metadata=db_user.user_metadata or {},
                        )
                    )
                    for db_user in db_users
                ]

            except SQLAlchemyError as e:
                raise BackendError(f"Database error: {e}")

    async def update_user_yapcoin_balance(self, username: str, amount: int) -> bool:
        """Update a user's YapCoin balance."""
        self._initialize_database()

        with self._get_session() as session:
            try:
                db_user = (
                    session.query(UserModel)
                    .filter(UserModel.username == username)
                    .first()
                )

                if not db_user:
                    return False

                db_user.yapcoin_balance = (db_user.yapcoin_balance or 0) + amount
                db_user.updated_at = datetime.utcnow()
                session.commit()
                return True

            except SQLAlchemyError as e:
                session.rollback()
                raise BackendError(f"Database error: {e}")

    async def close(self) -> None:
        """Close the database connection."""
        if hasattr(self, "engine"):
            self.engine.dispose()
        logger.info("PostgreSQL backend closed")

    async def health_check(self) -> bool:
        """Perform a health check on the database."""
        try:
            self._initialize_database()
            with self._get_session() as session:
                session.execute(text("SELECT 1"))
                return True
        except Exception as e:
            logger.error(f"PostgreSQL health check failed: {e}")
            return False
