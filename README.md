# Gatekeeper - Authentication and Authorization Library

A comprehensive authentication and authorization library for Python applications, providing secure user management, JWT token handling, role-based access control, and flexible backend integration.

## Features

- 🔐 **Secure Password Hashing**: Modern Argon2 hashing with optimal security parameters
- 🎫 **JWT Token Management**: Access and refresh tokens with configurable expiration
- 👥 **Role-Based Access Control**: Flexible role system (admin, regular, guest)
- 🗄️ **Abstract Backend Interface**: Easy integration with any storage system
- 🚀 **FastAPI Integration**: Built-in dependency injection and route helpers
- 🔒 **Security First**: Comprehensive security features and best practices
- 📦 **Modular Design**: Clean separation of concerns and easy extensibility

## Quick Start

### Installation

```bash
pip install gatekeeper
```

### Basic Usage

```python
import asyncio
from gatekeeper import AuthManager, TokenConfig, UserCreate, UserRole
from gatekeeper.backends.memory import MemoryBackend

async def main():
    # Initialize authentication manager
    token_config = TokenConfig(
        secret_key="your-secret-key-here",
        access_token_expire_minutes=30,
        refresh_token_expire_days=7
    )
    
    auth_manager = AuthManager(
        backend=MemoryBackend(),
        token_config=token_config
    )
    
    # Create a user
    user_data = UserCreate(
        username="john_doe",
        password="SecurePassword123!",
        email="john@example.com",
        role=UserRole.REGULAR
    )
    
    user = await auth_manager.create_user(user_data)
    print(f"Created user: {user.username}")
    
    # Authenticate user
    tokens = await auth_manager.authenticate("john_doe", "SecurePassword123!")
    if tokens:
        print(f"Access token: {tokens.access_token}")
        print(f"Refresh token: {tokens.refresh_token}")
    
    # Get current user from token
    current_user = await auth_manager.get_current_user(tokens.access_token)
    print(f"Current user: {current_user.username}")

if __name__ == "__main__":
    asyncio.run(main())
```

## FastAPI Integration

```python
from fastapi import FastAPI, Depends, HTTPException
from gatekeeper import AuthManager, TokenConfig, UserCreate, UserRole
from gatekeeper.backends.memory import MemoryBackend
from gatekeeper.api.dependencies import get_current_user, require_role
from gatekeeper.models.user import User

app = FastAPI()

# Initialize auth manager
token_config = TokenConfig(secret_key="your-secret-key")
auth_manager = AuthManager(backend=MemoryBackend(), token_config=token_config)

@app.post("/register")
async def register(user_data: UserCreate):
    try:
        user = await auth_manager.create_user(user_data)
        return {"message": "User created successfully", "username": user.username}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/login")
async def login(username: str, password: str):
    tokens = await auth_manager.authenticate(username, password)
    if not tokens:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return tokens

@app.get("/me")
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    return {"username": current_user.username, "role": current_user.role}

@app.get("/admin-only")
async def admin_endpoint(current_user: User = Depends(require_role(UserRole.ADMIN))):
    return {"message": "Admin access granted"}
```

## Core Components

### AuthManager

The main orchestrator for all authentication operations:

```python
from gatekeeper import AuthManager

auth_manager = AuthManager(
    backend=your_backend,
    token_config=token_config,
    password_security_level=SecurityLevel.MEDIUM
)

# User management
user = await auth_manager.create_user(user_data)
tokens = await auth_manager.authenticate(username, password)
current_user = await auth_manager.get_current_user(token)

# User operations
await auth_manager.update_user(username, user_update)
await auth_manager.delete_user(username)
await auth_manager.change_password(username, current_password, new_password)
```

### PasswordManager

Handles secure password operations with Argon2:

```python
from gatekeeper import PasswordManager, SecurityLevel

password_manager = PasswordManager(security_level=SecurityLevel.HIGH)

# Hash password
hashed_password = password_manager.hash_password("my_password")

# Verify password
is_valid = password_manager.verify_password("my_password", hashed_password)

# Validate password strength
is_strong, reason = password_manager.validate_password_strength("my_password")
```

### TokenManager

Manages JWT token creation and validation:

```python
from gatekeeper import TokenManager, TokenConfig

token_config = TokenConfig(
    secret_key="your-secret-key",
    access_token_expire_minutes=30,
    refresh_token_expire_days=7
)

token_manager = TokenManager(token_config)

# Create tokens
tokens = token_manager.create_token_pair("username", "role")

# Verify tokens
result = token_manager.verify_access_token(token)
if result.is_valid:
    user_data = result.payload
```

## Backend Implementations

### Memory Backend

For testing and development:

```python
from gatekeeper.backends.memory import MemoryBackend

backend = MemoryBackend()
# Data is lost when application restarts
```

### Custom Backend

Implement the `UserBackend` interface for your storage system:

```python
from gatekeeper.backends.base import UserBackend, User, UserCreate

class MyDatabaseBackend(UserBackend):
    async def create_user(self, user: UserCreate) -> User:
        # Your implementation here
        pass
    
    async def get_user_by_username(self, username: str) -> Optional[User]:
        # Your implementation here
        pass
    
    # ... implement all required methods
```

## Security Features

### Password Security

- **Argon2 Hashing**: Modern, memory-hard hashing algorithm
- **Modern Security**: Argon2 with configurable security levels
- **Configurable Security Levels**: Low, Medium, High, Paranoid
- **Password Strength Validation**: Enforces strong password requirements

### Token Security

- **JWT Tokens**: Industry-standard JSON Web Tokens
- **Access & Refresh Tokens**: Separate short-lived and long-lived tokens
- **Configurable Expiration**: Flexible token lifetime settings
- **Token Validation**: Comprehensive token verification

### Role-Based Access Control

- **Flexible Roles**: Admin, Regular, Guest (easily extensible)
- **Role Validation**: Built-in role checking utilities
- **Permission System**: Easy to extend with custom permissions

## Configuration

### Token Configuration

```python
from gatekeeper import TokenConfig

token_config = TokenConfig(
    secret_key="your-secret-key-here",
    algorithm="HS256",
    access_token_expire_minutes=30,
    refresh_token_expire_days=7,
    issuer="your-app",
    audience="your-app-users"
)
```

### Password Security Levels

```python
from gatekeeper import SecurityLevel

# Development/Testing
password_manager = PasswordManager(security_level=SecurityLevel.LOW)

# General Use
password_manager = PasswordManager(security_level=SecurityLevel.MEDIUM)

# High Security
password_manager = PasswordManager(security_level=SecurityLevel.HIGH)

# Maximum Security
password_manager = PasswordManager(security_level=SecurityLevel.PARANOID)
```

## API Reference

### Models

- `User`: Complete user model with all fields
- `UserCreate`: User creation model with validation
- `UserUpdate`: User update model
- `UserPublic`: Public user model (no sensitive data)
- `TokenResponse`: Authentication response with tokens
- `TokenConfig`: JWT configuration

### Core Classes

- `AuthManager`: Main authentication orchestrator
- `PasswordManager`: Password hashing and validation
- `TokenManager`: JWT token management
- `UserBackend`: Abstract backend interface

### Backends

- `MemoryBackend`: In-memory storage for testing
- `UserBackend`: Abstract interface for custom backends

## Development

### Installation for Development

```bash
git clone <repository>
cd gatekeeper
pip install -e ".[dev]"
```

### Running Tests

```bash
pytest
```

### Code Formatting

```bash
black gatekeeper/
isort gatekeeper/
```

### Type Checking

```bash
mypy gatekeeper/
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Security

If you discover any security-related issues, please email <security@example.com> instead of using the issue tracker.
