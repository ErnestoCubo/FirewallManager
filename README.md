# FirewallManager

A comprehensive RESTful API for managing network firewalls, policies, and security rules with JWT authentication, Role-Based Access Control (RBAC), and many-to-many relationship support.

## 📋 Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [API Documentation](#api-documentation)
- [Authentication](#authentication)
- [Database Schema](#database-schema)
- [Testing](#testing)
- [Development](#development)
- [Examples](#examples)
- [Contributing](#contributing)
- [License](#license)

## ✨ Features

- **JWT Authentication** for secure API access
- **Role-Based Access Control (RBAC)** with admin, operator, and user roles
- **Complete CRUD Operations** for Firewalls, Policies, and Rules
- **User Management** with registration, login, and admin controls
- **Many-to-Many Relationships** between entities
- **RESTful API** following best practices
- **SQLAlchemy ORM** with SQLite database
- **Comprehensive Test Suite** with pytest
- **Input Validation** with custom validators
- **Audit Trail** tracking created_by and last_modified_by
- **Token Blacklist** for secure logout
- **Health Check Endpoint** for monitoring
- **Permission-based Access** with hierarchical role system

## 🏗️ Architecture

```
FirewallManager/
├── instance/
│   └── firewall_manager.db         # SQLite database
├── src/
│   ├── app.py                      # Flask application entry point
│   ├── config.py                   # Configuration settings
│   ├── endpoints/                  # API endpoints
│   │   ├── __init__.py
│   │   ├── admin.py                # Admin management endpoints
│   │   ├── auth.py                 # Authentication endpoints
│   │   ├── firewalls.py            # Firewall CRUD endpoints
│   │   ├── firewall_policies.py    # Policy CRUD endpoints
│   │   ├── firewall_rules.py       # Rule CRUD endpoints
│   │   └── health.py               # Health check endpoint
│   ├── models/                     # Database models
│   │   ├── __init__.py
│   │   ├── base.py                 # SQLAlchemy base
│   │   ├── associations.py         # Many-to-many association tables
│   │   ├── firewall.py             # Firewall model
│   │   ├── firewall_policy.py      # Policy model
│   │   ├── firewall_rule.py        # Rule model
│   │   ├── user.py                 # User model
│   │   └── token_block_list.py     # Token blacklist model
│   ├── rbac/                       # Role-Based Access Control
│   │   ├── __init__.py
│   │   ├── role_based_access_control.py  # RBAC implementation
│   │   └── config/
│   │       └── permission_settings.json  # Role permissions config
│   ├── utils/                      # Utility functions
│   │   ├── __init__.py
│   │   ├── firewall_utils.py       # Firewall helper functions
│   │   ├── firewall_policies_utils.py
│   │   └── firewall_rules_utils.py
│   └── validators/                 # Input validators
│       ├── __init__.py
│       └── input_validators.py     # Validation functions
├── tests/                          # Test suite
│   ├── conftest.py                 # Pytest fixtures
│   ├── test_admin_endpoints.py     # Admin endpoint tests
│   ├── test_auth_endpoints.py      # Authentication tests
│   ├── test_firewall_endpoints.py
│   ├── test_firewall_policies_endpoints.py
│   ├── test_firewall_rules_endpoints.py
│   ├── test_rbac.py                # RBAC tests
│   └── test_validations.py         # Validator tests
├── pyproject.toml                  # Poetry dependencies
├── poetry.lock                     # Locked dependencies
├── pytest.ini                      # Pytest configuration
└── README.md                       # Documentation
```

## 🚀 Installation

### Prerequisites

- Python 3.10.12+
- Poetry (for dependency management)

### Setup Steps

1. **Clone the repository:**

   ```bash
   git clone <repository-url>
   cd FirewallManager
   ```

2. **Install dependencies with Poetry:**

   ```bash
   poetry install
   ```

3. **Activate the virtual environment:**

   ```bash
   poetry shell
   ```

4. **Set environment variables:**

   Create a `.env` file in the root directory:

   ```bash
   FLASK_ENV=development
   FLASK_DEBUG=1
   DATABASE_URI=sqlite:///instance/firewall_manager.db
   SECRET_KEY=your-secret-key-here
   JWT_SECRET_KEY=your-jwt-secret-key-here
   ```

5. **Initialize the database:**

   ```bash
   poetry run python -c "from src.app import create_app; from src.models.base import db; app = create_app(); app.app_context().push(); db.create_all()"
   ```

6. **Run the application:**

   ```bash
   poetry run python src/app.py
   ```

   The API will be available at `http://localhost:5000`

## 📚 API Documentation

### Base URL

```
http://localhost:5000/api
```

### Endpoints

#### 🔐 Authentication

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/auth/register` | Register a new user | No |
| POST | `/auth/login` | Login and get tokens | No |
| POST | `/auth/refresh` | Refresh access token | Yes (Refresh) |
| POST | `/auth/logout` | Logout and blacklist token | Yes |
| POST | `/auth/logout_refresh` | Logout refresh token | Yes (Refresh) |

#### 👤 Admin Management

| Method | Endpoint | Description | Auth Required | Role Required |
|--------|----------|-------------|---------------|---------------|
| GET | `/admin/users` | List all users | Yes | Admin |
| GET | `/admin/users/search` | Search users | Yes | Admin |
| GET | `/admin/users/<id>` | Get specific user | Yes | Admin |
| PUT | `/admin/users/<id>/role` | Update user role | Yes | Admin |
| DELETE | `/admin/users/<id>` | Delete user | Yes | Admin |
| POST | `/admin/users/<id>/reset_password` | Reset user password | Yes | Admin |
| GET | `/admin/roles` | Get all roles and permissions | Yes | Admin |

#### 🔥 Firewalls

| Method | Endpoint | Description | Auth Required | Min Role |
|--------|----------|-------------|---------------|----------|
| GET | `/firewalls` | List all firewalls | Yes | User |
| POST | `/firewalls` | Create a new firewall | Yes | Operator |
| PUT | `/firewalls/<id>` | Update firewall (replaces policies) | Yes | Operator |
| PATCH | `/firewalls/<id>/policies` | Add policies to firewall | Yes | Operator |
| DELETE | `/firewalls/<id>/policies/<policy_id>` | Remove policy from firewall | Yes | Operator |
| DELETE | `/firewalls/<id>` | Delete firewall | Yes | Operator |

#### 📋 Policies

| Method | Endpoint | Description | Auth Required | Min Role |
|--------|----------|-------------|---------------|----------|
| GET | `/firewall_policies` | List all policies | Yes | User |
| POST | `/firewall_policies` | Create a new policy | Yes | Operator |
| PUT | `/firewall_policies/<id>` | Update policy (replaces rules) | Yes | Operator |
| PATCH | `/firewall_policies/<id>/rules` | Add rules to policy | Yes | Operator |
| DELETE | `/firewall_policies/<id>/rules/<rule_id>` | Remove rule from policy | Yes | Operator |
| DELETE | `/firewall_policies/<id>` | Delete policy | Yes | Operator |

#### 🛡️ Rules

| Method | Endpoint | Description | Auth Required | Min Role |
|--------|----------|-------------|---------------|----------|
| GET | `/firewall_rules` | List all rules | Yes | User |
| POST | `/firewall_rules` | Create a new rule | Yes | Operator |
| PUT | `/firewall_rules/<id>` | Update rule | Yes | Operator |
| DELETE | `/firewall_rules/<id>` | Delete rule | Yes | Operator |

#### 🏥 Health

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/health` | Health check | No |

## 🔐 Authentication

The API uses JWT (JSON Web Tokens) for authentication and Role-Based Access Control (RBAC) for authorization.

### Role Hierarchy

1. **Admin** (Level 3): Full system access including user management
2. **Operator** (Level 2): Full access to firewall, policy, and rule management
3. **User** (Level 1): Read-only access to firewall resources

### Registration

```bash
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "SecurePassword123!",
    "email": "admin@example.com"
  }'
```

### Login

```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "SecurePassword123!"
  }'
```

Response:

```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
```

### Using the Token

Include the access token in the Authorization header for protected endpoints:

```bash
curl -X GET http://localhost:5000/api/firewalls \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc..."
```

## 🗄️ Database Schema

### Models

#### User

```python
{
    "id": "integer (primary key)",
    "username": "string (unique)",
    "password_hash": "string (hashed)",
    "email": "string (unique)",
    "role": "string (default: 'user')",
    "created_at": "datetime",
    "updated_at": "datetime"
}
```

#### Firewall

```python
{
    "id": "integer (primary key)",
    "name": "string (unique)",
    "hostname": "string (unique, format: XX-XXX-DDD)",
    "description": "string",
    "ip_address": "string (valid IP)",
    "vendor": "string",
    "model": "string",
    "os_version": "string",
    "country": "string",
    "city": "string",
    "created_at": "datetime",
    "updated_at": "datetime",
    "policies": "relationship (many-to-many)"
}
```

#### FirewallPolicy

```python
{
    "id": "integer (primary key)",
    "name": "string (unique)",
    "description": "string",
    "policy_type": "string (inbound|outbound|nat|vpn)",
    "is_active": "boolean",
    "priority": "integer (non-negative)",
    "created_by": "string",
    "last_modified_by": "string",
    "created_at": "datetime",
    "updated_at": "datetime",
    "firewalls": "relationship (many-to-many)",
    "rules": "relationship (many-to-many)"
}
```

#### FirewallRule

```python
{
    "id": "integer (primary key)",
    "name": "string",
    "description": "string",
    "action": "string (allow|deny|reject)",
    "source_ip": "string (valid IP)",
    "destination_ip": "string (valid IP)",
    "protocol": "string (tcp|udp|icmp|any)",
    "port": "integer (1-65535)",
    "is_active": "boolean",
    "created_by": "string",
    "last_modified_by": "string",
    "created_at": "datetime",
    "updated_at": "datetime",
    "policies": "relationship (many-to-many)"
}
```

#### TokenBlocklist

```python
{
    "id": "integer (primary key)",
    "jti": "string (unique)",
    "type": "string",
    "created_at": "datetime"
}
```

### Relationships

- **Firewalls ↔ Policies**: Many-to-Many
- **Policies ↔ Rules**: Many-to-Many
- **User → Created/Modified**: One-to-Many (audit trail)

## 🧪 Testing

### Run all tests

```bash
poetry run pytest
```

### Run with coverage

```bash
poetry run pytest --cov=src --cov-report=html
```

### Run specific test file

```bash
poetry run pytest tests/test_firewall_endpoints.py
```

### Run tests with verbose output

```bash
poetry run pytest -v
```

### Test Coverage Areas

- Authentication and authorization
- Role-Based Access Control (RBAC)
- Admin management endpoints
- CRUD operations for all entities
- Many-to-many relationship management
- Input validation with custom validators
- Error handling
- Token management

## 💻 Development

### Environment Variables

Create a `.env` file for configuration:

```bash
# Flask Configuration
FLASK_ENV=development
FLASK_DEBUG=1

# Database
DATABASE_URI=sqlite:///instance/firewall_manager.db

# Security
SECRET_KEY=your-secret-key-here
JWT_SECRET_KEY=your-jwt-secret-key-here
JWT_ACCESS_TOKEN_EXPIRES=3600  # 1 hour in seconds
JWT_REFRESH_TOKEN_EXPIRES=2592000  # 30 days in seconds
```

### Database Management

#### Reset database

```bash
rm instance/firewall_manager.db
poetry run python -c "from src.app import create_app; from src.models.base import db; app = create_app(); app.app_context().push(); db.create_all()"
```

#### Access database shell

```bash
sqlite3 instance/firewall_manager.db
```

#### View tables

```sql
.tables
.schema firewalls
SELECT * FROM firewalls;
```

## 📝 Examples

### Complete Workflow Example

#### 1. Register and Login

```bash
# Register a new user
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "SecurePassword123!",
    "email": "admin@example.com"
  }'

# Login to get tokens
TOKEN=$(curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "SecurePassword123!"
  }' | jq -r '.access_token')
```

#### 2. Set User Role (Admin Only)

```bash
# Get user ID first
USER_ID=$(curl -X GET http://localhost:5000/api/admin/users \
  -H "Authorization: Bearer $TOKEN" | jq -r '.users[] | select(.username=="admin") | .id')

# Update user role to admin
curl -X PUT http://localhost:5000/api/admin/users/$USER_ID/role \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin"}'
```

#### 3. Create Rules

```bash
# Create a rule for SSH
curl -X POST http://localhost:5000/api/firewall_rules \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Allow SSH",
    "description": "Allow SSH traffic",
    "action": "allow",
    "source_ip": "10.0.0.0",
    "destination_ip": "192.168.1.10",
    "protocol": "tcp",
    "port": 22,
    "is_active": true
  }'
```

#### 4. Create Policy with Rules

```bash
# Create a policy
curl -X POST http://localhost:5000/api/firewall_policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Server Management Policy",
    "description": "Policy for server management",
    "policy_type": "inbound",
    "is_active": true,
    "priority": 1,
    "rules_id": [1]
  }'
```

#### 5. Create Firewall with Policies

```bash
# Create a firewall
curl -X POST http://localhost:5000/api/firewalls \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Main Firewall",
    "hostname": "us-nyc-001",
    "ip_address": "192.168.1.1",
    "vendor": "Cisco",
    "model": "ASA 5505",
    "os_version": "9.2",
    "country": "USA",
    "city": "New York",
    "policies_ids": [1]
  }'
```

#### 6. Add More Policies (PATCH)

```bash
# Add policies without removing existing ones
curl -X PATCH http://localhost:5000/api/firewalls/1/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"policies_ids": [2, 3]}'
```

#### 7. User Management (Admin Only)

```bash
# List all users
curl -X GET http://localhost:5000/api/admin/users \
  -H "Authorization: Bearer $TOKEN"

# Search for users
curl -X GET http://localhost:5000/api/admin/users/search?query=admin \
  -H "Authorization: Bearer $TOKEN"

# Reset user password
curl -X POST http://localhost:5000/api/admin/users/$USER_ID/reset_password \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"password": "NewSecurePassword123!"}'

# Get all roles and permissions
curl -X GET http://localhost:5000/api/admin/roles \
  -H "Authorization: Bearer $TOKEN"
```

#### 8. Logout

```bash
# Logout and blacklist token
curl -X POST http://localhost:5000/api/auth/logout \
  -H "Authorization: Bearer $TOKEN"
```

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Code Style

- Follow PEP 8 guidelines
- Use type hints where appropriate
- Write docstrings for all functions
- Maintain test coverage above 80%
- Include tests for new features

### Testing Guidelines

- Write unit tests for all new functions
- Test both success and failure cases
- Mock external dependencies
- Test authentication and authorization
- Test RBAC permissions

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Flask framework for the web foundation
- Flask-JWT-Extended for JWT authentication
- SQLAlchemy for ORM capabilities
- Poetry for dependency management
- Pytest for testing framework

## 📧 Contact

For questions or support, please open an issue in the GitHub repository.

---
**Version:** 1.0.0  
**Last Updated:** September 2025  
**Author:** Your Name
