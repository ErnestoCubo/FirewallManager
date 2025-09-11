# FirewallManager

A comprehensive RESTful API for managing network firewalls, policies, and security rules with many-to-many relationship support.

## 📋 Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [API Documentation](#api-documentation)
- [Database Schema](#database-schema)
- [Testing](#testing)
- [Development](#development)
- [Examples](#examples)
- [Contributing](#contributing)
- [License](#license)

## ✨ Features

- **Complete CRUD Operations** for Firewalls, Policies, and Rules
- **Many-to-Many Relationships** between entities
- **RESTful API** following best practices
- **SQLAlchemy ORM** with SQLite database
- **Comprehensive Test Suite** with pytest
- **Input Validation** and error handling
- **Health Check Endpoint** for monitoring

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
│   │   └── firewall_rule.py        # Rule model
│   └── utils/                      # Utility functions
│       ├── __init__.py
│       ├── firewall_utils.py       # Firewall helper functions
│       ├── firewall_policies_utils.py
│       └── firewall_rules_utils.py
├── tests/                          # Test suite
│   ├── conftest.py                 # Pytest fixtures
│   ├── test_firewall_endpoints.py
│   ├── test_firewall_policies_endpoints.py
│   └── test_firewall_rules_endpoint.py
├── pyproject.toml                  # Poetry dependencies
├── poetry.lock                     # Locked dependencies
├── pytest.ini                      # Pytest configuration
└── README.md                       # Documentation
```

## 🚀 Installation

### Prerequisites

- Python 3.8+
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

4. **Initialize the database:**

   ```bash
   poetry run python -c "from src.app import app, db; app.app_context().push(); db.create_all()"
   ```

5. **Run the application:**

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

#### 🔥 Firewalls

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/firewalls` | List all firewalls |
| POST | `/firewalls` | Create a new firewall |
| GET | `/firewalls/<hostname>` | Get firewall by hostname |
| PUT | `/firewalls/<hostname>` | Update firewall (replaces policies) |
| PATCH | `/firewalls/<hostname>/policies` | Add policies to firewall |
| DELETE | `/firewalls/<hostname>` | Delete firewall |

#### 📋 Policies

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/firewall_policies` | List all policies |
| POST | `/firewall_policies` | Create a new policy |
| GET | `/firewall_policies/<id>` | Get policy by ID |
| PUT | `/firewall_policies/<id>` | Update policy (replaces rules) |
| PATCH | `/firewall_policies/<id>/rules` | Add rules to policy |
| DELETE | `/firewall_policies/<id>` | Delete policy |

#### 🛡️ Rules

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/firewall_rules` | List all rules |
| POST | `/firewall_rules` | Create a new rule |
| GET | `/firewall_rules/<id>` | Get rule by ID |
| PUT | `/firewall_rules/<id>` | Update rule |
| DELETE | `/firewall_rules/<id>` | Delete rule |

#### 🏥 Health

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |

## 🗄️ Database Schema

### Models

#### Firewall

```python
{
    "id": "integer (primary key)",
    "name": "string (unique)",
    "hostname": "string (unique)",
    "description": "string",
    "ip_address": "string",
    "vendor": "string",
    "model": "string",
    "os_version": "string",
    "country": "string",
    "city": "string",
    "created_at": "datetime",
    "updated_at": "datetime"
}
```

#### FirewallPolicy

```python
{
    "id": "integer (primary key)",
    "name": "string (unique)",
    "description": "string",
    "policy_type": "string",
    "is_active": "boolean",
    "priority": "integer",
    "created_by": "string",
    "last_modified_by": "string",
    "created_at": "datetime",
    "updated_at": "datetime"
}
```

#### FirewallRule

```python
{
    "id": "integer (primary key)",
    "name": "string",
    "description": "string",
    "action": "string",
    "source_ip": "string",
    "destination_ip": "string",
    "protocol": "string",
    "port": "string",
    "is_active": "boolean",
    "created_by": "string",
    "last_modified_by": "string",
    "created_at": "datetime",
    "updated_at": "datetime"
}
```

### Relationships

- **Firewalls ↔ Policies**: Many-to-Many
- **Policies ↔ Rules**: Many-to-Many

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

## 💻 Development

### Environment Variables

Create a `.env` file for custom configuration:

```bash
FLASK_ENV=development
FLASK_DEBUG=1
DATABASE_URI=sqlite:///instance/firewall_manager.db
```

### Database Management

#### Reset database

```bash
rm instance/firewall_manager.db
poetry run python -c "from src.app import app, db; app.app_context().push(); db.create_all()"
```

#### Access database shell

```bash
sqlite3 instance/firewall_manager.db
```

## 📝 Examples

### Create a Firewall with Policies

```bash
# Create a firewall
curl -X POST http://localhost:5000/api/firewalls \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Main Firewall",
    "hostname": "fw-main-01",
    "ip_address": "192.168.1.1",
    "vendor": "Cisco",
    "model": "ASA 5505",
    "os_version": "9.2",
    "country": "USA",
    "city": "New York",
    "policies_ids": [1, 2]
  }'
```

### Create a Policy with Rules

```bash
# Create a policy
curl -X POST http://localhost:5000/api/firewall_policies \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Web Server Policy",
    "description": "Policy for web servers",
    "policy_type": "inbound",
    "is_active": true,
    "priority": 1,
    "rules_ids": [1, 2, 3]
  }'
```

### Add Policies to Existing Firewall (PATCH)

```bash
# Add policies without removing existing ones
curl -X PATCH http://localhost:5000/api/firewalls/fw-main-01/policies \
  -H "Content-Type: application/json" \
  -d '{"policies_ids": [3, 4]}'
```

### Replace All Firewall Policies (PUT)

```bash
# Replace all existing policies
curl -X PUT http://localhost:5000/api/firewalls/fw-main-01 \
  -H "Content-Type: application/json" \
  -d '{"policies_ids": [5, 6]}'
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

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Flask framework for the web foundation
- SQLAlchemy for ORM capabilities
- Poetry for dependency management
- Pytest for testing framework

## 📧 Contact

For questions or support, please open an issue in the GitHub repository.

---
**Version:** 1.0.0  
**Last Updated:** September 2025
