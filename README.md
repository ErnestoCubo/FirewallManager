# FirewallManager

## Project Description

FirewallManager is a RESTful API for managing firewalls, firewall policies, and rules. It allows users to create, update, delete, and retrieve firewall configurations, supporting operations for network security management in a scalable way.

## Project Structure

```
FirewallManager/
├── instance/
│   └── firewall_manager.db         # SQLite database file
├── src/
│   ├── app.py                     # Main application entrypoint
│   ├── config.py                  # Configuration settings
│   ├── endpoints/                 # API endpoint definitions
│   │   ├── firewalls.py           # Firewall endpoints
│   │   ├── health.py              # Health check endpoint
│   ├── models/                    # ORM models
│   │   ├── firewall.py            # Firewall model
│   │   ├── firewall_policy.py     # Policy model
│   │   ├── firewall_rule.py       # Rule model
│   │   ├── base.py                # Base model
│   ├── utils/                     # Utility functions
│   │   └── firewall_utils.py      # Firewall helpers
├── tests/
│   ├── test_firewall_endpoints.py # Endpoint tests
│   └── conftest.py                # Pytest fixtures
├── pyproject.toml                 # Poetry configuration
├── poetry.lock                    # Poetry lock file
├── pytest.ini                     # Pytest configuration
└── README.md                      # Project documentation
```

## API Endpoints

- `GET /api/firewalls` - List all firewalls
- `POST /api/firewalls` - Create a new firewall
- `PUT /api/firewalls/<hostname>` - Update a firewall by hostname
- `DELETE /api/firewalls/<hostname>` - Delete a firewall by hostname
- `GET /api/health` - Health check endpoint

## Defined Models

- **Firewall** (`models/firewall.py`):
  - `hostname`: str
  - `name`: str
  - `description`: str
  - `ip_address`: str
  - `city`: str
  - `country`: str

- **FirewallPolicy** (`models/firewall_policy.py`):
  - Policy attributes (see file for details)

- **FirewallRule** (`models/firewall_rule.py`):
  - Rule attributes (see file for details)

## Setup Guide

1. **Clone the repository:**

   ```bash
   git clone <repo-url>
   cd FirewallManager
   ```

2. **Install dependencies with Poetry:**

   ```bash
   poetry install
   ```

3. **Run the application:**

   ```bash
   poetry run python src/app.py
   ```

4. **Run tests:**

   ```bash
   poetry run pytest
   ```

5. **Configuration:**
   - Edit `src/config.py` for custom settings.
   - The SQLite database is located at `instance/firewall_manager.db`.

## Notes

- The API is designed for local development and testing. For production, configure environment variables and database settings as needed.
- See `tests/` for example usage and endpoint tests.
