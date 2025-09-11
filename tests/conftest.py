import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.app import create_app
from src.models.base import db
from src.config import TestConfig

@pytest.fixture
def app():
    app = create_app()
    app.config.from_object(TestConfig)

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def sample_firewall():
    return {
        "name": "TestFirewall",
        "description": "A test firewall",
        "hostname": "es-mad-fw1",
        "ip_address": "192.168.1.1",
        "vendor": "cisco",
        "model": "cisco_2901",
        "os_version": "15.1(4)M",
        "country": "spain",
        "city": "madrid",
    }

@pytest.fixture
def sample_firewall_policy():
    return {
        "name": "TestPolicy",
        "description": "A test firewall policy",
        "policy_type": "inbound",
        "is_active": True,
        "priority": 1,
        "rules": [],
    }

@pytest.fixture
def sample_firewall_rule():
    return {
        "name": "AllowSSH",
        "description": "Allow SSH traffic",
        "action": "allow",
        "source_ip": "192.168.1.10",
        "destination_ip": "192.168.1.20",
        "protocol": "tcp",
        "port": 22,
        "is_active": True,
        "created_by": "tester",
        "last_modified_by": "tester",
    }

@pytest.fixture
def sample_user():
    return {
        "username": "testuser",
        "password": "TestPassword123!",
        "email": "testuser@example.com"
    }