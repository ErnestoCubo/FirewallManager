import json
import pytest
from werkzeug.security import generate_password_hash
from src.models.user import User
from src.models.base import db


def create_user_with_role(client, username, role):
    """Helper to create a user with specific role and return auth headers"""
    from src.models.user import User
    from src.models.base import db
    from werkzeug.security import generate_password_hash
    
    # Create user
    user = User(
        username=username,
        email=f"{username}@example.com",
        password_hash=generate_password_hash("password123", method='scrypt', salt_length=8),
        role=role
    )
    db.session.add(user)
    db.session.commit()
    
    # Login to get token
    login_data = {
        "username": username,
        "password": "password123"
    }
    response = client.post('/api/auth/login',
                          data=json.dumps(login_data),
                          headers={'Content-Type': 'application/json'})
    token = json.loads(response.data)["access_token"]
    
    return {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

def create_user_headers(client):
    """Create headers for a regular user"""
    return create_user_with_role(client, "test_user", "user")

def create_operator_headers(client):
    """Create headers for an operator user"""
    return create_user_with_role(client, "test_operator", "operator")

def create_admin_headers(client):
    """Create headers for an admin user"""
    return create_user_with_role(client, "test_admin", "admin")


class TestRoleHierarchy:
    def test_user_role_read_only_access(self, client):
        """Test that user role has read-only access"""
        user_headers = create_user_headers(client)
        
        # User should be able to read
        response = client.get('/api/firewalls', headers=user_headers)
        assert response.status_code == 200
        
        # User should NOT be able to create
        firewall_data = {
            "name": "TestFirewall",
            "hostname": "test.example.com",
            "ip_address": "192.168.1.1",
            "vendor": "TestVendor",
            "model": "TestModel",
            "os_version": "1.0"
        }
        response = client.post('/api/firewalls',
                              data=json.dumps(firewall_data),
                              headers=user_headers)
        assert response.status_code == 403

    def test_operator_role_full_firewall_access(self, client):
        """Test that operator role has full firewall access"""
        operator_headers = create_operator_headers(client)
        
        # Operator should be able to create firewall
        firewall_data = {
            "name": "OperatorFirewall",
            "hostname": "operator.example.com",
            "ip_address": "192.168.1.2",
            "vendor": "TestVendor",
            "model": "TestModel",
            "os_version": "1.0"
        }
        response = client.post('/api/firewalls',
                              data=json.dumps(firewall_data),
                              headers=operator_headers)
        assert response.status_code == 201

class TestUserManagementPermissions:
    def test_user_cannot_access_user_management(self, client):
        """Test that regular users cannot access user management"""
        user_headers = create_user_headers(client)
        
        # User should not be able to access admin endpoints
        response = client.get('/api/admin/users', headers=user_headers)
        assert response.status_code == 403  # Should be 403 for forbidden

class TestRBACEdgeCases:
    def test_unauthorized_request(self, client):
        """Test request without authentication"""
        response = client.get('/api/firewalls')
        assert response.status_code == 401  # Should be 401 for unauthorized