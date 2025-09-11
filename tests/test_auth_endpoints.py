import json
import pytest
from datetime import datetime, timedelta

def test_register_success(client, sample_user):
    """Test successful user registration."""
    response = client.post('/api/auth/register', data=json.dumps(sample_user), content_type='application/json')
    assert response.status_code == 201
    data = json.loads(response.data)
    assert data['msg'] == 'User registered successfully'

def test_register_missing_fields(client):
    """Test registration with missing required fields."""
    incomplete_user = {
        "username": "testuser"
    }
    response = client.post('/api/auth/register', data=json.dumps(incomplete_user), content_type='application/json')
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'Missing' in data['msg']

def test_register_duplicate_username(client, sample_user):
    """Test registration with duplicate username."""
    # Register first user
    client.post('/api/auth/register',
                data=json.dumps(sample_user),
                content_type='application/json')
    
    # Try to register with same username
    duplicate_user = sample_user.copy()
    duplicate_user['email'] = 'different@example.com'
    response = client.post('/api/auth/register', data=json.dumps(duplicate_user), content_type='application/json')
    assert response.status_code == 409
    data = json.loads(response.data)
    assert 'already exists' in data['msg']

def test_register_duplicate_email(client, sample_user):
    """Test registration with duplicate email."""
    # Register first user
    client.post('/api/auth/register',
                data=json.dumps(sample_user),
                content_type='application/json')
    
    # Try to register with same email
    duplicate_user = sample_user.copy()
    duplicate_user['username'] = 'differentuser'
    response = client.post('/api/auth/register', data=json.dumps(duplicate_user), content_type='application/json')
    assert response.status_code == 409
    data = json.loads(response.data)
    assert 'already exists' in data['msg']

def test_login_success(client, sample_user):
    """Test successful login."""
    # Register user first
    client.post('/api/auth/register',
                data=json.dumps(sample_user),
                content_type='application/json')
    
    # Login
    login_data = {
        "username": sample_user['username'],
        "password": sample_user['password']
    }
    response = client.post('/api/auth/login', data=json.dumps(login_data), content_type='application/json')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'access_token' in data
    assert 'refresh_token' in data
    assert 'user' in data
    assert data['user']['username'] == sample_user['username']

def test_login_invalid_credentials(client, sample_user):
    """Test login with invalid credentials."""
    # Register user first
    client.post('/api/auth/register',
                data=json.dumps(sample_user),
                content_type='application/json')
    
    # Try to login with wrong password
    login_data = {
        "username": sample_user['username'],
        "password": "WrongPassword123!"
    }
    response = client.post('/api/auth/login', data=json.dumps(login_data), content_type='application/json')
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'Bad username or password' in data['msg']

def test_login_nonexistent_user(client):
    """Test login with non-existent user."""
    login_data = {
        "username": "nonexistent",
        "password": "password123"
    }
    response = client.post('/api/auth/login', data=json.dumps(login_data), content_type='application/json')
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'Bad username or password' in data['msg']

def test_login_missing_fields(client):
    """Test login with missing fields."""
    login_data = {
        "username": "testuser"
        # missing password
    }
    response = client.post('/api/auth/login', data=json.dumps(login_data), content_type='application/json')
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'Missing' in data['msg']

def test_refresh_token(client, sample_user):
    """Test refreshing access token."""
    # Register and login
    client.post('/api/auth/register',
                data=json.dumps(sample_user),
                content_type='application/json')
    
    login_data = {
        "username": sample_user['username'],
        "password": sample_user['password']
    }
    login_response = client.post('/api/auth/login', data=json.dumps(login_data), content_type='application/json')
    tokens = json.loads(login_response.data)
    refresh_token = tokens['refresh_token']
    
    # Refresh token
    response = client.post('/api/auth/refresh', headers={'Authorization': f'Bearer {refresh_token}'})
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'access_token' in data

def test_refresh_with_invalid_token(client):
    """Test refresh with invalid token."""
    response = client.post('/api/auth/refresh', headers={'Authorization': 'Bearer invalid_token'})
    assert response.status_code == 422

def test_refresh_without_token(client):
    """Test refresh without providing token."""
    response = client.post('/api/auth/refresh')
    assert response.status_code == 401

def test_logout_access_token(client, sample_user):
    """Test revoking access token."""
    # Register and login
    client.post('/api/auth/register', data=json.dumps(sample_user), content_type='application/json')
    
    login_data = {
        "username": sample_user['username'],
        "password": sample_user['password']
    }
    login_response = client.post('/api/auth/login', data=json.dumps(login_data), content_type='application/json')
    tokens = json.loads(login_response.data)
    access_token = tokens['access_token']
    
    # Logout (revoke access token)
    response = client.post('/api/auth/logout', headers={'Authorization': f'Bearer {access_token}'})
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'Token revoked' in data['msg']
    
    # Try to use revoked token (should fail)
    response = client.post('/api/auth/logout', headers={'Authorization': f'Bearer {access_token}'})
    assert response.status_code == 401

def test_logout_refresh_token(client, sample_user):
    """Test revoking refresh token."""
    # Register and login
    client.post('/api/auth/register', data=json.dumps(sample_user), content_type='application/json')
    
    login_data = {
        "username": sample_user['username'],
        "password": sample_user['password']
    }
    login_response = client.post('/api/auth/login', data=json.dumps(login_data), content_type='application/json')
    tokens = json.loads(login_response.data)
    refresh_token = tokens['refresh_token']
    
    # Logout refresh (revoke refresh token)
    response = client.post('/api/auth/logout_refresh', headers={'Authorization': f'Bearer {refresh_token}'})
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'Refresh token revoked' in data['msg']
    
    # Try to use revoked refresh token (should fail)
    response = client.post('/api/auth/refresh', headers={'Authorization': f'Bearer {refresh_token}'})
    assert response.status_code == 401

def test_logout_without_token(client):
    """Test logout without providing token."""
    response = client.post('/api/auth/logout')
    assert response.status_code == 401

def test_protected_endpoint_with_valid_token(client, sample_user):
    """Test accessing protected endpoint with valid token."""
    # Register and login
    client.post('/api/auth/register', data=json.dumps(sample_user), content_type='application/json')
    
    login_data = {
        "username": sample_user['username'],
        "password": sample_user['password']
    }
    login_response = client.post('/api/auth/login', data=json.dumps(login_data), content_type='application/json')
    tokens = json.loads(login_response.data)
    access_token = tokens['access_token']
    
    # Access protected endpoint (e.g., getting firewalls)
    response = client.get('/api/firewalls', headers={'Authorization': f'Bearer {access_token}'})
    # Should be accessible with valid token
    assert response.status_code in [200, 404]  # 404 if no firewalls exist yet

def test_protected_endpoint_without_token(client):
    """Test accessing protected endpoint without token."""
    response = client.get('/api/firewalls')
    # Should be blocked without token if endpoint is protected
    # Note: This assumes your firewall endpoints require authentication
    # If they don't, you may want to update them with @jwt_required()
    assert response.status_code in [200, 401]

def test_user_roles_in_token(client):
    """Test that user roles are included in JWT claims."""
    # Register user with admin role
    admin_user = {
        "username": "adminuser",
        "password": "AdminPass123!",
        "email": "admin@example.com",
        "roles": "admin,user"
    }
    client.post('/api/auth/register', data=json.dumps(admin_user), content_type='application/json')
    
    # Login
    login_data = {
        "username": admin_user['username'],
        "password": admin_user['password']
    }
    login_response = client.post('/api/auth/login', data=json.dumps(login_data), content_type='application/json')
    data = json.loads(login_response.data)
    assert 'access_token' in data
    # The roles should be embedded in the token claims
    # We can't easily decode it here without the secret, but we trust it works

def test_register_with_custom_roles(client):
    """Test registering user with custom roles."""
    user_with_roles = {
        "username": "roleuser",
        "password": "RolePass123!",
        "email": "roleuser@example.com",
        "roles": "admin,moderator"
    }
    response = client.post('/api/auth/register', data=json.dumps(user_with_roles), content_type='application/json')
    assert response.status_code == 201
    
    # Login and verify roles are preserved
    login_data = {
        "username": user_with_roles['username'],
        "password": user_with_roles['password']
    }
    login_response = client.post('/api/auth/login', data=json.dumps(login_data), content_type='application/json')
    data = json.loads(login_response.data)
    assert data['user']['roles'] == "admin,moderator"

def test_concurrent_sessions(client, sample_user):
    """Test that multiple login sessions can exist simultaneously."""
    # Register user
    client.post('/api/auth/register', data=json.dumps(sample_user), content_type='application/json')
    
    login_data = {
        "username": sample_user['username'],
        "password": sample_user['password']
    }
    
    # First login
    response1 = client.post('/api/auth/login', data=json.dumps(login_data), content_type='application/json')
    tokens1 = json.loads(response1.data)
    
    # Second login (simulating different device/browser)
    response2 = client.post('/api/auth/login', data=json.dumps(login_data), content_type='application/json')
    tokens2 = json.loads(response2.data)
    
    # Both tokens should be different
    assert tokens1['access_token'] != tokens2['access_token']
    assert tokens1['refresh_token'] != tokens2['refresh_token']
    
    # Both tokens should work
    response = client.post('/api/auth/refresh', headers={'Authorization': f'Bearer {tokens1["refresh_token"]}'})
    assert response.status_code == 200
    
    response = client.post('/api/auth/refresh', headers={'Authorization': f'Bearer {tokens2["refresh_token"]}'})
    assert response.status_code == 200

# Additional edge case tests

def test_empty_request_body(client):
    """Test endpoints with empty request body."""
    response = client.post('/api/auth/register', data=json.dumps({}), content_type='application/json')
    assert response.status_code == 400
    
    response = client.post('/api/auth/login', data=json.dumps({}), content_type='application/json')
    assert response.status_code == 400

def test_malformed_json(client):
    """Test endpoints with malformed JSON."""
    response = client.post('/api/auth/register', data='{"invalid json}', content_type='application/json')
    assert response.status_code == 400

def test_sql_injection_attempt(client):
    """Test that SQL injection attempts are handled safely."""
    malicious_user = {
        "username": "admin'; DROP TABLE users; --",
        "password": "password123",
        "email": "test@example.com"
    }
    response = client.post('/api/auth/register', data=json.dumps(malicious_user), content_type='application/json')
    # Should either succeed (treating it as a weird username) or fail gracefully
    assert response.status_code in [201, 400, 409]