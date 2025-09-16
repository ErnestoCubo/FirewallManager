import pytest
import json
from datetime import timedelta
from src.models.user import User
from src.models.base import db
from src.models.firewall_policy import FirewallPolicy

def get_auth_headers(client, sample_user):
    """Helper function to get authentication headers"""
    # Register user
    client.post("/api/auth/register", data=json.dumps(sample_user), content_type="application/json")
    
    user = User.query.filter_by(id=1).first()
    user.role = "admin"
    db.session.commit()

    # Login to get token
    login_response = client.post("/api/auth/login", data=json.dumps({"username": sample_user["username"], "password": sample_user["password"]}), content_type="application/json")

    token = json.loads(login_response.data)["access_token"]
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def create_operator_user(client):
    """Create an operator user and return JWT headers"""
    from src.models.user import User
    from src.models.base import db
    from werkzeug.security import generate_password_hash
    
    # Create operator user
    operator = User(
        username="operator_user",
        email="operator@example.com",
        password_hash=generate_password_hash("password123", method='scrypt', salt_length=8),
        role="operator"
    )
    db.session.add(operator)
    db.session.commit()
    
    # Login to get token
    login_data = {
        "username": "operator_user",
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


def test_get_firewalls_empty(client, sample_user):
    """Test retrieving all firewalls when none exist"""
    headers = get_auth_headers(client, sample_user)
    response = client.get("/api/firewalls", headers=headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["firewalls"] == []


def test_create_firewall(client, sample_firewall, sample_user):
    """Test creating a new firewall"""
    headers = get_auth_headers(client, sample_user)
    
    # Create the firewall
    response = client.post("/api/firewalls", data=json.dumps(sample_firewall), headers=headers)
    assert response.status_code == 201
    data = json.loads(response.data)
    assert data["message"] == "Firewall created"
    assert data["firewall"]["hostname"] == sample_firewall["hostname"]


def test_create_firewall_duplicate_hostname(client, sample_firewall, sample_user):
    """Test creating a firewall with duplicate hostname"""
    headers = get_auth_headers(client, sample_user)
    
    # Create the first firewall
    client.post("/api/firewalls", data=json.dumps(sample_firewall), headers=headers)
    
    # Attempt to create a second firewall with the same hostname
    response = client.post("/api/firewalls", data=json.dumps(sample_firewall), headers=headers)
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "already exists" in data["message"]


def test_create_firewall_duplicate_name(client, sample_firewall, sample_user):
    """Test creating a firewall with duplicate name"""
    headers = get_auth_headers(client, sample_user)
    
    # Create the first firewall
    client.post("/api/firewalls", 
                data=json.dumps(sample_firewall), 
                headers=headers)
    
    # Attempt to create a second firewall with the same name but different hostname
    new_firewall = sample_firewall.copy()
    new_firewall["hostname"] = "es-mad-fw2"
    response = client.post("/api/firewalls", data=json.dumps(new_firewall), headers=headers)
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "already exists" in data["message"]


def test_update_firewall(client, sample_firewall, sample_user):
    """Test updating an existing firewall"""
    headers = get_auth_headers(client, sample_user)
    
    # Create a firewall
    client.post("/api/firewalls", data=json.dumps(sample_firewall), headers=headers)
    
    # Update the firewall
    update_data = {
        "description": "Updated description",
        "ip_address": "192.168.1.2"
    }
    response = client.put("/api/firewalls/1", data=json.dumps(update_data), headers=headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "Firewall updated" in data["message"]
    assert data["firewall"]["description"] == update_data["description"]
    assert data["firewall"]["ip_address"] == update_data["ip_address"]


def test_update_firewall_not_found(client, sample_user):
    """Test updating a non-existent firewall"""
    headers = get_auth_headers(client, sample_user)
    
    update_data = {
        "description": "Updated description",
        "ip_address": "192.168.1.2"
    }
    response = client.put("/api/firewalls/999", data=json.dumps(update_data), headers=headers)
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "not found" in data["message"]


def test_update_firewall_duplicate_hostname(client, sample_firewall, sample_user):
    """Test updating a firewall to a duplicate hostname"""
    headers = get_auth_headers(client, sample_user)
    
    # Create first firewall
    client.post("/api/firewalls", data=json.dumps(sample_firewall), headers=headers)
    
    # Create second firewall
    new_firewall = sample_firewall.copy()
    new_firewall["hostname"] = "es-mad-fw2"
    new_firewall["name"] = "TestFirewall2"
    client.post("/api/firewalls", data=json.dumps(new_firewall), headers=headers)

    # Attempt to update first firewall's hostname to the second's
    update_data = {
        "hostname": "es-mad-fw2"
    }
    response = client.put("/api/firewalls/1", data=json.dumps(update_data), headers=headers)
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "already exists" in data["message"]


def test_patch_firewall_policies(client, sample_firewall):
    """Test patching firewall policies"""
    # Use the existing create_operator_user function from this file
    headers = create_operator_user(client)
    
    response = client.post('/api/firewalls', 
                          data=json.dumps(sample_firewall), 
                          headers=headers)
    assert response.status_code == 201
    firewall_id = json.loads(response.data)["firewall"]["id"]
    
    # Create a policy to add
    policy = FirewallPolicy(
        name="TestPolicy",
        policy_type="security",
        created_by="testuser",
        last_modified_by="testuser"
    )
    db.session.add(policy)
    db.session.commit()
    
    # Now patch with valid policy ID
    patch_data = {"policies_ids": [policy.id]}
    response = client.patch(f'/api/firewalls/{firewall_id}/policies',
                           data=json.dumps(patch_data),
                           headers=headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data["firewall"]["policies"]) == 1


def test_get_firewalls_non_empty(client, sample_firewall, sample_user):
    """Test retrieving all firewalls when some exist"""
    headers = get_auth_headers(client, sample_user)
    
    # Create a firewall
    client.post("/api/firewalls", data=json.dumps(sample_firewall), headers=headers)
    
    # Retrieve all firewalls
    response = client.get("/api/firewalls", headers=headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data["firewalls"]) == 1
    assert data["firewalls"][0]["hostname"] == sample_firewall["hostname"]


def test_delete_firewall(client, sample_firewall, sample_user):
    """Test deleting an existing firewall"""
    headers = get_auth_headers(client, sample_user)
    
    # Create a firewall
    client.post("/api/firewalls", data=json.dumps(sample_firewall), headers=headers)
    
    # Delete the firewall
    response = client.delete("/api/firewalls/1", headers=headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "deleted" in data["message"]


def test_delete_firewall_not_found(client, sample_user):
    """Test deleting a non-existent firewall"""
    headers = get_auth_headers(client, sample_user)
    
    # Attempt to delete a non-existent firewall
    response = client.delete("/api/firewalls/999", headers=headers)
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "not found" in data["message"]


def test_get_firewalls_unauthorized(client):
    """Test retrieving all firewalls without authentication"""
    response = client.get("/api/firewalls")
    assert response.status_code == 401