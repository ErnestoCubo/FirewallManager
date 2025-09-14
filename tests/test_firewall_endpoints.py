import pytest
import json
from datetime import timedelta
from src.models.user import User
from src.models.base import db

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


def test_patch_firewall_policies(client, sample_firewall, sample_firewall_policy, sample_user):
    """Test patching firewall to add policies without removing existing ones"""
    headers = get_auth_headers(client, sample_user)
    
    # Create a firewall
    client.post("/api/firewalls", data=json.dumps(sample_firewall), headers=headers)
    
    # Create two policies
    client.post("/api/firewall_policies", data=json.dumps(sample_firewall_policy), headers=headers)
    new_policy = sample_firewall_policy.copy()
    new_policy["name"] = "TestPolicy2"
    client.post("/api/firewall_policies", data=json.dumps(new_policy), headers=headers)

    # Patch the firewall to add the first policy
    patch_data_1 = {
        "policies_ids": [1]
    }
    response = client.patch("/api/firewalls/1/policies", data=json.dumps(patch_data_1), headers=headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data["firewall"]["policies"]) == 1
    assert data["firewall"]["policies"][0]["id"] == 1

    # Patch the firewall to add the second policy without removing the first
    patch_data_2 = {
        "policies_ids": [2]
    }
    response = client.patch("/api/firewalls/1/policies", data=json.dumps(patch_data_2), headers=headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data["firewall"]["policies"]) == 2
    policy_ids = [policy["id"] for policy in data["firewall"]["policies"]]
    assert 1 in policy_ids and 2 in policy_ids


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