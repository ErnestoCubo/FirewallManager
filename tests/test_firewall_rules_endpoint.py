import pytest
import json

def get_auth_headers(client, sample_user):
    """Helper function to get authentication headers"""
    # Register user
    client.post("/api/auth/register", data=json.dumps(sample_user), content_type="application/json")
    
    # Login to get token
    login_response = client.post("/api/auth/login", data=json.dumps({"username": sample_user["username"], "password": sample_user["password"]}), content_type="application/json")

    token = json.loads(login_response.data)["access_token"]
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def test_get_firewall_rules_empty(client, sample_user):
    """Test retrieving all firewall rules when none exist"""
    headers = get_auth_headers(client, sample_user)
    response = client.get("/api/firewall_rules", headers=headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["firewall_rules"] == []


def test_create_firewall_rule(client, sample_firewall_rule, sample_user):
    """Test creating a new firewall rule"""
    headers = get_auth_headers(client, sample_user)
    response = client.post("/api/firewall_rules", data=json.dumps(sample_firewall_rule), headers=headers)
    assert response.status_code == 201
    data = json.loads(response.data)
    assert data["message"] == "Firewall rule created"
    assert data["firewall_rule"]["name"] == sample_firewall_rule["name"]


def test_create_firewall_rule_duplicate_name(client, sample_firewall_rule, sample_user):
    """Test creating a firewall rule with duplicate name (should succeed as names are not unique)"""
    headers = get_auth_headers(client, sample_user)
    
    # Create the first firewall rule
    client.post("/api/firewall_rules", data=json.dumps(sample_firewall_rule), headers=headers)
    
    # Create a second firewall rule with the same name (should succeed)
    response = client.post("/api/firewall_rules", data=json.dumps(sample_firewall_rule), headers=headers)
    assert response.status_code == 201
    data = json.loads(response.data)
    assert data["message"] == "Firewall rule created"
    assert data["firewall_rule"]["name"] == sample_firewall_rule["name"]


def test_create_firewall_rule_missing_fields(client, sample_user):
    """Test creating a firewall rule with missing required fields"""
    headers = get_auth_headers(client, sample_user)
    
    incomplete_rule = {
        "name": "IncompleteRule",
        "description": "Missing required fields"
    }
    
    response = client.post("/api/firewall_rules", data=json.dumps(incomplete_rule), headers=headers)
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "Missing required field" in data["message"]


def test_update_firewall_rule(client, sample_firewall_rule, sample_user):
    """Test updating an existing firewall rule"""
    headers = get_auth_headers(client, sample_user)
    
    # Create a firewall rule
    create_response = client.post("/api/firewall_rules", data=json.dumps(sample_firewall_rule), headers=headers)
    rule_id = json.loads(create_response.data)["firewall_rule"]["id"]
    
    # Update the firewall rule
    update_data = {
        "description": "Updated description",
        "is_active": False
    }

    response = client.put(f"/api/firewall_rules/{rule_id}", data=json.dumps(update_data), headers=headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "Firewall rule updated" in data["message"]
    assert data["firewall_rule"]["description"] == update_data["description"]
    assert data["firewall_rule"]["is_active"] == update_data["is_active"]


def test_update_nonexistent_firewall_rule(client, sample_user):
    """Test updating a non-existent firewall rule"""
    headers = get_auth_headers(client, sample_user)
    
    update_data = {
        "description": "Updated description",
        "is_active": False
    }
    response = client.put("/api/firewall_rules/999", data=json.dumps(update_data), headers=headers)
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "not found" in data["message"]


def test_delete_firewall_rule(client, sample_firewall_rule, sample_user):
    """Test deleting an existing firewall rule"""
    headers = get_auth_headers(client, sample_user)
    
    # Create a firewall rule
    create_response = client.post("/api/firewall_rules", data=json.dumps(sample_firewall_rule), headers=headers)
    rule_id = json.loads(create_response.data)["firewall_rule"]["id"]
    
    # Delete the firewall rule
    response = client.delete(f"/api/firewall_rules/{rule_id}", headers=headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "deleted" in data["message"]


def test_delete_nonexistent_firewall_rule(client, sample_user):
    """Test deleting a non-existent firewall rule"""
    headers = get_auth_headers(client, sample_user)
    response = client.delete("/api/firewall_rules/999", headers=headers)
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "not found" in data["message"]


def test_get_firewall_rules_unauthorized(client):
    """Test accessing endpoint without authentication"""
    response = client.get("/api/firewall_rules")
    assert response.status_code == 401


def test_get_firewall_rules_non_empty(client, sample_firewall_rule, sample_user):
    """Test retrieving all firewall rules when some exist"""
    headers = get_auth_headers(client, sample_user)
    
    # Create two firewall rules
    client.post("/api/firewall_rules", data=json.dumps(sample_firewall_rule), headers=headers)
    rule2 = sample_firewall_rule.copy()
    rule2["name"] = "AllowHTTP"
    rule2["port"] = 80
    client.post("/api/firewall_rules", data=json.dumps(rule2), headers=headers)
    
    # Retrieve all rules
    response = client.get("/api/firewall_rules", headers=headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data["firewall_rules"]) == 2
    rule_names = [rule["name"] for rule in data["firewall_rules"]]
    assert sample_firewall_rule["name"] in rule_names
    assert "AllowHTTP" in rule_names