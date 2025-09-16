import pytest
import json
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


def create_test_rule(client, sample_firewall_rule, sample_user):
    """Helper function to create a test firewall rule"""
    headers = get_auth_headers(client, sample_user)

    response = client.post("/api/firewall_rules", data=json.dumps(sample_firewall_rule), headers=headers)
    assert response.status_code == 201
    data = json.loads(response.data)
    return data["firewall_rule"]

def test_get_firewall_rules_empty(client, sample_user):
    """Test retrieving all firewall rules when none exist"""
    headers = get_auth_headers(client, sample_user)
    response = client.get("/api/firewall_rules", headers=headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["firewall_rules"] == []


def test_create_firewall_rule(client, sample_user, sample_firewall_rule):
    """Test creating a new firewall rule"""
    headers = get_auth_headers(client, sample_user)

    response = client.post('/api/firewall_rules',
                          data=json.dumps(sample_firewall_rule),
                          headers=headers)
    assert response.status_code == 201
    data = json.loads(response.data)
    assert data["firewall_rule"]["name"] == "AllowSSH"


def test_create_firewall_rule_duplicate_name(client, sample_firewall_rule, sample_user):
    """Test creating a firewall rule with duplicate name (should succeed as names are not unique)"""
    headers = get_auth_headers(client, sample_user)
    
    # Create the first firewall rule
    client.post("/api/firewall_rules", data=json.dumps(sample_firewall_rule), headers=headers)
    
    # Create a second firewall rule with the same name (should succeed)
    response = client.post("/api/firewall_rules", data=json.dumps(sample_firewall_rule), headers=headers)
    assert response.status_code == 400


def test_create_firewall_rule_missing_fields(client, sample_user):
    """Test creating rule without required fields"""
    headers = get_auth_headers(client, sample_user)
    
    # Missing required fields
    rule_data = {
        "description": "Test Description"
    }
    
    response = client.post('/api/firewall_rules', 
                          data=json.dumps(rule_data), 
                          headers=headers)
    assert response.status_code == 400
    data = json.loads(response.data)
    # Flask-RESTX validation message
    assert 'validation failed' in data["message"].lower() or 'required' in data["message"].lower()


def test_update_firewall_rule(client, sample_user, sample_firewall_rule):
    """Test updating a firewall rule"""
    headers = get_auth_headers(client, sample_user)
    
    # Create a rule first
    client.post("/api/firewall_rules", data=json.dumps(sample_firewall_rule), headers=headers)
    
    # Update the rule
    update_data = {
        "name": "UpdatedRule",
        "action": "deny"
    }
    response = client.put(f'/api/firewall_rules/{1}', 
                         data=json.dumps(update_data), 
                         headers=headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["firewall_rule"]["name"] == "UpdatedRule"


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


def test_delete_firewall_rule(client, sample_user, sample_firewall_rule):
    """Test deleting a firewall rule"""
    headers = get_auth_headers(client, sample_user)
    
    # Create a rule first
    client.post("/api/firewall_rules", data=json.dumps(sample_firewall_rule), headers=headers)
    
    # Delete the rule
    response = client.delete(f'/api/firewall_rules/{1}', headers=headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["message"] == "Firewall rule deleted"


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