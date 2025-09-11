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


def test_get_firewall_policies_empty(client, sample_user):
    """Test retrieving all firewall policies when none exist"""
    headers = get_auth_headers(client, sample_user)
    response = client.get("/api/firewall_policies", headers=headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["firewall_policies"] == []


def test_create_firewall_policy(client, sample_firewall_policy, sample_user):
    """Test creating a new firewall policy"""
    headers = get_auth_headers(client, sample_user)
    
    # Create the firewall policy
    response = client.post("/api/firewall_policies", data=json.dumps(sample_firewall_policy), headers=headers)
    assert response.status_code == 201
    data = json.loads(response.data)
    assert data["message"] == "Firewall policy created"
    assert data["firewall_policy"]["name"] == sample_firewall_policy["name"]


def test_create_firewall_policy_duplicate_name(client, sample_firewall_policy, sample_user):
    """Test creating a firewall policy with duplicate name"""
    headers = get_auth_headers(client, sample_user)
    
    # Create the first firewall policy
    client.post("/api/firewall_policies", data=json.dumps(sample_firewall_policy), headers=headers)
    
    # Attempt to create a second firewall policy with the same name
    response = client.post("/api/firewall_policies", data=json.dumps(sample_firewall_policy), headers=headers)
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "already exists" in data["message"]


def test_update_firewall_policy(client, sample_firewall_policy, sample_user):
    """Test updating an existing firewall policy"""
    headers = get_auth_headers(client, sample_user)
    
    # Create a firewall policy
    client.post("/api/firewall_policies", data=json.dumps(sample_firewall_policy), headers=headers)
    
    # Update the firewall policy
    update_data = {
        "description": "Updated description",
        "is_active": False
    }

    response = client.put("/api/firewall_policies/1", data=json.dumps(update_data), headers=headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "Firewall policy updated" in data["message"]
    assert data["firewall_policy"]["description"] == update_data["description"]
    assert data["firewall_policy"]["is_active"] == update_data["is_active"]


def test_update_nonexistent_firewall_policy(client, sample_user):
    """Test updating a non-existent firewall policy"""
    headers = get_auth_headers(client, sample_user)
    
    update_data = {
        "description": "Updated description",
        "is_active": False
    }
    response = client.put("/api/firewall_policies/999", data=json.dumps(update_data), headers=headers)
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "not found" in data["message"]


def test_add_firewall_rule_to_policy(client, sample_firewall_policy, sample_firewall_rule, sample_user):
    """Test adding a firewall rule to a policy"""
    headers = get_auth_headers(client, sample_user)
    
    # Create a firewall policy
    client.post("/api/firewall_policies", data=json.dumps(sample_firewall_policy), headers=headers)

    # Create a firewall rule
    client.post("/api/firewall_rules", data=json.dumps(sample_firewall_rule), headers=headers)

    # Add a firewall rule to the policy
    response = client.patch("/api/firewall_policies/1/rules", data=json.dumps({"rules_id": [1]}), headers=headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert f"Rules added to policy {sample_firewall_policy['name']}" in data["message"]
    assert len(data["firewall_policy"]["rules"]) == 1
    assert data["firewall_policy"]["rules"][0]["name"] == sample_firewall_rule["name"]


def test_delete_firewall_rule_from_policy(client, sample_firewall_policy, sample_firewall_rule, sample_user):
    """Test deleting a firewall rule from a policy"""
    headers = get_auth_headers(client, sample_user)
    
    # Create a firewall policy
    client.post("/api/firewall_policies", data=json.dumps(sample_firewall_policy), headers=headers)

    # Create a firewall rule
    client.post("/api/firewall_rules", 
                data=json.dumps(sample_firewall_rule), 
                headers=headers)

    # Add a firewall rule to the policy
    response = client.patch("/api/firewall_policies/1/rules", data=json.dumps({"rules_id": [1]}), headers=headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert f"Rules added to policy {sample_firewall_policy['name']}" in data["message"]
    assert len(data["firewall_policy"]["rules"]) == 1
    assert data["firewall_policy"]["rules"][0]["name"] == sample_firewall_rule["name"]

    # Remove the firewall rule from the policy
    response = client.delete("/api/firewall_policies/1/rules/1", headers=headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert f"Rule {sample_firewall_rule['name']} removed from policy {sample_firewall_policy['name']}" in data["message"]
    assert len(data["firewall_policy"]["rules"]) == 0


def test_delete_firewall_policy(client, sample_firewall_policy, sample_user):
    """Test deleting an existing firewall policy"""
    headers = get_auth_headers(client, sample_user)
    
    # Create a firewall policy
    client.post("/api/firewall_policies", data=json.dumps(sample_firewall_policy), headers=headers)
    
    # Delete the firewall policy
    response = client.delete("/api/firewall_policies/1", headers=headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert f"Firewall policy {sample_firewall_policy['name']} deleted" in data["message"]


def test_delete_nonexistent_firewall_policy(client, sample_user):
    """Test deleting a non-existent firewall policy"""
    headers = get_auth_headers(client, sample_user)
    
    response = client.delete("/api/firewall_policies/999", headers=headers)
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "not found" in data["message"]


def test_get_firewall_policies_unauthorized(client):
    """Test retrieving firewall policies without authentication"""
    response = client.get("/api/firewall_policies")
    assert response.status_code == 401


def test_update_firewall_policy_duplicate_name(client, sample_firewall_policy, sample_user):
    """Test updating a firewall policy to a name that already exists"""
    headers = get_auth_headers(client, sample_user)
    
    # Create first firewall policy
    client.post("/api/firewall_policies", data=json.dumps(sample_firewall_policy), headers=headers)
    
    # Create second firewall policy
    new_policy = sample_firewall_policy.copy()
    new_policy["name"] = "TestPolicy2"
    client.post("/api/firewall_policies", data=json.dumps(new_policy), headers=headers)
    
    # Attempt to update first policy's name to the second's
    update_data = {
        "name": "TestPolicy2"
    }
    response = client.put("/api/firewall_policies/1", data=json.dumps(update_data), headers=headers)
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "already exists" in data["message"]


def test_patch_rules_without_rules_id(client, sample_firewall_policy, sample_user):
    """Test patching firewall policy rules without providing rules_id"""
    headers = get_auth_headers(client, sample_user)
    
    # Create a firewall policy
    client.post("/api/firewall_policies", data=json.dumps(sample_firewall_policy), headers=headers)
    
    # Attempt to patch without rules_id
    response = client.patch("/api/firewall_policies/1/rules", data=json.dumps({}), headers=headers)
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "No rules_id provided" in data["message"]


def test_add_multiple_rules_to_policy(client, sample_firewall_policy, sample_firewall_rule, sample_user):
    """Test adding multiple firewall rules to a policy"""
    headers = get_auth_headers(client, sample_user)
    
    # Create a firewall policy
    client.post("/api/firewall_policies", data=json.dumps(sample_firewall_policy), headers=headers)
    
    # Create first firewall rule
    client.post("/api/firewall_rules", data=json.dumps(sample_firewall_rule), headers=headers)
    
    # Create second firewall rule
    rule2 = sample_firewall_rule.copy()
    rule2["name"] = "AllowHTTP"
    rule2["port"] = 80
    client.post("/api/firewall_rules", data=json.dumps(rule2), headers=headers)
    
    # Add first rule to the policy
    response = client.patch("/api/firewall_policies/1/rules", data=json.dumps({"rules_id": [1]}), headers=headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data["firewall_policy"]["rules"]) == 1
    
    # Add second rule to the policy (should keep the first one)
    response = client.patch("/api/firewall_policies/1/rules", data=json.dumps({"rules_id": [2]}), headers=headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data["firewall_policy"]["rules"]) == 2
    rule_ids = [rule["id"] for rule in data["firewall_policy"]["rules"]]
    assert 1 in rule_ids and 2 in rule_ids