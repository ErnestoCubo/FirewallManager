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
    data = json.loads(response.data)
    assert "Firewall policy updated" in data["message"]
    assert response.status_code == 200
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


def test_create_firewall_policy_missing_required_fields(client, sample_user):
    """Test creating a firewall policy with missing required fields"""
    headers = get_auth_headers(client, sample_user)
    
    # Missing 'name' field
    incomplete_policy = {
        "description": "Missing name field",
        "policy_type": "inbound",
        "is_active": True,
        "priority": 1
    }
    response = client.post("/api/firewall_policies", data=json.dumps(incomplete_policy), headers=headers)
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "Missing required field: name" in data["message"]
    
    # Missing 'policy_type' field
    incomplete_policy = {
        "name": "TestPolicy",
        "is_active": True,
        "priority": 1
    }
    response = client.post("/api/firewall_policies", data=json.dumps(incomplete_policy), headers=headers)
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "Missing required field: policy_type" in data["message"]
    
    # Missing 'is_active' field
    incomplete_policy = {
        "name": "TestPolicy",
        "policy_type": "inbound",
        "priority": 1
    }
    response = client.post("/api/firewall_policies", data=json.dumps(incomplete_policy), headers=headers)
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "Missing required field: is_active" in data["message"]
    
    # Missing 'priority' field
    incomplete_policy = {
        "name": "TestPolicy",
        "policy_type": "inbound",
        "is_active": True
    }
    response = client.post("/api/firewall_policies", data=json.dumps(incomplete_policy), headers=headers)
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "Missing required field: priority" in data["message"]


def test_create_firewall_policy_with_rules(client, sample_firewall_policy, sample_firewall_rule, sample_user):
    """Test creating a firewall policy with initial rules"""
    headers = get_auth_headers(client, sample_user)
    
    # Create firewall rules first
    rule1_response = client.post("/api/firewall_rules", data=json.dumps(sample_firewall_rule), headers=headers)
    rule1_id = json.loads(rule1_response.data)["firewall_rule"]["id"]
    
    rule2 = sample_firewall_rule.copy()
    rule2["name"] = "AllowHTTP"
    rule2["port"] = 80
    rule2_response = client.post("/api/firewall_rules", data=json.dumps(rule2), headers=headers)
    rule2_id = json.loads(rule2_response.data)["firewall_rule"]["id"]
    
    # Create policy with rules
    policy_with_rules = sample_firewall_policy.copy()
    policy_with_rules["rules_id"] = [rule1_id, rule2_id]
    
    response = client.post("/api/firewall_policies", data=json.dumps(policy_with_rules), headers=headers)
    assert response.status_code == 201
    data = json.loads(response.data)
    assert data["message"] == "Firewall policy created"
    assert len(data["firewall_policy"]["rules"]) == 2
    rule_ids = [rule["id"] for rule in data["firewall_policy"]["rules"]]
    assert rule1_id in rule_ids and rule2_id in rule_ids


def test_update_firewall_policy_with_no_data(client, sample_firewall_policy, sample_user):
    """Test updating a firewall policy with no data provided"""
    headers = get_auth_headers(client, sample_user)
    
    # Create a firewall policy
    client.post("/api/firewall_policies", data=json.dumps(sample_firewall_policy), headers=headers)
    
    # Try to update with no data
    response = client.put("/api/firewall_policies/1", data=json.dumps(None), headers=headers)
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "No input data provided" in data["message"]


def test_remove_rule_from_policy_rule_not_found(client, sample_firewall_policy, sample_user):
    """Test removing a non-existent rule from a policy"""
    headers = get_auth_headers(client, sample_user)
    
    # Create a firewall policy
    client.post("/api/firewall_policies", 
                data=json.dumps(sample_firewall_policy), 
                headers=headers)
    
    # Try to remove a non-existent rule
    response = client.delete("/api/firewall_policies/1/rules/999", headers=headers)
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "Rule with id 999 not found" in data["message"]


def test_remove_rule_from_policy_policy_not_found(client, sample_user):
    """Test removing a rule from a non-existent policy"""
    headers = get_auth_headers(client, sample_user)
    
    # Try to remove rule from non-existent policy
    response = client.delete("/api/firewall_policies/999/rules/1", headers=headers)
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "Firewall policy not found" in data["message"]


def test_patch_rules_to_nonexistent_policy(client, sample_user):
    """Test patching rules to a non-existent policy"""
    headers = get_auth_headers(client, sample_user)
    
    # Try to patch rules to non-existent policy
    response = client.patch("/api/firewall_policies/999/rules", data=json.dumps({"rules_id": [1]}), headers=headers)
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "Firewall policy not found" in data["message"]


def test_get_firewall_policies_non_empty(client, sample_firewall_policy, sample_user):
    """Test retrieving all firewall policies when some exist"""
    headers = get_auth_headers(client, sample_user)
    
    # Create multiple policies
    client.post("/api/firewall_policies", data=json.dumps(sample_firewall_policy), headers=headers)
    
    policy2 = sample_firewall_policy.copy()
    policy2["name"] = "TestPolicy2"
    policy2["policy_type"] = "outbound"
    client.post("/api/firewall_policies", 
                data=json.dumps(policy2), headers=headers)
    
    # Retrieve all policies
    response = client.get("/api/firewall_policies", headers=headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data["firewall_policies"]) == 2
    policy_names = [policy["name"] for policy in data["firewall_policies"]]
    assert sample_firewall_policy["name"] in policy_names
    assert "TestPolicy2" in policy_names


def test_update_firewall_policy_all_fields(client, sample_firewall_policy, sample_user):
    """Test updating all fields of a firewall policy"""
    headers = get_auth_headers(client, sample_user)
    
    # Create a firewall policy
    client.post("/api/firewall_policies", data=json.dumps(sample_firewall_policy), headers=headers)
    
    # Update all fields
    update_data = {
        "name": "UpdatedPolicy",
        "description": "Completely updated description",
        "policy_type": "outbound",
        "is_active": False,
        "priority": 10
    }
    
    response = client.put("/api/firewall_policies/1", data=json.dumps(update_data), headers=headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "Firewall policy updated" in data["message"]
    assert data["firewall_policy"]["name"] == update_data["name"]
    assert data["firewall_policy"]["description"] == update_data["description"]
    assert data["firewall_policy"]["policy_type"] == update_data["policy_type"]
    assert data["firewall_policy"]["is_active"] == update_data["is_active"]
    assert data["firewall_policy"]["priority"] == update_data["priority"]


def test_remove_rule_not_in_policy(client, sample_firewall_policy, sample_firewall_rule, sample_user):
    """Test removing a rule that exists but is not associated with the policy"""
    headers = get_auth_headers(client, sample_user)
    
    # Create a firewall policy
    client.post("/api/firewall_policies", data=json.dumps(sample_firewall_policy), headers=headers)
    
    # Create a firewall rule but don't add it to the policy
    client.post("/api/firewall_rules", data=json.dumps(sample_firewall_rule), headers=headers)
    
    # Try to remove the rule that was never added
    response = client.delete("/api/firewall_policies/1/rules/1", headers=headers)
    # This will raise an exception since the rule is not in the policy's rules list
    assert response.status_code == 500
    data = json.loads(response.data)
    assert "message" in data


def test_patch_rules_with_invalid_rule_ids(client, sample_firewall_policy, sample_user):
    """Test patching a policy with non-existent rule IDs"""
    headers = get_auth_headers(client, sample_user)
    
    # Create a firewall policy
    client.post("/api/firewall_policies", data=json.dumps(sample_firewall_policy), headers=headers)
    
    # Try to add non-existent rules
    response = client.patch("/api/firewall_policies/1/rules", data=json.dumps({"rules_id": [999, 1000]}), headers=headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    # No rules should be added since they don't exist
    assert len(data["firewall_policy"]["rules"]) == 0


def test_create_firewall_policy_with_invalid_json(client, sample_user):
    """Test creating a firewall policy with invalid JSON"""
    headers = get_auth_headers(client, sample_user)
    headers["Content-Type"] = "application/json"
    
    # Send invalid JSON
    response = client.post("/api/firewall_policies", data="invalid json {", headers=headers)
    assert response.status_code == 400 or response.status_code == 500


def test_update_firewall_policy_maintains_audit_trail(client, sample_firewall_policy, sample_user):
    """Test that updating a policy maintains the audit trail"""
    headers = get_auth_headers(client, sample_user)
    
    # Create a firewall policy
    create_response = client.post("/api/firewall_policies", data=json.dumps(sample_firewall_policy), headers=headers)
    created_policy = json.loads(create_response.data)["firewall_policy"]
    
    # Update the policy
    update_data = {"description": "Updated for audit trail test"}
    response = client.put("/api/firewall_policies/1", data=json.dumps(update_data), headers=headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    
    # Check audit trail
    assert data["firewall_policy"]["created_by"] == created_policy["created_by"]
    assert "last_modified_by" in data["firewall_policy"]
    # The last_modified_by should be updated to current user