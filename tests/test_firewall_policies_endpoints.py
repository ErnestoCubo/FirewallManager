import pytest
import json

# Test retrieving all firewall policies when none exist
def test_get_firewall_policies_empty(client):
    response = client.get("/api/firewall_policies")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["firewall_policies"] == []

# Test creating a new firewall policy
def test_create_firewall_policy(client, sample_firewall_policy):
    # Create the firewall policy
    response = client.post("/api/firewall_policies", data=json.dumps(sample_firewall_policy), content_type="application/json")
    assert response.status_code == 201
    data = json.loads(response.data)
    assert data["message"] == "Firewall policy created"
    assert data["firewall_policy"]["name"] == sample_firewall_policy["name"]

# Test creating a firewall policy with duplicate name
def test_create_firewall_policy_duplicate_name(client, sample_firewall_policy):
    # Create the first firewall policy
    client.post("/api/firewall_policies", data=json.dumps(sample_firewall_policy), content_type="application/json")
    
    # Attempt to create a second firewall policy with the same name
    response = client.post("/api/firewall_policies", data=json.dumps(sample_firewall_policy), content_type="application/json")
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "already exists" in data["message"]

# Test updating an existing firewall policy
def test_update_firewall_policy(client, sample_firewall_policy):
    # Create a firewall policy
    client.post("/api/firewall_policies", data=json.dumps(sample_firewall_policy), content_type="application/json")
    
    # Update the firewall policy
    update_data = {
        "description": "Updated description",
        "is_active": False
    }
    response = client.put("/api/firewall_policies/1", data=json.dumps(update_data), content_type="application/json")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "Firewall policy updated" in data["message"]
    assert data["firewall_policy"]["description"] == update_data["description"]
    assert data["firewall_policy"]["is_active"] == update_data["is_active"]

# Test updating a non-existent firewall policy
def test_update_nonexistent_firewall_policy(client):
    update_data = {
        "description": "Updated description",
        "is_active": False
    }
    response = client.put("/api/firewall_policies/1", data=json.dumps(update_data), content_type="application/json")
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "not found" in data["message"]

# Test adding a firewall rule to a policy
def test_add_firewall_rule_to_policy(client, sample_firewall_policy, sample_firewall_rule):
    # Create a firewall policy
    client.post("/api/firewall_policies", data=json.dumps(sample_firewall_policy), content_type="application/json")

    # Create a firewall rule
    client.post("/api/firewall_rules", data=json.dumps(sample_firewall_rule), content_type="application/json")

    # Add a firewall rule to the policy
    response = client.patch("/api/firewall_policies/1/rules", data=json.dumps({"rules_id": [1]}), content_type="application/json")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert f"Rules added to policy {sample_firewall_policy['name']}" in data["message"]
    assert len(data["firewall_policy"]["rules"]) == 1
    assert data["firewall_policy"]["rules"][0]["name"] == sample_firewall_rule["name"]

# Test deleteting a firewall rule from a policy
def test_delete_firewall_rule_from_policy(client, sample_firewall_policy, sample_firewall_rule):
    # Create a firewall policy
    client.post("/api/firewall_policies", data=json.dumps(sample_firewall_policy), content_type="application/json")

    # Create a firewall rule
    client.post("/api/firewall_rules", data=json.dumps(sample_firewall_rule), content_type="application/json")

    # Add a firewall rule to the policy
    response = client.patch("/api/firewall_policies/1/rules", data=json.dumps({"rules_id": [1]}), content_type="application/json")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert f"Rules added to policy {sample_firewall_policy['name']}" in data["message"]
    assert len(data["firewall_policy"]["rules"]) == 1
    assert data["firewall_policy"]["rules"][0]["name"] == sample_firewall_rule["name"]

    # Remove the firewall rule from the policy
    response = client.delete("/api/firewall_policies/1/rules/1", content_type="application/json")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert f"Rule {sample_firewall_rule['name']} removed from policy {sample_firewall_policy['name']}" in data["message"]
    assert len(data["firewall_policy"]["rules"]) == 0

# Test deleting an existing firewall policy
def test_delete_firewall_policy(client, sample_firewall_policy):
    # Create a firewall policy
    client.post("/api/firewall_policies", data=json.dumps(sample_firewall_policy), content_type="application/json")
    
    # Delete the firewall policy
    response = client.delete("/api/firewall_policies/1")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert f"Firewall policy {sample_firewall_policy['name']} deleted" in data["message"]

# Test deleting a non-existent firewall policy
def test_delete_nonexistent_firewall_policy(client):
    response = client.delete("/api/firewall_policies/1")
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "not found" in data["message"]