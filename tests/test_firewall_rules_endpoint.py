import pytest
import json

# Test retrieving all firewall rules when none exist
def test_get_firewall_rules_empty(client):
    response = client.get("/api/firewall_rules")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["firewall_rules"] == []

# Test creating a new firewall rule
def test_create_firewall_rule(client, sample_firewall_rule):
    response = client.post("/api/firewall_rules", data=json.dumps(sample_firewall_rule), content_type="application/json")
    assert response.status_code == 201
    data = json.loads(response.data)
    assert data["message"] == "Firewall rule created"
    assert data["firewall_rule"]["name"] == sample_firewall_rule["name"]

# Test creating a firewall rule with duplicate name
def test_create_firewall_rule_duplicate_name(client, sample_firewall_rule):
    # Create the first firewall rule
    client.post("/api/firewall_rules", data=json.dumps(sample_firewall_rule), content_type="application/json")
    
    # Attempt to create a second firewall rule with the same name
    response = client.post("/api/firewall_rules", data=json.dumps(sample_firewall_rule), content_type="application/json")
    assert response.status_code == 201
    data = json.loads(response.data)
    assert data["message"] == "Firewall rule created"
    assert data["firewall_rule"]["name"] == sample_firewall_rule["name"]

# Test updating an existing firewall rule
def test_update_firewall_rule(client, sample_firewall_rule):
    # Create a firewall rule
    create_response = client.post("/api/firewall_rules", data=json.dumps(sample_firewall_rule), content_type="application/json")
    rule_id = json.loads(create_response.data)["firewall_rule"]["id"]
    
    # Update the firewall rule
    update_data = {
        "description": "Updated description",
        "is_active": False
    }
    response = client.put(f"/api/firewall_rules/{rule_id}", data=json.dumps(update_data), content_type="application/json")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "Firewall rule updated" in data["message"]
    assert data["firewall_rule"]["description"] == update_data["description"]
    assert data["firewall_rule"]["is_active"] == update_data["is_active"]

# Test updating a non-existent firewall rule
def test_update_nonexistent_firewall_rule(client):
    update_data = {
        "description": "Updated description",
        "is_active": False
    }
    response = client.put("/api/firewall_rules/999", data=json.dumps(update_data), content_type="application/json")
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "not found" in data["message"]

# Test deleting an existing firewall rule
def test_delete_firewall_rule(client, sample_firewall_rule):
    # Create a firewall rule
    create_response = client.post("/api/firewall_rules", data=json.dumps(sample_firewall_rule), content_type="application/json")
    rule_id = json.loads(create_response.data)["firewall_rule"]["id"]
    
    # Delete the firewall rule
    response = client.delete(f"/api/firewall_rules/{rule_id}")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "Firewall rule deleted" in data["message"]

# Test deleting a non-existent firewall rule
def test_delete_nonexistent_firewall_rule(client):
    response = client.delete("/api/firewall_rules/999")
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "not found" in data["message"]