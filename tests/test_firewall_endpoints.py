import pytest
import json

# Test retrieving all firewalls when none exist
def test_get_firewalls_empty(client):
    response = client.get("/api/firewalls")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["firewalls"] == []

# Test creating a new firewall
def test_create_firewall(client, sample_firewall):
    # Create the firewall
    response = client.post("/api/firewalls", data=json.dumps(sample_firewall), content_type="application/json")
    assert response.status_code == 201
    data = json.loads(response.data)
    assert data["message"] == "Firewall created"
    assert data["firewall"]["hostname"] == sample_firewall["hostname"]

# Test creating a firewall with duplicate hostname
def test_create_firewall_duplicate_hostname(client, sample_firewall):
    # Create the first firewall
    client.post("/api/firewalls", data=json.dumps(sample_firewall), content_type="application/json")
    
    # Attempt to create a second firewall with the same hostname
    response = client.post("/api/firewalls", data=json.dumps(sample_firewall), content_type="application/json")
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "already exists" in data["message"]

# Test creating a firewall with duplicate name
def test_create_firewall_duplicate_name(client, sample_firewall):
    # Create the first firewall
    client.post("/api/firewalls", data=json.dumps(sample_firewall), content_type="application/json")
    
    # Attempt to create a second firewall with the same name but different hostname
    new_firewall = sample_firewall.copy()
    new_firewall["hostname"] = "es-mad-fw2"
    response = client.post("/api/firewalls", data=json.dumps(new_firewall), content_type="application/json")
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "already exists" in data["message"]

# Test updating an existing firewall
def test_update_firewall(client, sample_firewall):
    # Create a firewall
    client.post("/api/firewalls", data=json.dumps(sample_firewall), content_type="application/json")
    
    # Update the firewall
    update_data = {
        "description": "Updated description",
        "ip_address": "192.168.1.2"
    }
    response = client.put("/api/firewalls/es-mad-fw1", data=json.dumps(update_data), content_type="application/json")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "Firewall updated" in data["message"]
    assert data["firewall"]["description"] == update_data["description"]
    assert data["firewall"]["ip_address"] == update_data["ip_address"]

# Test updating a non existent firewall
def test_update_firewall_not_found(client):
    update_data = {
        "description": "Updated description",
        "ip_address": "192.168.1.2"
    }
    response = client.put("/api/firewalls/es-mad-fw3", data=json.dumps(update_data), content_type="application/json")
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "not found" in data["message"]

# Test updating firewall hostname to a duplicate
def test_update_firewall_duplicate_hostname(client, sample_firewall):
    # Create first firewall
    client.post("/api/firewalls", data=json.dumps(sample_firewall), content_type="application/json")
    
    # Create second firewall
    new_firewall = sample_firewall.copy()
    new_firewall["hostname"] = "es-mad-fw2"
    new_firewall["name"] = "TestFirewall2"
    client.post("/api/firewalls", data=json.dumps(new_firewall), content_type="application/json")

    # Attempt to update first firewall's hostname to the second's
    update_data = {
        "hostname": "es-mad-fw2"
    }
    response = client.put("/api/firewalls/es-mad-fw1", data=json.dumps(update_data), content_type="application/json")
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "already exists" in data["message"]

# Test retrieving all firewalls when some exist
def test_get_firewalls_non_empty(client, sample_firewall):
    # Create a firewall
    client.post("/api/firewalls", data=json.dumps(sample_firewall), content_type="application/json")
    
    # Retrieve all firewalls
    response = client.get("/api/firewalls")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert len(data["firewalls"]) == 1
    assert data["firewalls"][0]["hostname"] == sample_firewall["hostname"]

# Test deleting an existing firewall
def test_delete_firewall(client, sample_firewall):
    # Create a firewall
    client.post("/api/firewalls", data=json.dumps(sample_firewall), content_type="application/json")
    # Delete the firewall
    response = client.delete("/api/firewalls/es-mad-fw1")
    assert response.status_code == 200

# Test deleting a non existent firewall
def test_delete_firewall_not_found(client):
    # Attempt to delete a non-existent firewall
    response = client.delete("/api/firewalls/es-mad-fw3")
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "not found" in data["message"]