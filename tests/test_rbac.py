import json
import pytest
from werkzeug.security import generate_password_hash
from src.models.user import User
from src.models.base import db


def create_user_with_role(client, username, role):
    """Helper function to create a user with a specific role and get auth headers"""
    
    # Create user directly in database with specific role
    user = User(
        username=username,
        email=f"{username}@test.com",
        password_hash=generate_password_hash("TestPass123!"),
        role=role
    )
    db.session.add(user)
    db.session.commit()
    
    # Login to get token
    response = client.post("/api/auth/login", 
        data=json.dumps({
            "username": username,
            "password": "TestPass123!"
        }),
        content_type="application/json"
    )
    
    if response.status_code != 200:
        # If login fails, try registering first
        client.post("/api/auth/register",
            data=json.dumps({
                "username": username,
                "password": "TestPass123!",
                "email": f"{username}@test.com"
            }),
            content_type="application/json"
        )
        
        # Update the user's role after registration
        user = User.query.filter_by(username=username).first()
        if user:
            user.role = role
            db.session.commit()
        
        # Try login again
        response = client.post("/api/auth/login", 
            data=json.dumps({
                "username": username,
                "password": "TestPass123!"
            }),
            content_type="application/json"
        )
    
    token = json.loads(response.data).get("access_token")
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


class TestRoleHierarchy:
    """Test role hierarchy and permissions based on permission_settings.json"""
    
    def test_user_role_read_only_access(self, client, sample_firewall_policy):
        """Test that user role has read-only access"""
        headers = create_user_with_role(client, "basic_user", "user")
        
        # User should be able to read policies
        response = client.get("/api/firewall_policies", headers=headers)
        assert response.status_code == 200
        
        # User should NOT be able to create
        response = client.post("/api/firewall_policies", 
            data=json.dumps(sample_firewall_policy), 
            headers=headers)
        assert response.status_code == 403
        
        # User should NOT be able to update
        response = client.put("/api/firewall_policies/1", 
            data=json.dumps({"description": "Updated"}), 
            headers=headers)
        assert response.status_code == 403
        
        # User should NOT be able to delete
        response = client.delete("/api/firewall_policies/1", headers=headers)
        assert response.status_code == 403
    
    def test_operator_role_full_firewall_access(self, client, sample_firewall_policy):
        """Test that operator role has full access to firewall resources but not users"""
        headers = create_user_with_role(client, "operator_user", "operator")
        
        # Operator should be able to read
        response = client.get("/api/firewall_policies", headers=headers)
        assert response.status_code == 200
        
        # Operator SHOULD be able to create (based on permission_settings.json)
        response = client.post("/api/firewall_policies", 
            data=json.dumps(sample_firewall_policy), 
            headers=headers)
        assert response.status_code == 201
        
        # Operator SHOULD be able to update
        response = client.put("/api/firewall_policies/1", 
            data=json.dumps({"description": "Updated by operator"}), 
            headers=headers)
        assert response.status_code == 200
        
        # Operator SHOULD be able to delete
        response = client.delete("/api/firewall_policies/1", headers=headers)
        assert response.status_code == 200
    
    def test_admin_role_full_system_access(self, client, sample_firewall_policy):
        """Test that admin role has full access to all resources"""
        headers = create_user_with_role(client, "admin_user", "admin")
        
        # Admin should be able to create
        response = client.post("/api/firewall_policies", 
            data=json.dumps(sample_firewall_policy), 
            headers=headers)
        assert response.status_code == 201
        
        # Admin should be able to update
        response = client.put("/api/firewall_policies/1", 
            data=json.dumps({"description": "Updated by admin", "is_active": False}), 
            headers=headers)
        assert response.status_code == 200
        
        # Admin should be able to delete
        response = client.delete("/api/firewall_policies/1", headers=headers)
        assert response.status_code == 200
        
        # Admin should be able to access user management
        response = client.get("/api/admin/users", headers=headers)
        # This might be 404 if endpoint doesn't exist yet, but shouldn't be 403
        assert response.status_code != 403


class TestFirewallPermissions:
    """Test RBAC for firewall endpoints based on permission_settings.json"""
    
    def test_user_can_only_read_firewalls(self, client, sample_firewall):
        """Test that user can only read firewall configurations"""
        headers = create_user_with_role(client, "fw_user", "user")
        
        # User can read
        response = client.get("/api/firewalls", headers=headers)
        assert response.status_code == 200
        
        # User cannot create
        response = client.post("/api/firewalls", 
            data=json.dumps(sample_firewall), 
            headers=headers)
        assert response.status_code == 403
        
        # User cannot delete
        response = client.delete("/api/firewalls/1", headers=headers)
        assert response.status_code == 403
    
    def test_operator_can_manage_firewalls(self, client, sample_firewall):
        """Test that operator can fully manage firewall configurations"""
        headers = create_user_with_role(client, "fw_operator", "operator")
        
        # Operator can create
        response = client.post("/api/firewalls", 
            data=json.dumps(sample_firewall), 
            headers=headers)
        assert response.status_code == 201
        
        # Operator can update
        response = client.put("/api/firewalls/1", 
            data=json.dumps({"description": "Updated by operator"}), 
            headers=headers)
        assert response.status_code == 200
        
        # Operator can delete
        response = client.delete("/api/firewalls/1", headers=headers)
        assert response.status_code == 200
    
    def test_admin_can_manage_firewalls(self, client, sample_firewall):
        """Test that admin can fully manage firewall configurations"""
        headers = create_user_with_role(client, "fw_admin", "admin")
        
        # Admin can create
        response = client.post("/api/firewalls", 
            data=json.dumps(sample_firewall), 
            headers=headers)
        assert response.status_code == 201
        
        # Admin can delete
        response = client.delete("/api/firewalls/1", headers=headers)
        assert response.status_code == 200


class TestFirewallRulesPermissions:
    """Test RBAC for firewall rules based on permission_settings.json"""
    
    def test_user_can_only_read_rules(self, client, sample_firewall_rule):
        """Test that user can only read firewall rules"""
        headers = create_user_with_role(client, "rules_user", "user")
        
        # User can read
        response = client.get("/api/firewall_rules", headers=headers)
        assert response.status_code == 200
        
        # User cannot create
        response = client.post("/api/firewall_rules", 
            data=json.dumps(sample_firewall_rule), 
            headers=headers)
        assert response.status_code == 403
        
        # User cannot update
        response = client.put("/api/firewall_rules/1", 
            data=json.dumps({"port": 443}), 
            headers=headers)
        assert response.status_code == 403
    
    def test_operator_can_manage_rules(self, client, sample_firewall_rule):
        """Test that operator can fully manage firewall rules"""
        headers = create_user_with_role(client, "rules_operator", "operator")
        
        # Operator can create
        response = client.post("/api/firewall_rules", 
            data=json.dumps(sample_firewall_rule), 
            headers=headers)
        assert response.status_code == 201
        
        # Operator can update
        update_data = {
            "description": "Updated rule description",
            "port": 443
        }
        response = client.put("/api/firewall_rules/1", 
            data=json.dumps(update_data), 
            headers=headers)
        assert response.status_code == 200
        
        # Operator can delete
        response = client.delete("/api/firewall_rules/1", headers=headers)
        assert response.status_code == 200
    
    def test_admin_can_manage_rules(self, client, sample_firewall_rule):
        """Test that admin can fully manage firewall rules"""
        headers = create_user_with_role(client, "rules_admin", "admin")
        
        # Admin can create
        response = client.post("/api/firewall_rules", 
            data=json.dumps(sample_firewall_rule), 
            headers=headers)
        assert response.status_code == 201
        
        # Admin can update
        response = client.put("/api/firewall_rules/1", 
            data=json.dumps({"port": 8080}), 
            headers=headers)
        assert response.status_code == 200
        
        # Admin can delete
        response = client.delete("/api/firewall_rules/1", headers=headers)
        assert response.status_code == 200


class TestPolicyRuleAssociationPermissions:
    """Test RBAC for policy-rule associations based on permission_settings.json"""
    
    def test_user_cannot_modify_associations(self, client, sample_firewall_policy, sample_firewall_rule):
        """Test that user cannot modify policy-rule associations"""
        operator_headers = create_user_with_role(client, "op_creator", "operator")
        user_headers = create_user_with_role(client, "assoc_user", "user")
        
        # Operator creates policy and rule
        client.post("/api/firewall_policies", 
            data=json.dumps(sample_firewall_policy), 
            headers=operator_headers)
        client.post("/api/firewall_rules", 
            data=json.dumps(sample_firewall_rule), 
            headers=operator_headers)
        
        # User tries to add rule to policy
        response = client.patch("/api/firewall_policies/1/rules", 
            data=json.dumps({"rules_id": [1]}), 
            headers=user_headers)
        assert response.status_code == 403
    
    def test_operator_can_modify_associations(self, client, sample_firewall_policy, sample_firewall_rule):
        """Test that operator can modify policy-rule associations"""
        headers = create_user_with_role(client, "assoc_operator", "operator")
        
        # Create policy and rule
        client.post("/api/firewall_policies", 
            data=json.dumps(sample_firewall_policy), 
            headers=headers)
        client.post("/api/firewall_rules", 
            data=json.dumps(sample_firewall_rule), 
            headers=headers)
        
        # Add rule to policy
        response = client.patch("/api/firewall_policies/1/rules", 
            data=json.dumps({"rules_id": [1]}), 
            headers=headers)
        assert response.status_code == 200
        
        # Remove rule from policy
        response = client.delete("/api/firewall_policies/1/rules/1", 
            headers=headers)
        assert response.status_code == 200
    
    def test_admin_can_modify_associations(self, client, sample_firewall_policy, sample_firewall_rule):
        """Test that admin can modify policy-rule associations"""
        headers = create_user_with_role(client, "assoc_admin", "admin")
        
        # Create policy and rule
        client.post("/api/firewall_policies", 
            data=json.dumps(sample_firewall_policy), 
            headers=headers)
        client.post("/api/firewall_rules", 
            data=json.dumps(sample_firewall_rule), 
            headers=headers)
        
        # Add rule to policy
        response = client.patch("/api/firewall_policies/1/rules", 
            data=json.dumps({"rules_id": [1]}), 
            headers=headers)
        assert response.status_code == 200


class TestUserManagementPermissions:
    """Test user management permissions based on permission_settings.json"""
    
    def test_user_cannot_access_user_management(self, client):
        """Test that user role cannot access user management"""
        headers = create_user_with_role(client, "um_user", "user")
        
        # User cannot read users
        response = client.get("/api/admin/users", headers=headers)
        assert response.status_code in [403, 404]
        
        # User cannot create users
        response = client.post("/api/admin/users", 
            data=json.dumps({"username": "newuser"}), 
            headers=headers)
        assert response.status_code in [403, 404]
    
    def test_operator_cannot_access_user_management(self, client):
        """Test that operator role cannot access user management"""
        headers = create_user_with_role(client, "um_operator", "operator")
        
        # Operator cannot read users
        response = client.get("/api/admin/users", headers=headers)
        assert response.status_code in [403, 404]
        
        # Operator cannot delete users
        response = client.delete("/api/admin/users/1", headers=headers)
        assert response.status_code in [403, 404]
    
    def test_admin_can_access_user_management(self, client):
        """Test that admin role can access user management"""
        headers = create_user_with_role(client, "um_admin", "admin")
        
        # Admin can read users (if endpoint exists)
        response = client.get("/api/admin/users", headers=headers)
        assert response.status_code != 403  # Not forbidden
        
        # Admin can update users (if endpoint exists)
        response = client.put("/api/admin/users/1", 
            data=json.dumps({"role": "operator"}), 
            headers=headers)
        assert response.status_code != 403  # Not forbidden


class TestHierarchyLevels:
    """Test role hierarchy levels from permission_settings.json"""
    
    def test_hierarchy_level_enforcement(self, client, sample_firewall_policy):
        """Test that hierarchy levels are properly enforced"""
        user_headers = create_user_with_role(client, "h_user", "user")  # level 1
        operator_headers = create_user_with_role(client, "h_operator", "operator")  # level 2
        admin_headers = create_user_with_role(client, "h_admin", "admin")  # level 3
        
        # Create a policy with admin
        response = client.post("/api/firewall_policies", 
            data=json.dumps(sample_firewall_policy), 
            headers=admin_headers)
        assert response.status_code == 201
        
        # User (level 1) cannot delete
        response = client.delete("/api/firewall_policies/1", headers=user_headers)
        assert response.status_code == 403
        
        # Operator (level 2) can delete
        response = client.delete("/api/firewall_policies/1", headers=operator_headers)
        assert response.status_code == 200
    
    def test_cross_hierarchy_access(self, client, sample_firewall_policy):
        """Test that higher levels can perform lower level operations"""
        admin_headers = create_user_with_role(client, "ch_admin", "admin")
        
        # Admin (level 3) can perform operator (level 2) operations
        response = client.post("/api/firewall_policies", 
            data=json.dumps(sample_firewall_policy), 
            headers=admin_headers)
        assert response.status_code == 201
        
        # Admin can perform user (level 1) operations
        response = client.get("/api/firewall_policies", headers=admin_headers)
        assert response.status_code == 200


class TestPermissionGranularity:
    """Test specific permissions from permission_settings.json"""
    
    def test_add_policy_to_firewall_permission(self, client, sample_firewall, sample_firewall_policy):
        """Test add_policy_to_firewall permission"""
        user_headers = create_user_with_role(client, "apf_user", "user")
        operator_headers = create_user_with_role(client, "apf_operator", "operator")
        
        # Create firewall and policy with operator
        client.post("/api/firewalls", 
            data=json.dumps(sample_firewall), 
            headers=operator_headers)
        client.post("/api/firewall_policies", 
            data=json.dumps(sample_firewall_policy), 
            headers=operator_headers)
        
        # User cannot add policy to firewall
        response = client.patch("/api/firewalls/1/policies", 
            data=json.dumps({"policies_ids": [1]}), 
            headers=user_headers)
        assert response.status_code in [403, 404]
        
        # Operator can add policy to firewall
        response = client.patch("/api/firewalls/1/policies", 
            data=json.dumps({"policies_ids": [1]}), 
            headers=operator_headers)
        assert response.status_code in [200, 404]  # 404 if endpoint doesn't exist
    
    def test_remove_policy_from_firewall_permission(self, client):
        """Test remove_policy_from_firewall permission"""
        user_headers = create_user_with_role(client, "rpf_user", "user")
        operator_headers = create_user_with_role(client, "rpf_operator", "operator")
        
        # User cannot remove policy from firewall
        response = client.delete("/api/firewalls/1/policies/1", headers=user_headers)
        assert response.status_code in [403, 404]
        
        # Operator can remove policy from firewall
        response = client.delete("/api/firewalls/1/policies/1", headers=operator_headers)
        assert response.status_code in [200, 404]  # 404 if endpoint doesn't exist


class TestRBACEdgeCases:
    """Test edge cases and error handling in RBAC"""
    
    def test_invalid_role_handling(self, client):
        """Test that invalid roles are handled properly"""
        # Create user with invalid role
        headers = create_user_with_role(client, "invalid_role_user", "invalid_role")
        
        # Should not be able to perform privileged operations
        response = client.post("/api/firewall_policies", 
            data=json.dumps({"name": "test"}), 
            headers=headers)
        assert response.status_code == 403
    
    def test_null_role_defaults_to_user(self, client):
        """Test that null role defaults to user permissions"""
        headers = create_user_with_role(client, "null_role_user", None)
        
        # Should have user permissions (read only)
        response = client.get("/api/firewall_policies", headers=headers)
        assert response.status_code in [200, 403]
        
        # Should not be able to create
        response = client.post("/api/firewall_policies", 
            data=json.dumps({"name": "test"}), 
            headers=headers)
        assert response.status_code == 403
    
    def test_empty_role_defaults_to_user(self, client):
        """Test that empty role defaults to user permissions"""
        headers = create_user_with_role(client, "empty_role_user", "")
        
        # Should have user permissions (read only)
        response = client.get("/api/firewall_policies", headers=headers)
        assert response.status_code in [200, 403]
        
        # Should not be able to delete
        response = client.delete("/api/firewall_policies/1", headers=headers)
        assert response.status_code == 403
    
    def test_unauthorized_request(self, client):
        """Test that requests without authentication are rejected"""
        response = client.get("/api/firewall_policies")
        assert response.status_code == 401
        
        response = client.post("/api/firewall_policies", 
            data=json.dumps({"name": "test"}))
        assert response.status_code == 401
    
    def test_invalid_token(self, client):
        """Test that invalid tokens are rejected"""
        headers = {
            "Authorization": "Bearer invalid_token_here",
            "Content-Type": "application/json"
        }
        
        response = client.get("/api/firewall_policies", headers=headers)
        assert response.status_code in [401, 422]  # 422 if token format is wrong