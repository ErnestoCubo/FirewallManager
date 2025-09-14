import pytest
from src.validators.input_validators import (
    user_validator,
    firewall_validator,
    validate_hostname,
    validate_ip,
    firewall_policies_validator,
    validate_policy_schema,
    firewall_rules_validator,
    validate_rule_schema,
    validate_firewall_schema,
    NO_INPUT_DATA_ERROR,
    NAME_MUST_BE_STRING_ERROR,
    DESCRIPTION_MUST_BE_STRING_ERROR
)


class TestUserValidator:
    """Test suite for user validation functions"""
    
    def test_user_validator_valid_data(self):
        """Test user validator with valid data"""
        data = {
            "username": "testuser",
            "password": "TestPass123!",
            "email": "test@example.com"
        }
        is_valid, message = user_validator(data)
        assert is_valid is True
        assert message == ""
    
    def test_user_validator_missing_required_fields(self):
        """Test user validator with missing required fields"""
        # Missing username
        data = {
            "password": "TestPass123!",
            "email": "test@example.com"
        }
        is_valid, message = user_validator(data)
        assert is_valid is False
        assert "Missing required field: username" in message
        
        # Missing password
        data = {
            "username": "testuser",
            "email": "test@example.com"
        }
        is_valid, message = user_validator(data)
        assert is_valid is False
        assert "Missing required field: password" in message
        
        # Missing email
        data = {
            "username": "testuser",
            "password": "TestPass123!"
        }
        is_valid, message = user_validator(data)
        assert is_valid is False
        assert "Missing required field: email" in message
    
    def test_user_validator_invalid_email_format(self):
        """Test user validator with invalid email format"""
        data = {
            "username": "testuser",
            "password": "TestPass123!",
            "email": "invalid-email"
        }
        is_valid, message = user_validator(data)
        assert is_valid is False
        assert "email must be a valid email address" in message
        
        data["email"] = "@example.com"
        is_valid, message = user_validator(data)
        assert is_valid is False
        assert "email must be a valid email address" in message
        
        data["email"] = "test@"
        is_valid, message = user_validator(data)
        assert is_valid is False
        assert "email must be a valid email address" in message
    
    def test_user_validator_invalid_data_types(self):
        """Test user validator with invalid data types"""
        # Non-string username
        data = {
            "username": 123,
            "password": "TestPass123!",
            "email": "test@example.com"
        }
        is_valid, message = user_validator(data)
        assert is_valid is False
        assert "username must be a string" in message
        
        # Non-string password
        data = {
            "username": "testuser",
            "password": 123,
            "email": "test@example.com"
        }
        is_valid, message = user_validator(data)
        assert is_valid is False
        assert "password must be a string" in message
        
        # Non-string email
        data = {
            "username": "testuser",
            "password": "TestPass123!",
            "email": 123
        }
        is_valid, message = user_validator(data)
        assert is_valid is False
        assert "email must be a string" in message
    
    def test_user_validator_empty_data(self):
        """Test user validator with empty data"""
        is_valid, message = user_validator({})
        assert is_valid is False
        assert message == NO_INPUT_DATA_ERROR
    
    def test_user_validator_none_data(self):
        """Test user validator with None data"""
        is_valid, message = user_validator(None)
        assert is_valid is False
        assert message == NO_INPUT_DATA_ERROR


class TestFirewallValidator:
    """Test suite for firewall validation functions"""
    
    def test_firewall_validator_valid_data(self):
        """Test firewall validator with valid data"""
        data = {
            "name": "TestFirewall",
            "hostname": "us-nyc-001",
            "ip_address": "192.168.1.1",
            "vendor": "cisco",
            "model": "ASA5505",
            "os_version": "9.1",
            "description": "Test description",
            "country": "USA",
            "city": "New York"
        }
        is_valid, message = firewall_validator(data)
        assert is_valid is True
        assert message == ""
    
    def test_firewall_validator_missing_required_fields(self):
        """Test firewall validator with missing required fields"""
        required_fields = ["name", "hostname", "ip_address", "vendor", "model", "os_version"]
        
        for field in required_fields:
            data = {
                "name": "TestFirewall",
                "hostname": "us-nyc-001",
                "ip_address": "192.168.1.1",
                "vendor": "cisco",
                "model": "ASA5505",
                "os_version": "9.1"
            }
            del data[field]
            is_valid, message = firewall_validator(data)
            assert is_valid is False
            assert f"Missing required field: {field}" in message
    
    def test_firewall_validator_invalid_hostname_format(self):
        """Test firewall validator with invalid hostname format"""
        data = {
            "name": "TestFirewall",
            "hostname": "invalid-hostname",
            "ip_address": "192.168.1.1",
            "vendor": "cisco",
            "model": "ASA5505",
            "os_version": "9.1"
        }
        is_valid, message = firewall_validator(data)
        assert is_valid is False
        assert "hostname must be in the format XX-XXX-DDD" in message
    
    def test_firewall_validator_invalid_ip_address(self):
        """Test firewall validator with invalid IP address"""
        data = {
            "name": "TestFirewall",
            "hostname": "us-nyc-001",
            "ip_address": "999.999.999.999",
            "vendor": "cisco",
            "model": "ASA5505",
            "os_version": "9.1"
        }
        is_valid, message = firewall_validator(data)
        assert is_valid is False
        assert "ip_address must be a valid IP address" in message
    
    def test_firewall_validator_invalid_data_types(self):
        """Test firewall validator with invalid data types"""
        base_data = {
            "name": "TestFirewall",
            "hostname": "us-nyc-001",
            "ip_address": "192.168.1.1",
            "vendor": "cisco",
            "model": "ASA5505",
            "os_version": "9.1"
        }
        
        # Test each field with wrong type
        fields_to_test = ["name", "hostname", "ip_address", "vendor", "model", "os_version"]
        for field in fields_to_test:
            data = base_data.copy()
            data[field] = 123  # Use integer instead of string
            is_valid, message = firewall_validator(data)
            assert is_valid is False
            assert f"{field} must be a string" in message
    
    def test_firewall_validator_empty_data(self):
        """Test firewall validator with empty data"""
        is_valid, message = firewall_validator({})
        assert is_valid is False
        assert message == NO_INPUT_DATA_ERROR
    
    def test_firewall_validator_none_data(self):
        """Test firewall validator with None data"""
        is_valid, message = firewall_validator(None)
        assert is_valid is False
        assert message == NO_INPUT_DATA_ERROR


class TestValidateHostname:
    """Test suite for hostname validation"""
    
    def test_valid_hostnames(self):
        """Test valid hostname formats"""
        valid_hostnames = [
            "us-nyc-001",
            "uk-lon-999",
            "jp-tok-1",
            "de-ber-100",
            "AU-SYD-050",
            "ca-tor-5",
            "fr-par-123"
        ]
        for hostname in valid_hostnames:
            assert validate_hostname(hostname) is True
    
    def test_invalid_hostnames(self):
        """Test invalid hostname formats"""
        invalid_hostnames = [
            "usa-nyc-001",  # First part should be 2 chars
            "us-ny-001",    # Second part should be 3 chars
            "us-nyc-a01",   # Third part should be only digits
            "us_nyc_001",   # Should use hyphens, not underscores
            "us.nyc.001",   # Should use hyphens, not dots
            "usnyc001",     # Missing separators
            "us-nyc",       # Missing third part
            "us-001",       # Missing second part
            "-nyc-001",     # Missing first part
            ""              # Empty string
        ]
        for hostname in invalid_hostnames:
            assert validate_hostname(hostname) is False


class TestValidateIP:
    """Test suite for IP address validation"""
    
    def test_valid_ip_addresses(self):
        """Test valid IP addresses"""
        valid_ips = [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "8.8.8.8",
            "255.255.255.255",
            "0.0.0.0",
            "::1",  # IPv6 localhost
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",  # IPv6
            "fe80::1",  # IPv6 link-local
            "::ffff:192.168.1.1"  # IPv4-mapped IPv6
        ]
        for ip in valid_ips:
            assert validate_ip(ip) is True
    
    def test_invalid_ip_addresses(self):
        """Test invalid IP addresses"""
        invalid_ips = [
            "256.256.256.256",
            "192.168.1",
            "192.168.1.1.1",
            "192.168.-1.1",
            "abc.def.ghi.jkl",
            "192.168.1.1/24",  # CIDR notation not accepted
            "",
            "not-an-ip",
            "192.168.1.",
            ".192.168.1.1",
            "192..168.1.1"
        ]
        for ip in invalid_ips:
            assert validate_ip(ip) is False


class TestFirewallPoliciesValidator:
    """Test suite for firewall policies validation"""
    
    def test_valid_firewall_policy(self):
        """Test firewall policies validator with valid data"""
        data = {
            "name": "TestPolicy",
            "description": "Test description",
            "policy_type": "inbound",
            "is_active": True,
            "priority": 1,
            "created_by": "admin",
            "last_modified_by": "admin"
        }
        is_valid, message = firewall_policies_validator(data)
        assert is_valid is True
        assert message == ""
    
    def test_firewall_policy_string_boolean_conversion(self):
        """Test that string booleans are converted properly"""
        # Test "true" string conversion
        data = {
            "name": "TestPolicy",
            "policy_type": "outbound",
            "is_active": "true",
            "priority": 5
        }
        is_valid, message = firewall_policies_validator(data)
        assert is_valid is True
        assert data["is_active"] is True
        
        # Test "false" string conversion
        data = {
            "name": "TestPolicy",
            "policy_type": "outbound",
            "is_active": "false",
            "priority": 5
        }
        is_valid, message = firewall_policies_validator(data)
        assert is_valid is True
        assert data["is_active"] is False
        
        # Test any other string defaults to True
        data = {
            "name": "TestPolicy",
            "policy_type": "outbound",
            "is_active": "yes",
            "priority": 5
        }
        is_valid, message = firewall_policies_validator(data)
        assert is_valid is True
        assert data["is_active"] is True
    
    def test_firewall_policy_invalid_policy_type(self):
        """Test firewall policies validator with invalid policy type"""
        data = {
            "name": "TestPolicy",
            "policy_type": "invalid",
            "is_active": True,
            "priority": 1
        }
        is_valid, message = firewall_policies_validator(data)
        assert is_valid is False
        assert "policy_type must be one of the following: inbound, outbound, nat, vpn" in message
    
    def test_firewall_policy_negative_priority(self):
        """Test firewall policies validator with negative priority"""
        data = {
            "name": "TestPolicy",
            "policy_type": "inbound",
            "is_active": True,
            "priority": -1
        }
        is_valid, message = firewall_policies_validator(data)
        assert is_valid is False
        assert "priority must be a non-negative integer" in message
    
    def test_firewall_policy_missing_required_fields(self):
        """Test firewall policies validator with missing required fields"""
        required_fields = ["name", "policy_type", "is_active", "priority"]
        
        for field in required_fields:
            data = {
                "name": "TestPolicy",
                "policy_type": "inbound",
                "is_active": True,
                "priority": 1
            }
            del data[field]
            is_valid, message = firewall_policies_validator(data)
            assert is_valid is False
            assert f"Missing required field: {field}" in message
    
    def test_firewall_policy_invalid_data_types(self):
        """Test firewall policies validator with invalid data types"""
        # Test invalid name type
        data = {
            "name": 123,
            "policy_type": "inbound",
            "is_active": True,
            "priority": 1
        }
        is_valid, message = firewall_policies_validator(data)
        assert is_valid is False
        assert NAME_MUST_BE_STRING_ERROR in message
        
        # Test invalid priority type
        data = {
            "name": "TestPolicy",
            "policy_type": "inbound",
            "is_active": True,
            "priority": "not-a-number"
        }
        is_valid, message = firewall_policies_validator(data)
        assert is_valid is False
        assert "priority must be an integer" in message
        
        # Test invalid is_active type (not bool or string)
        data = {
            "name": "TestPolicy",
            "policy_type": "inbound",
            "is_active": 123,
            "priority": 1
        }
        is_valid, message = firewall_policies_validator(data)
        assert is_valid is False
        assert "is_active must be a boolean" in message
    
    def test_validate_policy_schema_with_firewall_policies_list(self):
        """Test validate_policy_schema with firewall_policies field"""
        data = {
            "name": "TestPolicy",
            "firewall_policies": "not-a-list",
            "policy_type": "inbound",
            "is_active": True,
            "priority": 1
        }
        is_valid, message = validate_policy_schema(data)
        assert is_valid is False
        assert "firewall_policies must be a list" in message
        
        # Valid list
        data["firewall_policies"] = []
        is_valid, message = validate_policy_schema(data)
        assert is_valid is True


class TestFirewallRulesValidator:
    """Test suite for firewall rules validation"""
    
    def test_valid_firewall_rule(self):
        """Test firewall rules validator with valid data"""
        data = {
            "name": "AllowSSH",
            "description": "Allow SSH traffic",
            "action": "allow",
            "source_ip": "192.168.1.10",
            "destination_ip": "192.168.1.20",
            "protocol": "tcp",
            "port": 22,
            "is_active": True
        }
        is_valid, message = firewall_rules_validator(data)
        assert is_valid is True
        assert message == ""
    
    def test_firewall_rule_string_boolean_conversion(self):
        """Test that string booleans are converted properly for rules"""
        # Test "false" string conversion
        data = {
            "name": "AllowHTTP",
            "action": "allow",
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "protocol": "tcp",
            "port": 80,
            "is_active": "false"
        }
        is_valid, message = firewall_rules_validator(data)
        assert is_valid is True
        assert data["is_active"] is False
        
        # Test "true" and other strings default to True
        data["is_active"] = "true"
        is_valid, message = firewall_rules_validator(data)
        assert is_valid is True
        assert data["is_active"] is True
        
        data["is_active"] = "yes"
        is_valid, message = firewall_rules_validator(data)
        assert is_valid is True
        assert data["is_active"] is True
    
    def test_firewall_rule_invalid_action(self):
        """Test firewall rules validator with invalid action"""
        data = {
            "name": "TestRule",
            "action": "invalid",
            "source_ip": "192.168.1.1",
            "destination_ip": "192.168.1.2",
            "protocol": "tcp",
            "port": 443
        }
        is_valid, message = firewall_rules_validator(data)
        assert is_valid is False
        assert "action must be one of the following: allow, deny, reject" in message
    
    def test_firewall_rule_invalid_protocol(self):
        """Test firewall rules validator with invalid protocol"""
        data = {
            "name": "TestRule",
            "action": "allow",
            "source_ip": "192.168.1.1",
            "destination_ip": "192.168.1.2",
            "protocol": "invalid",
            "port": 443
        }
        is_valid, message = firewall_rules_validator(data)
        assert is_valid is False
        assert "protocol must be one of the following: tcp, udp, icmp, any" in message
    
    def test_firewall_rule_invalid_port_range(self):
        """Test firewall rules validator with invalid port numbers"""
        base_data = {
            "name": "TestRule",
            "action": "allow",
            "source_ip": "192.168.1.1",
            "destination_ip": "192.168.1.2",
            "protocol": "tcp"
        }
        
        # Test port 0 (invalid)
        data = base_data.copy()
        data["port"] = 0
        is_valid, message = firewall_rules_validator(data)
        assert is_valid is False
        assert "port must be between 1 and 65535" in message
        
        # Test port > 65535 (invalid)
        data = base_data.copy()
        data["port"] = 65536
        is_valid, message = firewall_rules_validator(data)
        assert is_valid is False
        assert "port must be between 1 and 65535" in message
        
        # Test negative port (invalid)
        data = base_data.copy()
        data["port"] = -1
        is_valid, message = firewall_rules_validator(data)
        assert is_valid is False
        assert "port must be between 1 and 65535" in message
        
        # Test valid port boundaries
        data = base_data.copy()
        data["port"] = 1
        is_valid, message = firewall_rules_validator(data)
        assert is_valid is True
        
        data["port"] = 65535
        is_valid, message = firewall_rules_validator(data)
        assert is_valid is True
    
    def test_firewall_rule_invalid_ip_addresses(self):
        """Test firewall rules validator with invalid IP addresses"""
        base_data = {
            "name": "TestRule",
            "action": "allow",
            "protocol": "tcp",
            "port": 80
        }
        
        # Test invalid source IP
        data = base_data.copy()
        data["source_ip"] = "999.999.999.999"
        data["destination_ip"] = "192.168.1.1"
        is_valid, message = firewall_rules_validator(data)
        assert is_valid is False
        assert "source_ip must be a valid IP address" in message
        
        # Test invalid destination IP
        data = base_data.copy()
        data["source_ip"] = "192.168.1.1"
        data["destination_ip"] = "not-an-ip"
        is_valid, message = firewall_rules_validator(data)
        assert is_valid is False
        assert "destination_ip must be a valid IP address" in message
    
    def test_firewall_rule_missing_required_fields(self):
        """Test firewall rules validator with missing required fields"""
        required_fields = ["name", "action", "source_ip", "destination_ip", "protocol", "port"]
        
        for field in required_fields:
            data = {
                "name": "TestRule",
                "action": "allow",
                "source_ip": "192.168.1.1",
                "destination_ip": "192.168.1.2",
                "protocol": "tcp",
                "port": 443
            }
            del data[field]
            is_valid, message = firewall_rules_validator(data)
            assert is_valid is False
            assert f"Missing required field: {field}" in message
    
    def test_firewall_rule_protocol_case_insensitive(self):
        """Test that protocol validation is case-insensitive"""
        base_data = {
            "name": "TestRule",
            "action": "allow",
            "source_ip": "192.168.1.1",
            "destination_ip": "192.168.1.2",
            "port": 443
        }
        
        protocols = ["TCP", "Tcp", "udp", "UDP", "ICMP", "icmp", "Any", "ANY"]
        for protocol in protocols:
            data = base_data.copy()
            data["protocol"] = protocol
            is_valid, message = firewall_rules_validator(data)
            assert is_valid is True
    
    def test_firewall_rule_invalid_data_types(self):
        """Test firewall rules validator with invalid data types"""
        base_data = {
            "name": "TestRule",
            "action": "allow",
            "source_ip": "192.168.1.1",
            "destination_ip": "192.168.1.2",
            "protocol": "tcp",
            "port": 443
        }
        
        # Test invalid name type
        data = base_data.copy()
        data["name"] = 123
        is_valid, message = firewall_rules_validator(data)
        assert is_valid is False
        assert NAME_MUST_BE_STRING_ERROR in message
        
        # Test invalid port type
        data = base_data.copy()
        data["port"] = "not-a-number"
        is_valid, message = firewall_rules_validator(data)
        assert is_valid is False
        assert "port must be a integer" in message
        
        # Test invalid action type
        data = base_data.copy()
        data["action"] = 123
        is_valid, message = firewall_rules_validator(data)
        assert is_valid is False
        assert "action must be a string" in message


class TestValidateSchemaFunctions:
    """Test suite for schema validation functions"""
    
    def test_validate_firewall_schema_empty_data(self):
        """Test validate_firewall_schema with empty data"""
        is_valid, message = validate_firewall_schema({})
        assert is_valid is False
        assert message == NO_INPUT_DATA_ERROR
        
        is_valid, message = validate_firewall_schema(None)
        assert is_valid is False
        assert message == NO_INPUT_DATA_ERROR
    
    def test_validate_policy_schema_empty_data(self):
        """Test validate_policy_schema with empty data"""
        is_valid, message = validate_policy_schema({})
        assert is_valid is False
        assert message == NO_INPUT_DATA_ERROR
        
        is_valid, message = validate_policy_schema(None)
        assert is_valid is False
        assert message == NO_INPUT_DATA_ERROR
    
    def test_validate_rule_schema_empty_data(self):
        """Test validate_rule_schema with empty data"""
        is_valid, message = validate_rule_schema({})
        assert is_valid is False
        assert message == NO_INPUT_DATA_ERROR
        
        is_valid, message = validate_rule_schema(None)
        assert is_valid is False
        assert message == NO_INPUT_DATA_ERROR
    
    def test_validate_firewall_schema_optional_fields(self):
        """Test validate_firewall_schema with optional fields"""
        data = {
            "name": "TestFirewall",
            "hostname": "us-nyc-001",
            "ip_address": "192.168.1.1",
            "vendor": "cisco",
            "model": "ASA5505",
            "os_version": "9.1",
            "description": "",  # Empty string should be valid
            "country": "",      # Empty string should be valid
            "city": ""          # Empty string should be valid
        }
        is_valid, message = validate_firewall_schema(data)
        assert is_valid is True
        assert message == ""


class TestEdgeCases:
    """Test edge cases and error handling"""
    
    def test_validators_with_none_values(self):
        """Test validators with None values in fields"""
        # User validator
        data = {"username": None, "password": "pass", "email": "test@test.com"}
        is_valid, message = user_validator(data)
        assert is_valid is False
        
        # Firewall validator
        data = {
            "name": None,
            "hostname": "us-nyc-001",
            "ip_address": "192.168.1.1",
            "vendor": "cisco",
            "model": "ASA5505",
            "os_version": "9.1"
        }
        is_valid, message = firewall_validator(data)
        assert is_valid is False
    
    def test_validators_with_empty_strings(self):
        """Test validators with empty strings"""
        # Hostname validation
        assert validate_hostname("") is False
        
        # IP validation
        assert validate_ip("") is False
        
        # Email validation in user_validator
        data = {
            "username": "test",
            "password": "pass",
            "email": ""
        }
        is_valid, message = user_validator(data)
        assert is_valid is False
        assert "email must be a valid email address" in message
    
    def test_validators_with_special_characters(self):
        """Test validators with special characters"""
        # Valid special characters in email
        data = {
            "username": "test.user",
            "password": "Pass@123!",
            "email": "test.user+tag@example.com"
        }
        is_valid, message = user_validator(data)
        assert is_valid is True
        
        # Special characters in hostname (should fail)
        assert validate_hostname("us-ny@-001") is False
        assert validate_hostname("us-nyc-00!") is False