import pytest
from src.validators.input_validators import (
    firewall_validator,
    validate_hostname,
    validate_ip,
    firewall_policies_validator,
    validate_policy_schema,
    firewall_rules_validator,
    validate_rule_schema,
    NO_INPUT_DATA_ERROR
)


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
        data = {
            "name": "TestFirewall",
            "hostname": "us-nyc-001",
            # Missing ip_address, vendor, model, os_version
        }
        is_valid, message = firewall_validator(data)
        assert is_valid is False
        assert "Missing required field:" in message
    
    def test_firewall_validator_invalid_hostname_format(self):
        """Test firewall validator with invalid hostname format"""
        data = {
            "name": "TestFirewall",
            "hostname": "invalid-hostname",  # Should be XX-XXX-DDD format
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
            "ip_address": "999.999.999.999",  # Invalid IP
            "vendor": "cisco",
            "model": "ASA5505",
            "os_version": "9.1"
        }
        is_valid, message = firewall_validator(data)
        assert is_valid is False
        assert "ip_address must be a valid IP address" in message
    
    def test_firewall_validator_empty_data(self):
        """Test firewall validator with empty data"""
        is_valid, message = firewall_validator({})
        assert is_valid is False
        assert message == NO_INPUT_DATA_ERROR or "Missing required field:" in message
    
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
            "AU-SYD-050"
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
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334"  # IPv6
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
            "not-an-ip"
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
        data = {
            "name": "TestPolicy",
            "policy_type": "outbound",
            "is_active": "true",
            "priority": 5
        }
        is_valid, _ = firewall_policies_validator(data)
        assert is_valid is True
        assert data["is_active"] is True  # Should be converted to boolean
        
        data["is_active"] = "false"
        is_valid, _ = firewall_policies_validator(data)
        assert is_valid is True
        assert data["is_active"] is False  # Should be converted to boolean
    
    def test_firewall_policy_invalid_policy_type(self):
        """Test firewall policies validator with invalid policy type"""
        data = {
            "name": "TestPolicy",
            "policy_type": "invalid",  # Not in allowed list
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
        base_data = {
            "name": "TestPolicy",
            "policy_type": "inbound",
            "is_active": True,
            "priority": 1
        }
        
        # Test invalid name type
        data = base_data.copy()
        data["name"] = 123
        is_valid, message = firewall_policies_validator(data)
        assert is_valid is False
        assert "name must be a string" in message
        
        # Test invalid priority type
        data = base_data.copy()
        data["priority"] = "not-a-number"
        is_valid, message = firewall_policies_validator(data)
        assert is_valid is False
        assert "priority must be an integer" in message


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
        data = {
            "name": "AllowHTTP",
            "action": "allow",
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "protocol": "tcp",
            "port": 80,
            "is_active": "true"
        }
        is_valid, _ = firewall_rules_validator(data)
        assert is_valid is True
        assert data["is_active"] is True
        
        data["is_active"] = "false"
        is_valid, _ = firewall_rules_validator(data)
        assert is_valid is True
        assert data["is_active"] is False
    
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
        data = {
            "name": "TestRule",
            "action": "allow",
            "source_ip": "192.168.1.1",
            "destination_ip": "192.168.1.2",
            "protocol": "TCP",
            "port": 443
        }
        is_valid, _ = firewall_rules_validator(data)
        assert is_valid is True
        
        data["protocol"] = "Tcp"
        is_valid, _ = firewall_rules_validator(data)
        assert is_valid is True