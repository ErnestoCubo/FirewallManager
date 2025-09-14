import ipaddress
import re

NO_INPUT_DATA_ERROR = "No input data provided"
NAME_MUST_BE_STRING_ERROR = "name must be a string"
DESCRIPTION_MUST_BE_STRING_ERROR = "description must be a string"

def user_validator(data: dict) -> tuple[bool, str]:
    required_fields = ["username", "password", "email"]

    if not data:
        return False, NO_INPUT_DATA_ERROR

    for field in required_fields:
        if field not in data:
            return False, f"Missing required field: {field}"

    if not isinstance(data.get("username", ""), str):
        return False, "username must be a string"

    if not isinstance(data.get("password", ""), str):
        return False, "password must be a string"

    if not isinstance(data.get("email", ""), str):
        return False, "email must be a string"
    elif not re.match(r"[^@]+@[^@]+\.[^@]+", data.get("email", "")):
        return False, "email must be a valid email address"

    return True, ""

def firewall_validator(data: dict) -> tuple[bool, str]:
    required_fields = ["name", "hostname", "ip_address", "vendor", "model", "os_version"]

    if not data:
        return False, NO_INPUT_DATA_ERROR

    for field in required_fields:
        if field not in data:
            return False, f"Missing required field: {field}"

    return validate_firewall_schema(data)


def validate_firewall_schema(data: dict) -> tuple[bool, str]:

    if not data:
        return False, NO_INPUT_DATA_ERROR

    if not isinstance(data.get("name", ""), str):
        return False, NAME_MUST_BE_STRING_ERROR

    if not isinstance(data.get("hostname", ""), str):
        return False, "hostname must be a string"
    elif not validate_hostname(data.get("hostname", "")):
        return False, "hostname must be in the format XX-XXX-DDD"

    if not isinstance(data.get("description", ""), str):
        return False, DESCRIPTION_MUST_BE_STRING_ERROR

    if not isinstance(data.get("ip_address", ""), str):
        return False, "ip_address must be a string"
    elif not validate_ip(data.get("ip_address", "")):
        return False, "ip_address must be a valid IP address"

    if not isinstance(data.get("vendor", ""), str):
        return False, "vendor must be a string"

    if not isinstance(data.get("model", ""), str):
        return False, "model must be a string"

    if not isinstance(data.get("os_version", ""), str):
        return False, "os_version must be a string"

    if not isinstance(data.get("country", ""), str):
        return False, "country must be a string"

    if not isinstance(data.get("city", ""), str):
        return False, "city must be a string"

    return True, ""

def validate_hostname(hostname: str) -> bool:
    regex = r"([a-zA-Z]{2})-([a-zA-Z]{3})-(\d{1,3})"
    if re.fullmatch(regex, hostname):
        return True
    return False

def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def firewall_policies_validator(data: dict) -> tuple[bool, str]:
    required_fields = ["name", "policy_type", "is_active", "priority"]

    if not data:
        return False, NO_INPUT_DATA_ERROR
    
    for field in required_fields:
        if field not in data:
            return False, f"Missing required field: {field}"

    return validate_policy_schema(data)


def validate_policy_schema(data: dict) -> tuple[bool, str]:
    if not data:
        return False, NO_INPUT_DATA_ERROR

    if not isinstance(data.get("name", ""), str):
        return False, NAME_MUST_BE_STRING_ERROR

    if not isinstance(data.get("firewall_policies", []), list):
        return False, "firewall_policies must be a list"

    if not isinstance(data.get("description", ""), str):
        return False, DESCRIPTION_MUST_BE_STRING_ERROR

    if not isinstance(data.get("policy_type", ""), str):
        return False, "policy_type must be a string"
    elif (data.get("policy_type")) and (data.get("policy_type", "") not in ["inbound", "outbound", "nat", "vpn"]):
        return False, "policy_type must be one of the following: inbound, outbound, nat, vpn"

    is_active = data.get("is_active", "")
    if isinstance(is_active, str):
        if is_active.lower() == "false":
            data["is_active"] = False
        else:
            data["is_active"] = True
    elif not isinstance(is_active, bool):
        return False, "is_active must be a boolean"

    if not isinstance(data.get("priority", 0), int):
        return False, "priority must be an integer"
    elif data.get("priority", 0) < 0:
        return False, "priority must be a non-negative integer"

    if not isinstance(data.get("created_by", ""), str):
        return False, "created_by must be a string"
    
    if not isinstance(data.get("last_modified_by", ""), str):
        return False, "last_modified_by must be a string"
    
    return True, ""


def firewall_rules_validator(data: dict) -> tuple[bool, str]:
    required_fields = ["name", "action", "source_ip", "destination_ip", "protocol", "port"]

    if not data:
            return False, NO_INPUT_DATA_ERROR

    for field in required_fields:
        if field not in data:
            return False, f"Missing required field: {field}"

    return validate_rule_schema(data)

def validate_rule_schema(data: dict) -> tuple[bool, str]:
    if not data:
        return False, NO_INPUT_DATA_ERROR

    if not isinstance(data.get("name", ""), str):
        return False, NAME_MUST_BE_STRING_ERROR

    if not isinstance(data.get("description", ""), str):
        return False, DESCRIPTION_MUST_BE_STRING_ERROR

    if not isinstance(data.get("action", ""), str):
        return False, "action must be a string"
    elif data.get("action") and data.get("action", "") not in ["allow", "deny", "reject"]:
        return False, "action must be one of the following: allow, deny, reject"

    if not isinstance(data.get("source_ip", ""), str):
        return False, "source_ip must be a string"
    elif data.get("source_ip") and not validate_ip(data.get("source_ip", "")):
        return False, "source_ip must be a valid IP address"

    if not isinstance(data.get("destination_ip", ""), str):
        return False, "destination_ip must be a string"
    elif data.get("destination_ip") and not validate_ip(data.get("destination_ip", "")):
        return False, "destination_ip must be a valid IP address"

    if not isinstance(data.get("protocol", ""), str):
        return False, "protocol must be a string"
    elif data.get("protocol") and data.get("protocol", "").lower() not in ["tcp", "udp", "icmp", "any"]:
        return False, "protocol must be one of the following: tcp, udp, icmp, any"
    
    if not isinstance(data.get("port", 0), int):
        return False, "port must be a integer"
    elif (data.get("port") is not None) and not (0 < data.get("port", 0) < 65536):
        return False, "port must be between 1 and 65535"

    is_active = data.get("is_active", "")
    if isinstance(is_active, str):
        if is_active.lower() == "false":
            data["is_active"] = False
        else:
            data["is_active"] = True
    elif not isinstance(is_active, bool):
        return False, "is_active must be a boolean"
    
    return True, ""