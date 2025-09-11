"""
Firewall policy utility functions.

This module provides helper functions for firewall policy operations including
field updates and rule associations.
"""
from typing import Dict, Any

try:
    from src.models.firewall_policy import FirewallPolicy
    from src.models.firewall_rule import FirewallRule
except ImportError:
    from models.firewall_policy import FirewallPolicy
    from models.firewall_rule import FirewallRule

def update_policy_rules(policy: FirewallPolicy, data: Dict[str, Any]) -> None:
    """
    This function manages the many-to-many relationship between firewall policies
    and rules. It adds new rules while preserving existing relationships.

    Args:
        policy (FirewallPolicy): The firewall policy instance to update.
        data (Dict[str, Any]): Request data containing 'rules_id' key.
    """
    rules_id = data.get("rules_id")
    if rules_id:
        rules = FirewallRule.query.filter(FirewallRule.id.in_(rules_id)).all()
        for rule in rules:
            if rule not in policy.rules:
                policy.rules.append(rule)

def update_firewall_policy_unique_field(firewall_policy: FirewallPolicy, data: Dict[str, Any], field_name: str) -> bool:
    """
    Update a unique field on a firewall policy, checking for conflicts.
    This function safely updates unique fields (like name) by
    first checking if another policy already uses the new value.

    Args:
        firewall_policy (FirewallPolicy): The firewall policy instance to update.
        data (Dict[str, Any]): Request data containing the new field value.
    
    Returns:
        bool: True if update is safe or field unchanged, False if conflict exists.
    """
    if field_name in data and data[field_name] != getattr(firewall_policy, field_name):
        existing_firewall = FirewallPolicy.query.filter_by(**{field_name: data[field_name]}).first()
        if existing_firewall:
            return False

        setattr(firewall_policy, field_name, data.get(field_name, getattr(firewall_policy, field_name)))
    
    return True

def update_firewall_policy_fields(firewall_policy: FirewallPolicy, data: Dict[str, Any]) -> FirewallPolicy:
    """
    This function updates non-unique fields of a firewall policy.

    Args:
        firewall_policy (FirewallPolicy): The firewall policy instance to update.
        data (Dict[str, Any]): Request data containing the new field values.

    Returns:
        FirewallPolicy: The updated firewall policy instance.
    """
    fields = ['description', 'policy_type', 'is_active', 'priority', 'last_modified_by']
    for field in fields:
        if field in data:
            setattr(firewall_policy, field, data.get(field, getattr(firewall_policy, field)))
    
    return firewall_policy