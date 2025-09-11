"""
Firewall rule utility functions.

This module provides helper functions for firewall rule operations including
field updates.
"""
from typing import Dict, Any

try:
    from src.models.firewall_rule import FirewallRule
except ImportError:
    from models.firewall_rule import FirewallRule

def update_firewall_rule_fields(firewall_rule: FirewallRule, data: Dict[str, Any]) -> FirewallRule:
    """
    This function safely updates fields of a firewall rule.

    Args:
        firewall_rule (FirewallRule): The firewall rule instance to update.
        data (Dict[str, Any]): Request data containing fields to update.

    Returns:
        FirewallRule: The updated firewall rule instance.
    """
    fields = ['name', 'description', 'action', 'source_ip', 'destination_ip', 'protocol', 'port', 'is_active', 'last_modified_by']
    for field in fields:
        if field in data:
            setattr(firewall_rule, field, data.get(field, getattr(firewall_rule, field)))
    return firewall_rule