"""
Firewall utility functions.

This module provides helper functions for firewall operations including
field updates and policy associations.
"""
from flask import jsonify
from typing import Tuple, Dict, Any

try:
    from src.models.firewall import Firewall
    from src.models.firewall_policy import FirewallPolicy
except ImportError:
    from models.firewall import Firewall
    from models.firewall_policy import FirewallPolicy

def set_firewall_policies(firewall: Firewall, data: Dict[str, Any]) -> Tuple[None, None] | Tuple[Dict[str, str], int]:
    """
    This function manages the many-to-many relationship between firewalls
    and policies. It adds new policies while preserving existing relationships.

    Args:
        firewall (Firewall): The firewall instance to update.
        data (Dict[str, Any]): Request data containing 'policies_ids' key.
    """
    policies_ids = data.get("policies_ids", [])
    if policies_ids:
        policies = FirewallPolicy.query.filter(FirewallPolicy.id.in_(policies_ids)).all()
        if not policies:
            return jsonify({
                "message": "One or more policies not found."
            }), 404
            
        for policy in policies:
            if policy not in firewall.policies:
                firewall.policies.append(policy)


def update_firewall_unique_field(firewall: Firewall, data: Dict[str, Any], field_name: str) -> bool:
    """
    Update a unique field on a firewall, checking for conflicts.
    
    This function safely updates unique fields (like hostname or name) by
    first checking if another firewall already uses the new value.
    
    Args:
        firewall (Firewall): The firewall instance to update.
        data (Dict[str, Any]): Request data containing the new field value.
        field_name (str): Name of the unique field to update.
    
    Returns:
        bool: True if update is safe or field unchanged, False if conflict exists.
    """
    if field_name in data and data[field_name] != getattr(firewall, field_name):
        existing_firewall = Firewall.query.filter_by(**{field_name: data[field_name]}).first()
        if existing_firewall:
            return False
            
        setattr(firewall, field_name, data.get(field_name, getattr(firewall, field_name)))
    
    return True


def update_firewall_fields(firewall: Firewall, data: Dict[str, Any]) -> None:
    """
    This function safely updates unique fields (like hostname or name) by
    first checking if another firewall already uses the new value.
    
    Args:
        firewall (Firewall): The firewall instance to update.
        data (Dict[str, Any]): Request data containing the new field value.
        field_name (str): Name of the unique field to update.
    
    Returns:
        bool: True if update is safe or field unchanged, False if conflict exists.
    """
    fields = ["description", "ip_address", "vendor", "model", "os_version", "country", "city"]
    for field in fields:
        if field in data:
            setattr(firewall, field, data.get(field, getattr(firewall, field)))