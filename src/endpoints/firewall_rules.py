"""
Firewall Rules endpoints

This module defines the RESTful API endpoints for managing firewall rules,
including creation, retrieval, updating, and deletion.
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from typing import Tuple, Dict, Any

try:
    from src.models.firewall_rule import db, FirewallRule
    from src.utils.firewall_rules_utils import update_firewall_rule_fields
except ImportError:
    from models.firewall_rule import db, FirewallRule
    from utils.firewall_rules_utils import update_firewall_rule_fields


firewall_rules_bp = Blueprint('firewall_rules', __name__, url_prefix='/api')


@firewall_rules_bp.route('/firewall_rules', methods=['GET'])
@jwt_required()
def get_firewall_rules() -> Tuple[Dict[str, Any], int]:
    """
    Returns a list of all firewall rules in the system.

    Returns:
        tuple: JSON response with list of firewall rules and HTTP status code.

    Responses:
        200: List of firewall rules retrieved.
        500: Internal server error.
    """
    try:
        rules = FirewallRule.query.all()
        return jsonify({
            "firewall_rules": [rule.to_dict() for rule in rules]
        }), 200

    except Exception as e:
        return jsonify({
            "message": str(e)
        }), 500


@firewall_rules_bp.route('/firewall_rules', methods=['POST'])
@jwt_required()
def create_firewall_rule() -> Tuple[Dict[str, Any], int]:
    """
    Create a new firewall rule with the provided information.

    Request Body:
        name (str): Name of the firewall rule.
        description (str, optional): Description of the firewall rule.
        action (str): Action of the firewall rule (e.g., "allow", "deny").
        source_ip (str): Source IP address or range.
        destination_ip (str): Destination IP address or range.
        protocol (str): Protocol (e.g., "tcp", "udp", "icmp").
        port (str): Port or port range.
        is_active (bool, optional): Whether the rule is active. Defaults to True.
        last_modified_by (str): User who last modified the rule.

    Returns:
        tuple: JSON response with the created firewall rule and HTTP status code.
    
    Responses:
        201: Firewall rule created successfully.
        400: Bad request (e.g., missing required fields).
        500: Internal server error.
    """
    try:
        data = request.get_json()
        user_identity = get_jwt_identity()

        required_fields = ["name", "action", "source_ip", "destination_ip", "protocol", "port", "last_modified_by"]
        for field in required_fields:
            if field not in data:
                return jsonify({
                    "message": f"Missing required field: {field}"
                }), 400

        new_rule = FirewallRule(
            name=data.get("name"),
            description=data.get("description"),
            action=data.get("action"),
            source_ip=data.get("source_ip"),
            destination_ip=data.get("destination_ip"),
            protocol=data.get("protocol"),
            port=data.get("port"),
            is_active=data.get("is_active", True),
            created_by=user_identity,
            last_modified_by=data.get("last_modified_by"),
        )

        db.session.add(new_rule)
        db.session.commit()

        return jsonify({
            "message": "Firewall rule created",
            "firewall_rule": new_rule.to_dict()
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "message": str(e)}
        ), 500


@firewall_rules_bp.route('/firewall_rules/<int:rule_id>', methods=['PUT'])
@jwt_required()
def update_firewall_rule(rule_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Update an existing firewall rule with the provided information.
    
    Args:
        rule_id (int): ID of the firewall rule to update.
    
    Returns:
        tuple: JSON response with updated firewall rule details and HTTP status code.

    Responses:
        200: Firewall rule updated successfully.
        400: Bad request (e.g., invalid data).
        404: Firewall rule not found.   
        500: Internal server error.
    """

    try:
        rule = FirewallRule.query.filter_by(id=rule_id).first()

        if not rule:
            return jsonify({
                "message": "Firewall rule not found"
            }), 404

        data = request.get_json()
        update_firewall_rule_fields(rule, data)
        db.session.commit()

        return jsonify({
            "message": "Firewall rule updated",
            "firewall_rule": rule.to_dict()
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "message": str(e)}
        ), 500    


@firewall_rules_bp.route('/firewall_rules/<int:rule_id>', methods=['DELETE'])
@jwt_required()
def delete_firewall_rule(rule_id: int):
    """
    Delete a firewall rule by its ID.

    Args:
        rule_id (int): ID of the firewall rule to delete.

    Returns:
        tuple: JSON response with deletion status and HTTP status code.

    Responses:
        200: Firewall rule deleted successfully.
        404: Firewall rule not found.
        500: Internal server error.
    """
    try:
        rule = FirewallRule.query.filter_by(id=rule_id).first()

        if not rule:
            return jsonify({
                "message": "Firewall rule not found"
            }), 404

        db.session.delete(rule)
        db.session.commit()

        return jsonify({
            "message": "Firewall rule deleted",
            "firewall_rule": rule.to_dict()
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "message": str(e)}
        ), 500    