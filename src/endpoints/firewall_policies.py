"""
Firewall Policies API endpoints.

This module defines RESTful API endpoints for managing firewall policies,
including creation, retrieval, updating, deletion, and rule associations.
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from typing import Tuple, Dict, Any

try:
    from src.models.firewall_policy import db, FirewallPolicy
    from src.models.firewall_rule import FirewallRule
    from src.models.user import User
    from src.validators.input_validators import firewall_policies_validator, validate_policy_schema
    from src.utils.firewall_policies_utils import update_firewall_policy_fields, update_firewall_policy_unique_field, update_policy_rules
    from src.rbac.role_based_access_control import role_required
except ImportError:
    from models.firewall_policy import db, FirewallPolicy
    from models.firewall_rule import FirewallRule
    from models.user import User
    from validators.input_validators import firewall_policies_validator, validate_policy_schema
    from utils.firewall_policies_utils import update_firewall_policy_fields, update_firewall_policy_unique_field, update_policy_rules
    from rbac.role_based_access_control import role_required

firewall_policies_bp = Blueprint('firewall_policies', __name__, url_prefix='/api')

FIREWALL_POLICY_NOT_FOUND = "Firewall policy not found"

@firewall_policies_bp.route('/firewall_policies', methods=["GET"])
@jwt_required()
@role_required('user', 'read_policy')
def get_firewall_policies() -> Tuple[Dict[str, Any], int]:
    """
    Returns a list of all firewall policies in the system with their associated rules.

    Returns:
        tuple: JSON response with list of firewall policies and HTTP status code.

    Responses:
        200: List of firewall retrieved policies.
        500: Internal server error.
    """
    try:
        policies = FirewallPolicy.query.all()
        return jsonify({
            "firewall_policies": [policy.to_dict() for policy in policies]
        }), 200

    except Exception as e:
        return jsonify({
            "message": str(e)
        }), 500


@firewall_policies_bp.route('/firewall_policies', methods=["POST"])
@jwt_required()
@role_required('operator', 'create_policy')
def create_firewall_policy() -> Tuple[Dict[str, Any], int]:
    """
    Creates a new firewall policy with the provided information and optionally
    associates it with existing rules.

    Request Body:
        name (str): Name of the firewall policy.
        description (str, optional): Description of the firewall policy.
        policy_type (str): Type of the firewall policy.
        is_active (bool, optional): Whether the policy is active.
        priority (int, optional): Priority of the policy.
        rules_id (list[int], optional): List of rule IDs to associate with the policy.

    Returns:
        tuple: JSON response with created firewall policy details and HTTP status code.

    Responses:
        201: Firewall policy created successfully.
        400: Bad request (e.g., missing required fields, duplicate name).
        500: Internal server error.
    """
    try:
        data = request.get_json()
        is_valid, validation_message = firewall_policies_validator(data)
        if not is_valid:
            return jsonify({
                "message": validation_message
            }), 400

        policy_name = FirewallPolicy.query.filter_by(name=data['name']).first()
        if policy_name:
            return jsonify({
                "message": f"Firewall policy with this name {data['name']} already exists"
            }), 400
            
        user = get_jwt_identity()
        user = User.query.filter_by(id=user).first()

        new_policy = FirewallPolicy(
            name=data.get("name"),
            description=data.get("description"),
            policy_type=data.get("policy_type"),
            is_active=data.get("is_active", True),
            priority=data.get("priority"),
            created_by=user.username,
            last_modified_by=user.username,
        )

        # If provided associated rules, add them to the policy
        update_policy_rules(new_policy, data)
        db.session.add(new_policy)
        db.session.commit()

        return jsonify({
            "message": "Firewall policy created",
            "firewall_policy": new_policy.to_dict()
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "message": str(e)}
        ), 500


@firewall_policies_bp.route('/firewall_policies/<int:policy_id>', methods=["PUT"])
@jwt_required()
@role_required('operator', 'update_policy')
def update_firewall_policy(policy_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Updates an existing firewall policy with the provided information and replaces all rule associations
    if rules_id is provided.

    Args:
        policy_id (int): ID of the firewall policy to update.

    Request Body:
        Same fields as in create_firewall_policy endpoint.
        rules_id (list[int], optional): If provided, replaces all current rules.

    Returns:
        tuple: JSON response with updated firewall policy details and HTTP status code.
    
    Responses:
        200: Firewall policy updated successfully.
        400: Bad request (e.g., duplicate name).
        404: Firewall policy not found.
        500: Internal server error.
    """
    try:
        policy = FirewallPolicy.query.filter_by(id=policy_id).first()

        if not policy:
            return jsonify({
                "message": FIREWALL_POLICY_NOT_FOUND
            }), 404

        data = request.get_json()
        is_valid, validation_message = validate_policy_schema(data)
        if not is_valid:
            return jsonify({
                "message": validation_message
            }), 400

        if not update_firewall_policy_unique_field(policy, data, 'name'):
            return jsonify({
                "message": f"Firewall policy with this name {data['name']} already exists"
            }), 400

        data['last_modified_by'] = User.query.filter_by(id=get_jwt_identity()).first().username
        update_firewall_policy_fields(policy, data)
        db.session.commit()

        return jsonify({
            "message": f"Firewall policy updated {policy.name}",
            "firewall_policy": policy.to_dict()
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "message": str(e)}
        ), 500


@firewall_policies_bp.route('/firewall_policies/<int:policy_id>/rules', methods=["PATCH"])
@jwt_required()
@role_required('operator', 'add_rule_to_policy')
def patch_rules_to_policy(policy_id: int) -> Tuple[Dict[str, Any], int]:
    """
    This endpoint performs a partial update to an existing firewall policy by adding new rules
    to its current set of associated rules.

    Args:
        policy_id (int): ID of the firewall policy to update.

    Request Body:
        rules_id (list[int]): List of rule IDs to add to the policy.

    Returns:
        tuple: JSON response with updated firewall policy details and HTTP status code.

    Responses:
        200: Rules added to the firewall policy successfully.
        400: Bad request (e.g., no rules_id provided).
        404: Firewall policy not found.
        500: Internal server error.
    """
    try:
        policy = FirewallPolicy.query.filter_by(id=policy_id).first()
        if not policy:
            return jsonify({
                "message": FIREWALL_POLICY_NOT_FOUND
            }), 404

        data = request.get_json()
        if not data or "rules_id" not in data:
            return jsonify({
                "message": "No rules_id provided to add to policy",
                "firewall_policy": policy.to_dict()
            }), 400

        update_policy_rules(policy, data)
        policy.last_modified_by = User.query.filter_by(id=get_jwt_identity()).first().username
        db.session.commit()

        return jsonify({
            "message": f"Rules added to policy {policy.name}",
            "firewall_policy": policy.to_dict()
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "message": str(e)}
        ), 500


@firewall_policies_bp.route('/firewall_policies/<int:policy_id>/rules/<int:rule_id>', methods=["DELETE"])
@jwt_required()
@role_required('operator', 'delete_rule_from_policy')
def remove_rule_from_policy(policy_id: int, rule_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Remove a specific rule from a firewall policy.

    Args:
        policy_id (int): ID of the firewall policy.
        rule_id (int): ID of the rule to remove from the policy.

    Returns:
        tuple: JSON response with updated firewall policy details and HTTP status code.

    Responses:
        200: Rule removed from the firewall policy successfully.
        404: Firewall policy or rule not found.
        500: Internal server error.
    """
    try:
        policy = FirewallPolicy.query.filter_by(id=policy_id).first()
        rule = FirewallRule.query.filter_by(id=rule_id).first()

        if not policy:
            return jsonify({
                "message": FIREWALL_POLICY_NOT_FOUND
            }), 404

        if not rule:
            return jsonify({
                "message": f"Rule with id {rule_id} not found"
            }), 404

        policy.rules.remove(rule)
        db.session.commit()

        return jsonify({
            "message": f"Rule {rule.name} removed from policy {policy.name}",
            "firewall_policy": policy.to_dict()
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "message": str(e)}
        ), 500

@firewall_policies_bp.route('/firewall_policies/<int:policy_id>', methods=["DELETE"])
@jwt_required()
@role_required('operator', 'delete_policy')
def delete_firewall_policy(policy_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Removes a firewall policy and its associated rules from the system.

    Args:
        policy_id (int): ID of the firewall policy to delete.

    Returns:
        tuple: JSON response with details of the deleted firewall policy and HTTP status code.

    Responses:
        200: Firewall policy deleted successfully.
        404: Firewall policy not found.
        500: Internal server error. 
    """
    try:
        policy = FirewallPolicy.query.filter_by(id=policy_id).first()
        if not policy:
            return jsonify({
                "message": FIREWALL_POLICY_NOT_FOUND
            }), 404

        db.session.delete(policy)
        db.session.commit()

        return jsonify({
            "message": f"Firewall policy {policy.name} deleted",
            "firewall_policy": policy.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            "message": str(e)}
        ), 500