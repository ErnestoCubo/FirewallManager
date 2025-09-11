"""
Firewall endpoints.

This module defines RESTful API endpoints for managing firewall devices,
including creation, retrieval, updating, and deletion. It also handles
associations between firewalls and security policies.
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from typing import Tuple, Dict, Any

try:
    from src.models.firewall import db, Firewall
    from src.models.firewall_policy import FirewallPolicy
    from src.utils.firewall_utils import (
        set_firewall_policies,
        update_firewall_unique_field,
        update_firewall_fields
    )
except ImportError:
    from models.firewall import db, Firewall
    from models.firewall_policy import FirewallPolicy
    from utils.firewall_utils import (
        set_firewall_policies,
        update_firewall_unique_field,
        update_firewall_fields
    )

firewalls_bp = Blueprint('firewalls', __name__, url_prefix='/api')

FIREWALL_NOT_FOUND_MESSAGE = "Firewall not found"
FIREWALL_WITH_HOSTNAME_EXISTS = "Firewall with this hostname already exists"

@firewalls_bp.route('/firewalls', methods=["GET"])
@jwt_required()
def get_firewalls() -> Tuple[Dict[str, Any], int]:
    """
    Returns a list of all firewall devices in the system with their
    basic information.
    
    Returns:
        tuple: JSON response with list of firewalls and HTTP status code.
        
    Response:
        200: List of firewalls retrieved successfully.
        500: Internal server error.
    """
    try:
        firewalls = Firewall.query.all()
        return jsonify({
            "firewalls": [fw.to_dict() for fw in firewalls]
        }), 200
    except Exception as e:
        return jsonify({
            "message": str(e)}
        ), 500


@firewalls_bp.route('/firewalls', methods=["POST"])
@jwt_required()
def create_firewall() -> Tuple[Dict[str, Any], int]:
    """
    Creates a new firewall with the provided information and optionally
    associates it with existing policies.
    
    Request Body:
        name (str): Unique name for the firewall.
        hostname (str): Unique hostname for the firewall.
        ip_address (str): IP address of the firewall.
        vendor (str): Firewall vendor/manufacturer.
        model (str): Firewall model.
        os_version (str): Operating system version.
        description (str, optional): Description of the firewall.
        country (str, optional): Country location.
        city (str, optional): City location.
        policies_ids (list[int], optional): IDs of policies to associate.
    
    Returns:
        tuple: JSON response with created firewall and HTTP status code.
        
    Response:
        201: Firewall created successfully.
        400: Invalid input or duplicate hostname/name.
        500: Server error during creation.
    """
    try:
        data = request.get_json()

        required_fields = ['name', 'hostname', 'ip_address', 'vendor', 'model', 'os_version']
        missing_fields = [field for field in required_fields if not data.get(field)]

        if missing_fields:
            return jsonify({
                "message": f"Missing required fields: {', '.join(missing_fields)}"
            }), 400

        if Firewall.query.filter_by(hostname=data.get('hostname')).first():
            return jsonify({
                "message": FIREWALL_WITH_HOSTNAME_EXISTS
            }), 400

        if Firewall.query.filter_by(name=data['name']).first():
            return jsonify({
                "message": f"Firewall with this name {data['name']} already exists"
            }), 400

        # Creating a new firewall instance
        new_firewall = Firewall(
            name=data.get("name"),
            description=data.get("description"),
            hostname=data.get("hostname"),
            ip_address=data.get("ip_address"),
            vendor=data.get("vendor"),
            model=data.get("model"),
            os_version=data.get("os_version"),
            country=data.get("country"),
            city=data.get("city"),
        )

        # If provided associated policies, add them
        set_firewall_policies(new_firewall, data)

        db.session.add(new_firewall)
        db.session.commit()

        return jsonify({
            "message": "Firewall created",
            "firewall": new_firewall.to_dict()
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "message": str(e)}
        ), 500


@firewalls_bp.route('/firewalls/<int:firewall_id>', methods=["PUT"])
@jwt_required()
def update_firewall(firewall_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Updates firewall information and replaces all policy associations
    if policies_ids is provided.
    
    Args:
        hostname (str): Hostname of the firewall to update.
    
    Request Body:
        Same as create_firewall, all fields optional.
        policies_ids (list[int]): If provided, replaces all current policies.
    
    Returns:
        tuple: JSON response with updated firewall and HTTP status code.
        
    Response:
        200: Firewall updated successfully.
        400: Invalid input or duplicate hostname/name.
        404: Firewall not found.
        500: Server error during update.
    """
    try:
        firewall = Firewall.query.filter_by(id=firewall_id).first()

        if not firewall:
            return jsonify({
                "message": FIREWALL_NOT_FOUND_MESSAGE,
            }), 404

        data = request.get_json()

        if not data:
            return jsonify({
                "message": "No data provided for update",
                "firewall": firewall.to_dict()
            }), 400

        if not update_firewall_unique_field(firewall, data, "hostname"):
            return jsonify({
                "message": FIREWALL_WITH_HOSTNAME_EXISTS,
                "firewall": firewall.to_dict()
            }), 400

        if not update_firewall_unique_field(firewall, data, "name"):
            return jsonify({
                "message": f"Firewall with this name {data['name']} already exists",
                "firewall": firewall.to_dict()
            }), 400

        # Update normal fields
        update_firewall_fields(firewall, data)    
        db.session.commit()

        return jsonify({
            "message": f"Firewall updated {firewall.name}",
            "firewall": firewall.to_dict()
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "message": str(e)}
        ), 500


@firewalls_bp.route('/firewalls/<int:firewall_id>/policies', methods=["PATCH"])
@jwt_required()
def patch_firewall_policies(firewall_id: int) -> Tuple[Dict[str, Any], int]:
    """
    This endpoint performs a partial update, adding new policy associations
    while preserving existing ones.
    
    Args:
        hostname (str): Hostname of the firewall to update.
    
    Request Body:
        policies_ids (list[int]): IDs of policies to add.
    
    Returns:
        tuple: JSON response with updated firewall and HTTP status code.
        
    Response:
        200: Policies added successfully.
        400: Invalid input.
        404: Firewall not found.
        500: Server error during update.
    """
    try:
        firewall = Firewall.query.filter_by(id=firewall_id).first()

        if not firewall:
            return jsonify({
                "message": FIREWALL_NOT_FOUND_MESSAGE
            }), 404

        data = request.get_json()

        if not data or "policies_ids" not in data:
            return jsonify({
                "message": "No policies_ids provided for update",
                "firewall": firewall.to_dict()
            }), 400

        set_firewall_policies(firewall, data)
        db.session.commit()

        return jsonify({
            "message": f"Firewall policies updated {firewall.name}",
            "firewall": firewall.to_dict()
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "message": str(e)}
        ), 500


@firewalls_bp.route('/firewalls/<int:firewall_id>/policies/<int:policy_id>', methods=["DELETE"])
@jwt_required()
def remove_firewall_policy(firewall_id: int, policy_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Removes a specific policy association from a firewall.

    Args:
        firewall_id (int): ID of the firewall.
        policy_id (int): ID of the policy to remove.

    Returns:
        tuple: JSON response confirming removal and HTTP status code.

    Response:
        200: Policy removed successfully.
        404: Firewall or policy not found.
        500: Server error during removal.
    """

    try:
        firewall = Firewall.query.filter_by(id=firewall_id).first()
        policy = FirewallPolicy.query.filter_by(id=policy_id).first()

        if not firewall:
            return jsonify({
                "message": FIREWALL_NOT_FOUND_MESSAGE
            }), 404

        if not policy:
            return jsonify({
                "message": "Policy not found"
            }), 404

        firewall.policies.remove(policy)
        db.session.commit()

        return jsonify({
            "message": f"Policy {policy.name} removed from firewall {firewall.name}",
            "firewall": firewall.to_dict()
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({
            "message": str(e)}
        ), 500


@firewalls_bp.route('/firewalls/<int:firewall_id>', methods=["DELETE"])
@jwt_required()
def delete_firewall(firewall_id: int):
    """
    Removes a firewall and all its policy associations from the system.
    
    Args:
        hostname (str): Hostname of the firewall to delete.
    
    Returns:
        tuple: JSON response confirming deletion and HTTP status code.
        
    Response:
        200: Firewall deleted successfully.
        404: Firewall not found.
        500: Server error during deletion.
    """
    try:
        firewall = Firewall.query.filter_by(id=firewall_id).first()
        if not firewall:
            return jsonify({
                "message": FIREWALL_NOT_FOUND_MESSAGE
            }), 404

        db.session.delete(firewall)
        db.session.commit()

        return jsonify({
            "message": f"Firewall {firewall.name} deleted",
            "firewall": firewall.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            "message": str(e)}
        ), 500