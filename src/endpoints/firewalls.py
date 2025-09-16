"""
Firewall endpoints using Flask-RESTX.

This module defines RESTful API endpoints for managing firewall devices,
including creation, retrieval, updating, and deletion. It also handles
associations between firewalls and security policies.
"""

from flask import request
from flask_restx import Resource
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
    from src.rbac.role_based_access_control import role_required
    from src.api_models.firewall_models import (
        firewalls_ns,
        firewall_model,
        firewall_create_model,
        firewall_update_model,
        firewall_policies_patch_model,
        firewall_list_response,
        firewall_response,
        error_response
    )
except ImportError:
    from models.firewall import db, Firewall
    from models.firewall_policy import FirewallPolicy
    from utils.firewall_utils import (
        set_firewall_policies,
        update_firewall_unique_field,
        update_firewall_fields
    )
    from rbac.role_based_access_control import role_required
    from api_models.firewall_models import (
        firewalls_ns,
        firewall_model,
        firewall_create_model,
        firewall_update_model,
        firewall_policies_patch_model,
        firewall_list_response,
        firewall_response,
        error_response
    )

FIREWALL_NOT_FOUND_MESSAGE = "Firewall not found"
FIREWALL_WITH_HOSTNAME_EXISTS = "Firewall with this hostname already exists"


@firewalls_ns.route('')
class FirewallList(Resource):
    @jwt_required()
    @role_required('user', 'read_firewall')
    @firewalls_ns.doc('list_firewalls', security='Bearer')
    @firewalls_ns.response(200, 'Success', model=firewall_list_response)
    @firewalls_ns.response(401, 'Unauthorized - JWT token is missing or invalid', model=error_response)
    @firewalls_ns.response(403, 'Forbidden - Insufficient permissions', model=error_response)
    @firewalls_ns.response(500, 'Internal server error', model=error_response)
    def get(self) -> Tuple[Dict[str, Any], int]:
        """
        Returns a list of all firewall devices in the system with their
        basic information.
        
        Returns:
            tuple: JSON response with list of firewalls and HTTP status code.
        """
        try:
            firewalls = Firewall.query.all()
            return {
                "firewalls": [fw.to_dict() for fw in firewalls]
            }, 200
        except Exception as e:
            return {
                "message": str(e)
            }, 500

    @jwt_required()
    @role_required('operator', 'create_firewall')
    @firewalls_ns.doc('create_firewall', security='Bearer')
    @firewalls_ns.expect(firewall_create_model, validate=True)
    @firewalls_ns.response(201, 'Firewall created successfully', model=firewall_response)
    @firewalls_ns.response(400, 'Invalid input or duplicate hostname/name', model=error_response)
    @firewalls_ns.response(500, 'Server error during creation', model=error_response)
    def post(self) -> Tuple[Dict[str, Any], int]:
        """
        Creates a new firewall with the provided information and optionally
        associates it with existing policies.
        """
        try:
            data = request.get_json()

            required_fields = ['name', 'hostname', 'ip_address', 'vendor', 'model', 'os_version']
            missing_fields = [field for field in required_fields if not data.get(field)]

            if missing_fields:
                return {
                    "message": f"Missing required fields: {', '.join(missing_fields)}"
                }, 400

            if Firewall.query.filter_by(hostname=data.get('hostname')).first():
                return {
                    "message": FIREWALL_WITH_HOSTNAME_EXISTS
                }, 400

            if Firewall.query.filter_by(name=data['name']).first():
                return {
                    "message": f"Firewall with this name {data['name']} already exists"
                }, 400

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

            return {
                "message": "Firewall created",
                "firewall": new_firewall.to_dict()
            }, 201

        except Exception as e:
            db.session.rollback()
            return {
                "message": str(e)
            }, 500


@firewalls_ns.route('/<int:firewall_id>')
@firewalls_ns.param('firewall_id', 'The firewall identifier')
class FirewallResource(Resource):
    @jwt_required()
    @role_required('user', 'read_firewall')
    @firewalls_ns.doc('get_firewall', security='Bearer')
    @firewalls_ns.response(200, 'Success', model=firewall_response)
    @firewalls_ns.response(404, 'Firewall not found', model=error_response)
    @firewalls_ns.response(500, 'Internal server error', model=error_response)
    def get(self, firewall_id: int) -> Tuple[Dict[str, Any], int]:
        """
        Get a specific firewall by ID.
        
        Args:
            firewall_id (int): ID of the firewall to retrieve.
        
        Returns:
            tuple: JSON response with firewall details and HTTP status code.
        """
        try:
            firewall = Firewall.query.filter_by(id=firewall_id).first()
            
            if not firewall:
                return {
                    "message": FIREWALL_NOT_FOUND_MESSAGE
                }, 404
            
            return {
                "firewall": firewall.to_dict()
            }, 200
            
        except Exception as e:
            return {
                "message": str(e)
            }, 500

    @jwt_required()
    @role_required('operator', 'update_firewall')
    @firewalls_ns.doc('update_firewall', security='Bearer')
    @firewalls_ns.expect(firewall_update_model, validate=True)
    @firewalls_ns.response(200, 'Firewall updated successfully', model=firewall_response)
    @firewalls_ns.response(400, 'Invalid input or duplicate hostname/name', model=error_response)
    @firewalls_ns.response(404, 'Firewall not found', model=error_response)
    @firewalls_ns.response(500, 'Server error during update', model=error_response)
    def put(self, firewall_id: int) -> Tuple[Dict[str, Any], int]:
        """
        Updates firewall information and replaces all policy associations
        if policies_ids is provided.
        
        Args:
            firewall_id (int): ID of the firewall to update.
        
        Returns:
            tuple: JSON response with updated firewall and HTTP status code.
        """
        try:
            firewall = Firewall.query.filter_by(id=firewall_id).first()

            if not firewall:
                return {
                    "message": FIREWALL_NOT_FOUND_MESSAGE,
                }, 404

            data = request.get_json()

            if not data:
                return {
                    "message": "No data provided for update",
                    "firewall": firewall.to_dict()
                }, 400

            if not update_firewall_unique_field(firewall, data, "hostname"):
                return {
                    "message": FIREWALL_WITH_HOSTNAME_EXISTS,
                    "firewall": firewall.to_dict()
                }, 400

            if not update_firewall_unique_field(firewall, data, "name"):
                return {
                    "message": f"Firewall with this name {data['name']} already exists",
                    "firewall": firewall.to_dict()
                }, 400

            # Update normal fields
            update_firewall_fields(firewall, data)    
            db.session.commit()

            return {
                "message": f"Firewall updated {firewall.name}",
                "firewall": firewall.to_dict()
            }, 200

        except Exception as e:
            db.session.rollback()
            return {
                "message": str(e)
            }, 500

    @jwt_required()
    @role_required('operator', 'delete_firewall')
    @firewalls_ns.doc('delete_firewall', security='Bearer')
    @firewalls_ns.response(200, 'Firewall deleted successfully', model=firewall_response)
    @firewalls_ns.response(404, 'Firewall not found', model=error_response)
    @firewalls_ns.response(500, 'Server error during deletion', model=error_response)
    def delete(self, firewall_id: int) -> Tuple[Dict[str, Any], int]:
        """
        Removes a firewall and all its policy associations from the system.
        
        Args:
            firewall_id (int): ID of the firewall to delete.
        
        Returns:
            tuple: JSON response confirming deletion and HTTP status code.
        """
        try:
            firewall = Firewall.query.filter_by(id=firewall_id).first()
            if not firewall:
                return {
                    "message": FIREWALL_NOT_FOUND_MESSAGE
                }, 404

            # Store firewall data before deletion for response
            firewall_data = firewall.to_dict()

            db.session.delete(firewall)
            db.session.commit()

            return {
                "message": f"Firewall {firewall.name} deleted",
                "firewall": firewall_data
            }, 200
            
        except Exception as e:
            db.session.rollback()
            return {
                "message": str(e)
            }, 500


@firewalls_ns.route('/<int:firewall_id>/policies')
@firewalls_ns.param('firewall_id', 'The firewall identifier')
class FirewallPolicies(Resource):
    @jwt_required()
    @role_required('operator', 'add_policy_to_firewall')
    @firewalls_ns.doc('patch_firewall_policies', security='Bearer')
    @firewalls_ns.expect(firewall_policies_patch_model, validate=True)
    @firewalls_ns.response(200, 'Policies added successfully', model=firewall_response)
    @firewalls_ns.response(400, 'Invalid input', model=error_response)
    @firewalls_ns.response(404, 'Firewall not found', model=error_response)
    @firewalls_ns.response(500, 'Server error during update', model=error_response)
    def patch(self, firewall_id: int) -> Tuple[Dict[str, Any], int]:
        """
        This endpoint performs a partial update, adding new policy associations
        while preserving existing ones.
        
        Args:
            firewall_id (int): ID of the firewall to update.
        
        Returns:
            tuple: JSON response with updated firewall and HTTP status code.
        """
        try:
            firewall = Firewall.query.filter_by(id=firewall_id).first()

            if not firewall:
                return {
                    "message": FIREWALL_NOT_FOUND_MESSAGE
                }, 404

            data = request.get_json()

            if not data or not data.get("policies_ids"):
                return {
                    "message": "No policies_ids provided for update",
                    "firewall": firewall.to_dict()
                }, 400

            set_firewall_policies(firewall, data)
            db.session.commit()

            return {
                "message": f"Firewall policies updated {firewall.name}",
                "firewall": firewall.to_dict()
            }, 200

        except Exception as e:
            db.session.rollback()
            return {
                "message": str(e)
            }, 500


@firewalls_ns.route('/<int:firewall_id>/policies/<int:policy_id>')
@firewalls_ns.param('firewall_id', 'The firewall identifier')
@firewalls_ns.param('policy_id', 'The policy identifier')
class FirewallPolicy(Resource):
    @jwt_required()
    @role_required('operator', 'remove_policy_from_firewall')
    @firewalls_ns.doc('remove_firewall_policy', security='Bearer')
    @firewalls_ns.response(200, 'Policy removed successfully', model=firewall_response)
    @firewalls_ns.response(404, 'Firewall or policy not found', model=error_response)
    @firewalls_ns.response(500, 'Server error during removal', model=error_response)
    def delete(self, firewall_id: int, policy_id: int) -> Tuple[Dict[str, Any], int]:
        """
        Removes a specific policy association from a firewall.

        Args:
            firewall_id (int): ID of the firewall.
            policy_id (int): ID of the policy to remove.

        Returns:
            tuple: JSON response confirming removal and HTTP status code.
        """
        try:
            firewall = Firewall.query.filter_by(id=firewall_id).first()
            policy = FirewallPolicy.query.filter_by(id=policy_id).first()

            if not firewall:
                return {
                    "message": FIREWALL_NOT_FOUND_MESSAGE
                }, 404

            if not policy:
                return {
                    "message": "Policy not found"
                }, 404

            firewall.policies.remove(policy)
            db.session.commit()

            return {
                "message": f"Policy {policy.name} removed from firewall {firewall.name}",
                "firewall": firewall.to_dict()
            }, 200
        except Exception as e:
            db.session.rollback()
            return {
                "message": str(e)
            }, 500