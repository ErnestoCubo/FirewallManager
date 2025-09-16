"""
Firewall Rules API endpoints using Flask-RESTX.

This module defines RESTful API endpoints for managing firewall rules,
including creation, retrieval, updating, and deletion.
"""

from flask import request
from flask_restx import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity
from typing import Tuple, Dict, Any

try:
    from src.validators.input_validators import firewall_rules_validator, validate_rule_schema
    from src.models.firewall_rule import db, FirewallRule
    from src.models.user import User
    from src.utils.firewall_rules_utils import update_firewall_rule_fields
    from src.rbac.role_based_access_control import role_required
    from src.api_models.rule_models import (
        rules_ns,
        rule_model,
        rule_create_model,
        rule_update_model,
        rule_list_response,
        rule_response,
        error_response
    )
except ImportError:
    from validators.input_validators import firewall_rules_validator, validate_rule_schema
    from models.firewall_rule import db, FirewallRule
    from models.user import User
    from utils.firewall_rules_utils import update_firewall_rule_fields
    from rbac.role_based_access_control import role_required
    from api_models.rule_models import (
        rules_ns,
        rule_model,
        rule_create_model,
        rule_update_model,
        rule_list_response,
        rule_response,
        error_response
    )


@rules_ns.route('')
class FirewallRuleList(Resource):
    @jwt_required()
    @role_required('user', 'read_rule')
    @rules_ns.doc('list_rules', security='Bearer')  # Use 'Bearer' to match app.py
    @rules_ns.response(200, 'Success', model=rule_list_response)
    @rules_ns.response(500, 'Internal server error', model=error_response)
    def get(self) -> Tuple[Dict[str, Any], int]:
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
            return {
                "firewall_rules": [rule.to_dict() for rule in rules]
            }, 200

        except Exception as e:
            return {
                "message": str(e)
            }, 500

    @jwt_required()
    @role_required('operator', 'create_rule')
    @rules_ns.doc('create_rule', security='Bearer')
    @rules_ns.expect(rule_create_model, validate=True)
    @rules_ns.response(201, 'Rule created successfully', model=rule_response)
    @rules_ns.response(400, 'Bad request', model=error_response)
    @rules_ns.response(500, 'Internal server error', model=error_response)
    def post(self) -> Tuple[Dict[str, Any], int]:
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

        Returns:
            tuple: JSON response with the created firewall rule and HTTP status code.
        
        Responses:
            201: Firewall rule created successfully.
            400: Bad request (e.g., missing required fields).
            500: Internal server error.
        """
        try:
            data = request.get_json()
            user = User.query.filter_by(id=get_jwt_identity()).first()

            is_valid, validation_msg = firewall_rules_validator(data)
            if not is_valid:
                return {
                    "message": validation_msg
                }, 400

            # Check if rule name already exists
            existing_rule = FirewallRule.query.filter_by(name=data.get("name")).first()
            if existing_rule:
                return {
                    "message": f"Firewall rule with name '{data.get('name')}' already exists"
                }, 400

            new_rule = FirewallRule(
                name=data.get("name"),
                description=data.get("description"),
                action=data.get("action"),
                source_ip=data.get("source_ip"),
                destination_ip=data.get("destination_ip"),
                protocol=data.get("protocol"),
                port=data.get("port"),
                is_active=data.get("is_active", True),
                created_by=user.username,
                last_modified_by=user.username,
            )

            db.session.add(new_rule)
            db.session.commit()

            return {
                "message": "Firewall rule created",
                "firewall_rule": new_rule.to_dict()
            }, 201

        except Exception as e:
            db.session.rollback()
            return {
                "message": str(e)
            }, 500


@rules_ns.route('/<int:rule_id>')
@rules_ns.param('rule_id', 'The rule identifier')
class FirewallRuleResource(Resource):
    @jwt_required()
    @role_required('user', 'read_rule')
    @rules_ns.doc('get_rule', security='Bearer')
    @rules_ns.response(200, 'Success', model=rule_response)
    @rules_ns.response(404, 'Rule not found', model=error_response)
    @rules_ns.response(500, 'Internal server error', model=error_response)
    def get(self, rule_id: int) -> Tuple[Dict[str, Any], int]:
        """
        Get a specific firewall rule by ID.
        
        Args:
            rule_id (int): ID of the firewall rule to retrieve.
        
        Returns:
            tuple: JSON response with firewall rule details and HTTP status code.
        """
        try:
            rule = FirewallRule.query.filter_by(id=rule_id).first()
            
            if not rule:
                return {
                    "message": "Firewall rule not found"
                }, 404
            
            return {
                "firewall_rule": rule.to_dict()
            }, 200
            
        except Exception as e:
            return {
                "message": str(e)
            }, 500

    @jwt_required()
    @role_required('operator', 'update_rule')
    @rules_ns.doc('update_rule', security='Bearer')
    @rules_ns.expect(rule_update_model, validate=True)
    @rules_ns.response(200, 'Rule updated successfully', model=rule_response)
    @rules_ns.response(400, 'Bad request', model=error_response)
    @rules_ns.response(404, 'Rule not found', model=error_response)
    @rules_ns.response(500, 'Internal server error', model=error_response)
    def put(self, rule_id: int) -> Tuple[Dict[str, Any], int]:
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
                return {
                    "message": "Firewall rule not found"
                }, 404

            data = request.get_json()
            is_valid, validation_msg = validate_rule_schema(data)
            if not is_valid:
                return {
                    "message": validation_msg
                }, 400
            
            # Check if new name conflicts with existing rule
            if 'name' in data and data['name'] != rule.name:
                existing_rule = FirewallRule.query.filter_by(name=data['name']).first()
                if existing_rule:
                    return {
                        "message": f"Firewall rule with name '{data['name']}' already exists"
                    }, 400
                
            update_firewall_rule_fields(rule, data)
            user_identity = get_jwt_identity()
            rule.last_modified_by = User.query.filter_by(id=user_identity).first().username
            db.session.commit()

            return {
                "message": "Firewall rule updated",
                "firewall_rule": rule.to_dict()
            }, 200

        except Exception as e:
            db.session.rollback()
            return {
                "message": str(e)
            }, 500

    @jwt_required()
    @role_required('operator', 'delete_rule')
    @rules_ns.doc('delete_rule', security='Bearer')
    @rules_ns.response(200, 'Rule deleted successfully', model=rule_response)
    @rules_ns.response(404, 'Rule not found', model=error_response)
    @rules_ns.response(500, 'Internal server error', model=error_response)
    def delete(self, rule_id: int) -> Tuple[Dict[str, Any], int]:
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
                return {
                    "message": "Firewall rule not found"
                }, 404

            # Store rule data before deletion for response
            rule_data = rule.to_dict()

            db.session.delete(rule)
            db.session.commit()

            return {
                "message": "Firewall rule deleted",
                "firewall_rule": rule_data
            }, 200

        except Exception as e:
            db.session.rollback()
            return {
                "message": str(e)
            }, 500