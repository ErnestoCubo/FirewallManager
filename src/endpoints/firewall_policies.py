"""
Firewall Policies API endpoints using Flask-RESTX.

This module defines RESTful API endpoints for managing firewall policies,
including creation, retrieval, updating, deletion, and rule associations.
"""

from flask import request
from flask_restx import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity
from typing import Tuple, Dict, Any

try:
    from src.models.firewall_policy import db, FirewallPolicy
    from src.models.firewall_rule import FirewallRule
    from src.models.user import User
    from src.validators.input_validators import firewall_policies_validator, validate_policy_schema
    from src.utils.firewall_policies_utils import update_firewall_policy_fields, update_firewall_policy_unique_field, update_policy_rules
    from src.rbac.role_based_access_control import role_required
    from src.api_models.policy_models import (
        policies_ns,
        policy_model,
        policy_create_model,
        policy_update_model,
        policy_rules_patch_model,
        policy_list_response,
        policy_response,
        error_response
    )
except ImportError:
    from models.firewall_policy import db, FirewallPolicy
    from models.firewall_rule import FirewallRule
    from models.user import User
    from validators.input_validators import firewall_policies_validator, validate_policy_schema
    from utils.firewall_policies_utils import update_firewall_policy_fields, update_firewall_policy_unique_field, update_policy_rules
    from rbac.role_based_access_control import role_required
    from api_models.policy_models import (
        policies_ns,
        policy_model,
        policy_create_model,
        policy_update_model,
        policy_rules_patch_model,
        policy_list_response,
        policy_response,
        error_response
    )

FIREWALL_POLICY_NOT_FOUND = "Firewall policy not found"


@policies_ns.route('')
class FirewallPolicyList(Resource):
    @jwt_required()
    @role_required('user', 'read_policy')
    @policies_ns.doc('list_policies', security='Bearer')
    @policies_ns.response(200, 'Success', model=policy_list_response)
    @policies_ns.response(500, 'Internal server error', model=error_response)
    def get(self) -> Tuple[Dict[str, Any], int]:
        """Get all firewall policies."""
        try:
            policies = FirewallPolicy.query.all()
            return {
                "firewall_policies": [policy.to_dict() for policy in policies]
            }, 200

        except Exception as e:
            return {"message": str(e)}, 500

    @jwt_required()
    @role_required('operator', 'create_policy')
    @policies_ns.doc('create_policy', security='Bearer')
    @policies_ns.expect(policy_create_model, validate=True)
    @policies_ns.response(201, 'Policy created successfully', model=policy_response)
    @policies_ns.response(400, 'Bad request', model=error_response)
    @policies_ns.response(500, 'Internal server error', model=error_response)
    def post(self) -> Tuple[Dict[str, Any], int]:
        """Create a new firewall policy."""
        try:
            data = request.get_json()
            is_valid, validation_message = firewall_policies_validator(data)
            if not is_valid:
                return {"message": validation_message}, 400

            policy_name = FirewallPolicy.query.filter_by(name=data['name']).first()
            if policy_name:
                return {
                    "message": f"Firewall policy with this name {data['name']} already exists"
                }, 400
                
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

            return {
                "message": "Firewall policy created",
                "firewall_policy": new_policy.to_dict()
            }, 201

        except Exception as e:
            db.session.rollback()
            return {"message": str(e)}, 500


@policies_ns.route('/<int:policy_id>')
@policies_ns.param('policy_id', 'The policy identifier')
class FirewallPolicyResource(Resource):
    @jwt_required()
    @role_required('operator', 'update_policy')
    @policies_ns.doc('update_policy', security='Bearer')
    @policies_ns.expect(policy_update_model, validate=True)
    @policies_ns.response(200, 'Policy updated successfully', model=policy_response)
    @policies_ns.response(400, 'Bad request', model=error_response)
    @policies_ns.response(404, 'Policy not found', model=error_response)
    @policies_ns.response(500, 'Internal server error', model=error_response)
    def put(self, policy_id: int) -> Tuple[Dict[str, Any], int]:
        """Update an existing firewall policy."""
        try:
            policy = FirewallPolicy.query.filter_by(id=policy_id).first()

            if not policy:
                return {"message": FIREWALL_POLICY_NOT_FOUND}, 404

            data = request.get_json()
            is_valid, validation_message = validate_policy_schema(data)
            if not is_valid:
                return {"message": validation_message}, 400

            if not update_firewall_policy_unique_field(policy, data, 'name'):
                return {
                    "message": f"Firewall policy with this name {data['name']} already exists"
                }, 400

            data['last_modified_by'] = User.query.filter_by(id=get_jwt_identity()).first().username
            update_firewall_policy_fields(policy, data)
            db.session.commit()

            return {
                "message": f"Firewall policy updated {policy.name}",
                "firewall_policy": policy.to_dict()
            }, 200

        except Exception as e:
            db.session.rollback()
            return {"message": str(e)}, 500

    @jwt_required()
    @role_required('operator', 'delete_policy')
    @policies_ns.doc('delete_policy', security='Bearer')
    @policies_ns.response(200, 'Policy deleted successfully', model=policy_response)
    @policies_ns.response(404, 'Policy not found', model=error_response)
    @policies_ns.response(500, 'Internal server error', model=error_response)
    def delete(self, policy_id: int) -> Tuple[Dict[str, Any], int]:
        """Delete a firewall policy."""
        try:
            policy = FirewallPolicy.query.filter_by(id=policy_id).first()
            if not policy:
                return {"message": FIREWALL_POLICY_NOT_FOUND}, 404

            db.session.delete(policy)
            db.session.commit()

            return {
                "message": f"Firewall policy {policy.name} deleted",
                "firewall_policy": policy.to_dict()
            }, 200
            
        except Exception as e:
            db.session.rollback()
            return {"message": str(e)}, 500


@policies_ns.route('/<int:policy_id>/rules')
@policies_ns.param('policy_id', 'The policy identifier')
class FirewallPolicyRules(Resource):
    @jwt_required()
    @role_required('operator', 'add_rule_to_policy')
    @policies_ns.doc('add_rules_to_policy', security='Bearer')
    @policies_ns.expect(policy_rules_patch_model, validate=True)
    @policies_ns.response(200, 'Rules added successfully', model=policy_response)
    @policies_ns.response(400, 'Bad request', model=error_response)
    @policies_ns.response(404, 'Policy not found', model=error_response)
    @policies_ns.response(500, 'Internal server error', model=error_response)
    def patch(self, policy_id: int) -> Tuple[Dict[str, Any], int]:
        """Add rules to an existing firewall policy."""
        try:
            policy = FirewallPolicy.query.filter_by(id=policy_id).first()
            if not policy:
                return {"message": FIREWALL_POLICY_NOT_FOUND}, 404

            data = request.get_json()
            if not data or "rules_id" not in data:
                return {
                    "message": "No rules_id provided to add to policy",
                    "firewall_policy": policy.to_dict()
                }, 400

            update_policy_rules(policy, data)
            policy.last_modified_by = User.query.filter_by(id=get_jwt_identity()).first().username
            db.session.commit()

            return {
                "message": f"Rules added to policy {policy.name}",
                "firewall_policy": policy.to_dict()
            }, 200

        except Exception as e:
            db.session.rollback()
            return {"message": str(e)}, 500


@policies_ns.route('/<int:policy_id>/rules/<int:rule_id>')
@policies_ns.param('policy_id', 'The policy identifier')
@policies_ns.param('rule_id', 'The rule identifier')
class FirewallPolicyRule(Resource):
    @jwt_required()
    @role_required('operator', 'delete_rule_from_policy')
    @policies_ns.doc('remove_rule_from_policy', security='Bearer')
    @policies_ns.response(200, 'Rule removed successfully', model=policy_response)
    @policies_ns.response(404, 'Policy or rule not found', model=error_response)
    @policies_ns.response(500, 'Internal server error', model=error_response)
    def delete(self, policy_id: int, rule_id: int) -> Tuple[Dict[str, Any], int]:
        """Remove a specific rule from a firewall policy."""
        try:
            policy = FirewallPolicy.query.filter_by(id=policy_id).first()
            rule = FirewallRule.query.filter_by(id=rule_id).first()

            if not policy:
                return {"message": FIREWALL_POLICY_NOT_FOUND}, 404

            if not rule:
                return {"message": f"Rule with id {rule_id} not found"}, 404

            policy.rules.remove(rule)
            db.session.commit()

            return {
                "message": f"Rule {rule.name} removed from policy {policy.name}",
                "firewall_policy": policy.to_dict()
            }, 200

        except Exception as e:
            db.session.rollback()
            return {"message": str(e)}, 500