"""
Flask-RESTX models for firewall policy endpoints.
"""

from flask_restx import Namespace, fields

# Create namespace
policies_ns = Namespace('firewall_policies', description='Firewall policy management operations')

# Rule model (nested in policy)
rule_summary_model = policies_ns.model('RuleSummary', {
    'id': fields.Integer(readonly=True, description='Rule ID'),
    'name': fields.String(description='Rule name'),
    'action': fields.String(description='Rule action', enum=['allow', 'deny', 'reject']),
    'is_active': fields.Boolean(description='Whether the rule is active')
})

# Policy models
policy_model = policies_ns.model('FirewallPolicy', {
    'id': fields.Integer(readonly=True, description='Policy ID'),
    'name': fields.String(required=True, description='Policy name', example='DMZ_Policy'),
    'description': fields.String(description='Policy description', example='Policy for DMZ zone'),
    'policy_type': fields.String(required=True, description='Policy type', example='security'),
    'is_active': fields.Boolean(description='Whether the policy is active', example=True),
    'priority': fields.Integer(description='Policy priority', example=100),
    'rules': fields.List(fields.Nested(rule_summary_model), description='Associated rules'),
    'created_by': fields.String(readonly=True, description='User who created the policy'),
    'last_modified_by': fields.String(readonly=True, description='User who last modified the policy'),
    'created_at': fields.DateTime(readonly=True, description='Creation timestamp'),
    'updated_at': fields.DateTime(readonly=True, description='Last update timestamp')
})

policy_create_model = policies_ns.model('PolicyCreate', {
    'name': fields.String(required=True, description='Policy name', example='DMZ_Policy'),
    'description': fields.String(description='Policy description', example='Policy for DMZ zone'),
    'policy_type': fields.String(required=True, description='Policy type', example='security'),
    'is_active': fields.Boolean(description='Whether the policy is active', default=True, example=True),
    'priority': fields.Integer(description='Policy priority', example=100),
    'rules_id': fields.List(fields.Integer, description='List of rule IDs to associate', example=[1, 2, 3])
})

policy_update_model = policies_ns.model('PolicyUpdate', {
    'name': fields.String(description='Policy name', example='DMZ_Policy_Updated'),
    'description': fields.String(description='Policy description', example='Updated policy for DMZ zone'),
    'policy_type': fields.String(description='Policy type', example='security'),
    'is_active': fields.Boolean(description='Whether the policy is active', example=True),
    'priority': fields.Integer(description='Policy priority', example=150),
    'rules_id': fields.List(fields.Integer, description='List of rule IDs to replace current rules', example=[4, 5, 6])
})

policy_rules_patch_model = policies_ns.model('PolicyRulesPatch', {
    'rules_id': fields.List(fields.Integer, required=True, description='List of rule IDs to add', example=[7, 8])
})

policy_list_response = policies_ns.model('PolicyListResponse', {
    'firewall_policies': fields.List(fields.Nested(policy_model), description='List of firewall policies')
})

policy_response = policies_ns.model('PolicyResponse', {
    'message': fields.String(description='Response message'),
    'firewall_policy': fields.Nested(policy_model, description='Firewall policy details')
})

error_response = policies_ns.model('ErrorResponse', {
    'message': fields.String(description='Error message')
})