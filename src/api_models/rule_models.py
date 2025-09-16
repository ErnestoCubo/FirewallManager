"""
Flask-RESTX models for firewall rule endpoints.
"""

from flask_restx import Namespace, fields

# Create namespace
rules_ns = Namespace('firewall_rules', description='Firewall rule management operations')

# Rule models
rule_model = rules_ns.model('FirewallRule', {
    'id': fields.Integer(readonly=True, description='Rule ID'),
    'name': fields.String(required=True, description='Rule name', example='Block_SSH_External'),
    'description': fields.String(description='Rule description', example='Block SSH access from external networks'),
    'action': fields.String(required=True, description='Rule action', enum=['allow', 'deny', 'reject'], example='deny'),
    'source_ip': fields.String(required=True, description='Source IP address or CIDR', example='0.0.0.0/0'),
    'destination_ip': fields.String(required=True, description='Destination IP address or CIDR', example='192.168.1.0/24'),
    'protocol': fields.String(required=True, description='Network protocol', enum=['tcp', 'udp', 'icmp', 'any'], example='tcp'),
    'port': fields.Integer(description='Port', example=22),
    'is_active': fields.Boolean(description='Whether the rule is active', example=True),
    'created_by': fields.String(readonly=True, description='User who created the rule'),
    'last_modified_by': fields.String(readonly=True, description='User who last modified the rule'),
    'created_at': fields.DateTime(readonly=True, description='Creation timestamp'),
    'updated_at': fields.DateTime(readonly=True, description='Last update timestamp')
})

rule_create_model = rules_ns.model('RuleCreate', {
    'name': fields.String(required=True, description='Rule name', example='Allow_HTTP'),
    'description': fields.String(description='Rule description', example='Allow HTTP traffic'),
    'action': fields.String(required=True, description='Rule action', enum=['allow', 'deny', 'reject'], example='allow'),
    'source_ip': fields.String(required=True, description='Source IP address or CIDR', example='10.0.0.0/8'),
    'destination_ip': fields.String(required=True, description='Destination IP address or CIDR', example='192.168.1.10'),
    'protocol': fields.String(required=True, description='Network protocol', enum=['tcp', 'udp', 'icmp', 'any'], example='tcp'),
    'port': fields.Integer(description='Port', example=80),
    'is_active': fields.Boolean(description='Whether the rule is active', default=True, example=True)
})

rule_update_model = rules_ns.model('RuleUpdate', {
    'name': fields.String(description='Rule name', example='Allow_HTTPS'),
    'description': fields.String(description='Rule description', example='Allow HTTPS traffic'),
    'action': fields.String(description='Rule action', enum=['allow', 'deny', 'reject'], example='allow'),
    'source_ip': fields.String(description='Source IP address or CIDR', example='10.0.0.0/8'),
    'destination_ip': fields.String(description='Destination IP address or CIDR', example='192.168.1.10'),
    'protocol': fields.String(description='Network protocol', enum=['tcp', 'udp', 'icmp', 'any'], example='tcp'),
    'port': fields.Integer(description='Port', example=443),
    'is_active': fields.Boolean(description='Whether the rule is active', example=True)
})

rule_list_response = rules_ns.model('RuleListResponse', {
    'firewall_rules': fields.List(fields.Nested(rule_model), description='List of firewall rules')
})

rule_response = rules_ns.model('RuleResponse', {
    'message': fields.String(description='Response message'),
    'firewall_rule': fields.Nested(rule_model, description='Firewall rule details')
})

error_response = rules_ns.model('ErrorResponse', {
    'message': fields.String(description='Error message')
})