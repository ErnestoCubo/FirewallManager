"""
Flask-RESTX models for firewall endpoints.
"""

from flask_restx import Namespace, fields

# Create namespace
firewalls_ns = Namespace('firewalls', description='Firewall device management operations')

# Policy summary model (nested in firewall)
policy_summary_model = firewalls_ns.model('PolicySummary', {
    'id': fields.Integer(readonly=True, description='Policy ID'),
    'name': fields.String(description='Policy name'),
    'policy_type': fields.String(description='Policy type'),
    'is_active': fields.Boolean(description='Whether the policy is active')
})

# Firewall models
firewall_model = firewalls_ns.model('Firewall', {
    'id': fields.Integer(readonly=True, description='Firewall ID'),
    'name': fields.String(required=True, description='Unique firewall name', example='FW-HQ-01'),
    'hostname': fields.String(
        required=True, 
        description='Unique hostname (format: XX-XXX-DDD where X=letters, D=digits)', 
        example='us-nyc-001',
        pattern=r'^[a-zA-Z]{2}-[a-zA-Z]{3}-\d{1,3}$'
    ),
    'ip_address': fields.String(
        required=True, 
        description='IP address', 
        example='192.168.1.1',
        pattern=r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    ),
    'vendor': fields.String(required=True, description='Firewall vendor', example='Palo Alto'),
    'model': fields.String(required=True, description='Firewall model', example='PA-850'),
    'os_version': fields.String(required=True, description='OS version', example='10.1.0'),
    'description': fields.String(description='Firewall description', example='Headquarters main firewall'),
    'country': fields.String(description='Country location', example='USA'),
    'city': fields.String(description='City location', example='New York'),
    'policies': fields.List(fields.Nested(policy_summary_model), description='Associated policies'),
    'created_at': fields.DateTime(readonly=True, description='Creation timestamp'),
    'updated_at': fields.DateTime(readonly=True, description='Last update timestamp')
})

firewall_create_model = firewalls_ns.model('FirewallCreate', {
    'name': fields.String(required=True, description='Unique firewall name', example='FW-HQ-01'),
    'hostname': fields.String(
        required=True, 
        description='Unique hostname (format: XX-XXX-DDD where X=letters, D=digits)', 
        example='us-nyc-001',
        pattern=r'^[a-zA-Z]{2}-[a-zA-Z]{3}-\d{1,3}$'
    ),
    'ip_address': fields.String(
        required=True, 
        description='IP address', 
        example='192.168.1.1',
        pattern=r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    ),
    'vendor': fields.String(required=True, description='Firewall vendor', example='Palo Alto'),
    'model': fields.String(required=True, description='Firewall model', example='PA-850'),
    'os_version': fields.String(required=True, description='OS version', example='10.1.0'),
    'description': fields.String(description='Firewall description', example='Headquarters main firewall'),
    'country': fields.String(description='Country location', example='USA'),
    'city': fields.String(description='City location', example='New York'),
    'policies_ids': fields.List(fields.Integer, description='List of policy IDs to associate', example=[1, 2, 3])
})

firewall_update_model = firewalls_ns.model('FirewallUpdate', {
    'name': fields.String(description='Unique firewall name', example='FW-HQ-02'),
    'hostname': fields.String(
        description='Unique hostname (format: XX-XXX-DDD where X=letters, D=digits)', 
        example='us-bos-002',
        pattern=r'^[a-zA-Z]{2}-[a-zA-Z]{3}-\d{1,3}$'
    ),
    'ip_address': fields.String(
        description='IP address', 
        example='192.168.1.2',
        pattern=r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    ),
    'vendor': fields.String(description='Firewall vendor', example='Fortinet'),
    'model': fields.String(description='Firewall model', example='FortiGate 100F'),
    'os_version': fields.String(description='OS version', example='7.2.0'),
    'description': fields.String(description='Firewall description', example='Updated headquarters firewall'),
    'country': fields.String(description='Country location', example='USA'),
    'city': fields.String(description='City location', example='Boston'),
    'policies_ids': fields.List(fields.Integer, description='List of policy IDs to replace current policies', example=[4, 5, 6])
})

firewall_policies_patch_model = firewalls_ns.model('FirewallPoliciesPatch', {
    'policies_ids': fields.List(fields.Integer, required=True, description='List of policy IDs to add', example=[7, 8])
})

firewall_list_response = firewalls_ns.model('FirewallListResponse', {
    'firewalls': fields.List(fields.Nested(firewall_model), description='List of firewalls')
})

firewall_response = firewalls_ns.model('FirewallResponse', {
    'message': fields.String(description='Response message'),
    'firewall': fields.Nested(firewall_model, description='Firewall details')
})

error_response = firewalls_ns.model('ErrorResponse', {
    'message': fields.String(description='Error message')
})