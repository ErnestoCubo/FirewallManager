"""
Flask-RESTX models for admin endpoints.
"""

from flask_restx import Namespace, fields

# Create namespace
admin_ns = Namespace('admin', description='Administrative operations for user and role management')

# User model
user_model = admin_ns.model('User', {
    'id': fields.Integer(readonly=True, description='User ID'),
    'username': fields.String(required=True, description='Username', example='john_doe'),
    'email': fields.String(required=True, description='Email address', example='john@example.com'),
    'role': fields.String(description='User role', enum=['user', 'operator', 'admin'], example='user'),
    'created_at': fields.DateTime(readonly=True, description='Creation timestamp'),
    'updated_at': fields.DateTime(readonly=True, description='Last update timestamp')
})

# Role update model
role_update_model = admin_ns.model('RoleUpdate', {
    'role': fields.String(required=True, description='New role', enum=['user', 'operator', 'admin'], example='operator')
})

# Password reset model
password_reset_model = admin_ns.model('PasswordReset', {
    'password': fields.String(required=True, description='New password', min_length=8, example='NewSecurePass123!')
})

# User list response
user_list_response = admin_ns.model('UserListResponse', {
    'users': fields.List(fields.Nested(user_model), description='List of users')
})

# User response
user_response = admin_ns.model('UserResponse', {
    'user': fields.Nested(user_model, description='User details')
})

# Message response
message_response = admin_ns.model('MessageResponse', {
    'message': fields.String(description='Response message')
})

# Role model
role_model = admin_ns.model('Role', {
    'name': fields.String(description='Role name', example='admin'),
    'permissions': fields.List(fields.String, description='List of permissions')
})

# Roles response
roles_response = admin_ns.model('RolesResponse', {
    'roles': fields.List(fields.Nested(role_model), description='List of roles')
})

# Error response
error_response = admin_ns.model('ErrorResponse', {
    'message': fields.String(description='Error message')
})

# Search parser for query parameters
search_parser = admin_ns.parser()
search_parser.add_argument('query', type=str, location='args', help='Search query string (e.g., john)')