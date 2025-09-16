"""
Flask-RESTX models for authentication endpoints.
"""

from flask_restx import Namespace, fields

# Create namespace
auth_ns = Namespace('auth', description='Authentication operations')

# Define models for Swagger documentation
user_model = auth_ns.model('User', {
    'id': fields.Integer(readonly=True, description='User ID'),
    'username': fields.String(required=True, description='Username', example='john_doe'),
    'email': fields.String(required=True, description='Email address', example='john@example.com'),
    'role': fields.String(description='User role', example='user'),
    'created_at': fields.DateTime(readonly=True, description='Creation timestamp'),
    'updated_at': fields.DateTime(readonly=True, description='Last update timestamp')
})

register_model = auth_ns.model('Register', {
    'username': fields.String(required=True, min_length=3, max_length=50, description='Username', example='john_doe'),
    'email': fields.String(required=True, description='Email address', example='john@example.com'),
    'password': fields.String(required=True, min_length=8, description='Password', example='SecurePass123!'),
    'role': fields.String(description='User role', enum=['user', 'operator', 'admin'], default='user', example='user')
})

login_model = auth_ns.model('Login', {
    'username': fields.String(required=True, description='Username', example='john_doe'),
    'password': fields.String(required=True, description='Password', example='SecurePass123!')
})

token_response_model = auth_ns.model('TokenResponse', {
    'access_token': fields.String(description='JWT access token', example='eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...'),
    'refresh_token': fields.String(description='JWT refresh token', example='eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...'),
    'token_type': fields.String(description='Type of the token', example='Bearer', default='Bearer'),
    'user': fields.Nested(user_model, description='User information')
})

message_response = auth_ns.model('MessageResponse', {
    'msg': fields.String(description='Response message')
})

error_response = auth_ns.model('ErrorResponse', {
    'msg': fields.String(description='Error message'),
    'error': fields.String(description='Error details')
})