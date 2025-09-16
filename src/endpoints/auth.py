"""
Authentication endpoints module using Flask-RESTX.

This module provides endpoints for user registration, login, token refresh,
and logout using JWT for authentication and authorization.
"""

from flask import request
from flask_restx import Namespace, Resource, fields
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager,
    jwt_required,
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
    get_jwt,
)

try:
    from src.models.base import db
    from src.models.user import User
    from src.models.token_block_list import TokenBlocklist
    from src.validators.input_validators import user_validator
    from src.api_models.auth_models import (
        auth_ns,
        user_model,
        register_model,
        login_model,
        token_response_model,
        message_response,
        error_response
    )
except ImportError:
    from models.base import db
    from models.user import User
    from models.token_block_list import TokenBlocklist
    from validators.input_validators import user_validator
    from api_models.auth_models import (
        auth_ns,
        user_model,
        register_model,
        login_model,
        token_response_model,
        message_response,
        error_response
    )

def register_jwt(app):
    """
    Initialize JWT manager and configure callbacks.

    Args:
        app (Flask): The Flask application instance.

    Returns:
        JWTManager: The initialized JWT manager.
    """
    jwt = JWTManager(app)

    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header: dict, jwt_payload: dict):
        jti = jwt_payload['jti']
        return TokenBlocklist.query.filter_by(jti=jti).first() is not None

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return {'msg': 'The token has expired', 'error': 'token_expired'}, 401

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return {'msg': 'Signature verification failed', 'error': 'invalid_token'}, 422

    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return {'msg': 'Request does not contain an access token', 'error': 'authorization_required'}, 401

    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        return {'msg': 'The token has been revoked', 'error': 'token_revoked'}, 401

    return jwt


@auth_ns.route('/register')
class Register(Resource):
    @auth_ns.expect(register_model, validate=True)
    @auth_ns.response(201, 'User registered successfully', model=user_model)
    @auth_ns.response(400, 'Invalid input data', model=error_response)
    @auth_ns.response(409, 'Username or email already exists', model=error_response)
    @auth_ns.response(500, 'Internal server error', model=error_response)
    @auth_ns.doc('register_user')
    def post(self):
        """Register a new user."""
        try:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            email = data.get('email')
            role = data.get('role', 'user')

            validated, message = user_validator(data)
            if not validated:
                return {'msg': message}, 400

            if User.query.filter((User.username == username) | (User.email == email)).first():
                return {'msg': 'Username or email already exists'}, 409

            password_hash = generate_password_hash(password, method='scrypt', salt_length=8)
            new_user = User(username=username, password_hash=password_hash, email=email, role=role)
            db.session.add(new_user)
            db.session.commit()

            return {
                'msg': 'User registered successfully',
                'user': new_user.to_dict()
            }, 201
            
        except Exception as e:
            db.session.rollback()
            
            if 'Failed to decode JSON object' in str(e):
                return {'msg': 'Invalid JSON input'}, 400
                
            return {
                'msg': 'Internal server error',
                'error': str(e)
            }, 500


@auth_ns.route('/login')
class Login(Resource):
    @auth_ns.expect(login_model, validate=True)
    @auth_ns.response(200, 'Login successful', model=token_response_model)
    @auth_ns.response(400, 'Missing username or password', model=error_response)
    @auth_ns.response(401, 'Bad username or password', model=error_response)
    @auth_ns.response(500, 'Internal server error', model=error_response)
    @auth_ns.doc('login_user')
    def post(self):
        """Authenticate user and return tokens."""
        try:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')

            if not username or not password:
                return {'msg': 'Missing username or password'}, 400

            user = User.query.filter_by(username=username).first()
            if not user or not check_password_hash(user.password_hash, password):
                return {'msg': 'Bad username or password'}, 401

            additional_claims = {'role': user.role}
            access_token = create_access_token(identity=str(user.id), additional_claims=additional_claims)
            refresh_token = create_refresh_token(identity=str(user.id))

            return {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'token_type': 'Bearer', 
                'user': user.to_dict()
            }, 200

        except Exception as e:
            return {
                'msg': 'Internal server error',
                'error': str(e)
            }, 500


@auth_ns.route('/refresh')
class RefreshToken(Resource):
    @jwt_required(refresh=True)
    @auth_ns.response(200, 'Token refreshed successfully')
    @auth_ns.response(401, 'Invalid or expired refresh token', model=error_response)
    @auth_ns.response(404, 'User not found', model=error_response)
    @auth_ns.response(500, 'Internal server error', model=error_response)
    @auth_ns.doc('refresh_token', security='Bearer')
    def post(self):
        """Refresh access token."""
        try:
            current_user_id = get_jwt_identity()
            user = User.query.filter_by(id=int(current_user_id)).first()

            if not user:
                return {'msg': 'User not found'}, 404

            additional_claims = {'role': user.role}
            new_access_token = create_access_token(identity=str(current_user_id), additional_claims=additional_claims)

            return {'access_token': new_access_token}, 200

        except Exception as e:
            return {
                'msg': 'Internal server error',
                'error': str(e)
            }, 500


@auth_ns.route('/logout')
class Logout(Resource):
    @jwt_required()
    @auth_ns.response(200, 'Token revoked successfully', model=message_response)
    @auth_ns.response(500, 'Internal server error', model=error_response)
    @auth_ns.doc('logout_user', security='Bearer')
    def post(self):
        """Revoke the current user's access token."""
        try:
            jti = get_jwt()['jti']
            user_id = get_jwt_identity()
            token_type = get_jwt().get('type', 'access')

            revoked_token = TokenBlocklist(jti=jti, token_type=token_type, user_identity=str(user_id))
            db.session.add(revoked_token)
            db.session.commit()

            return {'msg': 'Token revoked'}, 200

        except Exception as e:
            db.session.rollback()
            return {
                'msg': 'Internal server error',
                'error': str(e)
            }, 500


@auth_ns.route('/logout_refresh')
class LogoutRefresh(Resource):
    @jwt_required(refresh=True)
    @auth_ns.response(200, 'Refresh token revoked successfully', model=message_response)
    @auth_ns.response(500, 'Internal server error', model=error_response)
    @auth_ns.doc('logout_refresh_token', security='Bearer')
    def post(self):
        """Revoke the current user's refresh token."""
        try:
            jti = get_jwt()['jti']
            user_id = get_jwt_identity()
            token_type = get_jwt().get('type', 'refresh')

            revoked_token = TokenBlocklist(jti=jti, token_type=token_type, user_identity=str(user_id))
            db.session.add(revoked_token)
            db.session.commit()

            return {'msg': 'Refresh token revoked'}, 200

        except Exception as e:
            db.session.rollback()
            return {
                'msg': 'Internal server error',
                'error': str(e)
            }, 500