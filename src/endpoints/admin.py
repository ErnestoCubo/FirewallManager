"""
Admin Endpoints for User and Role Management using Flask-RESTX.

This module provides administrative endpoints for managing users and roles within the system.
"""

import json
from flask import request
from flask_restx import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash
from typing import Dict, Any, Tuple

try:
    from src.models.user import User
    from src.models.base import db
    from src.rbac.role_based_access_control import role_required
    from src.api_models.admin_models import (
        admin_ns,
        user_model,
        role_update_model,
        password_reset_model,
        user_list_response,
        user_response,
        message_response,
        roles_response,
        error_response,
        search_parser
    )
except ImportError:
    from models.user import User
    from models.base import db
    from rbac.role_based_access_control import role_required
    from api_models.admin_models import (
        admin_ns,
        user_model,
        role_update_model,
        password_reset_model,
        user_list_response,
        user_response,
        message_response,
        roles_response,
        error_response,
        search_parser
    )

USER_NOT_FOUND_ERROR = "User not found"


@admin_ns.route('/users')
class UserList(Resource):
    @jwt_required()
    @role_required('admin', 'read_user')
    @admin_ns.doc('list_users', security='Bearer')
    @admin_ns.response(200, 'Success', model=user_list_response)
    @admin_ns.response(403, 'Insufficient permissions to access this endpoint', model=error_response)
    @admin_ns.response(500, 'Internal server error', model=error_response)
    def get(self) -> Tuple[Dict[str, Any], int]:
        """
        Retrieves all users in the system.

        Returns:
            Tuple[Dict[str, Any], int]: A tuple containing a dictionary with the list of users and the HTTP status code.
        """
        try:
            users = User.query.all()
            return {
                "users": [user.to_dict() for user in users]
            }, 200

        except Exception as e:
            return {
                "message": str(e)
            }, 500


@admin_ns.route('/users/search')
class UserSearch(Resource):
    @jwt_required()
    @role_required('admin', 'read_user')
    @admin_ns.doc('search_users', security='Bearer')
    @admin_ns.expect(search_parser)
    @admin_ns.response(200, 'Success', model=user_list_response)
    @admin_ns.response(403, 'Insufficient permissions to access this endpoint', model=error_response)
    @admin_ns.response(500, 'Internal server error', model=error_response)
    def get(self) -> Tuple[Dict[str, Any], int]:
        """
        Searches for users in the system based on query parameters.

        Query Parameters:
            query (str): The search string to filter usernames.

        Returns:
            Tuple[Dict[str, Any], int]: A tuple containing a dictionary with the search results and the HTTP status code.
        """
        try:
            args = search_parser.parse_args()
            query = args.get('query', '')
            
            if query:
                users = User.query.filter(User.username.contains(query)).all()
            else:
                users = User.query.all()
                
            return {
                "users": [user.to_dict() for user in users]
            }, 200

        except Exception as e:
            return {
                "message": str(e)
            }, 500


@admin_ns.route('/users/<int:user_id>')
@admin_ns.param('user_id', 'The user identifier')
class UserResource(Resource):
    @jwt_required()
    @role_required('admin', 'read_user')
    @admin_ns.doc('get_user', security='Bearer')
    @admin_ns.response(200, 'Success', model=user_response)
    @admin_ns.response(403, 'Insufficient permissions to access this endpoint', model=error_response)
    @admin_ns.response(404, 'User not found', model=error_response)
    @admin_ns.response(500, 'Internal server error', model=error_response)
    def get(self, user_id: int) -> Tuple[Dict[str, Any], int]:
        """
        Retrieves a specific user by ID.

        Args:
            user_id (int): The ID of the user to retrieve.

        Returns:
            Tuple[Dict[str, Any], int]: A tuple containing a dictionary with the user details and the HTTP status code.
        """
        try:
            user = User.query.filter_by(id=user_id).first()
            if not user:
                return {
                    "message": USER_NOT_FOUND_ERROR
                }, 404

            return {
                "user": user.to_dict()
            }, 200

        except Exception as e:
            return {
                "message": str(e)
            }, 500

    @jwt_required()
    @role_required('admin', 'delete_user')
    @admin_ns.doc('delete_user', security='Bearer')
    @admin_ns.response(200, 'User deleted successfully', model=message_response)
    @admin_ns.response(400, 'Cannot delete your own account', model=error_response)
    @admin_ns.response(403, 'Insufficient permissions to access this endpoint', model=error_response)
    @admin_ns.response(404, 'User not found', model=error_response)
    @admin_ns.response(500, 'Internal server error', model=error_response)
    def delete(self, user_id: int) -> Tuple[Dict[str, Any], int]:
        """
        Deletes a specific user by ID.

        Args:
            user_id (int): The ID of the user to delete.

        Returns:
            Tuple[Dict[str, Any], int]: A tuple containing a dictionary with the deletion status and the HTTP status code.
        """
        try:
            user = User.query.filter_by(id=user_id).first()
            if not user:
                return {
                    "message": USER_NOT_FOUND_ERROR
                }, 404

            # Prevent self-deletion
            current_user_id = get_jwt_identity()
            if user.id == int(current_user_id):
                return {
                    "message": "Cannot delete your own account"
                }, 400

            db.session.delete(user)
            db.session.commit()
            
            return {
                "message": "User deleted"
            }, 200

        except Exception as e:
            db.session.rollback()
            return {
                "message": str(e)
            }, 500


@admin_ns.route('/users/<int:user_id>/role')
@admin_ns.param('user_id', 'The user identifier')
class UserRole(Resource):
    @jwt_required()
    @role_required('admin', 'update_user_role')
    @admin_ns.doc('update_user_role', security='Bearer')
    @admin_ns.expect(role_update_model, validate=True)
    @admin_ns.response(200, 'User role updated successfully', model=message_response)
    @admin_ns.response(400, 'Bad request - Role is required or invalid', model=error_response)
    @admin_ns.response(403, 'Insufficient permissions to access this endpoint', model=error_response)
    @admin_ns.response(404, 'User not found', model=error_response)
    @admin_ns.response(500, 'Internal server error', model=error_response)
    def put(self, user_id: int) -> Tuple[Dict[str, Any], int]:
        """
        Updates the role of a specific user.

        Args:
            user_id (int): The ID of the user whose role is to be updated.

        Request Body:
            role (str): The new role for the user (user, operator, or admin).

        Returns:
            Tuple[Dict[str, Any], int]: A tuple containing a dictionary with the update status and the HTTP status code.
        """
        try:
            user = User.query.filter_by(id=user_id).first()
            if not user:
                return {
                    "message": USER_NOT_FOUND_ERROR
                }, 404

            data = request.get_json()
            new_role = data.get("role")
            
            if not new_role:
                return {
                    "message": "Role is required"
                }, 400

            # Validate role
            valid_roles = ['user', 'operator', 'admin']
            if new_role not in valid_roles:
                return {
                    "message": f"Invalid role. Must be one of: {', '.join(valid_roles)}"
                }, 400

            # Prevent self role change
            current_user_id = get_jwt_identity()
            if user.id == int(current_user_id):
                return {
                    "message": "Cannot change your own role"
                }, 400

            old_role = user.role
            user.role = new_role
            db.session.commit()
            
            return {
                "message": f"User role updated from {old_role} to {new_role}"
            }, 200

        except Exception as e:
            db.session.rollback()
            return {
                "message": str(e)
            }, 500


@admin_ns.route('/users/<int:user_id>/reset_password')
@admin_ns.param('user_id', 'The user identifier')
class UserPasswordReset(Resource):
    @jwt_required()
    @role_required('admin', 'reset_user_password')
    @admin_ns.doc('reset_user_password', security='Bearer')
    @admin_ns.expect(password_reset_model, validate=True)
    @admin_ns.response(200, 'Password reset successfully', model=message_response)
    @admin_ns.response(400, 'Bad request - Password is required or invalid', model=error_response)
    @admin_ns.response(403, 'Insufficient permissions to access this endpoint', model=error_response)
    @admin_ns.response(404, 'User not found', model=error_response)
    @admin_ns.response(500, 'Internal server error', model=error_response)
    def post(self, user_id: int) -> Tuple[Dict[str, Any], int]:
        """
        Resets the password for a specific user.

        Args:
            user_id (int): The ID of the user whose password is to be reset.

        Request Body:
            password (str): The new password for the user (minimum 8 characters).

        Returns:
            Tuple[Dict[str, Any], int]: A tuple containing a dictionary with the reset status and the HTTP status code.
        """
        try:
            user = User.query.filter_by(id=user_id).first()
            if not user:
                return {
                    "message": USER_NOT_FOUND_ERROR
                }, 404

            data = request.get_json()
            new_password = data.get("password")
            
            if not new_password:
                return {
                    "message": "New password is required"
                }, 400

            if len(new_password) < 8:
                return {
                    "message": "Password must be at least 8 characters long"
                }, 400

            user.password_hash = generate_password_hash(new_password, method='scrypt', salt_length=8)
            db.session.commit()

            return {
                "message": "User password reset"
            }, 200

        except Exception as e:
            db.session.rollback()
            return {
                "message": str(e)
            }, 500


@admin_ns.route('/roles')
class RoleList(Resource):
    @jwt_required()
    @role_required('admin', 'read_role')
    @admin_ns.doc('list_roles', security='Bearer')
    @admin_ns.response(200, 'Success', model=roles_response)
    @admin_ns.response(403, 'Insufficient permissions to access this endpoint', model=error_response)
    @admin_ns.response(500, 'Internal server error', model=error_response)
    def get(self) -> Tuple[Dict[str, Any], int]:
        """
        Retrieves all roles in the system.

        Returns:
            Tuple[Dict[str, Any], int]: A tuple containing a dictionary with the list of roles and the HTTP status code.
        """
        try:
            # Try multiple possible paths for the permission settings file
            file_paths = [
                'src/rbac/config/permission_settings.json',
                'rbac/config/permission_settings.json',
                '/home/estiwer/programming/FirewallManager/src/rbac/config/permission_settings.json'
            ]
            
            permission_settings = None
            for path in file_paths:
                try:
                    with open(path, 'r') as f:
                        permission_settings = json.load(f)
                        break
                except FileNotFoundError:
                    continue
            
            if not permission_settings:
                return {
                    "message": "Permission settings file not found"
                }, 500
            
            roles = permission_settings.get("roles", {})
            
            # Return the roles directly as they are in the JSON
            return {
                "roles": roles
            }, 200

        except Exception as e:
            return {
                "message": str(e)
            }, 500