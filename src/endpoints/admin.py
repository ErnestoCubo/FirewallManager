"""
Admin Endpoints for User and Role Management

This module provides administrative endpoints for managing users and roles within the system.
"""
import json
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash
from typing import Dict, Any, Tuple, List

try:
    from src.models.user import User
    from src.models.base import db
    from src.rbac.role_based_access_control import role_required
except ImportError as e:
    from src.models.user import User
    from src.models.base import db


admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')


USER_NOT_FOUND_ERROR = "User not found"


@admin_bp.route('/users', methods=['GET'])
@jwt_required()
@role_required('admin', 'read_user')
def get_all_users() -> Tuple[Dict[str, Any], int]:
    """
    Retrieves all users in the system.

    Returns:
        Tuple[Dict[str, Any], int]: A tuple containing a dictionary with the list of users and the HTTP status code.
    Responses:
        200: Successfully retrieved the list of users.
        403: Insufficient permissions to access this endpoint.
        500: Internal server error.
    """
    try:
        users = User.query.all()
        return jsonify({
            "users": [user.to_dict() for user in users]
            }), 200

    except Exception as e:
        return jsonify({
            "message": str(e)
            }), 500


@admin_bp.route('/users/search', methods=['GET'])
@jwt_required()
@role_required('admin', 'read_user')
def get_search_user() -> Tuple[Dict[str, Any], int]:
    """
    Searches for users in the system based on query parameters.

    Returns:
        Tuple[Dict[str, Any], int]: A tuple containing a dictionary with the search results and the HTTP status code.

    Responses:
        200: Successfully retrieved the search results.
        403: Insufficient permissions to access this endpoint.
        500: Internal server error.
    """
    try:
        query = request.args.get('query', '')
        users = User.query.filter(User.username.contains(query)).all()
        return jsonify({
            "users": [user.to_dict() for user in users]
            }), 200

    except Exception as e:
        return jsonify({
            "message": str(e)
            }), 500


@admin_bp.route('/users/<int:user_id>', methods=['GET'])
@jwt_required()
@role_required('admin', 'read_user')
def get_user(user_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Retrieves a specific user by ID.

    Args:
        user_id (int): The ID of the user to retrieve.

    Returns:
        Tuple[Dict[str, Any], int]: A tuple containing a dictionary with the user details and the HTTP status code.

    Responses:
        200: Successfully retrieved the user.
        403: Insufficient permissions to access this endpoint.
        404: User not found.
        500: Internal server error.
    """
    try:
        user = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({
                "message": USER_NOT_FOUND_ERROR
                }), 404

        return jsonify({
            "user": user.to_dict()
            }), 200

    except Exception as e:
        return jsonify({
            "message": str(e)
            }), 500


@admin_bp.route('/users/<int:user_id>/role', methods=['PUT'])
@jwt_required()
@role_required('admin', 'update_user_role')
def update_user_role(user_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Updates the role of a specific user.

    Args:
        user_id (int): The ID of the user whose role is to be updated.

    Returns:
        Tuple[Dict[str, Any], int]: A tuple containing a dictionary with the update status and the HTTP status code.

    Responses:
        200: Successfully updated the user's role.
        403: Insufficient permissions to access this endpoint.
        404: User not found.
        500: Internal server error.
    """
    try:
        user = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({
                "message": USER_NOT_FOUND_ERROR
            }), 404

        new_role = request.json.get("role")
        if not new_role:
            return jsonify({
                "message": "Role is required"
            }), 400

        user.role = new_role
        db.session.commit()
        return jsonify({
            "message": "User role updated"
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "message": str(e)
        }), 500


@admin_bp.route('/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
@role_required('admin', 'delete_user')
def delete_user(user_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Deletes a specific user by ID.

    Args:
        user_id (int): The ID of the user to delete.

    Returns:
        Tuple[Dict[str, Any], int]: A tuple containing a dictionary with the deletion status and the HTTP status code.

    Responses:
        200: Successfully deleted the user.
        403: Insufficient permissions to access this endpoint.
        404: User not found.
        500: Internal server error.
    """
    try:
        user = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({
                "message": USER_NOT_FOUND_ERROR
                }), 404

        db.session.delete(user)
        db.session.commit()
        return jsonify({
            "message": "User deleted"
            }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "message": str(e)
            }), 500


@admin_bp.route('/users/<int:user_id>/reset_password', methods=['POST'])
@jwt_required()
@role_required('admin', 'reset_user_password')
def reset_user_password(user_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Resets the password for a specific user.

    Args:
        user_id (int): The ID of the user whose password is to be reset.

    Returns:
        Tuple[Dict[str, Any], int]: A tuple containing a dictionary with the reset status and the HTTP status code.

    Responses:
        200: Successfully reset the user's password.
        403: Insufficient permissions to access this endpoint.
        404: User not found.
        500: Internal server error.
    """
    try:
        user = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({
                "message": USER_NOT_FOUND_ERROR
            }), 404

        new_password = request.json.get("password")
        if not new_password:
            return jsonify({
                "message": "New password is required"
            }), 400

        user.password_hash = generate_password_hash(new_password)
        db.session.commit()

        return jsonify({
            "message": "User password reset"
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "message": str(e)
        }), 500


@admin_bp.route('/roles', methods=['GET'])
@jwt_required()
@role_required('admin', 'read_role')
def get_all_roles() -> Tuple[Dict[str, Any], int]:
    """
    Retrieves all roles in the system.

    Returns:
        Tuple[Dict[str, Any], int]: A tuple containing a dictionary with the list of roles and the HTTP status code.

    Responses:
        200: Successfully retrieved the list of roles.
        403: Insufficient permissions to access this endpoint.
        500: Internal server error.
    """
    try:
        with open('src/rbac/config/permission_settings.json') as f:
            permission_settings = json.load(f)
            roles = permission_settings.get("roles", [])

        return jsonify({
            "roles": roles
            }), 200

    except Exception as e:
        return jsonify({
            "message": str(e)
            }), 500