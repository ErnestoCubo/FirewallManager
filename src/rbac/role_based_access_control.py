"""
Role Based Access Control (RBAC) implementation.

This module provides functionalities to manage user roles and permissions.
"""
import json
from flask import jsonify
from flask_jwt_extended import (
    jwt_required,
    get_jwt_identity,
    get_jwt,
    verify_jwt_in_request,
)


try:
    from src.models.user import User, db
except ImportError:
    from models.user import User, db


def role_required(role:str , permission: str = None):
    """
    Decorator to check if the user has the required role.

    Args:
        role (str): The required role for the endpoint.

    Returns:
        function: The decorated function with role check.
    """
    from functools import wraps
    from flask_jwt_extended import verify_jwt_in_request, get_jwt


    def wrapper(fn):
        @wraps(fn)
        @jwt_required()
        def decorator(*args, **kwargs):
            """
            Check if the user has the required role.
            Args:
                *args: Positional arguments.
                **kwargs: Keyword arguments.

            Returns:
                function: The original function if the role check passes.
            """
            verify_jwt_in_request()
            claims = get_jwt()
            user_id = get_jwt_identity()
            user = User.query.filter_by(id=user_id).first()

            if not user:
                return jsonify({"message": "User not found"}), 404

            token_role = claims.get('role', 'user').lower()

            if token_role != user.role:
                return jsonify({
                    'msg': 'Insufficient permissions'
                }), 403 

            if has_permission(token_role, role, permission) is False:
                return jsonify({
                    'msg': 'Insufficient permissions'
                }), 403
            
            return fn(*args, **kwargs)
        return decorator
    return wrapper


def get_role_permission(role: str) -> dict:
    """
    Get permissions based on role.

    Args:
        role (str): The role of the user.

    Returns:
        dict: Permissions associated with the role.
    """
    with open("src/rbac/config/permission_settings.json") as f:
        roles_permissions = json.load(f)
    return roles_permissions["roles"].get(role.lower(), roles_permissions["roles"]["user"])


def has_permission(user_role: str, required_role: str, required_permission: str) -> bool:
    """
    Check if the user has the specified permission.

    Args:
        role (str): The role of the user.
        permission (str): The permission to check.
    
    Returns:
        bool: True if the user has the permission, False otherwise.
    """

    user_permissions = get_role_permission(user_role)
    required_role_hierarchy = get_role_permission(required_role).get("hierarchy_level", 0)

    if user_permissions.get("hierarchy_level", 0) < required_role_hierarchy:
        return False

    return user_permissions["permissions"].get(required_permission, False)