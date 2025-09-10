from flask import Blueprint, request, jsonify

try:
    from src.models.firewall_policy import db, FirewallPolicy
    from src.utils.firewall_policies_utils import update_firewall_policy_fields, update_firewall_policy_unique_field
except ImportError:
    from models.firewall_policy import db, FirewallPolicy
    from utils.firewall_policies_utils import update_firewall_policy_fields, update_firewall_policy_unique_field

firewall_policies_bp = Blueprint('firewall_policies', __name__, url_prefix='/api')

@firewall_policies_bp.route('/firewall_policies', methods=["GET"])
def get_firewall_policies():
    """
    Retrieve all firewall policies
    """
    policies = FirewallPolicy.query.all()
    if policies:
        return jsonify({
            "firewall_policies": [policy.to_dict() for policy in policies]
        }), 200
    
    return jsonify({
        "firewall_policies": []
    }), 200

@firewall_policies_bp.route('/firewall_policies', methods=["POST"])
def create_firewall_policy():
    """
    Create a new firewall policy
    """
    data = request.get_json()

    policy_name = FirewallPolicy.query.filter_by(name=data['name']).first()
    if policy_name:
        return jsonify({
            "message": f"Firewall policy with this name {data['name']} already exists"
        }), 400

    new_policy = FirewallPolicy(
        name=data.get("name"),
        description=data.get("description"),
        policy_type=data.get("policy_type"),
        is_active=data.get("is_active", True),
        priority=data.get("priority"),
        created_by=data.get("created_by"),
        last_modified_by=data.get("last_modified_by"),
    )

    db.session.add(new_policy)
    db.session.commit()

    return jsonify({
        "message": "Firewall policy created",
        "firewall_policy": new_policy.to_dict()
    }), 201

@firewall_policies_bp.route('/firewall_policies/<string:policy_name>', methods=["PUT"])
def update_firewall_policy(policy_name: str):
    """
    Update an existing firewall policy
    """
    policy = FirewallPolicy.query.filter_by(name=policy_name).first()

    if not policy:
        return jsonify({
            "message": "Firewall policy not found"
        }), 404

    data = request.get_json()
    
    if not data:
        return jsonify({
            "message": "No data provided for update",
            "policy": policy.to_dict()
        }), 400

    if not update_firewall_policy_unique_field(policy, data, 'name'):
        return jsonify({
            "message": f"Firewall policy with this name {data['name']} already exists"
        }), 400

    update_firewall_policy_fields(policy, data)
    db.session.commit()

    return jsonify({
        "message": f"Firewall policy updated {policy_name}",
        "firewall_policy": policy.to_dict()
    }), 200

@firewall_policies_bp.route('/firewall_policies/<string:policy_name>', methods=["DELETE"])
def delete_firewall_policy(policy_name: str):
    """
    Delete an existing firewall policy
    """
    policy = FirewallPolicy.query.filter_by(name=policy_name).first()
    if not policy:
        return jsonify({
            "message": "Firewall policy not found"
        }), 404

    db.session.delete(policy)
    db.session.commit()

    return jsonify({
        "message": f"Firewall policy {policy_name} deleted",
        "firewall_policy": policy.to_dict()
    }), 200