from flask import Blueprint, request, jsonify

try:
    from src.models.firewall_policy import db, FirewallPolicy
    from src.models.firewall_rule import FirewallRule
    from src.utils.firewall_policies_utils import update_firewall_policy_fields, update_firewall_policy_unique_field, update_policy_rules
except ImportError:
    from models.firewall_policy import db, FirewallPolicy
    from models.firewall_rule import FirewallRule
    from utils.firewall_policies_utils import update_firewall_policy_fields, update_firewall_policy_unique_field, update_policy_rules

firewall_policies_bp = Blueprint('firewall_policies', __name__, url_prefix='/api')

FIREWALL_POLICY_NOT_FOUND = "Firewall policy not found"

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

    # If provided associated rules, add them to the policy
    update_policy_rules(new_policy, data)
    db.session.add(new_policy)
    db.session.commit()

    return jsonify({
        "message": "Firewall policy created",
        "firewall_policy": new_policy.to_dict()
    }), 201

@firewall_policies_bp.route('/firewall_policies/<int:policy_id>', methods=["PUT"])
def update_firewall_policy(policy_id: int):
    """
    Update an existing firewall policy
    """
    policy = FirewallPolicy.query.filter_by(id=policy_id).first()

    if not policy:
        return jsonify({
            "message": FIREWALL_POLICY_NOT_FOUND
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
        "message": f"Firewall policy updated {policy.name}",
        "firewall_policy": policy.to_dict()
    }), 200

@firewall_policies_bp.route('/firewall_policies/<int:policy_id>/rules', methods=["PATCH"])
def add_rules_to_policy(policy_id: int):
    """
    Add a rule to an existing firewall policy
    """
    policy = FirewallPolicy.query.filter_by(id=policy_id).first()

    if not policy:
        return jsonify({
            "message": FIREWALL_POLICY_NOT_FOUND
        }), 404

    data = request.get_json()
    
    if not data or "rules_id" not in data:
        return jsonify({
            "message": "No rules_id provided to add to policy",
            "firewall_policy": policy.to_dict()
        }), 400

    update_policy_rules(policy, data)
    db.session.commit()

    return jsonify({
        "message": f"Rules added to policy {policy.name}",
        "firewall_policy": policy.to_dict()
    }), 200

@firewall_policies_bp.route('/firewall_policies/<int:policy_id>/rules/<int:rule_id>', methods=["DELETE"])
def remove_rule_from_policy(policy_id: int, rule_id: int):
    """
    Remove a rule from an existing firewall policy
    """
    policy = FirewallPolicy.query.filter_by(id=policy_id).first()
    rule = FirewallRule.query.filter_by(id=rule_id).first()

    if not policy:
        return jsonify({
            "message": FIREWALL_POLICY_NOT_FOUND
        }), 404

    if not rule:
        return jsonify({
            "message": f"Rule with id {rule_id} not found"
        }), 404

    policy.rules.remove(rule)
    db.session.commit()

    return jsonify({
        "message": f"Rule {rule.name} removed from policy {policy.name}",
        "firewall_policy": policy.to_dict()
    }), 200

@firewall_policies_bp.route('/firewall_policies/<int:policy_id>', methods=["DELETE"])
def delete_firewall_policy(policy_id: int):
    """
    Delete an existing firewall policy
    """
    policy = FirewallPolicy.query.filter_by(id=policy_id).first()
    if not policy:
        return jsonify({
            "message": FIREWALL_POLICY_NOT_FOUND
        }), 404

    db.session.delete(policy)
    db.session.commit()

    return jsonify({
        "message": f"Firewall policy {policy.name} deleted",
        "firewall_policy": policy.to_dict()
    }), 200