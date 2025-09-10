from flask import Blueprint, request, jsonify

try:
    from src.models.firewall_rule import db, FirewallRule
    from src.utils.firewall_rules_utils import update_firewall_rule_fields
except ImportError:
    from models.firewall_rule import db, FirewallRule
    from utils.firewall_rules_utils import update_firewall_rule_fields

firewall_rules_bp = Blueprint('firewall_rules', __name__, url_prefix='/api')

# Retrieve all firewall rules
@firewall_rules_bp.route('/firewall_rules', methods=['GET'])
def get_firewall_rules():
    rules = FirewallRule.query.all()
    if rules:
        return jsonify({
            "firewall_rules": [rule.to_dict() for rule in rules]
        }), 200
    
    return jsonify({
        "firewall_rules": []
    }), 200

# Create a new firewall rule
@firewall_rules_bp.route('/firewall_rules', methods=['POST'])
def create_firewall_rule():
    data = request.get_json()

    new_rule = FirewallRule(
        name=data.get("name"),
        description=data.get("description"),
        action=data.get("action"),
        source_ip=data.get("source_ip"),
        destination_ip=data.get("destination_ip"),
        protocol=data.get("protocol"),
        port=data.get("port"),
        is_active=data.get("is_active", True),
        created_by=data.get("created_by"),
        last_modified_by=data.get("last_modified_by"),
    )

    db.session.add(new_rule)
    db.session.commit()

    return jsonify({
        "message": "Firewall rule created",
        "firewall_rule": new_rule.to_dict()
    }), 201

# Update an existing firewall rule
@firewall_rules_bp.route('/firewall_rules/<int:rule_id>', methods=['PUT'])
def update_firewall_rule(rule_id: int):
    rule = FirewallRule.query.filter_by(id=rule_id).first()

    if not rule:
        return jsonify({
            "message": "Firewall rule not found"
        }), 404

    data = request.get_json()
    update_firewall_rule_fields(rule, data)
    db.session.commit()

    return jsonify({
        "message": "Firewall rule updated",
        "firewall_rule": rule.to_dict()
    }), 200

# Delete a firewall rule
@firewall_rules_bp.route('/firewall_rules/<int:rule_id>', methods=['DELETE'])
def delete_firewall_rule(rule_id: int):
    rule = FirewallRule.query.filter_by(id=rule_id).first()

    if not rule:
        return jsonify({
            "message": "Firewall rule not found"
        }), 404

    db.session.delete(rule)
    db.session.commit()

    return jsonify({
        "message": "Firewall rule deleted",
        "firewall_rule": rule.to_dict()
    }), 200