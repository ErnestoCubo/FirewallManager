from flask import Blueprint, request, jsonify

try:
    from src.models.firewall import db, Firewall
    from src.models.firewall_policy import FirewallPolicy
    from src.utils.firewall_utils import update_firewall_fields, update_firewall_unique_field, set_firewall_policies
except ImportError:
    from models.firewall import db, Firewall
    from models.firewall_policy import FirewallPolicy
    from utils.firewall_utils import update_firewall_fields, update_firewall_unique_field, set_firewall_policies

firewalls_bp = Blueprint('firewalls', __name__, url_prefix='/api')

FIREWALL_NOT_FOUND_MESSAGE = "Firewall not found"

@firewalls_bp.route('/firewalls', methods=["GET"])
def get_firewalls():
    """
    Retrieve all firewalls
    """
    firewalls = Firewall.query.all()

    if firewalls:
        return jsonify({
            "firewalls": [fw.to_dict() for fw in firewalls]
        }), 200
    else:
        return jsonify({
            "firewalls": []
        }), 200

@firewalls_bp.route('/firewalls', methods=["POST"])
def create_firewall():
    """
    Create a new firewall
    """
    data = request.get_json()

    firewall_hostname = Firewall.query.filter_by(hostname=data['hostname']).first()
    firewall_name = Firewall.query.filter_by(name=data['name']).first()

    if firewall_hostname:
        return jsonify({
            "message": f"Firewall with this hostname {data['hostname']} already exists"
        }), 400

    if firewall_name:
        return jsonify({
            "message": f"Firewall with this name {data['name']} already exists"
        }), 400

    # Creating a new firewall instance
    new_firewall = Firewall(
        name=data.get("name"),
        description=data.get("description"),
        hostname=data.get("hostname"),
        ip_address=data.get("ip_address"),
        vendor=data.get("vendor"),
        model=data.get("model"),
        os_version=data.get("os_version"),
        country=data.get("country"),
        city=data.get("city"),
    )

    # If provided associated policies, add them
    set_firewall_policies(new_firewall, data)
    db.session.add(new_firewall)
    db.session.commit()

    return jsonify({
        "message": "Firewall created",
        "firewall": new_firewall.to_dict()
    }), 201

@firewalls_bp.route('/firewalls/<int:firewall_id>', methods=["PUT"])
def update_firewall(firewall_id: int):
    """
    Update an existing firewall
    """
    firewall = Firewall.query.filter_by(id=firewall_id).first()

    if not firewall:
        return jsonify({
            "message": FIREWALL_NOT_FOUND_MESSAGE,
        }), 404

    data = request.get_json()
    if not data:
        return jsonify({
            "message": "No data provided for update",
            "firewall": firewall.to_dict()
        }), 400

    if not update_firewall_unique_field(firewall, data, "hostname"):
        return jsonify({
            "message": "Hostname already exists",
            "firewall": firewall.to_dict()
        }), 400

    if not update_firewall_unique_field(firewall, data, "name"):
        return jsonify({
            "message": f"Firewall with this name {data['name']} already exists",
            "firewall": firewall.to_dict()
        }), 400

    # Update normal fields
    update_firewall_fields(firewall, data)    
    db.session.commit()

    return jsonify({
        "message": f"Firewall updated {firewall.name}",
        "firewall": firewall.to_dict()
    }), 200

@firewalls_bp.route('/firewalls/<int:firewall_id>/policies', methods=["PATCH"])
def update_firewall_policies(firewall_id: int):
    """
    Update firewall policies (add/remove) without using overwrite
    """
    firewall = Firewall.query.filter_by(id=firewall_id).first()

    if not firewall:
        return jsonify({
            "message": FIREWALL_NOT_FOUND_MESSAGE
        }), 404

    data = request.get_json()

    if not data or "policies_ids" not in data:
        return jsonify({
            "message": "No policies_ids provided for update",
            "firewall": firewall.to_dict()
        }), 400

    set_firewall_policies(firewall, data)
    db.session.commit()

    return jsonify({
        "message": f"Firewall policies updated {firewall.name}",
        "firewall": firewall.to_dict()
    }), 200

@firewalls_bp.route('/firewalls/<int:firewall_id>/policies/<int:policy_id>', methods=["DELETE"])
def remove_firewall_policy(firewall_id: int, policy_id: int):
    """
    Remove a specific policy from a firewall
    """
    firewall = Firewall.query.filter_by(id=firewall_id).first()
    policy = FirewallPolicy.query.filter_by(id=policy_id).first()

    if not firewall:
        return jsonify({
            "message": FIREWALL_NOT_FOUND_MESSAGE
        }), 404

    if not policy:
        return jsonify({
            "message": "Policy not found"
        }), 404

    firewall.policies.remove(policy)
    db.session.commit()

    return jsonify({
        "message": f"Policy {policy.name} removed from firewall {firewall.name}",
        "firewall": firewall.to_dict()
    }), 200

@firewalls_bp.route('/firewalls/<int:firewall_id>', methods=["DELETE"])
def delete_firewall(firewall_id: int):
    """
    Delete an existing firewall
    """
    firewall = Firewall.query.filter_by(id=firewall_id).first()
    if not firewall:
        return jsonify({
            "message": FIREWALL_NOT_FOUND_MESSAGE
        }), 404

    db.session.delete(firewall)
    db.session.commit()

    return jsonify({
        "message": f"Firewall {firewall.name} deleted",
        "firewall": firewall.to_dict()
    }), 200