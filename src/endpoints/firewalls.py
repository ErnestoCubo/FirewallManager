from flask import Blueprint, request, jsonify

try:
    from src.models.firewall import db, Firewall
    from src.utils.firewall_utils import update_firewall_fields, update_firewall_unique_field
except ImportError:
    from models.firewall import db, Firewall
    from utils.firewall_utils import update_firewall_fields, update_firewall_unique_field

firewalls_bp = Blueprint('firewalls', __name__, url_prefix='/api')

# Retrieve all firewalls
@firewalls_bp.route('/firewalls', methods=["GET"])
def get_firewalls():
    firewalls = Firewall.query.all()

    if firewalls:
        return jsonify({
            "firewalls": [fw.to_dict() for fw in firewalls]
        }), 200
    else:
        return jsonify({
            "firewalls": []
        }), 200

# Creates a new firewall
@firewalls_bp.route('/firewalls', methods=["POST"])
def create_firewall():
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

    db.session.add(new_firewall)
    db.session.commit()

    return jsonify({
        "message": "Firewall created",
        "firewall": new_firewall.to_dict()
    }), 201

# Updates an existing firewall
@firewalls_bp.route('/firewalls/<string:hostname>', methods=["PUT"])
def update_firewall(hostname):
    firewall = Firewall.query.filter_by(hostname=hostname).first()

    if not firewall:
        return jsonify({
            "message": "Firewall not found",
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

    update_firewall_fields(firewall, data)

    db.session.commit()

    return jsonify({
        "message": f"Firewall updated {hostname}",
        "firewall": firewall.to_dict()
    }), 200

# Deletes an existing firewall
@firewalls_bp.route('/firewalls/<string:hostname>', methods=["DELETE"])
def delete_firewall(hostname):
    firewall = Firewall.query.filter_by(hostname=hostname).first()
    if not firewall:
        return jsonify({
            "message": "Firewall not found"
        }), 404

    db.session.delete(firewall)
    db.session.commit()

    return jsonify({
        "message": f"Firewall {hostname} deleted",
        "firewall": firewall.to_dict()
    }), 200