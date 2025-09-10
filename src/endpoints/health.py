from flask import Blueprint, request, jsonify

health_bp = Blueprint('health', __name__, url_prefix='/api')

@health_bp.route('/health', methods=["GET"])
def health():
    """
    Health check endpoint
    """
    return jsonify({
        "status": "ok"
    }), 200