from flask import Blueprint, request, jsonify
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
except ImportError:
    from models.user import User
    from models.token_block_list import TokenBlocklist
    from src import db

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

def register_jwt(app):
    """
    Initialize JWT manager and configure callbacks.
    """
    jwt = JWTManager(app)

    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header: dict, jwt_payload: dict):
        jti = jwt_payload['jti']
        return TokenBlocklist.query.filter_by(jti=jti).first() is not None

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):  # Fixed function name
        return jsonify({
            'msg': 'The token has expired',
            'error': 'token_expired'
        }), 401

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return jsonify({
            'msg': 'Signature verification failed',
            'error': 'invalid_token'
        }), 422

    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return jsonify({
            'msg': 'Request does not contain an access token',
            'error': 'authorization_required'
        }), 401

    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        return jsonify({
            'msg': 'The token has been revoked',
            'error': 'token_revoked'
        }), 401

    return jwt

@auth_bp.route('/register', methods=['POST'])
def register():
    """
    Register a new user.
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    roles = data.get('roles', 'user')

    if not username or not password or not email:
        return jsonify({
            'msg': 'Missing username, password, or email'
        }), 400

    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({
            'msg': 'Username or email already exists'
        }), 409

    password_hash = generate_password_hash(password, method='scrypt', salt_length=8)
    new_user = User(username=username, password_hash=password_hash, email=email, roles=roles)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({
        'msg': 'User registered successfully',
        'user': new_user.to_dict()
    }), 201


@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Authenticate user and return tokens.
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({
            'msg': 'Missing username or password'
        }), 400

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({
            'msg': 'Bad username or password'
        }), 401

    additional_claims = {'roles': user.roles}
    access_token = create_access_token(identity=str(user.id), additional_claims=additional_claims)
    refresh_token = create_refresh_token(identity=str(user.id))

    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': user.to_dict()
    }), 200

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """
    Refresh access token.
    """
    current_user_id = get_jwt_identity()
    user = User.query.filter_by(id=int(current_user_id)).first()

    if not user:
        return jsonify({
            'msg': 'User not found'
        }), 404

    additional_claims = {'roles': user.roles}
    new_access_token = create_access_token(identity=str(current_user_id), additional_claims=additional_claims)

    return jsonify({
        'access_token': new_access_token
    }), 200

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """Revoke the current user's access token."""
    jti = get_jwt()['jti']
    user_id = get_jwt_identity()
    token_type = get_jwt().get('type', 'access')

    revoked_token = TokenBlocklist(jti=jti, token_type=token_type, user_identity=str(user_id))
    db.session.add(revoked_token)
    db.session.commit()

    return jsonify({
        'msg': 'Token revoked'
    }), 200

@auth_bp.route('/logout_refresh', methods=['POST'])
@jwt_required(refresh=True)
def logout_refresh():
    """Revoke the current user's refresh token."""
    jti = get_jwt()['jti']
    user_id = get_jwt_identity()
    token_type = get_jwt().get('type', 'refresh')

    revoked_token = TokenBlocklist(jti=jti, token_type=token_type, user_identity=str(user_id))
    db.session.add(revoked_token)
    db.session.commit()

    return jsonify({
        'msg': 'Refresh token revoked'
    }), 200

def role_required(role):
    """Decorator to check if the user has the required role."""
    from functools import wraps
    from flask_jwt_extended import verify_jwt_in_request, get_jwt

    def wrapper(fn):
        @wraps(fn)
        @jwt_required()
        def decorator(*args, **kwargs):
            claims = get_jwt()
            user_roles = claims.get('roles', [])
            if role not in user_roles:
                return jsonify({
                    'msg': 'Insufficient permissions'
                }), 403
            return fn(*args, **kwargs)
        return decorator
    return wrapper