"""
Main application module with Flask-RESTX and OpenAPI 3.0.3 support.
"""

from flask import Flask
from flask_restx import Api
from flask_cors import CORS

try:
    from src.config import Config
    from src.models.base import db
    from src.endpoints.auth import auth_ns, register_jwt
    from src.endpoints.firewalls import firewalls_ns
    from src.endpoints.firewall_policies import policies_ns
    from src.endpoints.firewall_rules import rules_ns
    from src.endpoints.admin import admin_ns
except ImportError:
    from config import Config
    from models.base import db
    from endpoints.auth import auth_ns, register_jwt
    from endpoints.firewalls import firewalls_ns
    from endpoints.firewall_policies import policies_ns
    from endpoints.firewall_rules import rules_ns
    from endpoints.admin import admin_ns


def create_app(config_class=Config):
    """Create and configure the Flask application with Flask-RESTX."""
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize database
    db.init_app(app)
    
    # Initialize JWT
    register_jwt(app)
    
    # Configure CORS
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    
    # Define authorizations for Swagger UI
    authorizations = {
        'Bearer': {
            'type': 'apiKey',
            'in': 'header',
            'name': 'Authorization',
            'description': 'Add a JWT token to the header with ** Bearer &lt;JWT&gt; ** token to authorize'
        }
    }
    
    # Initialize Flask-RESTX with proper Swagger UI configuration
    api = Api(
        app,
        version='1.0',
        title='Firewall Manager API',
        description='RESTful API for managing firewall devices, policies, and rules',
        doc='/api/docs',
        prefix='/api',
        authorizations=authorizations,
        security='Bearer'
    )
    
    # Add namespaces
    api.add_namespace(auth_ns, path='/auth')
    api.add_namespace(firewalls_ns, path='/firewalls')
    api.add_namespace(policies_ns, path='/firewall_policies')
    api.add_namespace(rules_ns, path='/firewall_rules')
    api.add_namespace(admin_ns, path='/admin')
    
    # Create database tables
    with app.app_context():
        db.create_all()
    
    return app


if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)