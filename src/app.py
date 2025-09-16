"""
Main application module with Flask-RESTX and OpenAPI 3.0.3 support.
"""
import os
from flask import Flask
from flask_restx import Api
from flask_cors import CORS
from werkzeug.security import generate_password_hash
from datetime import datetime
from sqlalchemy.exc import IntegrityError

try:
    from src.config import Config
    from src.models.base import db
    from src.models.user import User
    from src.endpoints.auth import auth_ns, register_jwt
    from src.endpoints.firewalls import firewalls_ns
    from src.endpoints.firewall_policies import policies_ns
    from src.endpoints.firewall_rules import rules_ns
    from src.endpoints.admin import admin_ns
    from src.endpoints.health import health_ns
except ImportError:
    from config import Config
    from models.base import db
    from models.user import User
    from endpoints.auth import auth_ns, register_jwt
    from endpoints.firewalls import firewalls_ns
    from endpoints.firewall_policies import policies_ns
    from endpoints.firewall_rules import rules_ns
    from endpoints.admin import admin_ns
    from endpoints.health import health_ns


def create_initial_admin_user():
    """Create initial admin user if it doesn't exist."""
    try:
        # Check if admin user already exists
        admin_user = User.query.filter_by(username='admin').first()
        
        if not admin_user:
            # Check if the email is already taken
            existing_email = User.query.filter_by(email='admin@firewall-manager.local').first()
            if existing_email:
                print("ℹ️  Admin email already exists, skipping admin user creation.")
                return False
                
            admin_user = User(
                username='admin',
                email='admin@firewall-manager.local',
                password_hash=generate_password_hash('admin', method='scrypt', salt_length=8),
                role='admin'
            )
            
            db.session.add(admin_user)
            db.session.commit()
            
            print("=" * 60)
            print("🔐 Initial admin user created!")
            print("   Username: admin")
            print("   Password: admin")
            print("⚠️  SECURITY WARNING: Change the admin password immediately!")
            print("=" * 60)
            
            return True
        else:
            print("ℹ️  Admin user already exists.")
            return False
            
    except IntegrityError:
        # This can happen when multiple workers try to create the user simultaneously
        db.session.rollback()
        print("ℹ️  Admin user creation skipped (already exists or concurrent creation).")
        return False
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error creating admin user: {e}")
        return False


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
        version='2.0.0',
        title='Firewall Manager API',
        description='RESTful API for managing firewall devices, policies, and rules',
        doc='/api/docs',
        prefix='/api',
        authorizations=authorizations,
        security='Bearer'
    )
    
    # Add namespaces
    api.add_namespace(health_ns, path='/health')
    api.add_namespace(auth_ns, path='/auth')
    api.add_namespace(firewalls_ns, path='/firewalls')
    api.add_namespace(policies_ns, path='/firewall_policies')
    api.add_namespace(rules_ns, path='/firewall_rules')
    api.add_namespace(admin_ns, path='/admin')
    
    # Create database tables and initial admin user
    with app.app_context():
        db.create_all()
        
        # Only create admin user if INIT_ADMIN is set or in development mode
        # Use worker ID to ensure only one worker creates the admin user
        worker_id = os.environ.get('APP_WORKER_ID', '0')
        if worker_id == '0' or worker_id == '1':  # Only first worker should create admin
            if os.environ.get('INIT_ADMIN', 'false').lower() == 'true' or app.config.get('FLASK_ENV') == 'development':
                create_initial_admin_user()
    
    return app


if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)