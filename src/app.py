"""
Main application module for the Firewall Manager.
This module initializes the Flask application, configures the database,
and registers the API endpoints.
"""
from flask import Flask
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

try:
    from src.models.base import db
    from src.endpoints.auth import auth_bp, register_jwt
    from src.endpoints.firewalls import firewalls_bp
    from src.endpoints.firewall_policies import firewall_policies_bp
    from src.endpoints.firewall_rules import firewall_rules_bp
    from src.endpoints.health import health_bp
    from src.config import Config
except ImportError:
    from models.base import db
    from endpoints.firewalls import firewalls_bp
    from endpoints.firewall_policies import firewall_policies_bp
    from endpoints.firewall_rules import firewall_rules_bp
    from endpoints.health import health_bp
    from config import Config

app = Flask(__name__)

def create_app():
    """
    Create and configure the Flask application.
    
    Returns:
        Flask: Configured Flask application instance.
    """
    app = Flask(__name__)
    app.config.from_object(Config)
    
    db.init_app(app)

    register_jwt(app)
    app.register_blueprint(auth_bp)
    app.register_blueprint(firewalls_bp)
    app.register_blueprint(firewall_policies_bp)
    app.register_blueprint(firewall_rules_bp)
    app.register_blueprint(health_bp)

    return app

if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        db.create_all()

    app.run(debug=True)