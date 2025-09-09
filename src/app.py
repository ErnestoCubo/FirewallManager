from flask import Flask
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

try:
    from src.models.base import db
    from src.endpoints.firewalls import firewalls_bp
    from src.endpoints.health import health_bp
    from src.config import Config
except ImportError:
    from models.base import db
    from endpoints.firewalls import firewalls_bp
    from endpoints.health import health_bp
    from config import Config

app = Flask(__name__)

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    db.init_app(app)

    app.register_blueprint(firewalls_bp)
    app.register_blueprint(health_bp)

    return app

if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        db.create_all()

    app.run(debug=True)