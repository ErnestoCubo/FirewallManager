from datetime import datetime
try:
    from src.models.base import db
except ImportError:
    from models.base import db

class Firewall(db.Model):
    __tablename__ = "firewalls"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.String(255), nullable=True)
    hostname = db.Column(db.String(255), nullable=False, unique=True)
    ip_address = db.Column(db.String(45), nullable=False, unique=False)
    vendor = db.Column(db.String(50), nullable=False)
    model = db.Column(db.String(50), nullable=False)
    os_version = db.Column(db.String(50), nullable=False)
    country = db.Column(db.String(100), nullable=True)
    city = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "description": self.description,
            "vendor": self.vendor,
            "model": self.model,
            "os_version": self.os_version,
            "country": self.country,
            "city": self.city,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    def __repr__(self):
        return f"<Firewall {self.name} ({self.hostname})>"