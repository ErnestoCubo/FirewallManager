from datetime import datetime
from sqlalchemy import PrimaryKeyConstraint

try:
    from src.models.base import db
    from src.models.associations import firewall_policy_association
except ImportError:
    from models.base import db
    from models.associations import firewall_policy_association

class Firewall(db.Model):
    __tablename__ = "firewalls"
    __table_args__ = (PrimaryKeyConstraint('id',),)

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

    policies = db.relationship("FirewallPolicy", secondary=firewall_policy_association, back_populates="firewalls")

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
            "policies": [policy.to_dict() for policy in self.policies]
        }

    def __repr__(self):
        return f"<Firewall {self.name} ({self.hostname})>"