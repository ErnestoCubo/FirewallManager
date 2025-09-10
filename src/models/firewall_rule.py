import datetime
from sqlalchemy import PrimaryKeyConstraint

try:
    from src.models.base import db
    from src.models.associations import firewall_rules_association
except ImportError:
    from models.base import db
    from models.associations import firewall_rules_association

class FirewallRule(db.Model):
    __tablename__ = "rules"
    __table_args__ = (db.PrimaryKeyConstraint('id',),)

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    action = db.Column(db.String(50), nullable=False)
    source_ip = db.Column(db.String(45), nullable=True)
    destination_ip = db.Column(db.String(45), nullable=True)
    protocol = db.Column(db.String(20), nullable=True)
    port = db.Column(db.String(20), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.String(100), nullable=True)
    last_modified_by = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    policies = db.relationship("FirewallPolicy", secondary=firewall_rules_association, back_populates="rules")

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "action": self.action,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "protocol": self.protocol,
            "port": self.port,
            "is_active": self.is_active,
            "created_by": self.created_by,
            "last_modified_by": self.last_modified_by,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    def __repr__(self):
        return f"<FirewallRule {self.name} (ID: {self.id})>"