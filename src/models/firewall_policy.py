import datetime
from sqlalchemy import PrimaryKeyConstraint

try:
    from src.models.base import db
    from src.models.associations import firewall_policy_association, firewall_rules_association
except ImportError:
    from models.base import db
    from models.associations import firewall_policy_association, firewall_rules_association

class FirewallPolicy(db.Model):
    __tablename__ = "policies"
    __table_args__ = (PrimaryKeyConstraint('id',),)

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.String(255), nullable=True)
    policy_type = db.Column(db.String(50), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    priority = db.Column(db.Integer, nullable=True)
    created_by = db.Column(db.String(100), nullable=True)
    last_modified_by = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    firewalls = db.relationship("Firewall", secondary=firewall_policy_association, back_populates="policies")
    rules = db.relationship("FirewallRule", secondary=firewall_rules_association, back_populates="policies")

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "policy_type": self.policy_type,
            "is_active": self.is_active,
            "priority": self.priority,
            "created_by": self.created_by,
            "last_modified_by": self.last_modified_by,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
    
    def __repr__(self):
        return f"<FirewallPolicy {self.name} (ID: {self.id})>"