"""
Firewall Policy model module.

This module defines the FirewallPolicy model representing security policies
that can be applied to firewalls and contain security rules.
"""
import datetime
from sqlalchemy import PrimaryKeyConstraint

try:
    from src.models.base import db
    from src.models.associations import firewall_policy_association, firewall_rules_association
except ImportError:
    from models.base import db
    from models.associations import firewall_policy_association, firewall_rules_association


class FirewallPolicy(db.Model):
    """
    Represents a firewall security policy.
    
    A policy is a collection of security rules that can be applied to one or more
    firewalls. Policies help organize and manage security rules in a hierarchical
    manner.
    
    Attributes:
        id (int): Primary key identifier.
        name (str): Unique name of the policy.
        description (str): Optional description of the policy's purpose.
        policy_type (str): Type of policy (e.g., 'inbound', 'outbound', 'both').
        is_active (bool): Whether the policy is currently active.
        priority (int): Priority level for policy application order.
        created_by (str): Username of the creator.
        last_modified_by (str): Username of the last modifier.
        created_at (datetime): Timestamp of creation.
        updated_at (datetime): Timestamp of last update.
        firewalls (relationship): Firewalls using this policy.
        rules (relationship): Security rules included in this policy.
    
    Example:
        >>> policy = FirewallPolicy(
        ...     name="Web Server Policy",
        ...     description="Allow HTTP/HTTPS traffic",
        ...     policy_type="inbound",
        ...     priority=1
        ... )
    """
    __tablename__ = "policies"
    __table_args__ = (PrimaryKeyConstraint('id'),)

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

    def to_dict(self) -> dict:
        """
        Convert policy instance to dictionary representation.
        
        Returns:
            dict: Dictionary containing all policy attributes.
        """
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
            "rules": [rule.to_dict() for rule in self.rules],
        }
    
    def __repr__(self) -> str:
        """Return string representation of the policy."""
        return f"<FirewallPolicy {self.name} (ID: {self.id})>"