"""Firewall rule module

This module defines the FirewallRule model representing individual firewall rules
and their relationships with firewall policies.
"""
import datetime
from sqlalchemy import PrimaryKeyConstraint

try:
    from src.models.base import db
    from src.models.associations import firewall_rules_association
except ImportError:
    from models.base import db
    from models.associations import firewall_rules_association

class FirewallRule(db.Model):
    """
    Represents an individual firewall rule.

    This model stores information about firewall rules including their
    configuration, action, and associated policies.

    Attributes:
        id (int): Primary key identifier.
        name (str): Name of the firewall rule.
        description (str): Optional description of the rule.
        action (str): Action to be taken (e.g., allow, deny).
        source_ip (str): Source IP address or range.
        destination_ip (str): Destination IP address or range.
        protocol (str): Network protocol (e.g., TCP, UDP).
        port (str): Port number or range.
        is_active (bool): Status of the rule (active/inactive).
        created_by (str): User who created the rule.
        last_modified_by (str): User who last modified the rule.
        created_at (datetime): Timestamp of creation.
        updated_at (datetime): Timestamp of last update.
        policies (relationship): Associated firewall policies.

    Example:
        >>> rule = FirewallRule(
        ...     name="Allow HTTP",
        ...     action="allow",
        ...     source_ip="
        ...     destination_ip="
        ...     protocol="TCP",
        ... )
    """
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

    def to_dict(self) -> dict:
        """
        Convert the FirewallRule instance to a dictionary representation.
        
        Returns:
            dict: Dictionary containing the firewall rule's attributes.
        """
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

    def __repr__(self) -> str:
        """Return string representation of the firewall rule."""
        return f"<FirewallRule {self.name} (ID: {self.id})>"