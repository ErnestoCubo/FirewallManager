"""
Firewall model module.

This module defines the Firewall model representing network firewall devices
and their relationships with security policies.
"""
from datetime import datetime
from sqlalchemy import PrimaryKeyConstraint
try:
    from src.models.base import db
    from src.models.associations import firewall_policy_association
except ImportError:
    from models.base import db
    from models.associations import firewall_policy_association

class Firewall(db.Model):
    """
    Represents a network firewall device.
    
    This model stores information about firewall devices including their
    configuration, location, and associated security policies.
    
    Attributes:
        id (int): Primary key identifier.
        name (str): Unique name of the firewall.
        hostname (str): Unique hostname for network identification.
        description (str): Optional description of the firewall.
        ip_address (str): IP address of the firewall.
        vendor (str): Manufacturer of the firewall (e.g., Cisco, Fortinet).
        model (str): Model number or name.
        os_version (str): Operating system version.
        country (str): Physical location country.
        city (str): Physical location city.
        created_at (datetime): Timestamp of creation.
        updated_at (datetime): Timestamp of last update.
        policies (relationship): Associated firewall policies.
    
    Example:
        >>> firewall = Firewall(
        ...     name="Main Office FW",
        ...     hostname="fw-main-01",
        ...     ip_address="192.168.1.1",
        ...     vendor="Cisco",
        ...     model="ASA 5505"
        ... )
    """
    __tablename__ = "firewalls"
    __table_args__ = (PrimaryKeyConstraint('id'),)

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    hostname = db.Column(db.String(255), nullable=False, unique=True)
    description = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(45), nullable=False)
    vendor = db.Column(db.String(50), nullable=False)
    model = db.Column(db.String(50), nullable=False)
    os_version = db.Column(db.String(50), nullable=False)
    country = db.Column(db.String(100), nullable=True)
    city = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    policies = db.relationship("FirewallPolicy", secondary=firewall_policy_association, back_populates="firewalls")

    def to_dict(self) -> dict:
        """
        Convert firewall instance to dictionary representation.
        
        Returns:
            dict: Dictionary containing all firewall attributes.
        """
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

    def __repr__(self) -> str:
        """Return string representation of the firewall."""
        return f"<Firewall {self.name} ({self.hostname})>"