"""
This module defines association tables for many-to-many relationships
between firewalls, policies, and rules using SQLAlchemy.
"""
try:
    from src.models.base import db
except ImportError:
    from models.base import db

firewall_policy_association = db.Table(
    'firewall_policy_association',
    db.Column('firewall_id', db.Integer, db.ForeignKey('firewalls.id'), primary_key=True),
    db.Column('policy_id', db.Integer, db.ForeignKey('policies.id'), primary_key=True)
)

firewall_rules_association = db.Table(
    'firewall_rules_association',
    db.Column('policy_id', db.Integer, db.ForeignKey('policies.id'), primary_key=True),
    db.Column('rule_id', db.Integer, db.ForeignKey('rules.id'), primary_key=True)
)