import datetime
try:
    from src.models.base import db
except ImportError:
    from models.base import db

class TokenBlocklist(db.Model):
    __tablename__ = 'token_blocklist'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    jti = db.Column(db.String(36), unique=True, nullable=False)
    token_type = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now(), nullable=False)
    user_identity = db.Column(db.String(50), nullable=False)