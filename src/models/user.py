from sqlalchemy import UniqueConstraint, PrimaryKeyConstraint

try:
    from src.models.base import db
except ImportError:
    from models.base import db

class User(db.Model):
    __tablename__ = 'users'
    __table_args__ = (
        PrimaryKeyConstraint('id'),
        UniqueConstraint('username', 'email', name='uq_user_username_email'),
    )

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    roles = db.Column(db.String(120), nullable=True, default='user')

    def has_role(self, role: str) -> bool:
        if not self.roles:
            return False
        return role in [r.strip() for r in self.roles.split(',')]

    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'roles': self.roles
        }

    def __repr__(self) -> str:
        return f'<User {self.username}>'