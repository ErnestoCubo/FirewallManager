"""
Initialize admin user script - to be run once before starting the application.
"""

import sys
import os
from werkzeug.security import generate_password_hash
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from src.app import create_app
    from src.models.base import db
    from src.models.user import User
except ImportError:
    from app import create_app
    from models.base import db
    from models.user import User


def init_admin_user():
    """Initialize the admin user."""
    app = create_app()
    
    with app.app_context():
        # Create tables if they don't exist
        db.create_all()
        
        # Check if any users exist
        user_count = User.query.count()
        
        if user_count == 0:
            print("No users found. Creating initial admin user...")
            
            admin_user = User(
                username='admin',
                email='admin@firewall-manager.local',
                password_hash=generate_password_hash('admin', method='scrypt', salt_length=8),
                role='admin'
            )
            
            try:
                db.session.add(admin_user)
                db.session.commit()
                
                print("=" * 60)
                print("✅ Initial admin user created successfully!")
                print("=" * 60)
                print("   Username: admin")
                print("   Password: admin")
                print("   Email: admin@firewall-manager.local")
                print("   Role: admin")
                print("=" * 60)
                print("⚠️  SECURITY WARNING: Change the admin password immediately!")
                print("=" * 60)
                
            except Exception as e:
                db.session.rollback()
                print(f"❌ Error creating admin user: {e}")
                return False
        else:
            print(f"ℹ️  Database already has {user_count} user(s).")
            
            # Check if admin user exists
            admin_user = User.query.filter_by(username='admin').first()
            if admin_user:
                print("✅ Admin user already exists.")
            else:
                print("⚠️  No admin user found, but other users exist.")
                print("   Run 'python src/cli.py create-user' to create an admin user.")
        
        # List all users
        print("\n📋 Current users in database:")
        print("-" * 40)
        users = User.query.all()
        for user in users:
            print(f"  • {user.username} ({user.role}) - {user.email}")
        print("-" * 40)
        
        return True


if __name__ == '__main__':
    init_admin_user()