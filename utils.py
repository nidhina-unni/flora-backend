import json
from flask_jwt_extended import create_access_token
from werkzeug.security import generate_password_hash, check_password_hash
from models.user import Admin


def hash_password(password):
    """Hashes a plaintext password."""
    return generate_password_hash(password)


def verify_password(hashed_password, password):
    """Verifies a hashed password against a plaintext password."""
    return check_password_hash(hashed_password, password)


def authenticate_user(admin_name, admin_password):
    admin = Admin.query.filter_by(admin_name=admin_name).first()
    if admin and check_password_hash(admin.admin_password, admin_password):
        # Create access token with serialized identity (string format)
        identity = json.dumps({'id': admin.admin_id, 'is_admin': admin.is_admin})
        return create_access_token(identity=identity)
    return None