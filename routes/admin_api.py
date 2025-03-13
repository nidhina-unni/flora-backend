from flask import Blueprint, request, jsonify, g
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, get_jwt
from werkzeug.security import generate_password_hash, check_password_hash
from models.user import Admin, User
from app import db

from utils import authenticate_user

# Define Blueprint for Admin Routes
admins_bp = Blueprint('admins_bp', __name__)


@admins_bp.route('/register-admin', methods=['POST'])
def user_register():
    data = request.get_json()

    # Validate input
    if not all(data.get(field) for field in ['admin_name', 'admin_password', 'is_admin']):
        return jsonify({"message": "All fields are required"}), 400

    # Ensure either email or phone number is provided
    if not data.get('email') and not data.get('phone_number'):
        return jsonify({"message": "Either email or phone number is required"}), 400

    # Check for existing username, email, or phone number
    if Admin.query.filter_by(admin_name=data['admin_name']).first():
        return jsonify({"message": "Username already exists"}), 409

    if data.get('email') and Admin.query.filter(Admin.email == data['email']).first():
        return jsonify({"message": "Email already exists"}), 409

    if data.get('phone_number') and Admin.query.filter_by(phone_number=data['phone_number']).first():
        return jsonify({"message": "Phone number already exists"}), 409

    # Fetch the current maximum admin_id from the database
    max_admin_id = db.session.query(db.func.max(Admin.admin_id)).scalar() or 0
    new_admin_id = max_admin_id + 1  # Increment the admin_id

    # Create new user
    hashed_password = generate_password_hash(data['admin_password'])
    new_user = Admin(
        admin_id=new_admin_id,
        admin_name=data['admin_name'],
        admin_password=hashed_password,
        is_admin=data.get('is_admin', False),
        email=data.get('email'),
        phone_number=data.get('phone_number')
    )
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User created successfully", "admin_id": new_admin_id}), 201


@admins_bp.route('/login-admin', methods=['POST'])
def admin_login():
    """
    Login endpoint for admin users.
    """
    data = request.get_json()

    # Validate input
    if not all(data.get(field) for field in ['admin_name', 'admin_password']):
        return jsonify({"message": "Username and password are required"}), 400

    # Authenticate the user
    token = authenticate_user(data['admin_name'], data['admin_password'])
    if not token:
        return jsonify({"message": "Invalid username or password"}), 401

    # Retrieve the admin details for response
    admin = Admin.query.filter_by(admin_name=data['admin_name']).first()

    return jsonify({
        "message": "Admin Login successful",
        "admin_id": admin.admin_id,
        "is_admin": admin.is_admin,
        "access_token": token
    }), 200


@admins_bp.route('/get-all-admins', methods=['GET'])
def get_all_admins():
    admins = Admin.query.all()
    admins_list = [
        {
            "admin_id": admin.admin_id,
            "admin_name": admin.admin_name,
            "is_admin": admin.is_admin,
            "email": admin.email,
            "phone_number": admin.phone_number,
        }
        for admin in admins
    ]
    return jsonify(admins_list), 200


@admins_bp.route('/admin/protected', methods=['GET'])
@jwt_required()
def protected():
    """
    A protected route that requires a valid JWT to access.
    """
    current_user = get_jwt_identity()  # Get the identity from the JWT
    print(current_user)
    return jsonify({
        "message": "Access granted to protected route",
        "user": current_user
    }), 200
