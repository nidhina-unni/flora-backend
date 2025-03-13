from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash
from db.connection import db
from models.user import User

user_bp = Blueprint("user_bp", __name__)

@user_bp.route('/user-register', methods=['POST'])
def user_register():
    data = request.get_json()

    # Validate input
    if not all(data.get(field) for field in ['username', 'password', 'email', 'phone']):
        return jsonify({"message": "All fields are required"}), 400

    # Check for existing user
    if User.query.filter_by(username=data['username']).first() or User.query.filter_by(email=data['email']).first():
        return jsonify({"message": "Username or email already exists"}), 409

    # Create new user
    hashed_password = generate_password_hash(data['password'])
    new_user = User(
        username=data['username'],
        password=hashed_password,
        email=data['email'],
        phone=data['phone'],
        is_seller=data.get('is_seller', False)
    )
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User created successfully"}), 201