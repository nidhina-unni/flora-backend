from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, get_jwt
from werkzeug.security import generate_password_hash, check_password_hash
from db.connection import db
from models.user import User
from sqlalchemy.exc import SQLAlchemyError

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
        address=data['address'],
        is_seller=data.get('is_seller', False)
    )
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User created successfully"}), 201


@user_bp.route('/user-delete', methods=['DELETE'])
def user_delete():
    """
    Delete a user account without JWT authentication.
    The username must be provided in the request body.
    """
    try:
        data = request.get_json()

        # Ensure 'username' is provided in the request
        if not data or 'username' not in data:
            return jsonify({"message": "Username is required"}), 400

        username = data['username']

        # Find the user in the database
        user = User.query.filter(User.username.ilike(username.strip())).first()

        if not user:
            return jsonify({"message": "User not found"}), 404

        # Delete the user
        db.session.delete(user)
        db.session.commit()

        return jsonify({"message": "User account deleted successfully"}), 200

    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({"message": "An error occurred", "error": str(e)}), 500


@user_bp.route('/update-address', methods=['PUT'])
@jwt_required()
def update_address():
    """
    Update the address of an authenticated user.
    """
    try:
        data = request.get_json()

        if not data or 'address' not in data:
            return jsonify({"message": "New address is required"}), 400

        # Get user ID from JWT identity and convert it to an integer
        user_id = int(get_jwt_identity())

        # Get username from additional JWT claims
        claims = get_jwt()
        username = claims.get("username", None)

        # Ensure valid user identity
        if not isinstance(user_id, int) or not username:
            return jsonify({"message": "Invalid user identity."}), 400

        # Fetch the user from the database
        user = User.query.filter_by(username=username).first()

        if not user:
            return jsonify({"message": "User not found"}), 404

        # Update only the address field
        user.address = data['address']
        db.session.commit()

        return jsonify({"message": "Address updated successfully"}), 200

    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({"message": "An error occurred", "error": str(e)}), 500


@user_bp.route('/user-login', methods=['POST'])
def user_login():
    data = request.get_json()

    if not all(data.get(field) for field in ['username', 'password']):
        return jsonify({"message": "Username and password are required"}), 400

    user = User.query.filter_by(username=data['username']).first()

    if user and check_password_hash(user.password, data['password']):
        # Use `user_id` as identity and store `username` as additional claims
        access_token = create_access_token(
            identity=str(user.user_id),  # Must be a string/int
            additional_claims={"username": user.username}  # Store extra data
        )

        return jsonify({
            "message": "Login successful",
            "token": access_token
        }), 200

    return jsonify({"message": "Invalid username or password"}), 401


@user_bp.route('/get-allusers', methods=['GET'])
def get_all_users():
    """
    Get all registered users without authentication.
    """
    # Fetch all users from the database
    users = User.query.all()

    # Convert users to JSON format
    users_data = [{
        "user_id": user.user_id,
        "username": user.username,
        "email": user.email,
        "phone": user.phone,
        "address": user.address,
        "is_seller": user.is_seller
    } for user in users]

    return jsonify({"users": users_data}), 200
