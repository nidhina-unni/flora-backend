import json

from flask import Blueprint, request, jsonify

from db.connection import db
from models.user import Payment, Order
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from datetime import datetime
from sqlalchemy.exc import SQLAlchemyError

payments_bp = Blueprint('payments', __name__)


@payments_bp.route('/payments', methods=['POST'])
@jwt_required()
def create_payment():
    """
    Create a new payment.
    Authenticated users can make a payment for an order.
    """
    try:
        data = request.get_json()

        # Validate input data
        order_id = data.get('order_id')
        amount = data.get('amount')

        if not order_id or not amount:
            return jsonify({"message": "Order ID and amount are required."}), 400

        # Get user ID from JWT identity and convert it back to an integer
        user_id = int(get_jwt_identity())  # Convert back to integer

        # Get username from additional claims
        claims = get_jwt()
        username = claims.get("username", None)

        print(f"User ID: {user_id}, Username: {username}")  # Debugging print

        # Ensure user_id is valid
        if not isinstance(user_id, int) or not username:
            return jsonify({"message": "Invalid user identity."}), 400

        # Validate that the order exists and belongs to the user
        # order = Order.query.filter_by(order_id=order_id, user_id=user_id).first()
        order = Order.query.get_or_404(order_id)
        if not order:
            return jsonify({"message": "Order not found or unauthorized"}), 404

        # Create a new payment record
        payment = Payment(
            user_id=user_id,
            order_id=order_id,
            amount=amount,
            payment_date=datetime.utcnow(),
            status='Pending'
        )
        db.session.add(payment)
        db.session.commit()

        return jsonify({
            "message": "Payment initiated successfully",
            "payment_id": payment.payment_id,
            "status": payment.status
        }), 201

    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({"message": "An error occurred", "error": str(e)}), 500


# Get all payments
@payments_bp.route('/get-all-payments', methods=['GET'])
@jwt_required()
def get_all_payments():
    """
    Get all payments for the authenticated user.
    """
    try:
        # Get the current user's identity from the JWT
        current_user = get_jwt_identity()

        # Parse user identity if it is a JSON string
        if isinstance(current_user, str):
            import json
            try:
                current_user = json.loads(current_user)
            except json.JSONDecodeError:
                return jsonify({"message": "Failed to decode user identity."}), 400

        # Ensure the identity is valid and extract user_id
        if not isinstance(current_user, dict) or 'id' not in current_user:
            return jsonify({"message": "Invalid token data", "error": "Invalid identity format"}), 401

        user_id = current_user['id']

        # Fetch all payments for the user
        payments = Payment.query.filter_by(user_id=user_id).all()

        # Format the result
        result = [{
            "payment_id": payment.payment_id,
            "order_id": payment.order_id,
            "amount": float(payment.amount),
            "payment_date": payment.payment_date.isoformat() if payment.payment_date else None,
            "status": payment.status
        } for payment in payments]

        return jsonify(result), 200

    except Exception as e:
        return jsonify({"message": "An error occurred while fetching payments", "error": str(e)}), 500


# Get payment details by ID
@payments_bp.route('/payments/<int:payment_id>', methods=['GET'])
@jwt_required()
def get_payment_by_id(payment_id):
    """
    Get payment details by payment ID.
    """
    try:
        # Get the current user's identity from the JWT
        current_user = get_jwt_identity()

        # Parse user identity if it is a JSON string
        if isinstance(current_user, str):
            import json
            try:
                current_user = json.loads(current_user)
            except json.JSONDecodeError:
                return jsonify({"message": "Failed to decode user identity."}), 400

        # Ensure the identity is valid and extract user_id
        if not isinstance(current_user, dict) or 'id' not in current_user:
            return jsonify({"message": "Invalid token data or unauthorized access."}), 403

        user_id = current_user['id']

        # Fetch the payment and validate ownership
        payment = Payment.query.filter_by(payment_id=payment_id, user_id=user_id).first()
        if not payment:
            return jsonify({"message": "Payment not found or unauthorized."}), 404

        # Prepare the result
        result = {
            "payment_id": payment.payment_id,
            "order_id": payment.order_id,
            "amount": float(payment.amount),
            "payment_date": payment.payment_date.isoformat() if payment.payment_date else None,
            "status": payment.status
        }

        return jsonify(result), 200

    except Exception as e:
        return jsonify({"message": "An error occurred while fetching payment details", "error": str(e)}), 500


# Update payment status
@payments_bp.route('/payments/<int:payment_id>', methods=['PUT'])
@jwt_required()
def update_payment_status(payment_id):
    """
    Update the status of a payment.
    Only admins or authorized payment processors should access this endpoint.
    """
    try:
        # Get the current user's identity
        current_user = get_jwt_identity()

        # Parse user identity if it is a JSON string
        if isinstance(current_user, str):
            import json
            try:
                current_user = json.loads(current_user)
            except json.JSONDecodeError:
                return jsonify({"message": "Failed to decode user identity."}), 400

        # Validate user role (e.g., only admin can update payment status)
        if not isinstance(current_user, dict) or not current_user.get('is_admin', False):
            return jsonify({"message": "Unauthorized access. Admin privileges required."}), 403

        # Validate input
        data = request.get_json()
        status = data.get('status')
        if status not in ['Pending', 'Completed', 'Failed']:
            return jsonify({"message": "Invalid status. Choose from 'Pending', 'Completed', 'Failed'."}), 400

        # Get the payment record
        payment = Payment.query.get(payment_id)
        if not payment:
            return jsonify({"message": "Payment not found"}), 404

        # Update the payment status
        payment.status = status
        db.session.commit()

        return jsonify({
            "message": "Payment status updated successfully",
            "payment_id": payment.payment_id,
            "new_status": payment.status
        }), 200

    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({"message": "A database error occurred", "error": str(e)}), 500
    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 500


@payments_bp.route('/payments/<int:payment_id>', methods=['DELETE'])
@jwt_required()
def delete_payment(payment_id):
    """
    Delete a payment record.
    Only admins or the user who initiated the payment can delete it.
    """
    try:
        # Get the current user's identity
        current_user = get_jwt_identity()

        # Parse user identity if it is a JSON string
        if isinstance(current_user, str):
            try:
                current_user = json.loads(current_user)
            except json.JSONDecodeError:
                return jsonify({"message": "Invalid token data format"}), 401

        # Check if the identity is a dictionary
        if not isinstance(current_user, dict):
            return jsonify({"message": "Invalid token data"}), 401

        user_id = current_user.get('id')
        is_admin = current_user.get('is_admin', False)

        if not user_id:
            return jsonify({"message": "User ID not found in token data"}), 401

        # Fetch the payment record
        payment = Payment.query.get(payment_id)
        if not payment:
            return jsonify({"message": "Payment not found"}), 404

        # Check if the user is the owner or an admin
        if not is_admin and payment.user_id != user_id:
            return jsonify({"message": "Unauthorized to delete this payment"}), 403

        # Delete the payment
        db.session.delete(payment)
        db.session.commit()

        return jsonify({"message": "Payment deleted successfully"}), 200

    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({"message": "An error occurred", "error": str(e)}), 500

    except Exception as e:
        return jsonify({"message": "An unexpected error occurred", "error": str(e)}), 500

