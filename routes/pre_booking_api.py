from flask import Blueprint, jsonify, request

from db.connection import db
from models.user import PreBooking, User, Product

from datetime import datetime

# Define the blueprint for pre-booking
pre_bookings_bp = Blueprint('pre_bookings_bp', __name__)


# Route to create a new pre-booking
@pre_bookings_bp.route('/add-pre-booking', methods=['POST'])
def create_pre_booking():
    try:
        data = request.get_json()

        # Validation for required fields
        if not all(field in data for field in ['user_id', 'product_id', 'expected_date']):
            return jsonify({"error": "Missing required fields: user_id, product_id, expected_date"}), 400

        user_id = data['user_id']
        product_id = data['product_id']
        expected_date = datetime.strptime(data['expected_date'], '%Y-%m-%d').date()  # Ensure correct date format

        # Validate that user exists
        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "User with the given ID does not exist"}), 404

        # Validate that product exists
        product = Product.query.get(product_id)
        if not product:
            return jsonify({"error": "Product with the given ID does not exist"}), 404

        # Create a new pre-booking record
        new_pre_booking = PreBooking(
            user_id=user_id,
            product_id=product_id,
            expected_date=expected_date
        )

        # Add to the database
        db.session.add(new_pre_booking)
        db.session.commit()

        return jsonify({
            "message": "Pre-booking created successfully",
            "pre_booking": {
                "pre_booking_id": new_pre_booking.pre_booking_id,
                "user_id": new_pre_booking.user_id,
                "product_id": new_pre_booking.product_id,
                "booking_date": new_pre_booking.booking_date,
                "expected_date": new_pre_booking.expected_date
            }
        }), 201

    except Exception as e:
        return jsonify({"error": "An error occurred while creating the pre-booking", "details": str(e)}), 500


# Route to get all pre-bookings (for admin or user)
@pre_bookings_bp.route('/get-pre-bookings', methods=['GET'])
def get_pre_bookings():
    try:
        pre_bookings = PreBooking.query.all()
        result = [
            {
                "pre_booking_id": pb.pre_booking_id,
                "user_id": pb.user_id,
                "product_id": pb.product_id,
                "booking_date": pb.booking_date,
                "expected_date": pb.expected_date
            }
            for pb in pre_bookings
        ]
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": "An error occurred while fetching pre-bookings", "details": str(e)}), 500


# Route to get pre-booking by ID
@pre_bookings_bp.route('/pre-booking/<int:id>', methods=['GET'])
def get_pre_booking(id):
    try:
        pre_booking = PreBooking.query.get_or_404(id)
        return jsonify({
            "pre_booking_id": pre_booking.pre_booking_id,
            "user_id": pre_booking.user_id,
            "product_id": pre_booking.product_id,
            "booking_date": pre_booking.booking_date,
            "expected_date": pre_booking.expected_date
        }), 200
    except Exception as e:
        return jsonify({"error": "An error occurred while fetching the pre-booking", "details": str(e)}), 500
