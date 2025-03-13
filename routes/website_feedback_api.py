import json
from flask import Blueprint, request, jsonify
from db.connection import db
from models.user import WebsiteFeedback
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime
from sqlalchemy.exc import SQLAlchemyError

website_feedback_bp = Blueprint('website_feedback', __name__)


# Add website feedback
@website_feedback_bp.route('/website-feedback', methods=['POST'])
@jwt_required(optional=True)
def add_website_feedback():
    """
    Submit website feedback.
    Authenticated users can include their user ID, while anonymous users can omit it.
    """
    try:
        data = request.get_json()

        # Validate input
        feedback_text = data.get('feedback_text')
        rating = data.get('rating')

        if not feedback_text or not rating or not (1 <= rating <= 5):
            return jsonify({"message": "Feedback text and a valid rating (1-5) are required."}), 400

        user_id = None
        if get_jwt_identity():
            user_id = get_jwt_identity()

        # Create new feedback
        feedback = WebsiteFeedback(
            user_id=user_id,
            feedback_text=feedback_text,
            rating=rating,
            feedback_date=datetime.utcnow()
        )
        db.session.add(feedback)
        db.session.commit()

        return jsonify({"message": "Feedback submitted successfully", "feedback_id": feedback.feedback_id}), 201

    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 500


# Get all website feedback
@website_feedback_bp.route('/website-feedback', methods=['GET'])
def get_all_website_feedback():
    """
    Retrieve all website feedback.
    """
    try:
        feedbacks = WebsiteFeedback.query.all()
        result = []

        for feedback in feedbacks:
            user = feedback.user  # Get the associated user, if any
            result.append({
                "feedback_id": feedback.feedback_id,
                "user_id": feedback.user_id,
                "user_name": user.username if user else "Anonymous",
                "feedback_text": feedback.feedback_text,
                "feedback_date": feedback.feedback_date.isoformat(),
                "rating": feedback.rating
            })

        return jsonify(result), 200

    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 500


# Get website feedback by ID
@website_feedback_bp.route('/website-feedback/<int:feedback_id>', methods=['GET'])
def get_website_feedback(feedback_id):
    """
    Retrieve a specific feedback entry by ID.
    """
    try:
        feedback = WebsiteFeedback.query.get(feedback_id)

        if not feedback:
            return jsonify({"message": "Feedback not found"}), 404

        user = feedback.user  # Get the associated user, if any
        result = {
            "feedback_id": feedback.feedback_id,
            "user_id": feedback.user_id,
            "user_name": user.username if user else "Anonymous",
            "feedback_text": feedback.feedback_text,
            "feedback_date": feedback.feedback_date.isoformat(),
            "rating": feedback.rating
        }

        return jsonify(result), 200

    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 500


@website_feedback_bp.route('/website-feedback/<int:feedback_id>', methods=['DELETE'])
@jwt_required()
def delete_website_feedback(feedback_id):
    """
    Delete a specific feedback entry by ID.
    Only an admin or the user who submitted the feedback can delete it.
    """
    try:
        # Get the feedback entry
        feedback = WebsiteFeedback.query.get(feedback_id)

        if not feedback:
            return jsonify({"message": "Feedback not found"}), 404

        # Get the current user's identity from the JWT
        current_user = get_jwt_identity()

        # Parse user identity if it's a string
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

        # Check if the user is the feedback owner or an admin
        if feedback.user_id != user_id and not is_admin:
            return jsonify({"message": "Unauthorized to delete this feedback"}), 403

        # Delete the feedback entry
        db.session.delete(feedback)
        db.session.commit()

        return jsonify({"message": "Feedback deleted successfully"}), 200

    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({"message": "An error occurred", "error": str(e)}), 500

    except Exception as e:
        return jsonify({"message": "An unexpected error occurred", "error": str(e)}), 500
