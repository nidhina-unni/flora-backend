from flask import Blueprint, request, jsonify
from models.user import db, Feedback, User, Product
from datetime import datetime

product_feedback_bp = Blueprint('feedback', __name__)


@product_feedback_bp.route('/feedback', methods=['POST'])
def add_feedback():
    data = request.get_json()
    try:
        # Validate request data
        if not data or not data.get('user_id') or not data.get('product_id') or not data.get('feedback_text') or not data.get('rating'):
            return jsonify({"message": "Invalid request data"}), 400

        # Add new feedback
        feedback = Feedback(
            user_id=data['user_id'],
            product_id=data['product_id'],
            feedback_text=data['feedback_text'],
            rating=data['rating'],
            feedback_date=datetime.utcnow()
        )
        db.session.add(feedback)
        db.session.commit()

        return jsonify({"message": "Feedback submitted successfully", "feedback_id": feedback.feedback_id}), 201
    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 500


@product_feedback_bp.route('/feedback/product/<int:product_id>', methods=['GET'])
def get_product_feedback(product_id):
    try:
        feedbacks = Feedback.query.filter_by(product_id=product_id).all()
        if not feedbacks:
            return jsonify({"message": "No feedback found for the product"}), 404

        result = []
        for feedback in feedbacks:
            user = User.query.get(feedback.user_id)
            result.append({
                "feedback_id": feedback.feedback_id,
                "user_id": feedback.user_id,
                "user_name": user.username if user else "Unknown",
                "feedback_text": feedback.feedback_text,
                "feedback_date": feedback.feedback_date.isoformat(),
                "rating": feedback.rating
            })

        return jsonify(result), 200
    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 500


@product_feedback_bp.route('/feedback/<int:feedback_id>', methods=['PUT'])
def update_feedback(feedback_id):
    data = request.get_json()
    try:
        feedback = Feedback.query.get(feedback_id)
        if not feedback:
            return jsonify({"message": "Feedback not found"}), 404

        # Update feedback attributes
        feedback.feedback_text = data.get('feedback_text', feedback.feedback_text)
        feedback.rating = data.get('rating', feedback.rating)
        db.session.commit()

        return jsonify({"message": "Feedback updated successfully"}), 200
    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 500


@product_feedback_bp.route('/feedback/<int:feedback_id>', methods=['DELETE'])
def delete_feedback(feedback_id):
    try:
        feedback = Feedback.query.get(feedback_id)
        if not feedback:
            return jsonify({"message": "Feedback not found"}), 404

        db.session.delete(feedback)
        db.session.commit()

        return jsonify({"message": "Feedback deleted successfully"}), 200
    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 500
