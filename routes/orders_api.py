from flask import Blueprint, jsonify, request
from models.user import Order, User
from app import db
from datetime import datetime

# Define the blueprint for orders
orders_bp = Blueprint('orders', __name__)


# Create a new order
@orders_bp.route('/orders', methods=['POST'])
def create_order():
    try:
        data = request.get_json()

        # Validate required fields
        if not all(field in data for field in ['user_id', 'total_price', 'shipping_address', 'status']):
            return jsonify({"error": "Missing required fields: user_id, total_price, shipping_address, status"}), 400

        user_id = data['user_id']
        total_price = data['total_price']
        shipping_address = data['shipping_address']
        status = data['status']

        # Validate user existence
        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "User with the given ID does not exist"}), 404

        # Validate status
        if status not in ['Pending', 'Shipped', 'Delivered', 'Cancelled']:
            return jsonify(
                {"error": "Invalid status. Must be one of: 'Pending', 'Shipped', 'Delivered', 'Cancelled'"}), 400

        # Create a new order
        new_order = Order(
            user_id=user_id,
            total_price=total_price,
            shipping_address=shipping_address,
            status=status
        )

        # Add to the database
        db.session.add(new_order)
        db.session.commit()

        return jsonify({
            "message": "Order created successfully",
            "order": {
                "order_id": new_order.order_id,
                "user_id": new_order.user_id,
                "order_date": new_order.order_date,
                "total_price": str(new_order.total_price),
                "shipping_address": new_order.shipping_address,
                "status": new_order.status
            }
        }), 201

    except Exception as e:
        return jsonify({"error": "An error occurred while creating the order", "details": str(e)}), 500


# Fetch all orders
@orders_bp.route('/get-all-orders', methods=['GET'])
def get_orders():
    try:
        orders = Order.query.all()
        return jsonify([
            {
                "order_id": order.order_id,
                "user_id": order.user_id,
                "order_date": order.order_date,
                "total_price": str(order.total_price),
                "shipping_address": order.shipping_address,
                "status": order.status
            }
            for order in orders
        ]), 200
    except Exception as e:
        return jsonify({"error": "An error occurred while fetching orders", "details": str(e)}), 500


# Fetch a single order by ID
@orders_bp.route('/orders/<int:order_id>', methods=['GET'])
def get_order(order_id):
    try:
        order = Order.query.get_or_404(order_id)
        return jsonify({
            "order_id": order.order_id,
            "user_id": order.user_id,
            "order_date": order.order_date,
            "total_price": str(order.total_price),
            "shipping_address": order.shipping_address,
            "status": order.status
        }), 200
    except Exception as e:
        return jsonify({"error": "An error occurred while fetching the order", "details": str(e)}), 500


# Update an order status
@orders_bp.route('/orders/<int:order_id>', methods=['PUT'])
def update_order_status(order_id):
    try:
        data = request.get_json()
        new_status = data.get('status')

        if not new_status or new_status not in ['Pending', 'Shipped', 'Delivered', 'Cancelled']:
            return jsonify({
                "error": "Invalid or missing status. Must be one of: 'Pending', 'Shipped', 'Delivered', 'Cancelled'"}), 400

        order = Order.query.get_or_404(order_id)
        order.status = new_status

        db.session.commit()

        return jsonify({"message": "Order status updated successfully", "order_id": order.order_id,
                        "new_status": order.status}), 200

    except Exception as e:
        return jsonify({"error": "An error occurred while updating the order", "details": str(e)}), 500


# Delete an order
@orders_bp.route('/orders/<int:order_id>', methods=['DELETE'])
def delete_order(order_id):
    try:
        order = Order.query.get_or_404(order_id)
        db.session.delete(order)
        db.session.commit()

        return jsonify({"message": "Order deleted successfully", "order_id": order_id}), 200

    except Exception as e:
        return jsonify({"error": "An error occurred while deleting the order", "details": str(e)}), 500
