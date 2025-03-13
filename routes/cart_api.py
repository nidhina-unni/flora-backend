from flask import Blueprint, request, jsonify

from db.connection import db
from models.user import CartItem, Product


cart_bp = Blueprint('cart', __name__)


@cart_bp.route('/cart', methods=['POST'])
def add_to_cart():
    data = request.get_json()
    try:
        if not data or not data.get('user_id') or not data.get('product_id') or not data.get('quantity'):
            return jsonify({"message": "Invalid request data"}), 400

        cart_item = CartItem(
            user_id=data['user_id'],
            product_id=data['product_id'],
            quantity=data['quantity']
        )
        db.session.add(cart_item)
        db.session.commit()

        return jsonify({"message": "Item added to cart successfully", "cart_item_id": cart_item.cart_item_id}), 201
    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 500


@cart_bp.route('/cart/<int:user_id>', methods=['GET'])
def view_cart(user_id):
    try:
        cart_items = CartItem.query.filter_by(user_id=user_id).all()
        if not cart_items:
            return jsonify({"message": "No cart items found for the user"}), 404

        result = []
        for item in cart_items:
            product = Product.query.get(item.product_id)
            result.append({
                "cart_item_id": item.cart_item_id,
                "product_id": item.product_id,
                "product_name": product.name,
                "quantity": item.quantity,
                "price_per_unit": product.price,
                "total_price": product.price * item.quantity
            })

        return jsonify(result), 200
    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 500


@cart_bp.route('/cart/<int:cart_item_id>', methods=['PUT'])
def update_cart_item(cart_item_id):
    data = request.get_json()
    try:
        cart_item = CartItem.query.get(cart_item_id)
        if not cart_item:
            return jsonify({"message": "Cart item not found"}), 404

        cart_item.quantity = data.get('quantity', cart_item.quantity)
        db.session.commit()

        return jsonify({"message": "Cart item updated successfully"}), 200
    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 500


@cart_bp.route('/cart/<int:cart_item_id>', methods=['DELETE'])
def remove_cart_item(cart_item_id):
    try:
        cart_item = CartItem.query.get(cart_item_id)
        if not cart_item:
            return jsonify({"message": "Cart item not found"}), 404

        db.session.delete(cart_item)
        db.session.commit()

        return jsonify({"message": "Cart item removed successfully"}), 200
    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 500


@cart_bp.route('/cart/user/<int:user_id>', methods=['DELETE'])
def clear_cart(user_id):
    try:
        cart_items = CartItem.query.filter_by(user_id=user_id).all()
        if not cart_items:
            return jsonify({"message": "No cart items found for the user"}), 404

        for item in cart_items:
            db.session.delete(item)
        db.session.commit()

        return jsonify({"message": "Cart cleared successfully"}), 200
    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 500
