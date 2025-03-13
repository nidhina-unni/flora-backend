from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash
from db.connection import db
from models.user import Product, User

products_bp = Blueprint("products_bp", __name__)


@products_bp.route('/get-all-products', methods=['GET'])
def get_products():
    try:
        products = Product.query.all()
        return jsonify([
            {
                "id": p.product_id,
                "name": p.name,
                "price": p.price,
                "stock": p.stock,
                "category": p.category,
                "description": p.description,
                "seller_id": p.seller_id
            }
            for p in products
        ]), 200
    except Exception as e:
        return jsonify({"error": "An error occurred while fetching products", "details": str(e)}), 500


# ---------------------------------------------------------------------------------------------------------------

# Fetch a single product by ID
@products_bp.route('/get-by-id/<int:id>', methods=['GET'])
def get_product(id):
    try:
        product = Product.query.get_or_404(id)
        return jsonify({
            "id": product.product_id,
            "name": product.name,
            "price": product.price,
            "stock": product.stock,
            "category": product.category,
            "description": product.description,
            "seller_id": product.seller_id
        }), 200
    except Exception as e:
        return jsonify({"error": "An error occurred while fetching the product", "details": str(e)}), 500


# --------------------------------------------------------------------------------------------------------------

# Add a new product
@products_bp.route('/add-product', methods=['POST'])
def add_product():
    try:
        # Parse and validate the JSON data
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid input, no data provided"}), 400

        # Extract the data fields
        name = data.get("name")
        price = data.get("price")
        stock = data.get("stock")
        category = data.get("category")
        description = data.get("description")
        seller_id = data.get("seller_id")

        # Validate input fields
        if not name or not isinstance(price, (int, float)) or not isinstance(stock, int):
            return jsonify({
                "error": "Invalid input. 'name' (string), 'price' (numeric), and 'stock' (integer) are required."
            }), 400

        if not category or not isinstance(category, str):
            return jsonify({"error": "'category' (string) is required"}), 400

        # Ensure the seller exists in the 'users' table
        seller = User.query.get(seller_id)
        if not seller:
            return jsonify({"error": "Seller with the given ID does not exist."}), 404

        # Create a new product instance
        new_product = Product(
            name=name,
            price=price,
            stock=stock,
            category=category,
            description=description,
            seller_id=seller_id
        )

        # Add to the database
        db.session.add(new_product)
        db.session.commit()

        # Return the product details without the product_id in the request body
        return jsonify({
            "message": "Product added successfully",
            "product": {
                "id": new_product.product_id,  # The product_id will be auto-generated
                "name": new_product.name,
                "price": new_product.price,
                "stock": new_product.stock,
                "category": new_product.category,
                "description": new_product.description,
                "seller_id": new_product.seller_id
            }
        }), 201

    except Exception as e:
        return jsonify({"error": "An error occurred while adding the product", "details": str(e)}), 500
