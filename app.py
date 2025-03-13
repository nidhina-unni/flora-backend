from flask import Flask
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from config import Config
from db.connection import init_db, db


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Set a secret key for JWT
    app.config['JWT_SECRET_KEY'] = 'a3f4c8d5e6b7a9d2c1e8f0b4a7d6e3c5f9a1b2c3d4e7f8a9b0c1d2e3f4g5h6i7'

    # Initialize JWTManager with Flask app
    jwt = JWTManager(app)

    init_db(app)

    Migrate(app, db)  # Initialize Flask-Migrate (no need to store in a variable)
    from routes.main import main_bp
    from routes.user_api import user_bp
    from routes.admin_api import admins_bp
    from routes.product_api import products_bp
    from routes.cart_api import cart_bp
    from routes.orders_api import orders_bp
    from routes.payment_api import payments_bp
    from routes.product_feedback_api import product_feedback_bp
    from routes.website_feedback_api import website_feedback_bp
    from routes.pre_booking_api import pre_bookings_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(admins_bp)
    app.register_blueprint(products_bp)
    app.register_blueprint(cart_bp)
    app.register_blueprint(orders_bp)
    app.register_blueprint(payments_bp)
    app.register_blueprint(product_feedback_bp)
    app.register_blueprint(website_feedback_bp)
    app.register_blueprint(pre_bookings_bp)

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
