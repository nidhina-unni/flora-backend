from db.connection import db
from datetime import datetime


class User(db.Model):
    __tablename__ = 'users'  # Table name in the database
    user_id = db.Column(db.Integer, primary_key=True)  # Primary key column
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    is_seller = db.Column(db.Boolean, default=False)

    # Define the relationship to Feedbacks
    feedbacks = db.relationship('Feedback', back_populates='user')
    website_feedbacks = db.relationship('WebsiteFeedback', back_populates='user', lazy='dynamic')

    # You can add additional relationships or properties if necessary

    def __repr__(self):
        return f"<User {self.username}>"


class Product(db.Model):
    __tablename__ = 'products'
    product_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    seller_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    seller = db.relationship('User', backref='products')


class PreBooking(db.Model):
    __tablename__ = 'pre_bookings'
    pre_booking_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.product_id'), nullable=False)
    booking_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expected_date = db.Column(db.Date, nullable=False)
    user = db.relationship('User', backref='pre_bookings')
    product = db.relationship('Product', backref='pre_bookings')


class Order(db.Model):
    __tablename__ = 'orders'
    order_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    order_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    total_price = db.Column(db.Numeric, nullable=False)
    shipping_address = db.Column(db.Text, nullable=False)
    status = db.Column(
        db.Enum('Pending', 'Shipped', 'Delivered', 'Cancelled', name='order_status_enum', create_type=False),
        nullable=False
    )
    user = db.relationship('User', backref='orders')


class CartItem(db.Model):
    __tablename__ = 'cart_items'
    cart_item_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.product_id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    user = db.relationship('User', backref='cart_items')
    product = db.relationship('Product', backref='cart_items')


class Feedback(db.Model):
    __tablename__ = 'feedback'
    feedback_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.product_id'), nullable=False)
    feedback_text = db.Column(db.Text, nullable=False)
    feedback_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    user = db.relationship('User', back_populates='feedbacks')
    product = db.relationship('Product', backref='feedback')


class WebsiteFeedback(db.Model):
    __tablename__ = 'website_feedback'
    feedback_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=True)
    feedback_text = db.Column(db.Text, nullable=False)
    feedback_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    rating = db.Column(db.Integer, nullable=False)  # 1 to 5 scale
    user = db.relationship('User', back_populates='website_feedbacks')


class Payment(db.Model):
    __tablename__ = 'payments'
    payment_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.order_id'), nullable=False)
    amount = db.Column(db.Numeric, nullable=False)
    payment_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    status = db.Column(db.Enum('Pending', 'Completed', 'Failed', name='payment_status_enum'), nullable=False)
    user = db.relationship('User', backref='payments')
    order = db.relationship('Order', backref='payments')


class Admin(db.Model):
    __tablename__ = 'admins'
    admin_id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # Primary key column
    admin_name = db.Column(db.String(80), unique=True, nullable=False)
    admin_password = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    email = db.Column(db.String(120), nullable=True)  # New field for email
    phone_number = db.Column(db.String(15), nullable=True)  # New field for phone number
