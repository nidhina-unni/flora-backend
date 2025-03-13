# from flask import Flask
# from flask_migrate import Migrate
# from config import Config
# from db.connection import init_db, db
# from models import User
# from routes.main import main_bp
#
#
# def create_app():
#     app = Flask(__name__)
#     app.config.from_object(Config)
#     init_db(app)
#
#     # Initialize Flask-Migrate
#     migrate = Migrate(app, db)
#
#     app.register_blueprint(main_bp)
#     migrate.init_app(app, db)
#
#     return app
#
#
# if __name__ == "__main__":
#     app = create_app()
#     app.run(debug=True)


from flask import Flask
from flask_migrate import Migrate
from config import Config
from db.connection import init_db, db


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    init_db(app)

    Migrate(app, db)  # Initialize Flask-Migrate (no need to store in a variable)
    from routes.main import main_bp
    from routes.user_api import user_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(user_bp)


    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
