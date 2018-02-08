from flask import Flask
from flask_cors import CORS

from app.auth.controllers import auth as auth_module, init_jwt

# Define the WSGI application object

app = Flask(__name__)

def setup_app(app):
    CORS(app)

    # Configurations
    app.config.from_object('config')

    # Sample HTTP error handling
    @app.errorhandler(404)
    def not_found(error):
        return 'Not found', 404

    # Register blueprint(s)
    app.register_blueprint(auth_module)
    init_jwt(app)

