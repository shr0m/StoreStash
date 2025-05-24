import os
from flask import Flask
from dotenv import load_dotenv
from config import Config
from app.db import get_db_connection

def create_app():
    load_dotenv(dotenv_path="../SSServer/.env")

    template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'SSClient', 'templates'))
    static_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'SSClient', 'static'))

    app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
    app.secret_key = os.getenv("FLASK_SECRET_KEY")
    app.config.from_object(Config)

    from .routes.auth import auth_bp
    from .routes.dashboard import dashboard_bp
    from .routes.admin import admin_bp
    from .routes.support import support_bp
    from .routes.settings import settings_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(support_bp)
    app.register_blueprint(settings_bp)

    return app