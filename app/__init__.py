import os
from flask import Flask, session
from dotenv import load_dotenv
from config import Config
from app.db import get_db_connection, close_db_connection

def create_app():
    load_dotenv(dotenv_path="../SSServer/.env")

    template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'SSClient', 'templates'))
    static_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'SSClient', 'static'))

    app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
    app.secret_key = os.getenv("FLASK_SECRET_KEY")
    app.config.from_object(Config)
    app.teardown_appcontext(close_db_connection)

    # Register blueprints
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
    
    @app.context_processor
    def inject_theme():
        theme = 'light'
        if 'user_id' in session:
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT theme FROM users WHERE id = ?", (session['user_id'],))
                result = cursor.fetchone()
                if result:
                    theme = result['theme']
            except Exception as e:
                print(f"Theme injection error: {e}")
        return {'current_theme': theme}

    return app