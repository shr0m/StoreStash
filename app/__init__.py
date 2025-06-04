import os
from flask import Flask, session
from dotenv import load_dotenv
from config import Config
from app.extensions import limiter
from app.db import get_supabase_client  # new function for Supabase client

def create_app():
    # Load environment variables
    load_dotenv(dotenv_path="../.env")

    # Template and static folder paths for Flask
    template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'SSClient', 'templates'))
    static_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'SSClient', 'static'))

    app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
    app.secret_key = os.getenv("FLASK_SECRET_KEY")
    app.config.from_object(Config)

    # Initialize shared limiter
    limiter.init_app(app)
    limiter.default_limits = ["200 per day", "50 per hour"]

    # Initialize Supabase client (just to ensure config is valid)
    get_supabase_client()

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

    # Context processor to inject theme from Supabase
    @app.context_processor
    def inject_theme():
        theme = 'light'
        if 'user_id' in session:
            try:
                supabase = get_supabase_client()
                response = supabase.table('users').select('theme').eq('id', session['user_id']).single().execute()
                data = response.data
                if data and 'theme' in data:
                    theme = data['theme']
            except Exception as e:
                print(f"Theme injection error (Supabase): {e}")
        return {'current_theme': theme}

    return app