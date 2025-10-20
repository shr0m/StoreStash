import os
from flask import Flask, session, redirect, url_for
from dotenv import load_dotenv
from config import Config
from app.extensions import limiter, RateLimitExceeded
from app.db import get_supabase_client
from app.bootstrap import ensure_root_user

def create_app():
    # Load environment variables
    load_dotenv(dotenv_path="../.env")

    # Template and static folder paths for Flask
    template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'templates'))
    static_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'static'))

    app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
    app.secret_key = os.getenv("FLASK_SECRET_KEY")
    app.config.from_object(Config)

    # Initialize shared limiter
    limiter.init_app(app)
    limiter.default_limits = ["200 per day", "50 per hour"]

    # Initialize Supabase client (just to ensure config is valid)
    get_supabase_client()

    ensure_root_user()

    # Register blueprints
    from .routes.auth import auth_bp
    from .routes.dashboard import dashboard_bp
    from .routes.admin import admin_bp
    from .routes.support import support_bp
    from .routes.settings import settings_bp
    from .routes.people import people_bp
    from .routes.home import home_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(support_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(people_bp)
    app.register_blueprint(home_bp)

    # Context processor to inject theme from Supabase
    @app.context_processor
    def inject_theme():
        theme = 'light'
        if 'user_id' in session:
            try:
                supabase = get_supabase_client()
                auth_resp = supabase.auth.admin.get_user_by_id(session['user_id'])
                auth_user = getattr(auth_resp, "user", None) or (auth_resp.get("user") if isinstance(auth_resp, dict) else None)
                metadata = getattr(auth_user, "user_metadata", {}) or {}
                theme = metadata.get('theme', 'light')
            except Exception as e:
                print(f"Theme injection error (Supabase): {e}")
        return {'current_theme': theme}

    return app