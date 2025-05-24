from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from app.db import get_db_connection

settings_bp = Blueprint('settings', __name__)

@settings_bp.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    
    return render_template('settings.html', settings=settings)