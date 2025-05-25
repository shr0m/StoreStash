from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
from app.db import get_db_connection  # Your DB helper

settings_bp = Blueprint('settings', __name__)

@settings_bp.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    return render_template('settings.html')
