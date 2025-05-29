from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from app.db import get_db_connection
from app import limiter

settings_bp = Blueprint('settings', __name__)

@settings_bp.route('/settings', methods=['GET', 'POST'])
@limiter.limit("100 per minute")
def settings():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        new_theme = 'dark' if request.form.get('theme') == 'dark' else 'light'
        cursor.execute("UPDATE users SET theme = ? WHERE id = ?", (new_theme, user_id))
        conn.commit()
        flash("Theme updated successfully.", "success")
        return redirect(url_for('settings.settings'))

    cursor.execute("SELECT theme FROM users WHERE id = ?", (user_id,))
    current_theme = cursor.fetchone()

    return render_template('settings.html', current_theme=current_theme['theme'] if current_theme else 'light')

@settings_bp.route('/hard_reset')
@limiter.limit("1 per minute")
def hard_reset():
    return redirect("https://www.youtube.com/watch?v=dQw4w9WgXcQ")