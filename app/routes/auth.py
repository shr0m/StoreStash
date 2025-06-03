from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.security import check_password_hash, generate_password_hash
from app.db import get_db_connection
from app.utils.otp_utils import verify_otp_and_update
import re
from app import limiter

auth_bp = Blueprint('auth', __name__)
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]{3,}@[a-zA-Z0-9.-]{3,}\.[a-zA-Z]{2,}$')
def is_logged():
    return 'user_id' in session


@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("100 per minute")
def login():
    if 'user_id' in session:
        session.clear()

    # If there are no users, redirect to admin setup
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM users')
    user_count = cursor.fetchone()[0]

    if user_count == 0:
        return redirect(url_for('admin.admin'))

    if request.method == 'POST':
        email = request.form['email'].strip()
        otp_or_password = request.form['otp'].strip()

        if not EMAIL_REGEX.match(email):
            flash("Invalid email format. Please enter a valid email address.", "error")
            return redirect(url_for('admin.admin'))

        cursor.execute(
            'SELECT id, username, password_hash, privilege, requires_password_change FROM users WHERE username = ?',
            (email,)
        )
        user = cursor.fetchone()

        if user and check_password_hash(user['password_hash'], otp_or_password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['privilege'] = user['privilege']


            if user['requires_password_change']:
                return redirect(url_for('auth.change_password'))
            return redirect(url_for('dashboard.dashboard'))

        # Try OTP
        if verify_otp_and_update(cursor, email, otp_or_password):
            cursor.execute('SELECT id, username, privilege, theme FROM users WHERE username = ?', (email,))
            user = cursor.fetchone()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['privilege'] = user['privilege']
            conn.commit()
            return redirect(url_for('auth.change_password'))

        flash('Invalid credentials', 'error')

    return render_template('login.html')
    

@auth_bp.route('/otp_login', methods=['POST'])
@limiter.limit("15 per minute")
def otp_login():
    email = request.form.get('email', '').strip()
    provided_password = request.form.get('otp', '').strip()  # OTP or password

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT id, username, password_hash, privilege, requires_password_change FROM users WHERE username = ?', (email,))
    user = cursor.fetchone()

    if not user:
        flash('Invalid credentials', 'error')
        return redirect(url_for('auth.login'))

    # Check password first
    if user['password_hash'] and check_password_hash(user['password_hash'], provided_password):
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['privilege'] = user['privilege']
        if user['requires_password_change']:
            return redirect(url_for('auth.change_password'))
        return redirect(url_for('dashboard.dashboard'))

    # Check OTP
    if verify_otp_and_update(cursor, email, provided_password):
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['privilege'] = user['privilege']

        # Update password_hash with hashed OTP, force password change
        hashed_otp = generate_password_hash(provided_password)
        cursor.execute('UPDATE users SET password_hash = ?, requires_password_change = 1 WHERE id = ?', (hashed_otp, user['id']))
        conn.commit()
        return redirect(url_for('auth.change_password'))

    flash('Invalid credentials', 'error')
    return redirect(url_for('auth.login'))

@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))

@auth_bp.route('/change_password', methods=['GET', 'POST'])
@limiter.limit("2 per week")
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash("New password and confirmation do not match.", "error")
            return redirect(url_for('auth.change_password'))

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash FROM users WHERE id = ?', (session['user_id'],))
        user = cursor.fetchone()

        if user is None:
            flash("User not found.", "error")
            return redirect(url_for('auth.change_password'))

        if not check_password_hash(user['password_hash'], current_password):
            flash("Current password is incorrect.", "error")
            return redirect(url_for('auth.change_password'))

        new_password_hashed = generate_password_hash(new_password)
        cursor.execute(
            'UPDATE users SET password_hash = ?, requires_password_change = 0 WHERE id = ?',
            (new_password_hashed, session['user_id'])
        )
        conn.commit()
        conn.close()

        flash("Password updated successfully!", "success")
        return redirect(url_for('dashboard.dashboard'))

    return render_template('change_password.html')