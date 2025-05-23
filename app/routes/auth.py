from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.security import check_password_hash, generate_password_hash
from app.db import get_db_connection
from app.utils.otp_utils import verify_otp_and_update, send_otp_email

auth_bp = Blueprint('auth', __name__)
def is_logged():
    return 'user_id' in session


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        session.clear()

    # If there are no users, redirect to admin setup
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM users')
    user_count = cursor.fetchone()[0]
    conn.close()

    if user_count == 0:
        return redirect(url_for('admin.admin'))

    if request.method == 'POST':
        email = request.form['email'].strip()
        otp_or_password = request.form['otp'].strip()

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT id, username, password_hash, privilege, requires_password_change FROM users WHERE username = ?', (email,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password_hash'], otp_or_password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['privilege'] = user['privilege']
            conn.close()
            if user['requires_password_change']:
                return redirect(url_for('auth.change_password'))
            return redirect(url_for('dashboard.dashboard'))

        # Try OTP
        if verify_otp_and_update(cursor, email, otp_or_password):
            cursor.execute('SELECT id, username, privilege FROM users WHERE username = ?', (email,))
            user = cursor.fetchone()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['privilege'] = user['privilege']
            conn.commit()
            conn.close()
            return redirect(url_for('auth.change_password'))

        flash('Invalid credentials', 'error')
        conn.close()

    return render_template('login.html')
    

@auth_bp.route('/otp_login', methods=['POST'])
def otp_login():
    email = request.form.get('email', '').strip()
    provided_password = request.form.get('otp', '').strip()  # OTP or password

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT id, username, password_hash, privilege, requires_password_change FROM users WHERE username = ?', (email,))
    user = cursor.fetchone()

    if not user:
        flash('Invalid credentials', 'error')
        conn.close()
        return redirect(url_for('auth.login'))

    # Check password first
    if user['password_hash'] and check_password_hash(user['password_hash'], provided_password):
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['privilege'] = user['privilege']
        conn.close()
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
        conn.close()
        return redirect(url_for('auth.change_password'))

    flash('Invalid credentials', 'error')
    conn.close()
    return redirect(url_for('auth.login'))

@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))

@auth_bp.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        new_password = generate_password_hash(request.form['new_password'])
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE users SET password_hash = ?, requires_password_change = 0 WHERE id = ?',
            (new_password, session['user_id'])
        )
        conn.commit()
        conn.close()
        flash("Password updated successfully!", "success")
        return redirect(url_for('dashboard.dashboard'))

    return render_template('change_password.html')