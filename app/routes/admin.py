from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash
from app.db import get_db_connection
from app import limiter
from app.utils.otp_utils import generate_otp, send_otp_email
import re

admin_bp = Blueprint('admin', __name__)
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]{3,}@[a-zA-Z0-9.-]{3,}\.[a-zA-Z]{2,}$')

def is_admin():
    return 'user_id' in session and session.get('privilege') == 'admin'

@admin_bp.route('/admin')
@limiter.limit("100 per minute")
def admin():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if users exist
    cursor.execute('SELECT COUNT(*) FROM users')
    user_count = cursor.fetchone()[0]

    # If users exist, restrict access to logged-in admins only
    if user_count > 0:
        if 'user_id' not in session or session.get('privilege') != 'admin':
            return redirect(url_for('auth.login'))

    # Fetch all users for display
    cursor.execute('SELECT id, username, privilege, name FROM users')
    users = cursor.fetchall()

    # Sort by privilege
    privilege_order = {'admin': 0, 'store team': 1, 'view': 2}
    sorted_users = sorted(users, key=lambda u: privilege_order.get(u['privilege'], 99))

    return render_template(
        'admin.html',
        users=sorted_users,
    )

@admin_bp.route('/send_otp', methods=['POST'])
@limiter.limit("10 per minute")
def send_otp_route():
    name = request.form['name']
    email = request.form['email']
    privilege = request.form['privilege']
    otp = generate_otp()

    if not EMAIL_REGEX.match(email):
        flash("Invalid email format. Please enter a valid email address.", "error")
        return redirect(url_for('admin.admin'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM users')
    user_count = cursor.fetchone()[0]

    if user_count == 0:
        privilege = 'admin'

    # Allow anyone to send OTP if it's the first user
    if user_count > 0 and not is_admin():
        flash("Unauthorized action", "error")
        return redirect(url_for('auth.login'))

    if send_otp_email(email, otp):
        conn = get_db_connection()
        cursor = conn.cursor()

        # Save OTP
        cursor.execute('INSERT INTO otps (email, otp) VALUES (?, ?)', (email, otp))

        # Create user if not exists
        cursor.execute('SELECT id FROM users WHERE username = ?', (email,))
        if not cursor.fetchone():
            hashed_otp = generate_password_hash(otp)
            cursor.execute(
                'INSERT INTO users (username, password_hash, privilege, name) VALUES (?, ?, ?, ?)',
                (email, hashed_otp, privilege, name)
            )

        conn.commit()

        flash("OTP sent to user email.", "success")

        # If first user, redirect to login so they can finish setup
        if user_count == 0:
            return redirect(url_for('auth.login'))

    else:
        flash("Failed to send OTP.", "error")

    return redirect(url_for('admin.admin'))


@admin_bp.route('/update_users', methods=['POST'])
@limiter.limit("3 per minute")
def update_users():
    if not is_admin():
        flash("Unauthorized action", "error")
        return redirect(url_for('auth.dashboard'))

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT id, privilege FROM users')
    existing_users = cursor.fetchall()
    existing_map = {user['id']: user['privilege'] for user in existing_users}

    for user_id, old_priv in existing_map.items():
        new_priv = request.form.get(f"privilege_{user_id}")
        reset = request.form.get(f"reset_{user_id}")
        delete = request.form.get(f"delete_{user_id}")

        # Prevent demoting the last admin
        if new_priv and new_priv != old_priv and old_priv == 'admin':
            cursor.execute("SELECT COUNT(*) FROM users WHERE privilege = 'admin'")
            admin_count = cursor.fetchone()[0]
            if admin_count <= 1:
                flash("Cannot demote the last admin.", "error")
                continue

        # Privilege change
        if new_priv and new_priv != old_priv:
            cursor.execute('UPDATE users SET privilege = ? WHERE id = ?', (new_priv, user_id))
            flash(f"Privilege updated for user {user_id}", "success")

        # Password reset
        if reset:
            default_hash = generate_password_hash('password')
            cursor.execute(
                'UPDATE users SET password_hash = ?, requires_password_change = 1 WHERE id = ?',
                (default_hash, user_id)
            )
            flash(f"Password reset for user {user_id}", "success")

        # Deletion
        if delete:
            if old_priv == 'admin':
                cursor.execute("SELECT COUNT(*) FROM users WHERE privilege = 'admin'")
                admin_count = cursor.fetchone()[0]
                if admin_count <= 1:
                    flash("Cannot delete the last admin.", "error")
                    continue
            cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
            flash(f"Deleted user {user_id}", "success")

    conn.commit()
    return redirect(url_for('admin.admin'))