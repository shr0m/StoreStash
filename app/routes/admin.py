from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash
from app.db import get_db_connection
from app.utils.otp_utils import generate_otp, send_otp_email
import re

admin_bp = Blueprint('admin', __name__)
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]{3,}@[a-zA-Z0-9.-]{3,}\.[a-zA-Z]{2,}$')

def is_admin():
    return 'user_id' in session and session.get('privilege') == 'admin'

@admin_bp.route('/admin')
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
    cursor.execute('SELECT id, username, privilege FROM users')
    users = cursor.fetchall()

    # Sort by privilege
    privilege_order = {'admin': 0, 'store team': 1, 'view': 2}
    sorted_users = sorted(users, key=lambda u: privilege_order.get(u['privilege'], 99))

    return render_template(
        'admin.html',
        users=sorted_users,
    )

@admin_bp.route('/send_otp', methods=['POST'])
def send_otp_route():
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
                'INSERT INTO users (username, password_hash, privilege) VALUES (?, ?, ?)',
                (email, hashed_otp, privilege)
            )

        conn.commit()

        flash("OTP sent to user email.", "success")

        # If first user, redirect to login so they can finish setup
        if user_count == 0:
            return redirect(url_for('auth.login'))

    else:
        flash("Failed to send OTP.", "error")

    return redirect(url_for('admin.admin'))

@admin_bp.route('/reset_password/<int:user_id>', methods=['POST'])
def reset_password(user_id):
    if not is_admin():
        flash("Unauthorized action", "error")
        return redirect(url_for('auth.dashboard'))

    conn = get_db_connection()
    cursor = conn.cursor()
    default_hash = generate_password_hash('password')
    cursor.execute('UPDATE users SET password_hash = ?, requires_password_change = 1 WHERE id = ?', (default_hash, user_id))
    conn.commit()
    flash("Password reset.", "success")
    return redirect(url_for('admin.admin'))

@admin_bp.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if not is_admin():
        flash("Unauthorized action", "error")
        return redirect(url_for('auth.dashboard'))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Check the privilege of the user being deleted
    cursor.execute('SELECT privilege FROM users WHERE id = ?', (user_id,))
    user_to_delete = cursor.fetchone()

    if not user_to_delete:
        flash("User not found.", "error")
        return redirect(url_for('admin.admin'))

    # Prevent deletion if this is the only admin
    
    if user_to_delete['privilege'] == 'admin':
        cursor.execute("SELECT COUNT(*) FROM users WHERE privilege = 'admin'")
        admin_count = cursor.fetchone()[0]

        if admin_count <= 1:
            flash("One admin must exist.", "error")
            return redirect(url_for('admin.admin'))

    # Proceed with deletion
    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()

    flash("User deleted.", "success")
    return redirect(url_for('admin.admin'))