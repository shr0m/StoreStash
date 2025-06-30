from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash
from app.db import get_supabase_client
from app import limiter
from app.utils.otp_utils import generate_otp, send_otp_email
from app.utils.email_utils import send_reset_email 
import re

admin_bp = Blueprint('admin', __name__)
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]{3,}@[a-zA-Z0-9.-]{3,}\.[a-zA-Z]{2,}$')

def is_admin():
    return 'user_id' in session and session.get('privilege') == 'admin'

@admin_bp.route('/admin')
@limiter.limit("100 per minute")
def admin():
    supabase = get_supabase_client()

    # Check if users exist
    response = supabase.table('users').select('id').limit(1).execute()
    user_count = len(response.data)

    # If users exist, restrict access to logged-in admins only
    if user_count > 0:
        if not is_admin():
            return redirect(url_for('auth.login'))

    # Fetch all users for display
    users_resp = supabase.table('users').select('id, username, privilege, name').execute()
    users = users_resp.data or []

    # Sort by privilege
    privilege_order = {'admin': 0, 'edit': 1, 'view': 2}
    sorted_users = sorted(users, key=lambda u: privilege_order.get(u.get('privilege'), 99))

    return render_template('admin.html', users=sorted_users)


@admin_bp.route('/send_otp', methods=['POST'])
@limiter.limit("10 per minute")
def send_otp_route():
    name = request.form['name']
    email = request.form['email']
    privilege = request.form['privilege']
    otp = generate_otp()

    if not EMAIL_REGEX.match(email):
        flash("Invalid email format. Please enter a valid email address.", "danger")
        return redirect(url_for('admin.admin'))

    supabase = get_supabase_client()

    # Check user count
    user_count_resp = supabase.table('users').select('id').limit(1).execute()
    user_count = len(user_count_resp.data)

    if user_count == 0:
        privilege = 'admin'

    if user_count > 0 and not is_admin():
        flash("Unauthorized action", "danger")
        return redirect(url_for('auth.login'))

    if send_otp_email(email, otp):
        # Save OTP
        supabase.table('otps').insert({'email': email, 'otp': otp}).execute()

        # Check if user exists
        user_resp = supabase.table('users').select('id').eq('username', email).limit(1).execute()

        if not user_resp.data:
            hashed_otp = generate_password_hash(otp)
            supabase.table('users').insert({
                'username': email,
                'password_hash': hashed_otp,
                'privilege': privilege,
                'name': name
            }).execute()

        flash("OTP sent to user email.", "success")

        if user_count == 0:
            return redirect(url_for('auth.login'))
    else:
        flash("Failed to send OTP.", "danger")

    return redirect(url_for('admin.admin'))


@admin_bp.route('/update_users', methods=['POST'])
@limiter.limit("3 per minute")
def update_users():
    if not is_admin():
        flash("Unauthorized action", "danger")
        return redirect(url_for('dashboard.dashboard'))

    supabase = get_supabase_client()

    users_resp = supabase.table('users').select('id, privilege').execute()
    existing_users = users_resp.data or []
    existing_map = {user['id']: user['privilege'] for user in existing_users}

    for user_id, old_priv in existing_map.items():
        new_priv = request.form.get(f"privilege_{user_id}")
        reset = request.form.get(f"reset_{user_id}")
        delete = request.form.get(f"delete_{user_id}")

        # Prevent demoting the last admin
        if new_priv and new_priv != old_priv and old_priv == 'admin':
            admin_count_resp = supabase.table('users').select('id').eq('privilege', 'admin').execute()
            admin_count = len(admin_count_resp.data)
            if admin_count <= 1:
                flash("Cannot demote the last admin.", "danger")
                continue

        # Privilege change
        if new_priv and new_priv != old_priv:
            supabase.table('users').update({'privilege': new_priv}).eq('id', user_id).execute()
            flash(f"Privilege updated for user {user_id}", "success")

        # Password reset
        if reset:
            default_hash = generate_password_hash('password')
            supabase.table('users').update({
                'password_hash': default_hash,
                'requires_password_change': True
            }).eq('id', user_id).execute()

            response = supabase.table('users').select('username').eq('id', user_id).execute()
            email = response.data[0]['username']
            send_reset_email(email)
            flash(f"Password reset for user {user_id}", "success")

        # Deletion
        if delete:
            if old_priv == 'admin':
                admin_count_resp = supabase.table('users').select('id').eq('privilege', 'admin').execute()
                admin_count = len(admin_count_resp.data)
                if admin_count <= 1:
                    flash("Cannot delete the last admin.", "danger")
                    continue
            supabase.table('users').delete().eq('id', user_id).execute()
            flash(f"Deleted user {user_id}", "success")

    return redirect(url_for('admin.admin'))