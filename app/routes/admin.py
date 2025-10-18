from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash
from app.db import get_supabase_client
from app import limiter
from app.utils.otp_utils import generate_otp, send_otp_email, redirect_if_password_change_required
from app.utils.email_utils import send_reset_email
from datetime import datetime, timezone, timedelta
import re

admin_bp = Blueprint('admin', __name__)
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]{3,}@[a-zA-Z0-9.-]{3,}\.[a-zA-Z]{2,}$')

def is_admin():
    return 'user_id' in session and session.get('privilege') == 'admin'

@admin_bp.route('/admin')
@limiter.limit("100 per minute")
def admin():
    if not is_admin():
        return redirect(url_for('auth.login'))

    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    supabase = get_supabase_client()
    users_resp = supabase.table('users').select('id, username, privilege, name').execute()
    users = users_resp.data or []

    privilege_order = {'admin': 0, 'edit': 1, 'view': 2}
    sorted_users = sorted(users, key=lambda u: privilege_order.get(u.get('privilege'), 99))

    containers_resp = supabase.table('containers').select('name').execute()
    containers = containers_resp.data or []

    return render_template('admin.html', users=sorted_users, containers=containers)


@admin_bp.route('/invite_user', methods=['POST'])
@limiter.limit("10 per minute")
def invite_user():
    if not is_admin():
        flash("Unauthorized action.", "danger")
        return redirect(url_for('auth.login'))

    name = request.form['name']
    email = request.form['email']
    privilege = request.form['privilege']

    if not EMAIL_REGEX.match(email):
        flash("Invalid email format.", "danger")
        return redirect(url_for('admin.admin'))

    supabase = get_supabase_client()

    # If first user, make admin
    user_count_resp = supabase.table('users').select('id').limit(1).execute()
    if not (user_count_resp.data or []):
        privilege = 'admin'

    # Generate OTP and expiry (10 minutes by your original behaviour)
    otp = generate_otp()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

    try:
        # Create Supabase Auth user with OTP as temporary password
        # Use admin.create_user so we can set the initial password (service role required)
        create_resp = supabase.auth.admin.create_user({
            "email": email,
            "password": otp,
            "email_confirm": True
        })

        auth_user = getattr(create_resp, "user", None) or (create_resp.get("user") if isinstance(create_resp, dict) else None)
        if not auth_user:
            flash("Failed to create auth user.", "danger")
            return redirect(url_for('admin.admin'))

        # Insert metadata into your users table (id aligned with auth user's id)
        supabase.table('users').insert({
            'id': auth_user.id,
            'username': email,
            'privilege': privilege,
            'name': name,
            'requires_password_change': True,
            'otp_expires_at': expires_at.isoformat()  # store ISO timestamp in UTC
        }).execute()

        # Send OTP via your existing email util (this keeps the same UX as before)
        if not send_otp_email(email, otp):
            # If sending failed, remove created auth user + users row to avoid dangling account
            try:
                supabase.auth.admin.delete_user(auth_user.id)
            except Exception:
                pass
            supabase.table('users').delete().eq('id', auth_user.id).execute()
            flash("Failed to send OTP email.", "danger")
            return redirect(url_for('admin.admin'))

        flash(f"User invited; OTP sent to {email}", "success")

    except Exception as e:
        flash(f"Error adding user: {e}", "danger")

    return redirect(url_for('admin.admin'))


@admin_bp.route('/update_users', methods=['POST'])
@limiter.limit("3 per minute")
def update_users():
    if not is_admin():
        flash("Unauthorized action", "danger")
        return redirect(url_for('home.home'))

    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    supabase = get_supabase_client()
    users_resp = supabase.table('users').select('id, privilege, username').execute()
    users = users_resp.data or []

    for user in users:
        user_id = user['id']
        username = user['username']
        old_priv = user['privilege']
        new_priv = request.form.get(f"privilege_{user_id}")
        reset = request.form.get(f"reset_{user_id}")
        delete = request.form.get(f"delete_{user_id}")

        # Update privilege
        if new_priv and new_priv != old_priv:
            supabase.table('users').update({'privilege': new_priv}).eq('id', user_id).execute()
            flash(f"Privilege updated for {username}", "success")

        # Reset password (admin operation -> set temp password and require change)
        if reset:
            try:
                new_temp = generate_otp()  # reuse OTP generator for a temporary password
                supabase.auth.admin.update_user_by_id(user_id, {"password": new_temp})
                # set requires_password_change and an expiry so user must reset
                expires_at = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
                supabase.table('users').update({
                    'requires_password_change': True,
                    'otp_expires_at': expires_at
                }).eq('id', user_id).execute()

                send_reset_email(username)  # your existing reset email util; could include temp password or a link
                flash(f"Password reset for {username}", "success")
            except Exception as e:
                flash(f"Failed to reset password: {e}", "danger")

        # Delete user
        if delete:
            try:
                supabase.auth.admin.delete_user(user_id)
            except Exception as e:
                flash(f"Failed to delete Auth user: {username}: {e}", "danger")

            supabase.table('users').delete().eq('id', user_id).execute()
            flash(f"Deleted {username}", "success")

    return redirect(url_for('admin.admin'))


@admin_bp.route('/add_container', methods=['POST'])
@limiter.limit("10 per minute")
def add_container():
    if not is_admin():
        flash("Unauthorized action.", "danger")
        return redirect(url_for('home.home'))

    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    name = request.form.get('container_name')
    if not name:
        flash("Container name cannot be empty.", "danger")
        return redirect(url_for('admin.admin'))

    supabase = get_supabase_client()
    supabase.table('containers').insert({'name': name}).execute()

    flash(f"Container '{name}' added successfully!", "success")
    return redirect(url_for('admin.admin'))

@admin_bp.route('/delete_container', methods=['POST'])
@limiter.limit("10 per minute")
def delete_container():
    if not is_admin():
        flash("Unauthorized action.", "danger")
        return redirect(url_for('home.home'))
    
    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    name = request.form.get('container_name')
    if not name:
        flash("Invalid request", "danger")
        return redirect(url_for('admin.admin'))
    
    supabase = get_supabase_client()
    
    try:
        container_data = supabase.table('containers').select('id').eq('name', name).execute()
        if not container_data.data:
            flash(f"No container found with name '{name}'.", "danger")
            return redirect(url_for('admin.admin'))

        container_id = container_data.data[0]['id']

        supabase.table('stock').delete().eq('container_id', container_id).execute()
        supabase.table('containers').delete().eq('id', container_id).execute()

        flash("Container and stored items were deleted", "success")

    except Exception as e:
        flash(f"Error deleting '{name}': {str(e)}", "danger")
    
    return redirect(url_for('admin.admin'))

@admin_bp.route('/edit_container', methods=['POST'])
@limiter.limit("30 per minute")
def edit_container():
    if not is_admin():
        flash("Unauthorized action.", "danger")
        return redirect(url_for('home.home'))
    
    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    # Current + new name
    current_name = request.form.get('container_name')
    new_name = request.form.get('new_container_name')

    if not current_name or not new_name:
        flash("Invalid request.", "danger")
        return redirect(url_for('admin.admin'))

    supabase = get_supabase_client()

    try:
        # Fetch container by current name
        container_data = (
            supabase.table('containers')
            .select('id')
            .eq('name', current_name)
            .execute()
        )

        if not container_data.data:
            flash(f"No container found with name '{current_name}'.", "danger")
            return redirect(url_for('admin.admin'))

        container_id = container_data.data[0]['id']

        # Check if new name already exists
        existing = (
            supabase.table('containers')
            .select('id')
            .eq('name', new_name)
            .execute()
        )
        if existing.data:
            flash(f"A container with the name '{new_name}' already exists.", "warning")
            return redirect(url_for('admin.admin'))

        # Perform update
        supabase.table('containers').update({"name": new_name}).eq('id', container_id).execute()

        flash(f"Container '{current_name}' renamed to '{new_name}'.", "success")
        return redirect(url_for('admin.admin'))

    except Exception as e:
        flash(f"Error updating container: {str(e)}", "danger")
        return redirect(url_for('admin.admin'))