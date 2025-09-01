from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash
from app.db import get_supabase_client
from app import limiter
from app.utils.otp_utils import generate_otp, send_otp_email, redirect_if_password_change_required
from app.utils.email_utils import send_reset_email 
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
    # Fetch all users for display
    users_resp = supabase.table('users').select('id, username, privilege, name').execute()
    users = users_resp.data or []

    # Sort by privilege
    privilege_order = {'admin': 0, 'edit': 1, 'view': 2}
    sorted_users = sorted(users, key=lambda u: privilege_order.get(u.get('privilege'), 99))

    containers_resp = supabase.table('containers').select('name').execute()
    containers = containers_resp.data or []

    return render_template('admin.html', users=sorted_users, containers=containers)


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
    
    redirect_resp = redirect_if_password_change_required()
    if user_count > 0 and redirect_resp:
        return redirect_resp

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
        return redirect(url_for('home.home'))

    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    supabase = get_supabase_client()

    users_resp = supabase.table('users').select('id, privilege').execute()
    existing_users = users_resp.data or []
    existing_map = {user['id']: user['privilege'] for user in existing_users}

    self_deleted = False  # Track if the current logged-in user was deleted

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

            # Check if the deleted user is the current session user
            if str(user_id) == str(session.get('user_id')):
                self_deleted = True

    if self_deleted:
        session.clear()
        flash("Your account has been deleted. You have been logged out.", "warning")
        return redirect(url_for('auth.login'))

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