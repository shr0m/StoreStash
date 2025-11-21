from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from app.db import get_supabase_client
from app import limiter
from app.utils.audit import log_audit_action
from app.utils.otp_utils import generate_otp, redirect_if_password_change_required, get_client_id
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

    # Get client_id
    client_id = get_client_id()
    if not client_id:
        flash("Invalid client_id", "danger")
        return redirect(url_for('auth.login'))

    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    supabase = get_supabase_client()

    # Fetch auth users
    try:
        auth_users_resp = supabase.auth.admin.list_users()
        if isinstance(auth_users_resp, list):
            all_auth_users = auth_users_resp
        elif hasattr(auth_users_resp, "users"):
            all_auth_users = auth_users_resp.users
        elif hasattr(auth_users_resp, "data"):
            all_auth_users = auth_users_resp.data
        elif isinstance(auth_users_resp, dict):
            all_auth_users = auth_users_resp.get("users") or auth_users_resp.get("data") or []
        else:
            all_auth_users = []
    except Exception as e:
        print(f"Warning: Could not fetch Auth users: {e}")
        all_auth_users = []

    client_auth_users = [
        u for u in all_auth_users
        if getattr(u, "user_metadata", None) and u.user_metadata.get("client_id") == client_id
    ]

    auth_users = {u.id: u for u in client_auth_users}
    user_ids = list(auth_users.keys())
    users = []

    if user_ids:
        users_resp = (
            supabase.table("users")
            .select("id, requires_password_change, support_allowed")
            .in_("id", user_ids)
            .execute()
        )
        users = users_resp.data or []

    for user in users:
        auth_user = auth_users.get(user["id"])
        if auth_user:
            metadata = getattr(auth_user, "user_metadata", {}) or {}
            user["name"] = metadata.get("full_name", "Unknown")
            user["username"] = getattr(auth_user, "email", "Unknown")
            user["theme"] = metadata.get("theme", "light")
            user["privilege"] = metadata.get("privilege", "view")
        else:
            user.update({
                "name": "Unknown",
                "username": "Unknown",
                "theme": "light",
                "privilege": "view",
            })

    privilege_order = {"admin": 0, "edit": 1, "view": 2}
    sorted_users = sorted(users, key=lambda u: privilege_order.get(u.get("privilege", ""), 99))

    # Fetch containers
    containers_resp = (
        supabase.table("containers")
        .select("name")
        .eq("client_id", client_id)
        .execute()
    )
    containers = containers_resp.data or []

    # Fetch audit logs
    audit_log_resp = (
        supabase.table("audit_log")
        .select("id, user_id, action, description, timestamp")
        .eq("client_id", client_id)
        .order("timestamp", desc=True)
        .limit(100)
        .execute()
    )
    audit_logs = audit_log_resp.data or []
    for log in audit_logs:
        ts_str = log.get("timestamp")
        if ts_str:
            try:
                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))  # Convert Zulu time
                log['timestamp'] = dt.strftime('%Y-%m-%d %H:%M:%S')
            except ValueError:
                log['timestamp'] = ts_str

    # Merge full_name from auth users into audit logs
    for log in audit_logs:
        user_id = log.get("user_id")
        auth_user = auth_users.get(user_id)
        if auth_user:
            metadata = getattr(auth_user, "user_metadata", {}) or {}
            log["user_name"] = metadata.get("full_name", "Unknown")
            log["user_email"] = getattr(auth_user, "email", "Unknown")
        else:
            log["user_name"] = "Unknown"
            log["user_email"] = "Unknown"

    return render_template(
        "admin.html",
        users=sorted_users,
        containers=containers,
        audit_logs=audit_logs
    )


@admin_bp.route('/invite_user', methods=['POST'])
@limiter.limit("10 per minute")
def invite_user():
    if not is_admin():
        flash("Unauthorized action.", "danger")
        return redirect(url_for('auth.login'))

    # Get client_id
    client_id = get_client_id()
    if not client_id:
        flash("Invalid client_id", "danger")
        return redirect(url_for('auth.login'))

    name = request.form['name']
    email = request.form['email']
    privilege = request.form['privilege']

    if not EMAIL_REGEX.match(email):
        flash("Invalid email format.", "danger")
        return redirect(url_for('admin.admin'))

    supabase = get_supabase_client()
    user_id = session.get('user_id')

    # Check if user exists already
    auth_users_resp = supabase.auth.admin.list_users()
    users_list = auth_users_resp.get("users") if isinstance(auth_users_resp, dict) else auth_users_resp

    if any(u.email == email for u in users_list):
        flash(f"User {email} already exists.", "warning")
        return redirect(url_for('admin.admin'))

    try:
        user_data = {
            "full_name": name,
            "privilege": privilege,
            "theme": "dark",
            "created_by": session.get("username"),
            "client_id": client_id
        }

        # Create user
        create_resp = supabase.auth.admin.create_user({
            "email": email,
            "email_confirm": False,  # Send confirmation email
            "user_metadata": user_data
        })

        auth_user = getattr(create_resp, "user", None) or (
            create_resp.get("user") if isinstance(create_resp, dict) else None
        )

        if not auth_user:
            flash("Failed to create auth user.", "danger")
            return redirect(url_for('admin.admin'))

        # Insert metadata into users table
        supabase.table('users').insert({
            'id': auth_user.id,
            'requires_password_change': True,   # Set password after confirmation
            'support_allowed': True,
        }).execute()

        # Log audit action
        log_audit_action(
            client_id=client_id,
            user_id=user_id,
            action="invite_user",
            description=f"Invited user '{name}' ({email}) with privilege '{privilege}'."
        )

        flash(f"User invited. A confirmation email was sent to {email}.", "success")

    except Exception as e:
        flash(f"Error adding user: {e}", "danger")

    return redirect(url_for('admin.admin'))


@admin_bp.route('/update_users', methods=['POST'])
@limiter.limit("15 per minute")
def update_users():
    if not is_admin():
        flash("Unauthorized action", "danger")
        return redirect(url_for('home.home'))

    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    supabase = get_supabase_client()
    client_id = get_client_id()
    if not client_id:
        flash("Invalid client_id", "danger")
        return redirect(url_for('auth.login'))

    current_user_id = session.get('user_id')

    # Fetch all auth users
    try:
        all_auth_users = supabase.auth.admin.list_users()
    except Exception as e:
        flash(f"Failed to fetch Auth users: {e}", "danger")
        return redirect(url_for('admin.admin'))

    # Filter by client_id in user_metadata
    client_auth_users = [
        u for u in all_auth_users
        if getattr(u, "user_metadata", {})
        and u.user_metadata.get("client_id") == client_id
    ]

    auth_users_by_id = {u.id: u for u in client_auth_users}
    admin_users = [u for u in client_auth_users if u.user_metadata.get("privilege") == "admin"]
    admin_count = len(admin_users)

    # Fetch users table
    users_resp = supabase.table("users").select("id").execute()
    internal_users = users_resp.data or []

    # User iteration
    for row in internal_users:
        target_user_id = row["id"]
        auth_user = auth_users_by_id.get(target_user_id)

        if not auth_user:
            continue  # skip users that don't exist in auth

        username = getattr(auth_user, "email", "Unknown")
        metadata = dict(auth_user.user_metadata or {})
        old_priv = metadata.get("privilege", "view")

        reset_requested = request.form.get(f"reset_{target_user_id}")
        delete_requested = request.form.get(f"delete_{target_user_id}")
        new_priv = request.form.get(f"privilege_{target_user_id}")

        # Stop last admin deletion
        if old_priv == "admin" and admin_count == 1:
            if delete_requested:
                flash(f"Cannot delete {username}: at least one admin is required.", "danger")
                continue
            if new_priv and new_priv != "admin":
                flash(f"Cannot demote {username}: at least one admin is required.", "danger")
                continue

        # Privilege upd
        if new_priv and new_priv != old_priv:
            try:
                metadata["privilege"] = new_priv
                resp = supabase.auth.admin.update_user_by_id(
                    target_user_id,
                    user_metadata=metadata
                )

                flash(f"Privilege updated for {username}", "success")

                log_audit_action(
                    client_id=client_id,
                    user_id=current_user_id,
                    action="update_privilege",
                    description=f"Changed privilege for '{username}' from '{old_priv}' to '{new_priv}'."
                )

                if old_priv == "admin":
                    admin_count -= 1
                if new_priv == "admin":
                    admin_count += 1

            except Exception as e:
                flash(f"Failed to update privilege for {username}: {e}", "danger")

        # Password reset
        if reset_requested:
            try:
                # Recovery email
                supabase.auth.reset_password_for_email(
                    username,
                    {
                        "redirect_to": request.url_root.rstrip('/') + url_for('auth.confirm_magic_link_page')
                    }
                )

                # New password needed on login
                supabase.table("users").update(
                    {"requires_password_change": True}
                ).eq("id", target_user_id).execute()

                flash(f"Password recovery email sent to {username}.", "success")

                # Log action
                log_audit_action(
                    client_id=client_id,
                    user_id=current_user_id,
                    action="admin_reset_password",
                    description=f"Admin triggered password reset for '{username}'."
                )

            except Exception as e:
                flash(f"Failed to initiate password reset for {username}: {e}", "danger")

        # Delete
        if delete_requested:
            try:
                supabase.auth.admin.delete_user(target_user_id)
            except Exception as e:
                flash(f"Failed to delete Auth user {username}: {e}", "danger")

            supabase.table("users").delete().eq("id", target_user_id).execute()

            log_audit_action(
                client_id=client_id,
                user_id=current_user_id,
                action="delete_user",
                description=f"Deleted user '{username}'."
            )

            if target_user_id == current_user_id:
                session.clear()
                flash("Your account has been deleted.", "info")
                return redirect(url_for("auth.login"))

            flash(f"Deleted {username}", "success")

    return redirect(url_for("admin.admin"))




@admin_bp.route('/add_container', methods=['POST'])
@limiter.limit("10 per minute")
def add_container():
    if not is_admin():
        flash("Unauthorized action.", "danger")
        return redirect(url_for('home.home'))

    client_id = get_client_id()
    if not client_id:
        flash("Invalid client_id", "danger")
        return redirect(url_for('auth.login'))

    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    name = request.form.get('container_name')
    if not name:
        flash("Container name cannot be empty.", "danger")
        return redirect(url_for('admin.admin'))

    supabase = get_supabase_client()
    insert_resp = supabase.table('containers').insert({'name': name, 'client_id': client_id}).execute()

    if insert_resp.data:
        flash(f"Container '{name}' added successfully!", "success")

        # Log audit
        log_audit_action(
            client_id=client_id,
            user_id=session.get('user_id'),
            action='add_container',
            description=f"Added container '{name}'."
        )
    else:
        flash("Failed to add container.", "danger")

    return redirect(url_for('admin.admin'))

@admin_bp.route('/delete_container', methods=['POST'])
@limiter.limit("10 per minute")
def delete_container():
    if not is_admin():
        flash("Unauthorized action.", "danger")
        return redirect(url_for('home.home'))

    client_id = get_client_id()
    if not client_id:
        flash("Invalid client_id", "danger")
        return redirect(url_for('auth.login'))

    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    name = request.form.get('container_name')
    if not name:
        flash("Invalid request", "danger")
        return redirect(url_for('admin.admin'))
    
    supabase = get_supabase_client()
    
    try:
        container_data = supabase.table('containers') \
            .select('id') \
            .eq('name', name) \
            .eq('client_id', client_id) \
            .execute()
        
        if not container_data.data:
            flash(f"No container found with name '{name}'.", "danger")
            return redirect(url_for('admin.admin'))

        container_id = container_data.data[0]['id']

        # Delete associated stock first
        supabase.table('stock').delete().eq('container_id', container_id).execute()
        supabase.table('containers').delete().eq('id', container_id).execute()

        flash("Container and stored items were deleted", "success")

        # Log audit
        log_audit_action(
            client_id=client_id,
            user_id=session.get('user_id'),
            action='delete_container',
            description=f"Deleted container '{name}' and its stock."
        )

    except Exception as e:
        flash(f"Error deleting '{name}': {str(e)}", "danger")
    
    return redirect(url_for('admin.admin'))

@admin_bp.route('/edit_container', methods=['POST'])
@limiter.limit("30 per minute")
def edit_container():
    if not is_admin():
        flash("Unauthorized action.", "danger")
        return redirect(url_for('home.home'))

    client_id = get_client_id()
    if not client_id:
        flash("Invalid client_id", "danger")
        return redirect(url_for('auth.login'))

    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

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
            .eq('client_id', client_id)
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
            .eq('client_id', client_id)
            .execute()
        )
        if existing.data:
            flash(f"A container with the name '{new_name}' already exists.", "warning")
            return redirect(url_for('admin.admin'))

        # Perform update
        supabase.table('containers').update({"name": new_name}).eq('id', container_id).execute()

        flash(f"Container '{current_name}' renamed to '{new_name}'.", "success")

        # Log audit
        log_audit_action(
            client_id=client_id,
            user_id=session.get('user_id'),
            action='edit_container',
            description=f"Renamed container '{current_name}' to '{new_name}'."
        )

        return redirect(url_for('admin.admin'))

    except Exception as e:
        flash(f"Error updating container: {str(e)}", "danger")
        return redirect(url_for('admin.admin'))