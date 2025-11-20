from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from app.db import get_supabase_client
from app import limiter
from datetime import datetime, timezone

auth_bp = Blueprint('auth', __name__)

def is_logged():
    return 'user_id' in session

@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("50 per minute")
def login():
    supabase = get_supabase_client()

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if not email or not password:
            flash("Email and password are required.", "danger")
            return redirect(url_for('auth.login'))

        try:
            # Normal login
            auth_resp = supabase.auth.sign_in_with_password({
                "email": email,
                "password": password
            })

            auth_user = getattr(auth_resp, "user", None) or (
                auth_resp.get("user") if isinstance(auth_resp, dict) else None
            )

            if not auth_user:
                flash("Invalid credentials.", "danger")
                return redirect(url_for('auth.login'))

            user_id = auth_user.id

            # Fetch user record
            user_resp = supabase.table('users').select('*').eq('id', user_id).maybe_single().execute()
            user_record = user_resp.data if user_resp else None

            if not user_record:
                flash("User record not found.", "danger")
                return redirect(url_for('auth.login'))

            session['user_id'] = user_id
            session['username'] = email
            session['privilege'] = auth_user.user_metadata.get('privilege')
            session['client_id'] = auth_user.user_metadata.get('client_id')

            if user_record.get('requires_password_change', False):
                return redirect(url_for('auth.change_password'))

            return redirect(url_for('home.home'))

        except Exception as e:
            print(e)
            flash("Invalid credentials.", "danger")
            return redirect(url_for('auth.login'))

    return render_template("login.html")


@auth_bp.route("/logout", methods=['GET'])
def logout():
    session.clear() 
    return redirect(url_for('auth.login'))


@auth_bp.route('/change_password', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    supabase = get_supabase_client()
    user_id = session['user_id']

    # Fetch user record
    user_resp = supabase.table('users').select('*').eq('id', user_id).maybe_single().execute()
    user_record = user_resp.data if user_resp else None

    if not user_record:
        flash("User record not found.", "danger")
        return redirect(url_for('auth.login'))

    requires_change = user_record.get('requires_password_change', False)
    email = session.get('username')

    # - requires_password_change (first login)
    # - password_reset_session (magic link)
    if not requires_change and not session.get('password_reset_session'):
        flash("Password change requires email confirmation.", "danger")
        return redirect(url_for('home.home'))

    # POST
    if request.method == 'POST':
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        if not new_password or not confirm_password:
            flash("Both password fields are required.", "danger")
            return redirect(url_for('auth.change_password'))

        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('auth.change_password'))

        try:
            # Update password
            supabase.auth.admin.update_user_by_id(user_id, {
                "password": new_password
            })

            # Clear flags
            supabase.table('users').update({
                'requires_password_change': False
            }).eq('id', user_id).execute()

            session.pop('password_reset_session', None)

            flash("Password updated successfully!", "success")
            return redirect(url_for('home.home'))

        except Exception as e:
            flash(f"Error updating password: {e}", "danger")
            return redirect(url_for('auth.change_password'))

    return render_template('set_password.html')

@auth_bp.route('/confirm', methods=['GET'])
def confirm_magic_link_page():
    if 'user_id' in session:
        return redirect(url_for('home.home'))
    return render_template("confirm.html")


@auth_bp.route('/request_password_change', methods=['POST'])
@limiter.limit("10 per minute")
def request_password_change():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    email = session['username']
    supabase = get_supabase_client()

    try:
        supabase.auth.reset_password_for_email(
            email,
            redirect_to=request.url_root.rstrip('/') + url_for('auth.confirm_magic_link_page')
        )
        flash("Password reset email sent.", "success")
    except Exception as e:
        flash(f"Could not send password reset email: {e}", "danger")

    return redirect(url_for('settings.settings'))


@auth_bp.route('/confirm/complete', methods=['POST'])
@limiter.limit('10 per minute')
def confirm_magic_link_complete():
    supabase = get_supabase_client()
    data = request.json

    access_token = data.get("access_token")
    refresh_token = data.get("refresh_token")
    type_param = data.get("type")

    if not access_token or not refresh_token:
        return redirect(url_for('auth.login'))

    # Get the user from the token
    try:
        user_resp = supabase.auth.get_user(access_token)
        auth_user = user_resp.user
    except Exception:
        return redirect(url_for('auth.login'))

    user_id = auth_user.id
    email = auth_user.email

    # Fetch user record
    user_db = supabase.table('users').select('*').eq('id', user_id).maybe_single().execute()
    user_record = user_db.data

    if not user_record:
        return redirect(url_for('auth.login'))

    # Store Flask session
    session['user_id'] = user_id
    session['username'] = email
    session['privilege'] = auth_user.user_metadata.get('privilege')
    session['client_id'] = auth_user.user_metadata.get('client_id')

    # First-time signup confirmation
    if type_param == "signup":
        return redirect(url_for('auth.change_password'))

    # Password recovery
    if type_param == "recovery":
        session['password_reset_session'] = True
        supabase.table('users').update({
            "requires_password_change": True
        }).eq('id', user_id).execute()

        return redirect(url_for('auth.change_password'))

    # Normal login fallback
    return redirect(url_for('home.home'))