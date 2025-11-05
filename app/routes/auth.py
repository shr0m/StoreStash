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
        password_or_otp = request.form.get('password', '').strip()

        if not email or not password_or_otp:
            flash("Email and password/OTP are required.", "danger")
            return redirect(url_for('auth.login'))

        try:
            # Authenticate user
            auth_resp = supabase.auth.sign_in_with_password({
                "email": email,
                "password": password_or_otp
            })

            auth_user = getattr(auth_resp, "user", None) or (
                auth_resp.get("user") if isinstance(auth_resp, dict) else None
            )

            if not auth_user:
                flash("Invalid credentials.", "danger")
                return redirect(url_for('auth.login'))

            user_id = auth_user.id
            auth_metadata = getattr(auth_user, "user_metadata", {}) or {}

            # Fetch user record from users table
            user_resp = supabase.table('users').select('*').eq('id', user_id).maybe_single().execute()
            user_record = user_resp.data if user_resp else None

            requires_password_change = user_record.get('requires_password_change') if user_record else False
            otp_expires = auth_metadata.get('otp_expires_at') if requires_password_change else None

            # Check OTP expiry
            if requires_password_change and otp_expires:
                try:
                    expires_dt = datetime.fromisoformat(otp_expires)
                    if expires_dt.tzinfo is None:
                        expires_dt = expires_dt.replace(tzinfo=timezone.utc)

                    now = datetime.now(timezone.utc)

                    # If current time is past expiry
                    if now > expires_dt:
                        hours_since_expiry = (now - expires_dt).total_seconds() / 3600
                        if hours_since_expiry > 12:
                            # Delete user if over 12h old
                            try:
                                supabase.auth.admin.delete_user(user_id)
                            except Exception as e:
                                print(f"Error deleting auth user: {e}")

                            supabase.table('users').delete().eq('id', user_id).execute()
                            flash("Your password reset link expired over 12 hours ago. Your account has been removed. Please contact an admin.", "danger")
                            return redirect(url_for('auth.login'))
                        else:
                            flash("Your password reset link has expired. Please contact an admin to get a new one.", "warning")
                            return redirect(url_for('auth.login'))

                except Exception as e:
                    print(f"Error checking OTP expiry: {e}")
                    pass

            # Save session info
            session['user_id'] = user_id
            session['username'] = email
            session['privilege'] = user_record.get('privilege') if user_record else auth_metadata.get('privilege')
            session['client_id'] = auth_metadata.get('client_id')

            # Redirect if change pass required
            if requires_password_change:
                return redirect(url_for('auth.change_password'))

            # Login successful
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

    # Fetch user record from users table
    user_resp = supabase.table('users').select('requires_password_change').eq('id', user_id).maybe_single().execute()
    user_record = user_resp.data if user_resp else None

    if not user_record:
        flash("User not found.", "danger")
        return redirect(url_for('auth.login'))

    requires_change = user_record.get('requires_password_change', False)

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
            # Fetch Auth user to update metadata
            auth_user_resp = supabase.auth.admin.get_user_by_id(user_id)
            auth_user = getattr(auth_user_resp, "user", None) or (
                auth_user_resp.get("user") if isinstance(auth_user_resp, dict) else None
            )
            metadata = getattr(auth_user, "user_metadata", {}) or {}

            # Clear OTP expiry in Auth metadata
            metadata.pop('otp_expires_at', None)

            # Update password and metadata
            supabase.auth.admin.update_user_by_id(user_id, {
                "password": new_password,
                "user_metadata": metadata
            })

            # Clear requires_password_change in users table
            supabase.table('users').update({'requires_password_change': False}).eq('id', user_id).execute()

            flash("Password set successfully!", "success")
            return redirect(url_for('home.home'))

        except Exception as e:
            flash(f"Error updating password: {e}", "danger")
            return redirect(url_for('auth.change_password'))

    # Decide which template to render
    template = 'set_password.html' if requires_change else 'change_password.html'
    return render_template(template)