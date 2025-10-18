from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.security import check_password_hash
from app.db import get_supabase_client
from app.utils.otp_utils import generate_password_hash, redirect_if_password_change_required
from app import limiter
from postgrest import APIError
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
            # Fetch user profile info
            user_meta_resp = supabase.table('users').select('*').eq('username', email).maybe_single().execute()
            user_meta = user_meta_resp.data if user_meta_resp else None

            # Supabase auth authenticate
            auth_resp = supabase.auth.sign_in_with_password({"email": email, "password": password_or_otp})
            auth_user = getattr(auth_resp, "user", None) or (auth_resp.get("user") if isinstance(auth_resp, dict) else None)

            if not auth_user:
                flash("Invalid credentials.", "danger")
                return redirect(url_for('auth.login'))

            # Success, edit session
            session['user_id'] = auth_user.id
            session['username'] = email

            if user_meta:
                session['privilege'] = user_meta.get('privilege')

                if user_meta.get('requires_password_change'):
                    otp_expires = user_meta.get('otp_expires_at')
                    if otp_expires:
                        try:
                            expires_dt = datetime.fromisoformat(otp_expires)
                            if expires_dt.tzinfo is None:
                                # assume UTC if naive
                                expires_dt = expires_dt.replace(tzinfo=timezone.utc)
                        except Exception:
                            expires_dt = None

                        if expires_dt and datetime.now(timezone.utc) > expires_dt:
                            # OTP expired, remove user
                            try:
                                supabase.auth.admin.delete_user(auth_user.id)
                            except Exception:
                                pass
                            supabase.table('users').delete().eq('id', auth_user.id).execute()
                            session.clear()
                            flash("OTP expired. Your account has been removed. Please contact an admin.", "danger")
                            return redirect(url_for('auth.login'))

                    # Redirect to change pass
                    return redirect(url_for('auth.change_password'))

            # Normal successful login
            flash("Login successful!", "success")
            return redirect(url_for('home.home'))

        except APIError as e:
            flash("Error during login. Please try again.", "danger")
            print(e)
            return redirect(url_for('auth.login'))
        except Exception as e:
            flash("Invalid credentials.", "danger")
            print(e)
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

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('auth.change_password'))

        try:
            # Update the password in Supabase Auth using admin API (service role)
            supabase.auth.admin.update_user_by_id(user_id, {"password": new_password})

            # Clear requires_password_change and otp_expires_at in your users table
            supabase.table('users').update({
                'requires_password_change': False,
                'otp_expires_at': None
            }).eq('id', user_id).execute()

            flash("Password set successfully!", "success")
            return redirect(url_for('home.home'))

        except Exception as e:
            flash(f"Error updating password: {e}", "danger")

    # Show change/set password pages
    user_resp = supabase.table('users').select('otp_expires_at, requires_password_change').eq('id', user_id).execute()
    user_data = user_resp.data or []

    if user_data[0] == None and user_data[1] == True:
        return render_template('set_password.html')
    else:
        return render_template('change_password.html')