from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.security import check_password_hash
from app.db import get_supabase_client
from app.utils.otp_utils import generate_password_hash
from app import limiter
from postgrest import APIError
from datetime import datetime, timezone

auth_bp = Blueprint('auth', __name__)

def is_logged():
    return 'user_id' in session

@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("50 per minute")
def login():
    if is_logged():
        session.clear()

    supabase = get_supabase_client()

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password_or_otp = request.form.get('otp', '').strip()

        if not email or not password_or_otp:
            flash("Email and password/OTP are required.", "danger")
            return redirect(url_for('auth.login'))

        try:
            # Step 1: Check if OTP exists
            otp_resp = supabase.table("otps")\
                .select("id, otp, created_at")\
                .eq("email", email).execute()

            otp_records = otp_resp.data or []
            otp_record = otp_records[0] if otp_records else None

            if otp_record:
                created_at = datetime.fromisoformat(
                    otp_record["created_at"].replace("Z", "+00:00")
                )
                age_minutes = (datetime.now(timezone.utc) - created_at).total_seconds() / 60

                if age_minutes < 10 and otp_record["otp"] == password_or_otp:
                    # ✅ OTP is valid → load user
                    user_resp = supabase.table("users").select("*").eq("username", email).execute()
                    users = user_resp.data or []
                    user = users[0] if users else None

                    if not user:
                        flash("Invalid credentials.", "danger")
                        return redirect(url_for('auth.login'))

                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['privilege'] = user['privilege']

                    supabase.table("otps").delete().eq("id", otp_record["id"]).execute()
                    flash("Logged in successfully with OTP.", "success")
                    return redirect(url_for('dashboard.dashboard'))

                else:
                    # ❌ OTP expired
                    supabase.table("otps").delete().eq("id", otp_record["id"]).execute()
                    supabase.table("users").delete().eq("username", email).execute()
                    flash("OTP expired. Your account has been removed.", "danger")
                    return redirect(url_for('auth.login'))

            # Step 2: No OTP → password login
            user_resp = supabase.table("users").select("*").eq("username", email).execute()
            users = user_resp.data or []
            user = users[0] if users else None

            if not user:
                flash("Invalid credentials.", "danger")
                return redirect(url_for('auth.login'))

            if user.get("password_hash") and check_password_hash(user["password_hash"], password_or_otp):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['privilege'] = user['privilege']

                return redirect(url_for('dashboard.dashboard'))

            flash("Invalid credentials.", "danger")
            return redirect(url_for('auth.login'))

        except APIError as e:
            flash("Error during login. Please try again.", "danger")
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
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('auth.change_password'))

        try:
            # Check current password against stored hash
            response = supabase.table('users').select('password_hash').eq('id', user_id).single().execute()
            user = response.data
            if not user or not check_password_hash(user['password_hash'], current_password):
                flash("Current password is incorrect.", "danger")
                return redirect(url_for('auth.change_password'))
        except APIError as e:
            if "Results contain 0 rows" in str(e):
                flash("User not found.", "danger")
                return redirect(url_for('auth.login'))
            else:
                raise

        new_hashed = generate_password_hash(new_password)
        supabase.table('users').update({
            'password_hash': new_hashed,
            'requires_password_change': False
        }).eq('id', user_id).execute()

        flash("Password updated successfully!", "success")
        return redirect(url_for('dashboard.dashboard'))

    return render_template('change_password.html')