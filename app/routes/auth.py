from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.security import check_password_hash, generate_password_hash
from app.db import get_supabase_client
from app.utils.otp_utils import verify_otp_and_update_supabase
from app import limiter
import re

# Import Supabase API error for handling no row found
from postgrest import APIError  

auth_bp = Blueprint('auth', __name__)
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]{3,}@[a-zA-Z0-9.-]{3,}\.[a-zA-Z]{2,}$')

def is_logged():
    return 'user_id' in session

@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("100 per minute")
def login():
    if is_logged():
        session.clear()

    supabase = get_supabase_client()

    if request.method == 'POST':
        email = request.form['email'].strip()
        otp_or_password = request.form['otp'].strip()

        if not EMAIL_REGEX.match(email):
            flash("Invalid email format.", "danger")
            return redirect(url_for('auth.login'))

        try:
            # Try to sign in using Supabase Auth
            auth_response = supabase.auth.sign_in_with_password({
                "email": email,
                "password": otp_or_password
            })
            user = auth_response.user

            if user:
                try:
                    # Load profile data from users table
                    profile_response = supabase.table('users')\
                        .select("id, username, privilege, requires_password_change")\
                        .eq("email", email).single().execute()
                    profile = profile_response.data

                    if not profile:
                        flash("No user profile found for this email.", "danger")
                        return redirect(url_for('auth.login'))

                    session['user_id'] = user.id
                    session['username'] = profile['username']
                    session['privilege'] = profile['privilege']

                    if profile['requires_password_change']:
                        return redirect(url_for('auth.change_password'))
                    return redirect(url_for('home.home'))

                except APIError as e:
                    if "Results contain 0 rows" in str(e):
                        flash("No user profile found for this email.", "danger")
                        return redirect(url_for('auth.login'))
                    else:
                        raise

        except Exception:
            # If Supabase Auth fails, try OTP fallback
            try:
                otp_user_resp = supabase.table('users')\
                    .select("id, username, privilege")\
                    .eq("email", email).single().execute()
                otp_user = otp_user_resp.data
            except APIError as e:
                otp_user = None

            if verify_otp_and_update_supabase(supabase, email, otp_or_password) and otp_user:
                session['user_id'] = otp_user['id']
                session['username'] = otp_user['username']
                session['privilege'] = otp_user['privilege']
                return redirect(url_for('auth.change_password'))

            flash('Invalid credentials', 'danger')

    return render_template('login.html')


@auth_bp.route('/otp_login', methods=['POST'])
@limiter.limit("15 per minute")
def otp_login():
    email = request.form.get('email', '').strip()
    provided_password = request.form.get('otp', '').strip()

    supabase = get_supabase_client()
    
    response = supabase.table('users').select('*').eq('username', email).limit(1).execute()
    users = response.data

    if not users:
        flash('Invalid credentials', 'danger')
        return redirect(url_for('auth.login'))

    user = users[0]

    # Local password fallback (not using Supabase Auth here)
    if user.get('password_hash') and check_password_hash(user['password_hash'], provided_password):
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['privilege'] = user['privilege']
        if user['requires_password_change']:
            return redirect(url_for('auth.change_password'))
        return redirect(url_for('home.home'))

    # OTP fallback
    if verify_otp_and_update_supabase(supabase, email, provided_password):
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['privilege'] = user['privilege']

        hashed_otp = generate_password_hash(provided_password)
        supabase.table('users').update({
            'password_hash': hashed_otp,
            'requires_password_change': True
        }).eq('id', user['id']).execute()

        return redirect(url_for('auth.change_password'))

    flash('Invalid credentials', 'danger')
    return redirect(url_for('auth.login'))


@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))


@auth_bp.route('/change_password', methods=['GET', 'POST'])
@limiter.limit("2 per week")
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
        return redirect(url_for('home.home'))

    return render_template('change_password.html')