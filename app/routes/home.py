from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from app.db import get_supabase_client
from app.utils.otp_utils import redirect_if_password_change_required
from app import limiter

home_bp = Blueprint('home', __name__)

def has_edit_privileges():
    return session.get('privilege') in ['admin', 'edit']

@home_bp.route('/')
@limiter.limit("100 per minute")
def root():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp
    return redirect(url_for('home.home'))

@home_bp.route('/home')
@limiter.limit("100 per minute")
def home():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    return render_template('home.html')

