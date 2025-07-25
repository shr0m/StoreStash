from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from app.utils.email_utils import send_support_email
from app.utils.otp_utils import redirect_if_password_change_required
from app import limiter, get_supabase_client
import re

support_bp = Blueprint('support', __name__)
FORBIDDEN_CHARS_PATTERN = r"[{}\[\]<>¬`~,]"

@support_bp.route('/support')
@limiter.limit("100 per minute")
def support():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    
    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    return render_template('support.html')

@support_bp.route('/submit_support', methods=['POST'])
@limiter.limit("10 per minute")
def submit_support():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    supabase = get_supabase_client()
    response = supabase.table('users')\
        .select('support_allowed')\
        .eq('id', session['user_id'])\
        .single()\
        .execute()

    user = response.data

    if not user or not user.get('support_allowed', False):
        flash("You have been blacklisted from sending support requests by the developer. Please contact an administrator to resolve.", "danger")
        return render_template('support.html')

    email = session.get('username')
    issue = request.form.get('issue')
    message = request.form.get('message')

    message = re.sub(FORBIDDEN_CHARS_PATTERN, '', message)

    send_support_email(email, issue, message)
    flash("Your ticket has been submitted. Please check your emails", "success")
    return render_template('support.html')