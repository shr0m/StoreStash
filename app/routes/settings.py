from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from app.db import get_supabase_client
from app import limiter
from app.utils.otp_utils import redirect_if_password_change_required
from app.utils.email_utils import generate_email_token, send_cemail_email, confirm_email_token

settings_bp = Blueprint('settings', __name__)

@settings_bp.route('/settings', methods=['GET', 'POST'])
@limiter.limit("100 per minute")
def settings():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    
    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    user_id = session['user_id']
    supabase = get_supabase_client()

    if request.method == 'POST':
        new_theme = 'dark' if request.form.get('theme') == 'dark' else 'light'
        supabase.table('users').update({'theme': new_theme}).eq('id', user_id).execute()
        flash("Theme updated successfully.", "success")
        return redirect(url_for('settings.settings'))

    response = supabase.table('users').select('theme').eq('id', user_id).single().execute()
    current_theme = response.data.get('theme') if response.data else 'light'

    return render_template('settings.html', current_theme=current_theme)

@settings_bp.route('/hard_reset')
@limiter.limit("1 per minute")
def hard_reset():
    return redirect("https://www.youtube.com/watch?v=dQw4w9WgXcQ")

@settings_bp.route('/change_email_request', methods=['POST'])
def change_email_request():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    new_email = request.form.get('new_email')
    if not new_email:
        flash("Email is required.", "danger")
        return redirect(url_for('settings.settings'))

    token = generate_email_token(new_email)
    confirm_url = url_for('settings.confirm_email', token=token, _external=True)
    html = f"""
    <h2>Email Change</h2>
    <p>If this email is unexpected, please contact an administrator immediately.</p>
    <p>Click the button below to confirm your new email address:</p>
    <p><a href="{confirm_url}" style="padding: 10px 20px; background: #0d6efd; color: white; text-decoration: none; border-radius: 5px;">Confirm Email</a></p>
    """

    send_cemail_email(
        subject="Confirm Your New Email",
        recipient=new_email,
        html_body=html
    )

    flash("A confirmation email has been sent to your new address.", "info")
    return redirect(url_for('settings.settings'))


@settings_bp.route('/confirm_email/<token>')
def confirm_email(token):
    new_email = confirm_email_token(token)
    if not new_email:
        flash("The confirmation link is invalid or has expired.", "danger")
        return redirect(url_for('settings.settings'))

    supabase = get_supabase_client()
    user_id = session.get('user_id')

    # Update the username (email) field
    supabase.table('users').update({'username': new_email}).eq('id', user_id).execute()
    flash("Email updated successfully.", "success")
    return redirect(url_for('settings.settings'))