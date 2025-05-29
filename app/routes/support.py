from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from app.utils.email_utils import send_support_email

support_bp = Blueprint('support', __name__)

@support_bp.route('/support')
def support():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    return render_template('support.html')

@support_bp.route('/submit_support', methods=['POST'])
def submit_support():
    email = session.get('username')
    issue = request.form.get('issue')
    message = request.form.get('message')

    send_support_email(email, issue, message)
    flash("Your ticket has been submitted. Please check your emails", "success")
    return render_template('support.html')