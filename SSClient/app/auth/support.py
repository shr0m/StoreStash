from flask import Blueprint, render_template, request, redirect, url_for, session, flash, current_app
import smtplib
from email.message import EmailMessage

support_bp = Blueprint('support', __name__)

def send_support_email(name, email, issue, message):
    try:
        sender = current_app.config['SUPPORT_EMAIL']
        receiver = current_app.config['SUPPORT_EMAIL_TO']
        password = current_app.config['SUPPORT_EMAIL_PASSWORD']

        # Compose message to support team
        msg_to_support = EmailMessage()
        msg_to_support['Subject'] = f'Support Ticket from {name}: {issue}'
        msg_to_support['From'] = sender
        msg_to_support['To'] = receiver
        msg_to_support.set_content(
            f"From: {name} <{email}>\n\nIssue: {issue}\n\nMessage:\n{message}"
        )

        # Compose confirmation message to user
        msg_to_user = EmailMessage()
        msg_to_user['Subject'] = 'Support Ticket Received'
        msg_to_user['From'] = sender
        msg_to_user['To'] = email
        msg_to_user.set_content(
            f"Hello {name},\n\n"
            f"Your support ticket has been received and forwarded to our team.\n\n"
            f"Issue: {issue}\n\n"
            f"Message:\n{message}\n\n"
            f"Thank you,\nStoreStash Support"
        )

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(sender, password)
            smtp.send_message(msg_to_support)
            smtp.send_message(msg_to_user)

        return True
    except Exception as e:
        current_app.logger.error(f'Error sending support email: {e}')
        return False

@support_bp.route('/', methods=['GET'])
def support():
    if 'user_id' not in session:
        flash("Please log in to access support.", "warning")
        return redirect(url_for('auth.login'))
    return render_template('support.html')

@support_bp.route('/submit', methods=['POST'])
def submit_support():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip()
    issue = request.form.get('issue', '').strip()
    message = request.form.get('message', '').strip()

    if not all([name, email, issue, message]):
        flash('All fields are required to submit a support ticket.', 'error')
        return redirect(url_for('support.support'))

    if send_support_email(name, email, issue, message):
        flash('Support ticket submitted successfully.', 'success')
    else:
        flash('Failed to submit support ticket.', 'error')

    return redirect(url_for('support.support'))