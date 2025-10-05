import os
import smtplib
import random
import string
import datetime
from email.message import EmailMessage
from werkzeug.security import generate_password_hash
from app.db import get_supabase_client
from flask import session, url_for, redirect


SUPPORT_EMAIL = os.getenv("SUPPORT_EMAIL")
SUPPORT_EMAIL_PASSWORD = os.getenv("SUPPORT_EMAIL_PASSWORD")

def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

def send_otp_email(to_email, otp):
    try:
        msg = EmailMessage()
        msg["Subject"] = "Your StoreStash OTP"
        msg["From"] = SUPPORT_EMAIL
        msg["To"] = to_email
        msg.set_content(f"Your OTP is: {otp}")

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(SUPPORT_EMAIL, SUPPORT_EMAIL_PASSWORD)
            smtp.send_message(msg)
        return True
    except Exception as e:
        print(f"Failed to send OTP email: {e}")
        return False

def redirect_if_password_change_required():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    supabase = get_supabase_client()
    user_id = session['user_id']

    try:
        response = supabase.table('users')\
            .select('requires_password_change')\
            .eq('id', user_id)\
            .single()\
            .execute()
    except Exception:
        redirect(url_for('auth.login'))

    user_data = response.data
    if user_data and user_data.get('requires_password_change'):
        return redirect(url_for('auth.change_password'))

    return None
