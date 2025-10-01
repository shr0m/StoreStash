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


def fetch_github_releases(repo: str, limit: int = 5):
    """
    Fetch the latest releases from a GitHub repository.
    
    :param repo: GitHub repo in "owner/repo" format
    :param limit: Max number of releases to return
    :return: List of releases with tag, name, body, and URL
    """
    url = f"https://api.github.com/repos/{repo}/releases"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        releases = response.json()
        return [
            {
                "tag": r.get("tag_name"),
                "name": r.get("name") or r.get("tag_name"),
                "body": r.get("body", ""),
                "url": r.get("html_url"),
                "published_at": r.get("published_at")
            }
            for r in releases[:limit]
        ]
    except requests.RequestException:
        return []