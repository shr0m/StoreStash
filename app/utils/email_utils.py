import os, smtplib, requests
from email.message import EmailMessage
from itsdangerous import URLSafeTimedSerializer
from flask import current_app
from email.mime.text import MIMEText

SUPPORT_EMAIL = os.getenv("SUPPORT_EMAIL")
SUPPORT_EMAIL_PASSWORD = os.getenv("SUPPORT_EMAIL_PASSWORD")
SUPPORT_EMAIL_TO = os.getenv("SUPPORT_EMAIL_TO")
CLIENT = os.getenv("CLIENT")

def send_support_email(email, issue, message):
    try:
        msg_to_support = EmailMessage()
        msg_to_support["Subject"] = f"Support Ticket: {issue}"
        msg_to_support["From"] = SUPPORT_EMAIL
        msg_to_support["To"] = SUPPORT_EMAIL_TO
        msg_to_support.set_content(f"From: {email}\nClient: {CLIENT}\n\nIssue: {issue}\n\nMessage:\n{message}")

        msg_to_user = EmailMessage()
        msg_to_user["Subject"] = "Support Ticket Received"
        msg_to_user["From"] = SUPPORT_EMAIL
        msg_to_user["To"] = email
        msg_to_user.set_content(f"Greetings valued user,\n\nWe've received your issue: {issue}\n\nMessage:\n{message}\n\nPlease allow 24 hours for a developer to reply. These emails are not monitored regularly.")

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(SUPPORT_EMAIL, SUPPORT_EMAIL_PASSWORD)
            smtp.send_message(msg_to_support)
            smtp.send_message(msg_to_user)

        return True
    except Exception as e:
        print(f"Support email error: {e}")
        return False

def send_reset_email(email):
    try:
        msg = EmailMessage()
        msg["Subject"] = f"Password Reset - StoreStash"
        msg["From"] = SUPPORT_EMAIL
        msg["To"] = email
        msg.set_content(f"Greetings valued user,\n\nAn administrator has reset your StoreStash password.\nPlease contact the administrator if you have not yet received the default password.")

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(SUPPORT_EMAIL, SUPPORT_EMAIL_PASSWORD)
            smtp.send_message(msg)
        return True
    except Exception as e:
        print(f"Support email error: {e}")
        return False
    
def fetch_github_releases(repo: str, limit: int = 5):
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