import os
import smtplib
import random
import string
import datetime
from email.message import EmailMessage
from werkzeug.security import generate_password_hash

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

def verify_otp_and_update(cursor, email, otp):
    cursor.execute('''
        SELECT created_at FROM otps
        WHERE email = ? AND otp = ?
        ORDER BY created_at DESC LIMIT 1
    ''', (email, otp))
    row = cursor.fetchone()
    if row:
        created_at = datetime.datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S")
        if datetime.datetime.now() - created_at <= datetime.timedelta(minutes=10):
            hashed_otp = generate_password_hash(otp)
            cursor.execute('UPDATE users SET password_hash = ?, requires_password_change = 1 WHERE username = ?', (hashed_otp, email))
            return True
    return False