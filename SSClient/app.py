import smtplib
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from email.mime.text import MIMEText
from dotenv import load_dotenv
import sqlite3
from email.message import EmailMessage
import json
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
load_dotenv(dotenv_path="../.env")

SUPPORT_EMAIL = os.getenv("SUPPORT_EMAIL")
SUPPORT_EMAIL_PASSWORD = os.getenv("SUPPORT_EMAIL_PASSWORD")
SUPPORT_EMAIL_TO = os.getenv("SUPPORT_EMAIL_TO")

DB_FILE = '../SSServer/storestash.db'

def send_support_email(name, email, issue, message):
    try:
        # Email the support team
        msg_to_support = EmailMessage()
        msg_to_support["Subject"] = f"Support Ticket from {name}: {issue}"
        msg_to_support["From"] = SUPPORT_EMAIL
        msg_to_support["To"] = SUPPORT_EMAIL_TO
        msg_to_support.set_content(f"From: {name} <{email}>\n\nIssue: {issue}\n\nMessage:\n{message}")

        # Email to user
        msg_to_user = EmailMessage()
        msg_to_user["Subject"] = "Support Ticket Received"
        msg_to_user["From"] = SUPPORT_EMAIL
        msg_to_user["To"] = email
        msg_to_user.set_content(
            f"Hello {name},\n\n"
            f"Your support ticket has been received and forwarded to our team.\n\n"
            f"Issue: {issue}\n\n"
            f"Message:\n{message}\n\n"
            f"Thank you,\nStoreStash Support"
        )

        # Send both emails in the same SMTP session
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(SUPPORT_EMAIL, SUPPORT_EMAIL_PASSWORD)
            smtp.send_message(msg_to_support)
            smtp.send_message(msg_to_user)

        return True
    except Exception as e:
        print(f"Error sending support email: {e}")
        return False

@app.route('/submit_support', methods=['POST'])
def submit_support():
    name = request.form.get('name')
    email = request.form.get('email')
    issue = request.form.get('issue')
    message = request.form.get('message')

    send_support_email(name, email, issue, message)
    return redirect(url_for('support'))


def get_stock_items():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM stock')
    items = cursor.fetchall()
    conn.close()
    return items

@app.route('/')
def dashboard():
    #if 'user_id' not in session:
     #   return redirect(url_for('login'))
    stock_items = get_stock_items()
    return render_template('dashboard.html', stock_items=stock_items)

@app.route('/add_stock_type', methods=['POST'])
def add_stock_type():
    try:
        new_type = request.form['new_type'].strip()
        initial_quantity = int(request.form['initial_quantity'])

        if not new_type:
            return "Item type is required", 400
        if initial_quantity < 0:
            return "Initial quantity must be zero or more", 400
    except (KeyError, ValueError, TypeError):
        return "Invalid input", 400

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Optional: prevent duplicate types (case-insensitive)
    cursor.execute('SELECT COUNT(*) FROM stock WHERE LOWER(type) = LOWER(?)', (new_type,))
    if cursor.fetchone()[0] > 0:
        conn.close()
        return "Stock type already exists", 400

    cursor.execute('INSERT INTO stock (type, quantity) VALUES (?, ?)', (new_type, initial_quantity))
    conn.commit()
    conn.close()

    return redirect(url_for('dashboard'))

@app.route('/update_stock_batch', methods=['POST'])
def update_stock_batch():
    try:
        data = json.loads(request.form['update_data'])
    except (KeyError, json.JSONDecodeError):
        return "Invalid data format", 400

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    for item in data:
        try:
            item_id = int(item['id'])
            quantity = int(item['quantity'])
        except (KeyError, ValueError, TypeError):
            continue  # Skip malformed item

        if quantity <= 0:
            # Delete item with 0 or negative quantity
            cursor.execute('DELETE FROM stock WHERE id = ?', (item_id,))
        else:
            # Update item with new quantity
            cursor.execute('UPDATE stock SET quantity = ? WHERE id = ?', (quantity, item_id))

    conn.commit()
    conn.close()
    return redirect(url_for('dashboard')) 

@app.route('/support')
def support():
    return render_template('support.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):  # user[2] = password_hash
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin')
def admin():
    return render_template('admin.html')