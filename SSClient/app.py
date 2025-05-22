import smtplib, os, string, random, json, sqlite3, datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash
from email.mime.text import MIMEText
from dotenv import load_dotenv
from email.message import EmailMessage
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
load_dotenv(dotenv_path="../.env")

app.secret_key = os.getenv("FLASK_SECRET_KEY")
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

@app.route('/', methods=['GET'])
def dashboard():
    if 'user_id' not in session:
       return redirect(url_for('login'))
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
   # if session.get('privilege') != 'admin':
    #    return redirect(url_for('login'))
    return render_template('admin.html')

def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

def send_otp_email(recipient_email, otp):
    try:
        msg = EmailMessage()
        msg["Subject"] = "Your StoreStash One-Time Password"
        msg["From"] = SUPPORT_EMAIL
        msg["To"] = recipient_email
        msg.set_content(f"Your username is your email.\nYour one-time password is: {otp}")

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(SUPPORT_EMAIL, SUPPORT_EMAIL_PASSWORD)
            smtp.send_message(msg)
        return True
    except Exception as e:
        print(f"Error sending OTP: {e}")
        return False
    
@app.route('/send_otp', methods=['POST'])
def send_otp():
    email = request.form.get('email')
    privilege = request.form.get('privilege')

    if not email or privilege not in ['admin', 'store team', 'view']:
        flash("Email and valid privilege required", "error")
        return redirect(url_for('admin'))

    otp = generate_otp()

    if send_otp_email(email, otp):
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        # Always store OTP (in plain text) in the otps table
        cursor.execute('INSERT INTO otps (email, otp) VALUES (?, ?)', (email, otp))

        # Check if user exists
        cursor.execute('SELECT id FROM users WHERE username = ?', (email,))
        existing_user = cursor.fetchone()

        if not existing_user:
            # New user: insert user with OTP as hashed temp password
            hashed_otp = generate_password_hash(otp)
            cursor.execute('''
                INSERT INTO users (username, password_hash, privilege)
                VALUES (?, ?, ?)
            ''', (email, hashed_otp, privilege))
        else:
            # Existing user: just update their password_hash (optional — or let OTP only exist in the otps table)
            pass  # Let login be handled entirely via the otps table

        conn.commit()
        conn.close()
        flash("OTP sent to user email.", "success")
    else:
        flash("Failed to send OTP.", "error")

    return redirect(url_for('admin'))

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    email = request.form.get('email')
    otp = request.form.get('otp')

    if not all([email, otp]):
        return "Missing fields", 400

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute('''
        SELECT created_at FROM otps
        WHERE email = ? AND otp = ?
        ORDER BY created_at DESC LIMIT 1
    ''', (email, otp))

    row = cursor.fetchone()
    conn.close()

    if row:
        created_time = datetime.datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S")
        if datetime.datetime.now() - created_time <= datetime.timedelta(minutes=10):
            return "OTP valid", 200
        else:
            return "OTP expired", 400
    return "Invalid OTP", 400

@app.route('/otp_login', methods=['POST'])
def otp_login():
    email = request.form.get('email', '').strip()
    provided_password = request.form.get('otp', '').strip()  # Might be OTP or actual password

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Check if user exists
    cursor.execute('SELECT id, username, password_hash, privilege, requires_password_change FROM users WHERE username = ?', (email,))
    user = cursor.fetchone()

    if not user:
        flash("User not found", "error")
        return redirect(url_for('login'))

    user_id, username, password_hash, privilege, requires_password_change = user

    # Try password match first
    if password_hash and check_password_hash(password_hash, provided_password):
        session['user_id'] = user_id
        session['username'] = username
        session['privilege'] = privilege
        conn.close()
        if requires_password_change:
            return redirect(url_for('change_password'))
        return redirect(url_for('dashboard'))

    # If password failed, try OTP
    cursor.execute('''
        SELECT created_at FROM otps
        WHERE email = ? AND otp = ?
        ORDER BY created_at DESC LIMIT 1
    ''', (email, provided_password))
    otp_row = cursor.fetchone()

    if otp_row:
        created_time = datetime.datetime.strptime(otp_row[0], "%Y-%m-%d %H:%M:%S")
        if datetime.datetime.now() - created_time <= datetime.timedelta(minutes=10):
            # OTP valid — log in, hash the OTP, force password change
            session['user_id'] = user_id
            session['username'] = username
            session['privilege'] = privilege

            hashed_otp = generate_password_hash(provided_password)
            cursor.execute('''
                UPDATE users SET password_hash = ?, requires_password_change = 1
                WHERE id = ?
            ''', (hashed_otp, user_id))

            conn.commit()
            conn.close()

            return redirect(url_for('change_password'))
        else:
            flash("OTP expired", "error")
    else:
        flash("Incorrect password or OTP", "error")

    conn.close()
    return redirect(url_for('login'))

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        hashed = generate_password_hash(new_password)

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE users SET password_hash = ?, requires_password_change = 0
            WHERE id = ?
        ''', (hashed, session['user_id']))
        conn.commit()
        conn.close()

        flash("Password updated successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('change_password.html')