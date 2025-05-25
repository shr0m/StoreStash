from flask import Blueprint, render_template, request, redirect, url_for, session
from app.db import get_db_connection
import json

dashboard_bp = Blueprint('dashboard', __name__)

def has_edit_privileges():
    return session.get('privilege') in ['admin', 'store team']

@dashboard_bp.route('/')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM stock')
    stock_items = cursor.fetchall()
    conn.close()

    return render_template(
        'dashboard.html',
        stock_items=stock_items,
        session=session,
    )

@dashboard_bp.route('/add_stock_type', methods=['POST'])
def add_stock_type():
    if not has_edit_privileges():
        return "Unauthorized", 403

    new_type = request.form.get('new_type', '').strip()
    try:
        initial_quantity = int(request.form.get('initial_quantity', 0))
    except ValueError:
        return "Invalid quantity", 400

    if not new_type or initial_quantity < 0:
        return "Invalid input", 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM stock WHERE LOWER(type) = LOWER(?)', (new_type,))
    if cursor.fetchone()[0] > 0:
        conn.close()
        return "Stock type already exists", 400

    cursor.execute('INSERT INTO stock (type, quantity) VALUES (?, ?)', (new_type, initial_quantity))
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard.dashboard'))

@dashboard_bp.route('/update_stock_batch', methods=['POST'])
def update_stock_batch():
    if not has_edit_privileges():
        return "Unauthorized", 403

    try:
        data = json.loads(request.form['update_data'])
    except Exception:
        return "Invalid data format", 400

    conn = get_db_connection()
    cursor = conn.cursor()

    for item in data:
        try:
            item_id = int(item['id'])
            quantity = int(item['quantity'])

            if quantity <= 0:
                cursor.execute('DELETE FROM stock WHERE id = ?', (item_id,))
            else:
                cursor.execute('UPDATE stock SET quantity = ? WHERE id = ?', (quantity, item_id))
        except:
            continue

    conn.commit()
    conn.close()
    return redirect(url_for('dashboard.dashboard'))