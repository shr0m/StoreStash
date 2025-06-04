from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from app.db import get_supabase_client
import json
from app import limiter

dashboard_bp = Blueprint('dashboard', __name__)

def has_edit_privileges():
    return session.get('privilege') in ['admin', 'store team']

@dashboard_bp.route('/')
@limiter.limit("100 per minute")
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    supabase = get_supabase_client()
    response = supabase.table('stock').select('*').execute()
    stock_items = response.data or []

    return render_template(
        'dashboard.html',
        stock_items=stock_items,
        session=session,
    )

@dashboard_bp.route('/add_stock_type', methods=['POST'])
@limiter.limit("20 per minute")
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

    supabase = get_supabase_client()

    # Check if stock type already exists (case-insensitive)
    response = supabase.table('stock')\
        .select('id')\
        .ilike('type', new_type)\
        .execute()
    if response.data:
        return "Stock type already exists", 400

    supabase.table('stock').insert({
        'type': new_type,
        'quantity': initial_quantity
    }).execute()

    flash("Stock type added.", "success")
    return redirect(url_for('dashboard.dashboard'))

@dashboard_bp.route('/update_stock_batch', methods=['POST'])
@limiter.limit("10 per minute")
def update_stock_batch():
    if not has_edit_privileges():
        return "Unauthorized", 403

    try:
        data = json.loads(request.form['update_data'])
    except Exception:
        return "Invalid data format", 400

    supabase = get_supabase_client()

    for item in data:
        try:
            item_id = int(item['id'])
            quantity = int(item['quantity'])

            if quantity <= 0:
                supabase.table('stock').delete().eq('id', item_id).execute()
            else:
                supabase.table('stock').update({'quantity': quantity}).eq('id', item_id).execute()
        except Exception:
            continue

    flash("Stock file updated.", "success")
    return redirect(url_for('dashboard.dashboard'))