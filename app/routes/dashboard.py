from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from app.db import get_supabase_client
import json
from app.utils.otp_utils import redirect_if_password_change_required
from app import limiter

dashboard_bp = Blueprint('dashboard', __name__)

def has_edit_privileges():
    return session.get('privilege') in ['admin', 'edit']

def normalize_sizing(sizing_str):
    """Normalize sizing input: return None if blank or equivalent to 'none'."""
    if not sizing_str:
        return None
    sizing_cleaned = sizing_str.strip().lower()
    return None if sizing_cleaned in ['', 'none', 'n/a'] else sizing_str.strip()

@dashboard_bp.route('/')
@limiter.limit("100 per minute")
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    supabase = get_supabase_client()

    # Group by type and sizing, count the number of items per group
    response = supabase.table('stock')\
        .select('type, sizing, id', count='exact')\
        .execute()
    stock_items = response.data or []

    # Aggregate counts by type and sizing
    aggregated = {}
    for item in stock_items:
        key = (item['type'], item['sizing'])  # None is valid for NULL sizing
        aggregated[key] = aggregated.get(key, 0) + 1

    # Convert to list of dicts for template
    stock_summary = [
        {'type': t, 'sizing': s, 'quantity': qty}
        for (t, s), qty in aggregated.items()
    ]

    return render_template(
        'dashboard.html',
        stock_items=stock_summary,
        session=session,
    )

@dashboard_bp.route('/add_stock_type', methods=['POST'])
@limiter.limit("20 per minute")
def add_stock_type():
    if not has_edit_privileges():
        return "Unauthorized", 403

    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    supabase = get_supabase_client()

    new_type = request.form.get('new_type', '').strip()
    try:
        initial_quantity = int(request.form.get('initial_quantity', 0))
    except ValueError:
        return "Invalid quantity", 400

    sizing_raw = request.form.get('sizing', '')
    sizing = normalize_sizing(sizing_raw)

    if not new_type or initial_quantity < 0:
        return "Invalid input", 400

    if len(new_type) > 30:
        flash("Character limit exceeded", "danger")
        return redirect(url_for('dashboard.dashboard'))

    # Check if stock type already exists (case-insensitive)
    query = supabase.table('stock').select('id').ilike('type', new_type)
    if sizing is None:
        query = query.is_('sizing', None)
    else:
        query = query.eq('sizing', sizing)
    response = query.execute()

    if response.data:
        return "Stock type already exists", 400

    # Insert one record per item
    rows_to_insert = [{'type': new_type, 'sizing': sizing} for _ in range(initial_quantity)]
    if rows_to_insert:
        supabase.table('stock').insert(rows_to_insert).execute()

    flash("Stock type added.", "success")
    return redirect(url_for('dashboard.dashboard'))

@dashboard_bp.route('/update_stock_batch', methods=['POST'])
@limiter.limit("1 per second")
def update_stock_batch():
    if not has_edit_privileges():
        return "Unauthorized", 403

    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    try:
        data = json.loads(request.form['update_data'])
    except Exception:
        return "Invalid data format", 400

    supabase = get_supabase_client()

    for item in data:
        item_type = item.get('type')
        sizing_raw = item.get('sizing', '')
        sizing = normalize_sizing(sizing_raw)

        try:
            quantity = int(item.get('quantity', 0))
        except Exception:
            continue  # skip invalid quantity

        if not item_type:
            continue  # skip invalid item

        # Fetch current available stock for this type & sizing
        query = supabase.table('stock').select('id').eq('type', item_type)
        if sizing is None:
            query = query.is_('sizing', None)
        else:
            query = query.eq('sizing', sizing)

        current_resp = query.execute()
        current_items = current_resp.data or []
        current_count = len(current_items)

        if quantity < current_count:
            # Delete excess items
            ids_to_delete = [itm['id'] for itm in current_items[:current_count - quantity]]
            del_resp = supabase.table('stock').delete().in_('id', ids_to_delete).execute()
            if del_resp.data is None:
                print(f"Error deleting items {ids_to_delete} for {item_type} ({sizing})")

        elif quantity > current_count:
            # Insert new items
            rows_to_insert = [{'type': item_type, 'sizing': sizing} for _ in range(quantity - current_count)]
            ins_resp = supabase.table('stock').insert(rows_to_insert).execute()
            if ins_resp.data is None:
                print(f"Error inserting items for {item_type} ({sizing})")

    flash("Stock file updated.", "success")
    return redirect(url_for('dashboard.dashboard'))
