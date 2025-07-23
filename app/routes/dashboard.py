from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from app.db import get_supabase_client
import json, re
from app.utils.otp_utils import redirect_if_password_change_required
from app import limiter
from collections import defaultdict

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
def root():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp
    return redirect(url_for('dashboard.dashboard'))
    

@dashboard_bp.route('/dashboard')
@limiter.limit("100 per minute")
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    supabase = get_supabase_client()

    # Fetch stock and categories
    response = supabase.table('stock')\
        .select('type, sizing, id, category_id, categories(category)')\
        .execute()
    stock_items = response.data or []

    aggregated = defaultdict(lambda: {'quantity': 0, 'category': None, 'category_id': None})
    for item in stock_items:
        key = (item['type'], item['sizing'])
        aggregated[key]['quantity'] += 1
        category_obj = item.get('categories') or {}
        aggregated[key]['category'] = category_obj.get('category', 'Uncategorized')
        aggregated[key]['category_id'] = item.get('category_id')

    stock_summary = [
        {'type': t, 'sizing': s, 'quantity': data['quantity'], 'category': data['category'], 'category_id': data['category_id']}
        for (t, s), data in aggregated.items()
    ]

    categories_response = supabase.table('categories').select('*').order('category').execute()
    categories = categories_response.data if categories_response else []

    overview_data = get_stock_overview()

    return render_template(
        'dashboard.html',
        categories=categories,
        stock_items=stock_summary,
        session=session,
        **overview_data
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
        flash("Initial quantity must be a number.", "danger")
        return redirect(url_for('dashboard.dashboard'))

    sizing_raw = request.form.get('sizing', '')
    sizing = normalize_sizing(sizing_raw)

    if not new_type or initial_quantity < 0:
        flash("Invalid item name or quantity.", "danger")
        return redirect(url_for('dashboard.dashboard'))

    if len(new_type) > 30:
        flash("Item name exceeds character limit.", "danger")
        return redirect(url_for('dashboard.dashboard'))

    # Validate category_id is present and valid
    category_id = request.form.get('category_id')
    if not category_id:
        flash("Please select a category.", "danger")
        return redirect(url_for('dashboard.dashboard'))

    # Validate category_id exists
    exists_resp = supabase.table('categories').select('id').eq('id', category_id).execute()
    if not exists_resp.data or len(exists_resp.data) == 0:
        flash("Invalid category selected.", "danger")
        return redirect(url_for('dashboard.dashboard'))

    # Check if stock type already exists (case-insensitive)
    query = supabase.table('stock').select('id').ilike('type', new_type)
    if sizing is None:
        query = query.is_('sizing', None)
    else:
        query = query.eq('sizing', sizing)
    response = query.execute()

    if response.data and len(response.data) > 0:
        flash("Stock type with this name and sizing already exists.", "danger")
        return redirect(url_for('dashboard.dashboard'))

    # Insert stock rows for the new type
    rows_to_insert = [{'type': new_type, 'sizing': sizing, 'category_id': category_id} for _ in range(initial_quantity)]

    if rows_to_insert:
        insert_resp = supabase.table('stock').insert(rows_to_insert).execute()
        if not insert_resp.data:
            flash("Error inserting stock items.", "danger")
            return redirect(url_for('dashboard.dashboard'))

    flash(f"Added {initial_quantity} items of type '{new_type}'.", "success")
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
        flash("Invalid data format.", "danger")
        return redirect(url_for('dashboard.dashboard'))

    supabase = get_supabase_client()

    for item in data:
        item_type = item.get('type')
        sizing_raw = item.get('sizing', '')
        sizing = normalize_sizing(sizing_raw)
        try:
            new_quantity = int(item.get('quantity', 0))
        except Exception:
            continue  # skip invalid quantity

        category_id = item.get('category_id')
        if not item_type or new_quantity < 0 or not category_id:
            continue  # skip invalid items

        # Fetch current stock entries matching type, sizing, and category_id
        query = supabase.table('stock').select('id').eq('type', item_type).eq('category_id', category_id)
        if sizing is None:
            query = query.is_('sizing', None)
        else:
            query = query.eq('sizing', sizing)
        current_resp = query.execute()

        current_items = current_resp.data or []
        current_count = len(current_items)

        if new_quantity < current_count:
            # Delete excess items — delete oldest first (lowest id)
            ids_to_delete = [itm['id'] for itm in sorted(current_items, key=lambda x: x['id'])[:current_count - new_quantity]]
            del_resp = supabase.table('stock').delete().in_('id', ids_to_delete).execute()
            if not del_resp.data:
                flash(f"Error deleting stock for {item_type} ({sizing})", "danger")

        elif new_quantity > current_count:
            # Insert missing items — create new identical records
            rows_to_insert = [{'type': item_type, 'sizing': sizing, 'category_id': category_id} for _ in range(new_quantity - current_count)]
            print(f"Adding stock: type={item_type}, sizing={sizing}, category_id={category_id}, quantity={new_quantity - current_count}")
            ins_resp = supabase.table('stock').insert(rows_to_insert).execute()
            if not ins_resp.data:
                flash(f"Error adding stock for {item_type} ({sizing})", "danger")


    flash("Stock updated successfully.", "success")
    return redirect(url_for('dashboard.dashboard'))


@dashboard_bp.route('/add_category', methods=['POST'])
def add_category():
    if session.get('privilege') not in ['admin', 'edit']:
        flash("You don't have permission to add categories.", "danger")
        return redirect('/')

    category_name = request.form.get('category_name', '').strip()

    if not category_name:
        flash("Category name cannot be empty.", "warning")
        return redirect('/')
    
    if not re.match(r'^[A-Za-z0-9\-\(\)\s]+$', category_name):
        flash("Category names cannot contain forbidden characters.", "danger")
        return redirect(url_for('dashboard.dashboard'))

    supabase = get_supabase_client()

    # Check if category already exists
    existing = supabase.table('categories').select('id').eq('category', category_name).execute()
    if existing.data and len(existing.data) > 0:
        flash("Category already exists.", "info")
        return redirect('/')

    # Insert new category
    ins_resp = supabase.table('categories').insert({'category': category_name}).execute()
    if ins_resp.data:
        flash(f"Category '{category_name}' added successfully.", "success")
    else:
        flash("Error adding category. Please try again.", "danger")

    return redirect('/')

def get_stock_overview():
    supabase = get_supabase_client()

    stock_resp = supabase.table('stock')\
        .select('category_id, categories(category)')\
        .execute()
    stock_data = stock_resp.data or []

    assigned_resp = supabase.table('issued_stock')\
        .select('category_id')\
        .execute()
    assigned_data = assigned_resp.data or []

    from collections import defaultdict
    summary = defaultdict(lambda: {'category': '', 'in_stock': 0, 'assigned': 0, 'total': 0})

    for item in stock_data:
        cat_id = item['category_id']
        cat_name = item.get('categories', {}).get('category', 'Unknown')
        summary[cat_id]['category'] = cat_name
        summary[cat_id]['in_stock'] += 1

    # Count assigned per category_id
    for item in assigned_data:
        cat_id = item['category_id']
        # If category not present in stock still to record it
        if cat_id not in summary:
            summary[cat_id]['category'] = 'Unknown'
        summary[cat_id]['assigned'] += 1

    # Calculate total per category
    for cat_id in summary:
        summary[cat_id]['total'] = summary[cat_id]['in_stock'] + summary[cat_id]['assigned']

    # Convert to list sorted by category name
    category_summaries = sorted(summary.values(), key=lambda x: x['category'])

    # Also total overall (can compute or from previous vars)
    total_in_store = sum(x['in_stock'] for x in category_summaries)
    total_assigned = sum(x['assigned'] for x in category_summaries)
    total_all = total_in_store + total_assigned

    return {
        'category_summaries': category_summaries,
        'total_in_store': total_in_store,
        'total_assigned': total_assigned,
        'total_all': total_all,
    }

@dashboard_bp.route('/stock')
def stock_view():
    overview_data = get_stock_overview()
    # plus other data like stock_items, categories, etc.
    return render_template('stock.html', **overview_data)

@dashboard_bp.route('/update_stock_category', methods=['POST'])
@limiter.limit("10 per minute")
def update_stock_category():
    if not has_edit_privileges():
        return "Unauthorized", 403

    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    item_type = request.form.get('type')
    sizing_raw = request.form.get('sizing')
    sizing = normalize_sizing(sizing_raw)
    new_category_id = request.form.get('category_id')

    if not item_type or not new_category_id:
        flash("Invalid input provided.", "danger")
        return redirect(url_for('dashboard.dashboard'))

    supabase = get_supabase_client()

    stock_query = supabase.table('stock').select('id, category_id').eq('type', item_type)
    stock_query = stock_query.is_('sizing', None) if sizing is None else stock_query.eq('sizing', sizing)
    stock_result = stock_query.execute()
    stock_items = stock_result.data or []
    old_category_ids = {item['category_id'] for item in stock_items if item.get('category_id')}

    stock_updated = False
    if stock_items:
        update_stock_query = supabase.table('stock')\
            .update({'category_id': new_category_id})\
            .eq('type', item_type)
        update_stock_query = update_stock_query.is_('sizing', None) if sizing is None else update_stock_query.eq('sizing', sizing)
        stock_update_result = update_stock_query.execute()
        stock_updated = bool(stock_update_result.data)

    issued_items_updated = False
    issued_items_found = False
    if old_category_ids:
        for cat_id in old_category_ids:
            issued_check = supabase.table('issued_stock').select('id').eq('category_id', cat_id).execute()
            issued_matches = issued_check.data or []
            if issued_matches:
                issued_items_found = True
                update_issued = supabase.table('issued_stock')\
                    .update({'category_id': new_category_id})\
                    .eq('category_id', cat_id).execute()
                if update_issued.data:
                    issued_items_updated = True

    if not stock_items and not issued_items_found:
        flash("No matching stock or issued items found to update.", "info")
    elif stock_items and not stock_updated:
        flash("Failed to update stock category.", "danger")
    elif issued_items_found and not issued_items_updated:
        flash("Stock updated, but failed to update issued items.", "warning")
    else:
        flash("Category updated successfully for stock and issued items.", "success")

    return redirect(url_for('dashboard.dashboard'))

@dashboard_bp.route('/delete_category/<string:category_id>', methods=['POST'])
@limiter.limit("30 per minute")
def delete_category(category_id):
    if session.get('privilege') not in ['admin', 'edit']:
        return redirect(url_for('dashboard.dashboard'))

    supabase = get_supabase_client()

    try:
        linked = supabase.table('stock')\
            .select('id')\
            .eq('category_id', category_id)\
            .limit(1)\
            .execute()
        
        if linked.data:
            flash('Category is in use and cannot be deleted.', 'warning')
            return redirect(url_for('dashboard.dashboard'))

        # Delete the category
        supabase.table('categories')\
            .delete()\
            .eq('id', category_id)\
            .execute()

        flash('Category deleted successfully.', 'success')
    except Exception as e:
        print(f"Error deleting category: {e}")
        flash('An error occurred while deleting the category.', 'danger')

    return redirect(url_for('dashboard.dashboard'))