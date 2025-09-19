from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from app.db import get_supabase_client
import json, re, uuid
from app.utils.otp_utils import redirect_if_password_change_required
from app import limiter
from collections import defaultdict

dashboard_bp = Blueprint('dashboard', __name__)

def is_valid_uuid(value):
    try:
        uuid.UUID(str(value))
        return True
    except ValueError:
        return False

def has_edit_privileges():
    return session.get('privilege') in ['admin', 'edit']

def normalize_sizing(sizing_str):
    """Normalize sizing input: return None if blank or equivalent to 'none'."""
    if not sizing_str:
        return None
    sizing_cleaned = sizing_str.strip().lower()
    return None if sizing_cleaned in ['', 'none', 'n/a'] else sizing_str.strip()

def redirect_to_dashboard():
    """Redirect using current container in session."""
    container_id = session.get('container_id')
    if container_id:
        return redirect(url_for('dashboard.dashboard', container_id=container_id))
    else:
        # fallback: default dashboard
        return redirect(url_for('dash_default'))
    
#----------------------------------------------------------------------------------------------


@dashboard_bp.route('/dashboard/<container_id>')
@limiter.limit("50 per minute")
def dashboard(container_id):
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp
    
    if not is_valid_uuid(container_id):
        flash("Invalid container ID format.", "danger")
        return redirect(url_for('home.home'))

    supabase = get_supabase_client()

    container_check = supabase.table('containers').select('id, name').eq('id', container_id).execute()
    if not container_check.data:
        flash("Invalid container selected.", "danger")
        return redirect(url_for('home.home'))
    
    session['container_id'] = container_id

    stock_response = supabase.table('stock')\
            .select('id, type, sizing, category_id, categories(category), container_id')\
            .eq('container_id', container_id)\
            .execute()
    stock_items = stock_response.data or []



    issued_response = supabase.table('issued_stock')\
        .select('id, category_id, categories(category), container_id')\
        .eq('container_id', container_id)\
        .execute()
    issued_items = issued_response.data or []

    categories_response = supabase.table('categories').select('*').order('category').execute()
    categories = categories_response.data if categories_response else []

    aggregated = defaultdict(lambda: {'quantity': 0, 'category': None, 'category_id': None})
    for item in stock_items:
        key = (item['type'], item['sizing'])
        aggregated[key]['quantity'] += 1
        category_obj = item.get('categories') or {}
        aggregated[key]['category'] = category_obj.get('category', 'Uncategorized')
        aggregated[key]['category_id'] = item.get('category_id')

    stock_summary = [
        {
            'type': t,
            'sizing': s,
            'quantity': data['quantity'],
            'category': data['category'],
            'category_id': data['category_id']
        }
        for (t, s), data in aggregated.items()
    ]

    category_summaries = []
    for cat in categories:
        cat_name = cat['category']
        cat_id = cat['id']

        in_stock = sum(1 for i in stock_items if i.get('category_id') == cat_id)
        assigned = sum(1 for i in issued_items if i.get('category_id') == cat_id)
        total = in_stock + assigned

        category_summaries.append({
            'category': cat_name,
            'in_stock': in_stock,
            'assigned': assigned,
            'total': total
        })


    stock_by_category = defaultdict(lambda: defaultdict(int))  # category_id -> type -> quantity
    for item in stock_items:
        category_id = item.get('category_id')
        type_ = item['type']
        if category_id is not None:
            stock_by_category[category_id][type_] += 1

    stock_by_category_serializable = {}
    for category_id, type_quantities in stock_by_category.items():
        stock_by_category_serializable[str(category_id)] = [
            {'label': type_, 'quantity': qty}
            for type_, qty in type_quantities.items()
        ]

    total_in_store = len(stock_items)
    total_assigned = len(issued_items)
    total_all = total_in_store + total_assigned

    return render_template(
        'dashboard.html',
        categories=categories,
        stock_items=stock_summary,
        category_summaries=category_summaries,
        stock_by_category=stock_by_category_serializable,
        session=session,
        total_in_store=total_in_store,
        total_assigned=total_assigned,
        total_all=total_all,
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

    # Get container_id
    container_id = session.get('container_id')
    if not container_id or not is_valid_uuid(container_id):
        flash("Invalid or missing container. Please select a container.", "danger")
        return redirect_to_dashboard()

    new_type = request.form.get('new_type', '').strip()
    try:
        initial_quantity = int(request.form.get('initial_quantity', 0))
    except ValueError:
        flash("Initial quantity must be a number.", "danger")
        return redirect_to_dashboard()

    sizing_raw = request.form.get('sizing', '')
    sizing = normalize_sizing(sizing_raw)

    if not new_type or initial_quantity < 0:
        flash("Invalid item name or quantity.", "danger")
        return redirect_to_dashboard()

    if len(new_type) > 30:
        flash("Item name exceeds character limit.", "danger")
        return redirect_to_dashboard()

    # Validate category_id
    category_id = request.form.get('category_id')
    if not category_id:
        flash("Please select a category.", "danger")
        return redirect_to_dashboard()

    exists_resp = supabase.table('categories').select('id').eq('id', category_id).execute()
    if not exists_resp.data:
        flash("Invalid category selected.", "danger")
        return redirect_to_dashboard()

    # Check if container has stock already
    query = supabase.table('stock').select('id').ilike('type', new_type)
    if sizing is None:
        query = query.is_('sizing', None)
    else:
        query = query.eq('sizing', sizing)

    query = query.eq('category_id', category_id).eq('container_id', container_id)
    response = query.execute()

    if response.data and len(response.data) > 0:
        flash("Stock type with this name and sizing already exists in the selected category for this container.", "danger")
        return redirect_to_dashboard()

    # Insert
    rows_to_insert = [
        {
            'type': new_type,
            'sizing': sizing,
            'category_id': category_id,
            'container_id': container_id
        }
        for _ in range(initial_quantity)
    ]

    if rows_to_insert:
        insert_resp = supabase.table('stock').insert(rows_to_insert).execute()
        if not insert_resp.data:
            flash("Error inserting stock items.", "danger")
            return redirect_to_dashboard()

    flash(f"Added {initial_quantity} items of type '{new_type}' to this container.", "success")
    return redirect_to_dashboard()

@dashboard_bp.route('/update_stock_batch', methods=['POST'])
@limiter.limit("1 per second")
def update_stock_batch():
    if not has_edit_privileges():
        return "Unauthorized", 403

    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    # Get container_id
    container_id = session.get('container_id')
    if not container_id or not is_valid_uuid(container_id):
        flash("Invalid or missing container. Please select a container.", "danger")
        return redirect_to_dashboard()

    try:
        data = json.loads(request.form['update_data'])
    except Exception:
        flash("Invalid data format.", "danger")
        return redirect_to_dashboard()

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

        query = (
            supabase.table('stock')
            .select('id')
            .eq('type', item_type)
            .eq('category_id', category_id)
            .eq('container_id', container_id)
        )
        if sizing is None:
            query = query.is_('sizing', None)
        else:
            query = query.eq('sizing', sizing)
        current_resp = query.execute()

        current_items = current_resp.data or []
        current_count = len(current_items)

        if new_quantity < current_count:
            # Delete excess items
            ids_to_delete = [itm['id'] for itm in sorted(current_items, key=lambda x: x['id'])[:current_count - new_quantity]]
            del_resp = supabase.table('stock').delete().in_('id', ids_to_delete).execute()
            if not del_resp.data:
                flash(f"Error deleting stock for {item_type} ({sizing})", "danger")

        elif new_quantity > current_count:
            # Insert missing items
            rows_to_insert = [
                {
                    'type': item_type,
                    'sizing': sizing,
                    'category_id': category_id,
                    'container_id': container_id,
                }
                for _ in range(new_quantity - current_count)
            ]
            ins_resp = supabase.table('stock').insert(rows_to_insert).execute()
            if not ins_resp.data:
                flash(f"Error adding stock for {item_type} ({sizing})", "danger")

    flash("Stock updated successfully.", "success")
    return redirect_to_dashboard()


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
        return redirect(redirect_to_dashboard())

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
        return redirect(redirect_to_dashboard())

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

    return redirect(redirect_to_dashboard())

@dashboard_bp.route('/delete_category/<string:category_id>', methods=['POST'])
@limiter.limit("30 per minute")
def delete_category(category_id):
    if session.get('privilege') not in ['admin', 'edit']:
        return redirect(redirect_to_dashboard())

    supabase = get_supabase_client()

    try:
        linked = supabase.table('stock')\
            .select('id')\
            .eq('category_id', category_id)\
            .limit(1)\
            .execute()
        
        if linked.data:
            flash('Category is in use and cannot be deleted.', 'warning')
            return redirect(redirect_to_dashboard())

        # Delete the category
        supabase.table('categories')\
            .delete()\
            .eq('id', category_id)\
            .execute()

        flash('Category deleted successfully.', 'success')
    except Exception as e:
        print(f"Error deleting category: {e}")
        flash('An error occurred while deleting the category.', 'danger')

    return redirect(redirect_to_dashboard())

@dashboard_bp.route('/dashboard')
@limiter.limit("50 per minute")
def dash_default():
    supabase = get_supabase_client()
    containers = supabase.table('containers').select('id').limit(1).execute().data
    if containers:
        container_id = containers[0]['id']
        session['container_id'] = container_id
        return redirect(url_for('dashboard.dashboard', container_id=container_id))
    else:
        flash("No containers found.", "warning")
        return redirect(url_for('home.home'))   