from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from app.db import get_supabase_client
import json, re, uuid
from app.utils.otp_utils import redirect_if_password_change_required, get_client_id
from app import limiter
from collections import defaultdict
from postgrest.exceptions import APIError

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
@limiter.limit("3 per second")
def dashboard(container_id):
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    
    # Check client_id valid
    client_id = get_client_id()
    if not client_id:
        flash("Invalid client_id", "danger")
        return redirect(url_for('auth.login'))

    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    if not is_valid_uuid(container_id):
        flash("Invalid container ID format.", "danger")
        return redirect(url_for('home.home'))

    supabase = get_supabase_client()

    # Validate container for this client
    container_check_resp = supabase.table('containers') \
        .select('id, name') \
        .eq('id', container_id) \
        .eq('client_id', client_id) \
        .execute()

    container_check = container_check_resp.data if container_check_resp else None

    if not container_check:
        flash("Invalid container selected.", "danger")
        return redirect(url_for('home.home'))

    session['container_id'] = container_id
    container_name = container_check[0]['name']

    # Fetch containers for dropdowns for this client
    containers_response = supabase.table('containers') \
        .select('id, name') \
        .eq('client_id', client_id) \
        .order('name').execute()
    containers = containers_response.data or []

    # Fetch all categories for this client
    categories_response = supabase.table('categories') \
        .select('*') \
        .eq('client_id', client_id) \
        .order('category').execute()
    categories = categories_response.data or []

    # Fetch stock items for the selected container and client
    stock_items_response = supabase.table('stock') \
        .select('id, quantity, container_id, alert_threshold, item_id, items(type, sizing, category_id, categories(category))') \
        .eq('container_id', container_id) \
        .eq('client_id', client_id) \
        .execute()
    stock_items = stock_items_response.data or []

    # Format summary data
    stock_summary = []
    for s in stock_items:
        item = s.get('items', {}) or {}
        category_info = item.get('categories', {}) or {}

        stock_summary.append({
            'id': s['id'],
            'type': item.get('type'),
            'sizing': item.get('sizing'),
            'quantity': s.get('quantity', 0),
            'category': category_info.get('category', 'Unknown'),
            'category_id': item.get('category_id'),
            'alert_threshold': s.get('alert_threshold')
        })

    # Summarize per category
    category_summaries = []
    for cat in categories:
        cat_id = cat['id']
        in_stock = sum(i.get('quantity', 0) for i in stock_summary if i.get('category_id') == cat_id)
        category_summaries.append({
            'category': cat['category'],
            'in_stock': in_stock
        })

    # Build chart data
    stock_by_category = defaultdict(lambda: defaultdict(int))
    for item in stock_summary:
        category_id = item.get('category_id')
        type_ = item.get('type')
        qty = item.get('quantity', 0)
        if category_id:
            stock_by_category[category_id][type_] += qty

    stock_by_category_serializable = {
        str(cat_id): [{'label': type_, 'quantity': qty} for type_, qty in type_quantities.items()]
        for cat_id, type_quantities in stock_by_category.items()
    }

    total_in_store = sum(item.get('quantity', 0) for item in stock_summary)

    return render_template(
        'dashboard.html',
        categories=categories,
        containers=containers,
        stock_items=stock_summary,
        category_summaries=category_summaries,
        stock_by_category=stock_by_category_serializable,
        session=session,
        total_in_store=total_in_store,
        container_name=container_name
    )


@dashboard_bp.route('/add_stock_type', methods=['POST'])
@limiter.limit("1 per second")
def add_stock_type():
    if not has_edit_privileges():
        return "Unauthorized", 403

    # Check client_id valid
    client_id = get_client_id()
    if not client_id:
        flash("Invalid client_id", "danger")
        return redirect(url_for('auth.login'))

    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    supabase = get_supabase_client()

    container_id = session.get('container_id')
    if not container_id or not is_valid_uuid(container_id):
        flash("Invalid or missing container. Please select a container.", "danger")
        return redirect_to_dashboard()

    new_type = request.form.get('new_type', '').strip()
    sizing_raw = request.form.get('sizing', '')
    sizing = normalize_sizing(sizing_raw)
    category_id = request.form.get('category_id')

    try:
        initial_quantity = int(request.form.get('initial_quantity', 0))
    except ValueError:
        flash("Initial quantity must be a number.", "danger")
        return redirect_to_dashboard()

    if not new_type or initial_quantity < 0:
        flash("Invalid item name or quantity.", "danger")
        return redirect_to_dashboard()

    if len(new_type) > 30:
        flash("Item name exceeds character limit.", "danger")
        return redirect_to_dashboard()

    if not category_id:
        flash("Please select a category.", "danger")
        return redirect_to_dashboard()

    # Validate category for this client
    exists_resp = supabase.table('categories').select('id') \
        .eq('id', category_id).eq('client_id', client_id).execute()
    if not exists_resp.data:
        flash("Invalid category selected.", "danger")
        return redirect_to_dashboard()

    # Check if item type already exists for this client
    item_query = supabase.table('items') \
        .select('id') \
        .eq('type', new_type) \
        .eq('category_id', category_id) \
        .eq('client_id', client_id)

    item_query = item_query.is_('sizing', None) if sizing is None else item_query.eq('sizing', sizing)
    item_resp = item_query.execute()

    if item_resp.data:
        item_id = item_resp.data[0]['id']
    else:
        # Insert new item definition
        insert_item = supabase.table('items').insert({
            'type': new_type,
            'sizing': sizing,
            'category_id': category_id,
            'client_id': client_id
        }).execute()

        if not insert_item.data:
            flash("Error creating new item type.", "danger")
            return redirect_to_dashboard()

        item_id = insert_item.data[0]['id']

    # Check if stock already exists in this container for this client
    stock_resp = supabase.table('stock').select('id, quantity') \
        .eq('item_id', item_id) \
        .eq('container_id', container_id) \
        .eq('client_id', client_id) \
        .execute()

    if stock_resp.data:
        stock_id = stock_resp.data[0]['id']
        current_qty = stock_resp.data[0].get('quantity', 0)
        new_qty = current_qty + initial_quantity

        update_resp = supabase.table('stock').update({'quantity': new_qty}) \
            .eq('id', stock_id).eq('client_id', client_id).execute()
        if not update_resp.data:
            flash("Error updating stock quantity.", "danger")
            return redirect_to_dashboard()
    else:
        insert_stock = supabase.table('stock').insert({
            'item_id': item_id,
            'container_id': container_id,
            'quantity': initial_quantity,
            'client_id': client_id
        }).execute()

        if not insert_stock.data:
            flash("Error inserting stock record.", "danger")
            return redirect_to_dashboard()

    flash(f"Added {initial_quantity} items of type '{new_type}' to this container.", "success")
    return redirect_to_dashboard()


@dashboard_bp.route('/update_stock_batch', methods=['POST'])
@limiter.limit("1 per second")
def update_stock_batch():
    if not has_edit_privileges():
        return "Unauthorized", 403

    # Check client_id valid
    client_id = get_client_id()
    if not client_id:
        flash("Invalid client_id", "danger")
        return redirect(url_for('auth.login'))    
    
    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    container_id = session.get('container_id')
    if not container_id or not is_valid_uuid(container_id):
        flash("Invalid or missing container. Please select a container.", "danger")
        return redirect_to_dashboard()

    raw_update_data = request.form.get("update_data", "").strip()
    if not raw_update_data:
        flash("No update data received.", "danger")
        return redirect_to_dashboard()

    try:
        data = json.loads(raw_update_data)
    except Exception as e:
        flash("Invalid data format.", "danger")
        print("JSON parse error:", e, "Raw input:", raw_update_data)
        return redirect_to_dashboard()

    supabase = get_supabase_client()

    for item in data:
        item_type = item.get('type')
        sizing_raw = item.get('sizing', '')
        sizing = normalize_sizing(sizing_raw)

        try:
            new_quantity = int(item.get('quantity', 0))
        except Exception:
            continue

        category_id = item.get('category_id')
        if not item_type or new_quantity < 0 or not category_id or not is_valid_uuid(category_id):
            continue

        # Find/Create item record for this client
        item_query = supabase.table('items') \
            .select('id') \
            .eq('type', item_type) \
            .eq('category_id', category_id) \
            .eq('client_id', client_id)
        item_query = item_query.is_('sizing', None) if sizing is None else item_query.eq('sizing', sizing)
        item_resp = item_query.execute()
        item_data = item_resp.data or []

        if item_data:
            item_id = item_data[0]['id']
        else:
            new_item = supabase.table('items').insert({
                'type': item_type,
                'sizing': sizing,
                'category_id': category_id,
                'client_id': client_id
            }).execute()

            if not new_item.data:
                print(f"Error creating item: {item_type} ({sizing})")
                continue

            item_id = new_item.data[0]['id']

        # Handle container stock for this client
        stock_resp = supabase.table('stock') \
            .select('id, quantity') \
            .eq('item_id', item_id) \
            .eq('container_id', container_id) \
            .eq('client_id', client_id) \
            .execute()
        stock_data = stock_resp.data or []

        if stock_data:
            stock_id = stock_data[0]['id']
            if new_quantity > 0:
                supabase.table('stock').update({'quantity': new_quantity}) \
                    .eq('id', stock_id).eq('client_id', client_id).execute()
            else:
                supabase.table('stock').delete().eq('id', stock_id).eq('client_id', client_id).execute()

                # Check if any other stock exists for this item
                remaining_stock_resp = supabase.table('stock') \
                    .select('id') \
                    .eq('item_id', item_id) \
                    .eq('client_id', client_id) \
                    .limit(1) \
                    .execute()
                if not remaining_stock_resp.data:
                    try:
                        supabase.table('items') \
                            .delete() \
                            .eq('id', item_id) \
                            .eq('client_id', client_id) \
                            .execute()
                    except APIError:
                        pass
        else:
            if new_quantity > 0:
                supabase.table('stock').insert({
                    'item_id': item_id,
                    'container_id': container_id,
                    'quantity': new_quantity,
                    'client_id': client_id
                }).execute()

    flash("Stock updated successfully.", "success")
    return redirect_to_dashboard()



@dashboard_bp.route('/add_category', methods=['POST'])
@limiter.limit("1 per second")
def add_category():

    # Check client_id valid
    client_id = get_client_id()
    if not client_id:
        flash("Invalid client_id", "danger")
        return redirect(url_for('auth.login'))

    if session.get('privilege') not in ['admin', 'edit']:
        flash("You don't have permission to add categories.", "danger")
        return redirect('/')

    category_name = request.form.get('category_name', '').strip()

    if not category_name:
        flash("Category name cannot be empty.", "warning")
        return redirect_to_dashboard()
    
    if not re.match(r'^[A-Za-z0-9\-\(\)\s]+$', category_name):
        flash("Category names cannot contain forbidden characters.", "danger")
        return redirect_to_dashboard()

    supabase = get_supabase_client()

    # Check if category already exists for this client
    existing = supabase.table('categories') \
        .select('id') \
        .eq('category', category_name) \
        .eq('client_id', client_id) \
        .execute()
    if existing.data and len(existing.data) > 0:
        flash("Category already exists.", "info")
        return redirect_to_dashboard()

    # Insert new category with client_id
    ins_resp = supabase.table('categories').insert({
        'category': category_name,
        'client_id': client_id
    }).execute()

    if ins_resp.data:
        flash(f"Category '{category_name}' added successfully.", "success")
    else:
        flash("Error adding category. Please try again.", "danger")

    return redirect_to_dashboard()

def get_stock_overview(client_id):
    supabase = get_supabase_client()

    # Fetch stock only for this client
    stock_resp = (
        supabase.table('stock')
        .select('category_id, quantity, categories(category)')
        .eq('client_id', client_id)
        .execute()
    )
    stock_data = stock_resp.data or []

    summary = defaultdict(lambda: {'category': '', 'in_stock': 0})

    for item in stock_data:
        cat_id = item['category_id']
        cat_name = item.get('categories', {}).get('category', 'Unknown')
        qty = item.get('quantity', 0) or 0

        summary[cat_id]['category'] = cat_name
        summary[cat_id]['in_stock'] += qty

    # Convert to list sorted by category name
    category_summaries = sorted(summary.values(), key=lambda x: x['category'])

    # Total across all categories
    total_in_store = sum(x['in_stock'] for x in category_summaries)

    return {
        'category_summaries': category_summaries,
        'total_in_store': total_in_store
    }

@dashboard_bp.route('/update_stock_settings', methods=['POST'])
@limiter.limit("1 per second")
def update_stock_settings():
    if not has_edit_privileges():
        return "Unauthorized", 403

    client_id = get_client_id()
    if not client_id:
        flash("Invalid client_id", "danger")
        return redirect(url_for('auth.login'))

    stock_id = request.form.get('stock_id')
    new_category_id = request.form.get('category_id')
    new_container_id = request.form.get('container_id')
    transfer_quantity_raw = request.form.get('transfer_quantity')
    alert_threshold_raw = request.form.get('alert_threshold')

    transfer_quantity = int(transfer_quantity_raw) if transfer_quantity_raw else None
    try:
        alert_threshold = int(alert_threshold_raw)
    except (TypeError, ValueError):
        alert_threshold = None

    if not stock_id:
        flash("No stock selected.", "danger")
        return redirect_to_dashboard()

    supabase = get_supabase_client()
    current_container_id = session.get('container_id')

    # Fetch the exact stock row
    stock_resp = supabase.table('stock') \
        .select('id, item_id, quantity, container_id, alert_threshold, items(category_id)') \
        .eq('id', stock_id).eq('client_id', client_id).execute()

    stock_items = stock_resp.data or []
    if not stock_items:
        flash("Stock item not found.", "info")
        return redirect_to_dashboard()

    stock_item = stock_items[0]
    item_id = stock_item['item_id']
    current_quantity = stock_item.get('quantity', 0)
    items_data = stock_item.get('items')
    current_category_id = items_data['category_id'] if items_data else None

    # Update alert_threshold for this exact stock row
    if alert_threshold is None or alert_threshold == 0:
        supabase.table('stock').update({'alert_threshold': None}) \
            .eq('id', stock_id).eq('client_id', client_id).execute()
    else:
        supabase.table('stock').update({'alert_threshold': alert_threshold}) \
            .eq('id', stock_id).eq('client_id', client_id).execute()


    # Update category if changed
    if new_category_id and new_category_id != current_category_id:
        supabase.table('items').update({'category_id': new_category_id}) \
            .eq('id', item_id).eq('client_id', client_id).execute()

    # Container transfer logic
    if new_container_id and new_container_id != current_container_id:
        qty_to_transfer = transfer_quantity if transfer_quantity and transfer_quantity > 0 else current_quantity
        remaining_quantity = current_quantity - qty_to_transfer

        # Update or delete original stock
        if remaining_quantity > 0:
            supabase.table('stock').update({'quantity': remaining_quantity}).eq('id', stock_id).eq('client_id', client_id).execute()
        else:
            supabase.table('stock').delete().eq('id', stock_id).eq('client_id', client_id).execute()

        # Merge or insert into target container
        target_resp = supabase.table('stock').select('id, quantity').eq('item_id', item_id) \
            .eq('container_id', new_container_id).eq('client_id', client_id).execute()
        target_items = target_resp.data or []

        if target_items:
            new_qty = target_items[0]['quantity'] + qty_to_transfer
            supabase.table('stock').update({'quantity': new_qty, 'alert_threshold': alert_threshold}) \
                .eq('id', target_items[0]['id']).eq('client_id', client_id).execute()
        else:
            supabase.table('stock').insert({
                'item_id': item_id,
                'container_id': new_container_id,
                'quantity': qty_to_transfer,
                'alert_threshold': alert_threshold,
                'client_id': client_id
            }).execute()

    flash("Stock settings updated successfully.", "success")
    return redirect_to_dashboard()


@dashboard_bp.route('/delete_category/<string:category_id>', methods=['POST'])
@limiter.limit("1 per second")
def delete_category(category_id):
    if session.get('privilege') not in ['admin', 'edit']:
        return redirect_to_dashboard()

    # Check client_id valid
    client_id = get_client_id()
    if not client_id:
        flash("Invalid client_id", "danger")
        return redirect(url_for('auth.login'))

    supabase = get_supabase_client()

    try:
        # Check if any stock items use this category for this client
        linked = supabase.table('items') \
            .select('id') \
            .eq('category_id', category_id) \
            .eq('client_id', client_id) \
            .limit(1) \
            .execute()
        
        if linked.data:
            flash('Category is in use and cannot be deleted.', 'warning')
            return redirect_to_dashboard()

        # Delete the category for this client
        supabase.table('categories') \
            .delete() \
            .eq('id', category_id) \
            .eq('client_id', client_id) \
            .execute()

        flash('Category deleted successfully.', 'success')
    except Exception as e:
        print(f"Error deleting category: {e}")
        flash('An error occurred while deleting the category.', 'danger')

    return redirect_to_dashboard()


@dashboard_bp.route('/dashboard')
@limiter.limit("3 per second")
def dash_default():
    supabase = get_supabase_client()

    # Check client_id valid
    client_id = get_client_id()
    if not client_id:
        flash("Invalid client_id", "danger")
        return redirect(url_for('auth.login'))

    # Get first container for this client
    containers_resp = supabase.table('containers') \
        .select('id') \
        .eq('client_id', client_id) \
        .limit(1) \
        .execute()

    containers = containers_resp.data or []

    if containers:
        container_id = containers[0]['id']
        session['container_id'] = container_id
        return redirect(url_for('dashboard.dashboard', container_id=container_id))
    else:
        flash("No containers found.", "warning")
        return redirect(url_for('home.home'))