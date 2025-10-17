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
@limiter.limit("3 per second")
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

    # Validate container
    container_check = supabase.table('containers').select('id, name').eq('id', container_id).execute()
    if not container_check.data:
        flash("Invalid container selected.", "danger")
        return redirect(url_for('home.home'))

    session['container_id'] = container_id
    container_name = container_check.data[0]['name']

    # Fetch containers for dropdowns
    containers_response = supabase.table('containers').select('id, name').order('name').execute()
    containers = containers_response.data or []

    # Fetch all categories
    categories_response = supabase.table('categories').select('*').order('category').execute()
    categories = categories_response.data if categories_response else []

    # ✅ Fetch stock joined with items + categories
    stock_items_response = (
        supabase.table('stock')
        .select('id, quantity, container_id, alert_threshold, item_id, items(type, sizing, category_id, categories(category))')
        .eq('container_id', container_id)
        .execute()
    )
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
            'alert_threshold': s.get('alert_threshold')  # ✅ from stock table
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
    from collections import defaultdict
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

    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    supabase = get_supabase_client()

    # Validate container
    container_id = session.get('container_id')
    if not container_id or not is_valid_uuid(container_id):
        flash("Invalid or missing container. Please select a container.", "danger")
        return redirect_to_dashboard()

    # Get form inputs
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

    # Validate category exists
    category_resp = supabase.table('categories').select('id').eq('id', category_id).execute()
    if not category_resp.data:
        flash("Invalid category selected.", "danger")
        return redirect_to_dashboard()

    # Find item
    item_query = supabase.table('items').select('id').eq('type', new_type).eq('category_id', category_id)
    item_query = item_query.is_('sizing', None) if sizing is None else item_query.eq('sizing', sizing)
    item_resp = item_query.execute()

    if item_resp.data:
        item_id = item_resp.data[0]['id']
    else:
        # Create new item
        insert_item = supabase.table('items').insert({
            'type': new_type,
            'sizing': sizing,
            'category_id': category_id
        }).execute()
        if not insert_item.data:
            flash("Error creating new item type.", "danger")
            return redirect_to_dashboard()
        item_id = insert_item.data[0]['id']

    # Find stock
    stock_resp = (
        supabase.table('stock')
        .select('id, quantity')
        .eq('item_id', item_id)
        .eq('container_id', container_id)
        .execute()
    )

    if stock_resp.data:
        # Stock exists, increment quantity
        stock_id = stock_resp.data[0]['id']
        current_qty = stock_resp.data[0].get('quantity', 0)
        new_qty = current_qty + initial_quantity

        update_resp = supabase.table('stock').update({'quantity': new_qty}).eq('id', stock_id).execute()
        if not update_resp.data:
            flash("Error updating stock quantity.", "danger")
            return redirect_to_dashboard()
    else:
        # Stock does not exist, insert new stock row
        insert_stock = supabase.table('stock').insert({
            'item_id': item_id,
            'container_id': container_id,
            'quantity': initial_quantity
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

        # Find/Create item record
        item_query = (
            supabase.table('items')
            .select('id')
            .eq('type', item_type)
            .eq('category_id', category_id)
        )
        item_query = item_query.is_('sizing', None) if sizing is None else item_query.eq('sizing', sizing)
        item_resp = item_query.execute()
        item_data = item_resp.data or []

        if item_data:
            item_id = item_data[0]['id']
        else:
            # Insert new definition if missing
            new_item = supabase.table('items').insert({
                'type': item_type,
                'sizing': sizing,
                'category_id': category_id
            }).execute()

            if not new_item.data:
                print(f"Error creating item: {item_type} ({sizing})")
                continue

            item_id = new_item.data[0]['id']

        # Handle container stock
        stock_resp = (
            supabase.table('stock')
            .select('id, quantity')
            .eq('item_id', item_id)
            .eq('container_id', container_id)
            .execute()
        )
        stock_data = stock_resp.data or []

        if stock_data:
            stock_id = stock_data[0]['id']
            if new_quantity > 0:
                # Update stock quantity
                supabase.table('stock').update({'quantity': new_quantity}).eq('id', stock_id).execute()
            else:
                # Delete stock
                supabase.table('stock').delete().eq('id', stock_id).execute()
                remaining_stock_resp = supabase.table('stock').select('id').eq('item_id', item_id).execute()
                if not remaining_stock_resp.data:
                    supabase.table('items').delete().eq('id', item_id).execute()
        else:
            # Check positive quantity insert
            if new_quantity > 0:
                supabase.table('stock').insert({
                    'item_id': item_id,
                    'container_id': container_id,
                    'quantity': new_quantity
                }).execute()

    flash("Stock updated successfully.", "success")
    return redirect_to_dashboard()



@dashboard_bp.route('/add_category', methods=['POST'])
@limiter.limit("1 per second")
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
        return redirect_to_dashboard()

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

    stock_resp = (
        supabase.table('stock')
        .select('category_id, quantity, categories(category)')
        .execute()
    )
    stock_data = stock_resp.data or []

    from collections import defaultdict
    summary = defaultdict(lambda: {'category': '', 'in_stock': 0})

    for item in stock_data:
        cat_id = item['category_id']
        cat_name = item.get('categories', {}).get('category', 'Unknown')
        qty = item.get('quantity', 0) or 0

        summary[cat_id]['category'] = cat_name
        summary[cat_id]['in_stock'] += qty

    # Convert to list sorted by category name
    category_summaries = sorted(summary.values(), key=lambda x: x['category'])

    # Total across all cats
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

    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    # Form data
    item_type = request.form.get('type')
    sizing_raw = request.form.get('sizing')
    sizing = normalize_sizing(sizing_raw)
    new_category_id = request.form.get('category_id')
    new_container_id = request.form.get('container_id')
    transfer_quantity_raw = request.form.get('transfer_quantity')
    alert_threshold_raw = request.form.get('alert_threshold')

    transfer_quantity = int(transfer_quantity_raw) if transfer_quantity_raw else None
    alert_threshold = int(alert_threshold_raw) if alert_threshold_raw else None  # None = NULL

    if not item_type:
        flash("Invalid input provided.", "danger")
        return redirect_to_dashboard()

    supabase = get_supabase_client()
    current_container_id = session.get('container_id')

    stock_query = (
        supabase.table('stock')
        .select('id, item_id, quantity, alert_threshold, container_id, items(type, sizing, category_id)')
        .eq('container_id', current_container_id)
        .eq('items.type', item_type)
    )
    stock_query = stock_query.is_('items.sizing', None) if sizing is None else stock_query.eq('items.sizing', sizing)
    stock_resp = stock_query.execute()
    stock_items = stock_resp.data or []

    if not stock_items:
        flash("No matching stock items found in this container.", "info")
        return redirect_to_dashboard()

    stock_item = stock_items[0]
    stock_id = stock_item['id']
    item_id = stock_item['item_id']
    current_quantity = stock_item.get('quantity', 0)
    current_category_id = stock_item.get('items', {}).get('category_id')

    update_data = {'alert_threshold': alert_threshold}

    # Category transfers
    if new_category_id and new_category_id != current_category_id:
        supabase.table('items').update({'category_id': new_category_id}).eq('id', item_id).execute()

        # Also update issued_stock category references
        issued_matches = supabase.table('issued_stock').select('id').eq('category_id', current_category_id).execute()
        if issued_matches.data:
            supabase.table('issued_stock').update({'category_id': new_category_id}).eq('category_id', current_category_id).execute()

    # Container transfers
    if new_container_id and new_container_id != current_container_id:
        if transfer_quantity and transfer_quantity > 0:
            if transfer_quantity > current_quantity:
                flash("Not enough items to transfer.", "danger")
                return redirect_to_dashboard()

            remaining_quantity = current_quantity - transfer_quantity

            # Decrease quantity in current container
            if remaining_quantity > 0:
                supabase.table('stock').update({'quantity': remaining_quantity, **update_data}).eq('id', stock_id).execute()
            else:
                supabase.table('stock').delete().eq('id', stock_id).execute()

            # Add to target container
            target_query = (
                supabase.table('stock')
                .select('id, quantity')
                .eq('item_id', item_id)
                .eq('container_id', new_container_id)
            )
            target_resp = target_query.execute()
            target_items = target_resp.data or []

            if target_items:
                new_qty = target_items[0]['quantity'] + transfer_quantity
                supabase.table('stock').update({'quantity': new_qty, 'alert_threshold': alert_threshold}).eq('id', target_items[0]['id']).execute()
            else:
                supabase.table('stock').insert({
                    'item_id': item_id,
                    'container_id': new_container_id,
                    'quantity': transfer_quantity,
                    'alert_threshold': alert_threshold
                }).execute()
        else:
            # Full transfer
            target_query = (
                supabase.table('stock')
                .select('id, quantity')
                .eq('item_id', item_id)
                .eq('container_id', new_container_id)
            )
            target_resp = target_query.execute()
            target_items = target_resp.data or []

            if target_items:
                new_qty = target_items[0]['quantity'] + current_quantity
                supabase.table('stock').update({'quantity': new_qty, 'alert_threshold': alert_threshold}).eq('id', target_items[0]['id']).execute()
                supabase.table('stock').delete().eq('id', stock_id).execute()
            else:
                update_data['container_id'] = new_container_id
                supabase.table('stock').update(update_data).eq('id', stock_id).execute()
    else:
        # No container transfer
        supabase.table('stock').update(update_data).eq('id', stock_id).execute()

    flash("Stock settings updated successfully.", "success")
    return redirect_to_dashboard()


@dashboard_bp.route('/delete_category/<string:category_id>', methods=['POST'])
@limiter.limit("1 per second")
def delete_category(category_id):
    if session.get('privilege') not in ['admin', 'edit']:
        return redirect_to_dashboard()

    supabase = get_supabase_client()

    try:
        linked = supabase.table('stock')\
            .select('id')\
            .eq('category_id', category_id)\
            .limit(1)\
            .execute()
        
        if linked.data:
            flash('Category is in use and cannot be deleted.', 'warning')
            return redirect_to_dashboard()

        # Delete the category
        supabase.table('categories')\
            .delete()\
            .eq('id', category_id)\
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
    containers = supabase.table('containers').select('id').limit(1).execute().data
    if containers:
        container_id = containers[0]['id']
        session['container_id'] = container_id
        return redirect(url_for('dashboard.dashboard', container_id=container_id))
    else:
        flash("No containers found.", "warning")
        return redirect(url_for('home.home'))   