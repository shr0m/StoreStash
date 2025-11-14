from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from app.db import get_supabase_client
import json, re, uuid
from app.utils.otp_utils import redirect_if_password_change_required, get_client_id
from app.utils.audit import log_audit_action
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


from collections import defaultdict

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

    # Sort the stock_summary
    stock_summary = sorted(
        stock_summary,
        key=lambda x: (
            x['category'],                            # First by category
            x['type'] if x['type'] != "None" else '', # Then by type (name)
            x['sizing']                               # Then by sizing
        )
    )

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

    # Pass to template
    return render_template(
        'dashboard.html',
        categories=categories,
        containers=containers,
        stock_items=stock_summary,
        category_summaries=category_summaries,
        stock_by_category=stock_by_category_serializable,
        session=session,
        total_in_store=total_in_store,
        container_name=container_name,
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
    user_id = session.get('user_id')

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

    if initial_quantity > 1000000:
        flash("Item quantity exceeds maximum quantity allowed (1 million assets).", "warning")

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

    container_resp = supabase.table("containers").select("name").eq("id", container_id).single().execute()
    container_name = container_resp.data.get("name") if container_resp.data else "Unknown Container"

    if stock_resp.data:
        stock_id = stock_resp.data[0]['id']
        current_qty = stock_resp.data[0].get('quantity', 0)
        new_qty = current_qty + initial_quantity

        update_resp = supabase.table('stock').update({'quantity': new_qty}) \
            .eq('id', stock_id).eq('client_id', client_id).execute()
        if not update_resp.data:
            flash("Error updating stock quantity.", "danger")
            return redirect_to_dashboard()

        # Log update action
        log_audit_action(
            client_id=client_id,
            user_id=user_id,
            action="update_stock",
            description=f"Updated quantity of '{new_type}' by +{initial_quantity} in container {container_name}.",
        )
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

        stock_id = insert_stock.data[0]['id']

        # Log action
        log_audit_action(
            client_id=client_id,
            user_id=user_id,
            action="create_stock",
            description=f"Added new stock of '{new_type}' ({initial_quantity} units) in container {container_name}."
        )

    flash(f"Added {initial_quantity} items of type '{new_type}' to this container.", "success")
    return redirect_to_dashboard()


@dashboard_bp.route('/update_stock_batch', methods=['POST'])
@limiter.limit("1 per second")
def update_stock_batch():
    if not has_edit_privileges():
        return "Unauthorized", 403

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
    user_id = session.get('user_id')

    for item in data:
        item_type = item.get('type')
        sizing_raw = item.get('sizing', '')
        sizing = normalize_sizing(sizing_raw)

        try:
            new_quantity = int(item.get('quantity', 0))
        except Exception:
            continue

        category_id = item.get('category_id')
        if not item_type or new_quantity < 0 or not category_id or not is_valid_uuid(category_id) or new_quantity > 1000000:
            continue

        # Find/Create item record
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

            # Log creation of a new item
            category_resp = supabase.table("categories").select("category").eq("id", category_id).single().execute()
            category_name = category_resp.data.get("category") if category_resp.data else "Unknown Category"
            log_audit_action(
                client_id=client_id,
                user_id=user_id,
                action="create_item",
                description=f"Created new item '{item_type}' ({sizing}) in category {category_name}."
            )

        # Handle container stock
        stock_resp = supabase.table('stock') \
            .select('id, quantity') \
            .eq('item_id', item_id) \
            .eq('container_id', container_id) \
            .eq('client_id', client_id) \
            .execute()
        stock_data = stock_resp.data or []

        container_resp = supabase.table("containers").select("name").eq("id", container_id).single().execute()
        container_name = container_resp.data.get("name") if container_resp.data else "Unknown Container"

        if stock_data:
            stock_id = stock_data[0]['id']
            old_qty = stock_data[0].get('quantity', 0)

            if new_quantity > 0:
                supabase.table('stock').update({'quantity': new_quantity}) \
                    .eq('id', stock_id).eq('client_id', client_id).execute()

                # Log update
                log_audit_action(
                    client_id=client_id,
                    user_id=user_id,
                    action="update_stock",
                    description=f"Updated stock of '{item_type}' ({sizing}) in container {container_name} from {old_qty} → {new_quantity}."
                )
            else:
                # Set the quantity to 0
                supabase.table('stock').update({'quantity': 0}) \
                    .eq('id', stock_id).eq('client_id', client_id).execute()

                log_audit_action(
                    client_id=client_id,
                    user_id=user_id,
                    action="zero_stock",
                    description=f"Set stock of '{item_type}' ({sizing}) to 0 in container {container_name}."
                )

            # Check if item can be deleted (no remaining stock or issued_stock)
            remaining_stock_resp = supabase.table('stock') \
                .select('id') \
                .eq('item_id', item_id) \
                .eq('client_id', client_id) \
                .limit(1) \
                .execute()

            remaining_issued_stock_resp = supabase.table('issued_stock') \
                .select('id') \
                .eq('item_id', item_id) \
                .eq('client_id', client_id) \
                .limit(1) \
                .execute()

            if not remaining_stock_resp.data and not remaining_issued_stock_resp.data:
                try:
                    supabase.table('items') \
                        .delete() \
                        .eq('id', item_id) \
                        .eq('client_id', client_id) \
                        .execute()

                except Exception:
                    pass
        else:
            if new_quantity > 0:
                supabase.table('stock').insert({
                    'item_id': item_id,
                    'container_id': container_id,
                    'quantity': new_quantity,
                    'client_id': client_id
                }).execute()

                # Log creation
                log_audit_action(
                    client_id=client_id,
                    user_id=user_id,
                    action="create_stock",
                    description=f"Created new stock of '{item_type}' ({sizing}) with quantity {new_quantity} in container {container_name}."
                )

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
    user_id = session.get('user_id')

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

        # Log audit action
        log_audit_action(
            client_id=client_id,
            user_id=user_id,
            action="create_category",
            description=f"Created new category '{category_name}'."
        )
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
    user_id = session.get('user_id')
    current_container_id = session.get('container_id')

    # Fetch the exact stock row
    stock_resp = supabase.table('stock') \
        .select('id, item_id, quantity, container_id, alert_threshold, items(category_id, type, sizing)') \
        .eq('id', stock_id).eq('client_id', client_id).execute()

    stock_items = stock_resp.data or []
    if not stock_items:
        flash("Stock item not found.", "info")
        return redirect_to_dashboard()

    stock_item = stock_items[0]
    item_id = stock_item['item_id']
    current_quantity = stock_item.get('quantity', 0)
    items_data = stock_item.get('items', {})
    current_category_id = items_data.get('category_id')
    item_type = items_data.get('type', 'Unknown')
    item_sizing = items_data.get('sizing')

    # Update alert_threshold for this stock row
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
        
        # Fetch old category name
        old_category_resp = supabase.table("categories").select("category").eq("id", current_category_id).single().execute()
        old_category_name = old_category_resp.data.get("category") if old_category_resp.data else "Unknown Category"

        # Fetch new category name
        new_category_resp = supabase.table("categories").select("category").eq("id", new_category_id).single().execute()
        new_category_name = new_category_resp.data.get("category") if new_category_resp.data else "Unknown Category"

        # Log audit action with category names
        log_audit_action(
            client_id=client_id,
            user_id=user_id,
            action="update_stock_category",
            description=(
                f"Changed category of '{item_type}' ({item_sizing}) "
                f"from '{old_category_name}' to '{new_category_name}'."
            )
        )

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

            # Fetch current container name
            current_container_resp = supabase.table("containers").select("name").eq("id", current_container_id).single().execute()
            current_container_name = current_container_resp.data.get("name") if current_container_resp.data else "Unknown Container"

            # Fetch new container name
            new_container_resp = supabase.table("containers").select("name").eq("id", new_container_id).single().execute()
            new_container_name = new_container_resp.data.get("name") if new_container_resp.data else "Unknown Container"

            # Log audit action with container names
            log_audit_action(
                client_id=client_id,
                user_id=user_id,
                action="transfer_stock",
                description=(
                    f"Transferred {qty_to_transfer} of '{item_type}' ({item_sizing}) "
                    f"from container '{current_container_name}' to '{new_container_name}'."
                )
            )

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
    user_id = session.get('user_id')

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

        # Fetch category name for audit log
        category_resp = supabase.table('categories') \
            .select('category') \
            .eq('id', category_id) \
            .eq('client_id', client_id) \
            .execute()
        category_name = category_resp.data[0]['category'] if category_resp.data else category_id

        # Delete the category for this client
        supabase.table('categories') \
            .delete() \
            .eq('id', category_id) \
            .eq('client_id', client_id) \
            .execute()

        # Log the deletion
        log_audit_action(
            client_id=client_id,
            user_id=user_id,
            action="delete_category",
            description=f"Deleted category '{category_name}'."
        )

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


@dashboard_bp.route('/delete_stock_record', methods=['POST'])
def delete_stock_record():
    if not has_edit_privileges():
        return "Unauthorized", 403

    client_id = get_client_id()
    if not client_id:
        return redirect(url_for('auth.login'))    

    stock_id = request.form.get("stock_id")
    if not stock_id:
        flash("Invalid stock record ID.", "danger")
        return redirect_to_dashboard()

    # Delete the stock record
    supabase = get_supabase_client()

    try:
        # Fetch item id
        id_resp = supabase.table('stock') \
            .select('item_id') \
            .eq('id', stock_id) \
            .eq('client_id', client_id) \
            .execute()

        # Check id_resp data
        if not id_resp.data:
            flash("Stock record not found.", "danger")
            return redirect_to_dashboard()

        # Extract item_id
        item_id = id_resp.data[0].get('item_id')

        if not item_id:
            flash("Associated item not found.", "danger")
            return redirect_to_dashboard()

        # Retrieve stock name
        stock_name_resp = supabase.table('items') \
            .select('type') \
            .eq('id', item_id) \
            .eq('client_id', client_id) \
            .execute()

        # Check data for expected
        if not stock_name_resp.data:
            flash("Item not found.", "danger")
            return redirect_to_dashboard()

        stock_name = stock_name_resp.data[0].get('type')

        # Delete from stock table
        response = supabase.table('stock') \
            .delete() \
            .eq('id', stock_id) \
            .eq('client_id', client_id) \
            .execute()

        # Check if deletion was successful
        if response.data:
            # Log the action
            user_id = session.get('user_id')
            log_audit_action(
                client_id=client_id,
                user_id=user_id,
                action="delete_stock",
                description=f"Deleted stock record {stock_name}."
            )
            flash("Stock record deleted successfully.", "success")

            # Now, check remaining records in stock and issued_stock
            remaining_stock_resp = supabase.table('stock') \
                .select('id') \
                .eq('item_id', item_id) \
                .eq('client_id', client_id) \
                .execute()

            remaining_issued_resp = supabase.table('issued_stock') \
                .select('id') \
                .eq('item_id', item_id) \
                .eq('client_id', client_id) \
                .execute()

            print(remaining_stock_resp.data)
            print()
            print(remaining_issued_resp.data)

            # If no issued/stock records, delete item
            if not remaining_stock_resp.data and not remaining_issued_resp.data:
                # Delete item record
                delete_item_response = supabase.table('items') \
                    .delete() \
                    .eq('id', item_id) \
                    .eq('client_id', client_id) \
                    .execute()
        else:
            flash(f"Failed to delete stock record. Error: {response.error['message']}", "danger")
        
    except Exception as e:
        flash(f"Error deleting stock record: {str(e)}", "danger")

    return redirect_to_dashboard()


