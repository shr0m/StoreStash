from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from app.db import get_supabase_client
import json, re
from app import limiter

dashboard_bp = Blueprint('dashboard', __name__)

def has_edit_privileges():
    return session.get('privilege') in ['admin', 'edit']

@dashboard_bp.route('/')
@limiter.limit("100 per minute")
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    supabase = get_supabase_client()

    # Group by type and sizing, count the number of items per group
    response = supabase.table('stock')\
        .select('type, sizing, id', count='exact')\
        .execute()
    stock_items = response.data or []

    # Aggregate counts by type and sizing (since Supabase might not support group by directly in this method)
    aggregated = {}
    for item in stock_items:
        key = (item['type'], item['sizing'])
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

    new_type = request.form.get('new_type', '').strip()
    try:
        initial_quantity = int(request.form.get('initial_quantity', 0))
    except ValueError:
        return "Invalid quantity", 400
    
    sizing = request.form.get('sizing', '').strip()

    if not new_type or initial_quantity < 0:
        return "Invalid input", 400
    
    if len(new_type) > 30:
        flash("Character limit exceeded", "danger")
        return redirect(url_for('dashboard.dashboard'))

    supabase = get_supabase_client()

    # Check if stock type already exists (case-insensitive)
    response = supabase.table('stock')\
        .select('id')\
        .ilike('type', new_type)\
        .eq('sizing', sizing)\
        .execute()
    if response.data:
        return "Stock type already exists", 400

    # Insert one record per item
    rows_to_insert = [{'type': new_type, 'sizing': sizing} for _ in range(initial_quantity)]
    if rows_to_insert:
        supabase.table('stock').insert(rows_to_insert).execute()

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

    # Expected data format:
    # [{ 'type': 'widget', 'sizing': 'small', 'quantity': 5 }, ...]

    for item in data:
        item_type = item.get('type')
        sizing = item.get('sizing')
        try:
            quantity = int(item.get('quantity', 0))
        except Exception:
            continue

        if not item_type or sizing is None:
            continue

        # Get current items of this type and sizing
        current_resp = supabase.table('stock')\
            .select('id')\
            .eq('type', item_type)\
            .eq('sizing', sizing)\
            .execute()

        current_items = current_resp.data or []
        current_count = len(current_items)

        if quantity < current_count:
            # Delete excess items (oldest or arbitrary)
            ids_to_delete = [item['id'] for item in current_items[:current_count - quantity]]
            for item_id in ids_to_delete:
                supabase.table('stock').delete().eq('id', item_id).execute()
        elif quantity > current_count:
            # Insert new items
            rows_to_insert = [{'type': item_type, 'sizing': sizing} for _ in range(quantity - current_count)]
            if rows_to_insert:
                supabase.table('stock').insert(rows_to_insert).execute()

    flash("Stock file updated.", "success")
    return redirect(url_for('dashboard.dashboard'))


# PEOPLE

@dashboard_bp.route('/people')
@limiter.limit("100 per minute")
def people():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    supabase = get_supabase_client()

    # Get all stock items (since we can't filter by quantity anymore)
    response = supabase.table('stock').select("*").execute()
    stock_data = response.data if response.data else []

    # Group by (type, sizing) to get dropdown-ready stock_items
    grouped_stock = {}
    for item in stock_data:
        key = (item.get('type'), item.get('sizing'))
        grouped_stock[key] = grouped_stock.get(key, 0) + 1

    # Reformat for dropdown: list of dicts like {'type': ..., 'sizing': ..., 'count': ...}
    stock_items = [
        {'type': k[0], 'sizing': k[1], 'count': v}
        for k, v in grouped_stock.items()
        if v > 0  # Only include if there's at least one item
    ]

    # Get people
    people_response = supabase.table('people').select("*").execute()
    people = people_response.data if people_response.data else []

    if not stock_data or not people_response.data:
        flash("Could not load data.", "danger")

    # Define rank priority (ensure lowercase keys for normalization)
    rank_order = {
        'cadet': 4,
        'corporal': 3,
        'sergeant': 2,
        'flight sergeant': 1,
        'cadet warrant officer': 0
    }

    def get_surname(full_name):
        if not full_name:
            return ''
        return full_name.strip().split()[-1].lower()

    def get_rank_priority(rank):
        if not rank:
            return -1  # Unknown ranks go to the bottom
        return rank_order.get(rank.strip().lower(), -1)

    # Sort by rank priority, then surname (case-insensitive)
    people.sort(key=lambda p: (
        get_rank_priority(p.get('rank')),
        get_surname(p.get('name'))
    ))

    return render_template("people.html", stock_items=stock_items, people=people)



@dashboard_bp.route('/add_person', methods=['POST'])
@limiter.limit("2 per second")
def add_person():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    name = request.form.get('name', '').strip()
    rank = request.form.get('rank', '').strip()

    # Valid ranks
    valid_ranks = {
        'Cadet',
        'Corporal',
        'Sergeant',
        'Flight Sergeant',
        'Cadet Warrant Officer'
    }

    # Validate name: only letters, spaces, and hyphens
    if not name or not re.fullmatch(r"[A-Za-z\- ]+", name):
        flash("Name must contain only letters, spaces, or hyphens.", "danger")
        return redirect(url_for('dashboard.people'))

    # Validate rank
    if rank not in valid_ranks:
        flash("Invalid rank selected.", "danger")
        return redirect(url_for('dashboard.people'))

    supabase = get_supabase_client()

    try:
        response = supabase.table('people').insert({
            'name': name.upper(),
            'rank': rank
        }).execute()

        if not response.data:
            flash("Failed to add person. Please try again.", "danger")
        else:
            flash("Person added successfully.", "success")

    except Exception as e:
        flash(f"An error occurred: {str(e)}", "danger")

    return redirect(url_for('dashboard.people'))


@dashboard_bp.route('/delete_person', methods=['POST'])
@limiter.limit("2 per second")
def delete_person():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    name = request.form.get('name')
    if not name:
        flash("Invalid request.", "danger")
        return redirect(url_for('dashboard.people'))

    supabase = get_supabase_client()

    try:
        supabase.table('people').delete().eq('name', name).execute()
        flash(f"{name} was deleted.", "success")
    except Exception as e:
        flash(f"Error deleting {name}: {str(e)}", "danger")

    return redirect(url_for('dashboard.people'))

@dashboard_bp.route('/assign_item', methods=['POST'])
@limiter.limit("2 per second")
def assign_item():
    if session.get('privilege') not in ['admin', 'edit']:
        flash('Unauthorized', 'danger')
        return redirect('/people')

    supabase = get_supabase_client()

    person_name = request.form.get('person_name')
    item_type = request.form.get('type')
    quantity = request.form.get('quantity', type=int)
    note = request.form.get('note', '')

    if not person_name or not item_type or not quantity or quantity < 1:
        flash('Invalid input data.', 'danger')
        return redirect('/people')

    try:
        # 1. Get person id by name
        person_resp = supabase.table('people').select('id').eq('name', person_name).single().execute()
        if not person_resp.data:
            flash("Person not found.", "danger")
            return redirect('/people')
        person_id = person_resp.data['id']

        # 2. Get stock item by type
        stock_resp = supabase.table('stock').select('id, quantity').eq('type', item_type).single().execute()
        if not stock_resp.data:
            flash("Item type not found in stock.", "danger")
            return redirect('/people')
        stock_item = stock_resp.data

        if stock_item['quantity'] < quantity:
            flash(f"Not enough stock for {item_type}. Available: {stock_item['quantity']}", "danger")
            return redirect('/people')

        # 3. Insert individual kit_issue records for each item assigned
        for _ in range(quantity):
            insert_resp = supabase.table('kit_issue').insert({
                'person_id': person_id,
                'type': item_type,
                'quantity': 1,
                'note': note
            }).execute()

            if insert_resp.data is None:
                flash(f"Error creating issued item.", "danger")
                return redirect('/people')

        # 4. Update stock quantity after assignment
        new_stock_quantity = stock_item['quantity'] - quantity
        stock_update_resp = supabase.table('stock').update({
            'quantity': new_stock_quantity
        }).eq('id', stock_item['id']).execute()

        if stock_update_resp.data is None:
            flash(f"Error updating stock quantity.", "danger")
            return redirect('/people')

        flash(f"Assigned {quantity} x {item_type} to {person_name}.", "success")

    except Exception as e:
        flash(f"Unexpected error: {str(e)}", "danger")

    return redirect('/people')