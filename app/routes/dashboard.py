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
    
    try:
        sizing = str(request.form.get('sizing', 0))
    except ValueError:
        return "Invalid quantity", 400

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
        .execute()
    if response.data:
        return "Stock type already exists", 400

    supabase.table('stock').insert({
        'type': new_type,
        'sizing': sizing,
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


# PEOPLE

@dashboard_bp.route('/people')
@limiter.limit("100 per minute")
def people():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    supabase = get_supabase_client()

    # Get stock items with quantity > 0
    response = supabase.table('stock').select("*").gt('quantity', 0).execute()
    stock_items = response.data if response.data else []

    # Get people
    people_response = supabase.table('people').select("*").execute()
    people = people_response.data if people_response.data else []

    if not response.data or not people_response.data:
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