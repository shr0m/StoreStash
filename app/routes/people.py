from app.extensions import limiter
from app.db import get_supabase_client
from app.utils.otp_utils import redirect_if_password_change_required
from flask import redirect, url_for, flash, render_template, session, request, Blueprint
import re

people_bp = Blueprint('people', __name__)

@people_bp.route('/people')
@limiter.limit("100 per minute")
def people():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

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



@people_bp.route('/add_person', methods=['POST'])
@limiter.limit("2 per second")
def add_person():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    name = request.form.get('name', '').strip()
    rank = request.form.get('rank', '').strip()

    valid_ranks = {
        'Cadet',
        'Corporal',
        'Sergeant',
        'Flight Sergeant',
        'Cadet Warrant Officer'
    }

    if not name or not re.fullmatch(r"[A-Za-z\- ]+", name):
        flash("Name must contain only letters, spaces, or hyphens.", "danger")
        return redirect(url_for('people.people'))

    if rank not in valid_ranks:
        flash("Invalid rank selected.", "danger")
        return redirect(url_for('people.people'))

    supabase = get_supabase_client()

    # Convert name to uppercase as you store it that way
    name_upper = name.upper()

    try:
        # Check for existing person with same name
        existing = supabase.table('people').select('name').eq('name', name_upper).execute()
        if existing.data and len(existing.data) > 0:
            flash("A person with this name already exists.", "danger")
            return redirect(url_for('people.people'))

        # Insert new person
        response = supabase.table('people').insert({
            'name': name_upper,
            'rank': rank
        }).execute()

        if not response.data:
            flash("Failed to add person. Please try again.", "danger")
        else:
            flash("Person added successfully.", "success")

    except Exception as e:
        flash(f"An error occurred: {str(e)}", "danger")

    return redirect(url_for('people.people'))


@people_bp.route('/delete_person', methods=['POST'])
@limiter.limit("2 per second")
def delete_person():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    name = request.form.get('name')
    if not name:
        flash("Invalid request.", "danger")
        return redirect(url_for('people.people'))

    supabase = get_supabase_client()

    try:
        supabase.table('people').delete().eq('name', name).execute()
        flash(f"{name} was deleted.", "success")
    except Exception as e:
        flash(f"Error deleting {name}: {str(e)}", "danger")

    return redirect(url_for('people.people'))


@people_bp.route('/edit_person', methods=['POST'])
@limiter.limit("2 per second")
def edit_person():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    
    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    original_name = request.form.get('original_name', '').strip()
    new_name = request.form.get('name', '').strip()
    new_rank = request.form.get('rank', '').strip()

    valid_ranks = {
        'Cadet',
        'Corporal',
        'Sergeant',
        'Flight Sergeant',
        'Cadet Warrant Officer'
    }

    # Validate names
    if not new_name or not re.fullmatch(r"[A-Za-z\- ]+", new_name):
        flash("Name must contain only letters, spaces, or hyphens.", "danger")
        return redirect(url_for('people.people'))

    # Validate rank
    if new_rank not in valid_ranks:
        flash("Invalid rank selected.", "danger")
        return redirect(url_for('people.people'))

    supabase = get_supabase_client()

    original_name_upper = original_name.upper()
    new_name_upper = new_name.upper()

    try:
        # Check if the original person exists
        existing_person = supabase.table('people').select('name').eq('name', original_name_upper).execute()
        if not existing_person.data or len(existing_person.data) == 0:
            flash("Original person not found.", "danger")
            return redirect(url_for('people.people'))

        # If name changed, check if new name already exists (to avoid duplicates)
        if new_name_upper != original_name_upper:
            duplicate_check = supabase.table('people').select('name').eq('name', new_name_upper).execute()
            if duplicate_check.data and len(duplicate_check.data) > 0:
                flash("A person with the new name already exists.", "danger")
                return redirect(url_for('people.people'))

        # Update the person record
        response = supabase.table('people')\
            .update({'name': new_name_upper, 'rank': new_rank})\
            .eq('name', original_name_upper)\
            .execute()

        if not response.data:
            flash("Failed to update person. Please try again.", "danger")
        else:
            flash("Person updated successfully.", "success")

    except Exception as e:
        flash(f"An error occurred: {str(e)}", "danger")

    return redirect(url_for('people.people'))
