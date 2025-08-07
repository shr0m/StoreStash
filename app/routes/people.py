from app.extensions import limiter
from app.db import get_supabase_client
from app.utils.otp_utils import redirect_if_password_change_required
from flask import redirect, url_for, flash, render_template, session, request, Blueprint, jsonify
import re

people_bp = Blueprint('people', __name__)

def normalize_sizing(sizing_str):
    """Normalize sizing input: return None if blank or equivalent to 'none'."""
    if not sizing_str:
        return None
    sizing_cleaned = sizing_str.strip().lower()
    return None if sizing_cleaned in ['', 'none', 'n/a'] else sizing_str.strip()

@people_bp.route('/people')
@limiter.limit("100 per minute")
def people():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    supabase = get_supabase_client()

    # Load stock
    response = supabase.table('stock').select("*").execute()
    stock_data = response.data if response.data else []

    grouped_stock = {}
    for item in stock_data:
        key = (item.get('type'), item.get('sizing'))
        grouped_stock[key] = grouped_stock.get(key, 0) + 1

    stock_items = [
        {'type': k[0], 'sizing': k[1], 'count': v}
        for k, v in grouped_stock.items()
        if v > 0
    ]

    # Load people
    people_response = supabase.table('people').select("*").execute()
    people = people_response.data if people_response.data else []

    # Load kit issues
    kit_issues_resp = supabase.table('kit_issue')\
        .select('person_id, issued_stock(type, sizing, note)')\
        .execute()
    kit_issues = kit_issues_resp.data if kit_issues_resp.data else []

    issued_by_person = {}
    for record in kit_issues:
        pid = record['person_id']
        stock = record.get('issued_stock', {})
        key = (stock.get('type'), stock.get('sizing'), stock.get('note'))

        if pid not in issued_by_person:
            issued_by_person[pid] = {}

        issued_by_person[pid][key] = issued_by_person[pid].get(key, 0) + 1

    # Load label assignments
    label_issues_resp = supabase.table('label_issue').select('person_id, label_id').execute()
    label_issues = label_issues_resp.data if label_issues_resp.data else []

    # Group label IDs by person
    labels_by_person = {}
    for record in label_issues:
        pid = record['person_id']
        lid = record['label_id']
        if pid not in labels_by_person:
            labels_by_person[pid] = []
        labels_by_person[pid].append(lid)

    # Load all labels
    labels_resp = supabase.table('labels').select('*').order('name').execute()
    all_labels = labels_resp.data if labels_resp.data else []

    # Create a lookup dict for label objects
    label_lookup = {label['id']: label for label in all_labels}

    # Attach data to each person
    for person in people:
        pid = person.get('id')

        # Issued stock
        grouped = issued_by_person.get(pid, {})
        person['issued_items'] = [
            {'type': t, 'sizing': s or 'N/A', 'note': n or '', 'quantity': q}
            for (t, s, n), q in grouped.items()
        ]

        # Assigned labels (full objects)
        label_ids = labels_by_person.get(pid, [])
        person['assigned_labels'] = [
            label_lookup[lid] for lid in label_ids if lid in label_lookup
        ]

    # Sort people by rank, then surname
    rank_order = {
        'cadet': 4,
        'corporal': 3,
        'sergeant': 2,
        'flight sergeant': 1,
        'cadet warrant officer': 0
    }

    def get_surname(full_name):
        return full_name.strip().split()[-1].lower() if full_name else ''

    def get_rank_priority(rank):
        return rank_order.get(rank.strip().lower(), -1) if rank else -1

    people.sort(key=lambda p: (
        get_rank_priority(p.get('rank')),
        get_surname(p.get('name'))
    ))

    # Render template
    return render_template(
        "people.html",
        stock_items=stock_items,
        people=people,
        all_labels=all_labels,
        labels=all_labels
    )


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

    if not name or not re.fullmatch(r"[A-Za-z\- ()]+", name):
        flash("Name must contain only letters, spaces, hyphens, or brackets.", "danger")
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
        person_data = supabase.table('people').select('id').eq('name', name).execute()
        if not person_data.data:
            flash(f"No person found with name '{name}'.", "danger")
            return redirect(url_for('people.people'))

        person_id = person_data.data[0]['id']

        supabase.table('label_issue').delete().eq('person_id', person_id).execute()
        supabase.table('kit_issue').delete().eq('person_id', person_id).execute()
        supabase.table('people').delete().eq('id', person_id).execute()

        flash(f"{name} and related issues were deleted.", "success")

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


@people_bp.route('/assign_item', methods=['POST'])
@limiter.limit("2 per second")
def assign_item():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    name = request.form.get('person_name', '').strip().upper()
    item_type = request.form.get('item_type', '').strip()
    sizing = normalize_sizing(request.form.get('sizing', ''))
    note = request.form.get('note', '').strip()
    quantity_str = request.form.get('quantity', '1').strip()

    try:
        quantity = int(quantity_str)
        if quantity < 1:
            quantity = 1
    except ValueError:
        quantity = 1

    if not name or not item_type:
        flash("Missing required fields for assignment.", "danger")
        return redirect(url_for('people.people'))

    supabase = get_supabase_client()

    try:
        # Get person ID
        person_resp = supabase.table('people').select('id').eq('name', name).limit(1).execute()
        if not person_resp.data:
            flash(f"Person '{name}' not found.", "danger")
            return redirect(url_for('people.people'))

        person_id = person_resp.data[0]['id']

        # Fetch enough matching stock items WITH category_id
        stock_query = supabase.table('stock').select('id, category_id').eq('type', item_type)
        if sizing is None:
            stock_query = stock_query.is_('sizing', None)
        else:
            stock_query = stock_query.eq('sizing', sizing)

        stock_resp = stock_query.limit(quantity).execute()
        stock_items = stock_resp.data or []

        if not stock_items:
            flash(f"No stock available for {item_type}{f' ({sizing})' if sizing else ''}.", "danger")
            return redirect(url_for('people.people'))

        assigned_count = len(stock_items)
        stock_ids = [item['id'] for item in stock_items]

        # Prepare issued_stock insert with category_id copied
        issued_records = [
            {
                'type': item_type,
                'sizing': sizing,
                'note': note if note else None,
                'category_id': item['category_id']
            }
            for item in stock_items
        ]
        issued_resp = supabase.table('issued_stock').insert(issued_records).execute()
        issued_data = issued_resp.data
        if not issued_data:
            flash("Failed to insert issued_stock records.", "danger")
            return redirect(url_for('people.people'))

        # Prepare kit_issue insert
        kit_issue_records = [
            {'person_id': person_id, 'issued_stock_id': issued['id']}
            for issued in issued_data
        ]
        supabase.table('kit_issue').insert(kit_issue_records).execute()

        # Delete used stock items
        supabase.table('stock').delete().in_('id', stock_ids).execute()

        flash(f"Assigned {assigned_count} x {item_type}{f' ({sizing})' if sizing else ''} to {name}.", "success")

    except Exception as e:
        flash(f"Error assigning item: {str(e)}", "danger")

    return redirect(url_for('people.people'))

def get_people_with_issued_items():
    supabase = get_supabase_client()

    # Step 1: Get all people
    people_resp = supabase.table('people').select('*').execute()
    people = people_resp.data

    # Step 2: For all people, get their issued items in one query (for efficiency)
    # Join kit_issue with issued_stock to get all issued items with type & sizing
    issued_resp = supabase.table('kit_issue')\
        .select('person_id, issued_stock(type, sizing)')\
        .execute()

    issued_items = issued_resp.data or []

    # Step 3: Group issued items by person
    issued_by_person = {}
    for record in issued_items:
        pid = record['person_id']
        stock = record.get('issued_stock', {})
        key = (stock.get('type'), stock.get('sizing'))

        if pid not in issued_by_person:
            issued_by_person[pid] = {}

        issued_by_person[pid][key] = issued_by_person[pid].get(key, 0) + 1

    # Step 4: Attach grouped issued_items to each person
    for person in people:
        pid = person['id']
        grouped = issued_by_person.get(pid, {})
        person['issued_items'] = [
            {'type': t, 'sizing': s or 'N/A', 'quantity': q}
            for (t, s), q in grouped.items()
        ]

    return people

@people_bp.route('/return_item', methods=['POST'])
@limiter.limit('30 per minute')
def return_item():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    supabase = get_supabase_client()

    person_name = request.form.get('person_name')
    item_type = request.form.get('item_type')
    sizing_input = request.form.get('sizing')
    sizing = normalize_sizing(sizing_input)

    try:
        quantity = int(request.form.get('quantity', 0))
    except ValueError:
        flash("Invalid quantity.", "danger")
        return redirect(request.referrer)

    if session.get('privilege') not in ['admin', 'edit']:
        flash("Unauthorized action.", "danger")
        return redirect(request.referrer)

    if quantity <= 0:
        flash("Invalid quantity.", "danger")
        return redirect(request.referrer)

    try:
        # Step 1: Get person ID
        person_resp = supabase.table('people').select('id').eq('name', person_name).limit(1).execute()
        if not person_resp.data:
            flash("Person not found.", "danger")
            return redirect(request.referrer)
        person_id = person_resp.data[0]['id']

        # Step 2: Get issued_stock records joined with kit_issue for this person, including category_id
        kit_resp = (
            supabase.table('kit_issue')
            .select('id, issued_stock_id, issued_stock(type, sizing, category_id)')
            .eq('person_id', person_id)
            .execute()
        )
        kit_issues = kit_resp.data or []

        # Filter matching items with normalized sizing
        matching = [
            issue for issue in kit_issues
            if issue['issued_stock']['type'] == item_type and normalize_sizing(issue['issued_stock']['sizing']) == sizing
        ]

        if len(matching) < quantity:
            flash("Not enough matching items to return.", "warning")
            return redirect(request.referrer)

        # Extract relevant IDs and category_ids
        return_kit_ids = [issue['id'] for issue in matching[:quantity]]
        return_stock_ids = [issue['issued_stock_id'] for issue in matching[:quantity]]

        # Step 3: Batch delete kit_issue and issued_stock records
        supabase.table('kit_issue').delete().in_('id', return_kit_ids).execute()
        supabase.table('issued_stock').delete().in_('id', return_stock_ids).execute()

        # Step 4: Insert returned items back to stock with category_id copied
        returned_items = [
            {
                'type': item_type,
                'sizing': sizing,
                'category_id': issue['issued_stock']['category_id']
            }
            for issue in matching[:quantity]
        ]
        supabase.table('stock').insert(returned_items).execute()

        flash(f"Returned {quantity} {item_type}(s) to stock.", "success")

    except Exception as e:
        flash(f"Error processing return: {str(e)}", "danger")

    return redirect('/people')

@people_bp.route('/mark_lost', methods=['POST'])
@limiter.limit('30 per minute')
def mark_lost():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    supabase = get_supabase_client()

    item_type = request.form.get('item_type')
    sizing_input = request.form.get('sizing')
    sizing = normalize_sizing(sizing_input)

    try:
        quantity = int(request.form.get('quantity', 0))
    except ValueError:
        flash("Invalid quantity.", "danger")
        return redirect(request.referrer)

    if session.get('privilege') not in ['admin', 'edit']:
        flash("Unauthorized action.", "danger")
        return redirect(request.referrer)

    if quantity <= 0:
        flash("Invalid quantity.", "danger")
        return redirect(request.referrer)

    try:
        # Build the query depending on whether sizing is None or not
        issued_query = supabase.table('issued_stock').select('id').eq('type', item_type)
        if sizing is None:
            issued_query = issued_query.is_('sizing', None)
        else:
            issued_query = issued_query.eq('sizing', sizing)
        
        issued_resp = issued_query.limit(quantity).execute()
        issued_items = issued_resp.data or []

        if len(issued_items) < quantity:
            flash("Not enough issued items to mark as lost.", "warning")
            return redirect(request.referrer)

        issued_ids = [item['id'] for item in issued_items]

        # Delete from kit_issue where issued_stock_id in issued_ids
        supabase.table('kit_issue').delete().in_('issued_stock_id', issued_ids).execute()

        # Delete from issued_stock
        supabase.table('issued_stock').delete().in_('id', issued_ids).execute()

        flash(f"Marked {quantity} {item_type}(s) as lost.", "success")
    except Exception as e:
        flash(f"Error processing loss: {str(e)}", "danger")

    return redirect('/people')

@people_bp.route('/create_label', methods=['POST'])
@limiter.limit("10 per minute")
def add_label():
    if session.get('privilege') not in ['admin', 'edit']:
        return "Unauthorized", 403

    label_name = request.form.get('label_name', '').strip()
    label_colour = request.form.get('label_color', '').strip()

    # Allowed Bootstrap-like colours
    allowed_colours = {'primary', 'secondary', 'success', 'danger', 'warning', 'info', 'dark'}

    # Validate colour
    if label_colour not in allowed_colours:
        flash("Invalid label colour selected.", "danger")
        return redirect(url_for('people.people'))

    # Validate name format
    if not re.match(r'^[A-Za-z0-9\-\(\)\s]+$', label_name):
        flash("Label names cannot contain forbidden characters.", "danger")
        return redirect(url_for('people.people'))
    
    if len(label_name) > 25:
        flash("Label name cannot exceed 25 characters")
        return redirect(url_for('people.people'))

    supabase = get_supabase_client()

    try:
        existing = supabase.table('labels').select("id", count='exact')\
            .ilike('name', label_name).execute()

        if existing.count and existing.count > 0:
            flash("A label with that name already exists.", "warning")
            return redirect(url_for('people.people'))

        insert_result = supabase.table('labels').insert({
            'name': label_name,
            'colour': label_colour
        }).execute()

        if insert_result.data:
            flash("Label created successfully.", "success")
        else:
            flash("Failed to create label.", "danger")

    except Exception as e:
        print(f"Error adding label: {e}")
        flash("An error occurred while creating the label.", "danger")

    return redirect(url_for('people.people'))

@people_bp.route('/delete_label/<label_id>', methods=['POST'])
@limiter.limit("10 per minute")
def delete_label(label_id):
    if session.get('privilege') not in ['admin', 'edit']:
        return "Unauthorized", 403

    supabase = get_supabase_client()

    try:
        # Check if label exists
        existing = supabase.table('labels').select('id').eq('id', label_id).execute()

        if existing.data and len(existing.data) > 0:
            # Delete related entries in label_issue first
            supabase.table('label_issue').delete().eq('label_id', label_id).execute()

            # Now delete from labels
            supabase.table('labels').delete().eq('id', label_id).execute()

            flash("Label and related assignments deleted successfully.", "success")
        else:
            flash("Label not found or already deleted.", "warning")

    except Exception as e:
        print(f"Error deleting label: {e}")
        flash("An error occurred while deleting the label.", "danger")

    return redirect(url_for('people.people'))


@people_bp.route('/assign_label', methods=['POST'])
@limiter.limit("20 per minute")
def assign_label():
    if session.get('privilege') not in ['admin', 'edit']:
        return "Unauthorized", 403

    person_id = request.form.get('person_id')
    label_id = request.form.get('label_id')

    if not person_id or not label_id:
        return "Missing data", 400

    supabase = get_supabase_client()

    try:
        # Check if already exists
        existing = supabase.table('label_issue').select('id', count='exact')\
            .eq('person_id', person_id).eq('label_id', label_id).execute()

        if existing.count > 0:
            return "Already assigned", 200

        supabase.table('label_issue').insert({
            'person_id': person_id,
            'label_id': label_id
        }).execute()

        return "Label assigned", 200

    except Exception as e:
        print(f"Error assigning label: {e}")
        return "Error assigning label", 500


@people_bp.route('/unassign_label', methods=['POST'])
@limiter.limit("20 per minute")
def unassign_label():
    if session.get('privilege') not in ['admin', 'edit']:
        return "Unauthorized", 403

    person_id = request.form.get('person_id')
    label_id = request.form.get('label_id')

    if not person_id or not label_id:
        return "Missing data", 400

    supabase = get_supabase_client()

    try:
        supabase.table('label_issue').delete()\
            .eq('person_id', person_id).eq('label_id', label_id).execute()

        return "Label unassigned", 200

    except Exception as e:
        print(f"Error unassigning label: {e}")
        return "Error unassigning label", 500


@people_bp.route('/toggle_label', methods=['POST'])
@limiter.limit("1 per second")
def toggle_label():
    if session.get('privilege') not in ['admin', 'edit']:
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json()
    person_id = data.get('person_id')
    label_id = data.get('label_id')

    if not person_id or not label_id:
        return jsonify({'error': 'Missing person_id or label_id'}), 400

    supabase = get_supabase_client()

    try:
        # Check if label already assigned
        existing = supabase.table('label_issue')\
            .select('id')\
            .eq('person_id', person_id)\
            .eq('label_id', label_id)\
            .execute()

        if existing.data:
            # Label exists — remove it
            supabase.table('label_issue')\
                .delete()\
                .eq('person_id', person_id)\
                .eq('label_id', label_id)\
                .execute()
            
            status = 'removed'
        else:
            # Label not assigned — insert it
            supabase.table('label_issue').insert({
                'person_id': person_id,
                'label_id': label_id
            }).execute()

            status = 'added'

        # Fetch updated list of assigned labels with name + colour
        updated_labels_resp = supabase.table('label_issue')\
            .select('label_id, labels(name, colour)')\
            .eq('person_id', person_id)\
            .execute()

        assigned_labels = [
            {
                'id': row['label_id'],
                'name': row['labels']['name'],
                'colour': row['labels']['colour']
            }
            for row in updated_labels_resp.data
        ]

        return jsonify({
            'status': status,
            'assigned_labels': assigned_labels
        })

    except Exception as e:
        print(f"Error toggling label: {e}")
        return jsonify({'error': 'Internal server error'}), 500