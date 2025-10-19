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

    # Load stock and items
    response = (
        supabase.table('stock')
        .select("id, quantity, container_id, item_id, items(type, sizing)")
        .execute()
    )
    stock_data = response.data if response.data else []

    stock_items = []
    for item in stock_data:
        if item.get('quantity', 0) > 0:
            item_info = item.get('items') or {}
            stock_items.append({
                'type': item_info.get('type'),
                'sizing': item_info.get('sizing'),
                'container_id': item.get('container_id'),
                'count': item.get('quantity', 0)
            })

    # Load people
    people_response = supabase.table('people').select("*").execute()
    people = people_response.data if people_response.data else []

    # Load issued_stock joined with items
    issued_resp = (
        supabase.table('issued_stock')
        .select("person_id, quantity, note, items(type, sizing)")
        .execute()
    )
    issued_records = issued_resp.data if issued_resp.data else []

    issued_by_person = {}
    for record in issued_records:
        pid = record['person_id']
        item_info = record.get('items') or {}
        key = (
            item_info.get('type'),
            item_info.get('sizing'),
            record.get('note')
        )
        qty = record.get('quantity', 0)

        if pid not in issued_by_person:
            issued_by_person[pid] = {}

        issued_by_person[pid][key] = issued_by_person[pid].get(key, 0) + qty

    # Load label issues
    label_issues_resp = supabase.table('label_issue').select('person_id, label_id').execute()
    label_issues = label_issues_resp.data if label_issues_resp.data else []

    labels_by_person = {}
    for record in label_issues:
        pid = record['person_id']
        lid = record['label_id']
        labels_by_person.setdefault(pid, []).append(lid)

    # Load labels
    labels_resp = supabase.table('labels').select('*').order('name').execute()
    all_labels = labels_resp.data if labels_resp.data else []
    label_lookup = {label['id']: label for label in all_labels}

    # Attach stock and labels to people
    for person in people:
        pid = person.get('id')

        # Issued stock
        grouped = issued_by_person.get(pid, {})
        person['issued_items'] = [
            {
                'type': t,
                'sizing': s or 'N/A',
                'note': n or '',
                'quantity': q
            }
            for (t, s, n), q in grouped.items() if q > 0
        ]

        # Assigned labels
        label_ids = labels_by_person.get(pid, [])
        person['assigned_labels'] = [
            label_lookup[lid] for lid in label_ids if lid in label_lookup
        ]

    # Sort people by rank then surname
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

    # Load containers
    containers_resp = supabase.table('containers').select('*').order('name').execute()
    containers = containers_resp.data if containers_resp.data else []

    return render_template(
        "people.html",
        stock_items=stock_items,
        people=people,
        all_labels=all_labels,
        labels=all_labels,
        containers=containers
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

    # Convert name to uppercase
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
        supabase.table('issued_stock').delete().eq('person_id', person_id).execute()
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

        # Check if name exists
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
        # Get person
        person_resp = supabase.table('people').select('id').eq('name', name).limit(1).execute()
        if not person_resp.data:
            flash(f"Person '{name}' not found.", "danger")
            return redirect(url_for('people.people'))
        person_id = person_resp.data[0]['id']

        # Find item record
        item_query = (
            supabase.table('items')
            .select('id, category_id')
            .eq('type', item_type)
        )
        item_query = item_query.is_('sizing', None) if sizing is None else item_query.eq('sizing', sizing)
        item_resp = item_query.limit(1).execute()
        if not item_resp.data:
            flash(f"Item '{item_type}' ({sizing or 'N/A'}) not found in items table.", "danger")
            return redirect(url_for('people.people'))

        item_id = item_resp.data[0]['id']
        category_id = item_resp.data[0]['category_id']

        # Check stock in current contianer
        container_id = session.get("container_id")
        if not container_id:
            flash("No container selected.", "danger")
            return redirect(url_for('people.people'))

        stock_resp = (
            supabase.table('stock')
            .select('id, quantity')
            .eq('item_id', item_id)
            .eq('container_id', container_id)
            .limit(1)
            .execute()
        )
        if not stock_resp.data:
            flash(f"No stock available for {item_type}{f' ({sizing})' if sizing else ''} in this container.", "danger")
            return redirect(url_for('people.people'))

        stock_item = stock_resp.data[0]
        available_qty = stock_item.get("quantity", 0)

        if available_qty < quantity:
            flash(f"Only {available_qty} available for {item_type}{f' ({sizing})' if sizing else ''}.", "warning")
            return redirect(url_for('people.people'))

        # Decrement stock
        supabase.table('stock').update({
            'quantity': available_qty - quantity
        }).eq('id', stock_item['id']).execute()

        # Check issued_stock for existing records
        issued_query = (
            supabase.table('issued_stock')
            .select('id, quantity')
            .eq('person_id', person_id)
            .eq('item_id', item_id)
        )
        if note:
            issued_query = issued_query.eq('note', note)
        else:
            issued_query = issued_query.is_('note', None)

        issued_resp = issued_query.execute()
        existing_issued = issued_resp.data or []

        if existing_issued:
            issued_id = existing_issued[0]['id']
            current_qty = existing_issued[0]['quantity'] or 0
            supabase.table('issued_stock').update({
                'quantity': current_qty + quantity
            }).eq('id', issued_id).execute()
        else:
            supabase.table('issued_stock').insert({
                'person_id': person_id,
                'item_id': item_id,
                'quantity': quantity,
                'note': note if note else None
            }).execute()

        flash(f"Assigned {quantity} × {item_type}{f' ({sizing})' if sizing else ''} to {name}.", "success")

    except Exception as e:
        flash(f"Error assigning item: {str(e)}", "danger")

    return redirect(url_for('people.people'))


@people_bp.route('/process_item', methods=['POST'])
@limiter.limit('30 per minute')
def process_item():
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
    action = request.form.get('action')  # "return" or "lost"

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
        # Resolve person
        person_resp = supabase.table('people').select('id').eq('name', person_name).limit(1).execute()
        if not person_resp.data:
            flash("Person not found.", "danger")
            return redirect(request.referrer)
        person_id = person_resp.data[0]['id']

        # Resolve item
        item_query = (
            supabase.table('items')
            .select('id, category_id')
            .eq('type', item_type)
        )
        item_query = item_query.is_('sizing', None) if sizing is None else item_query.eq('sizing', sizing)
        item_resp = item_query.limit(1).execute()
        if not item_resp.data:
            flash(f"Item '{item_type}' ({sizing or 'N/A'}) not found.", "danger")
            return redirect(request.referrer)

        item_id = item_resp.data[0]['id']

        # Find matching issued entry
        issued_resp = (
            supabase.table('issued_stock')
            .select('id, quantity')
            .eq('person_id', person_id)
            .eq('item_id', item_id)
            .limit(1)
            .execute()
        )
        if not issued_resp.data:
            flash("No matching issued items found.", "warning")
            return redirect(request.referrer)

        issued = issued_resp.data[0]
        issued_id = issued['id']
        current_quantity = issued.get('quantity', 0)

        if current_quantity < quantity:
            flash("Not enough issued items to process.", "warning")
            return redirect(request.referrer)

        # Action handling
        if action == "return":
            container_id = request.form.get('container_id')
            if not container_id:
                flash("You must select a container to return items.", "warning")
                return redirect(request.referrer)

            # Decrease issued quant
            new_quantity = current_quantity - quantity
            if new_quantity > 0:
                supabase.table('issued_stock').update({'quantity': new_quantity}).eq('id', issued_id).execute()
            else:
                supabase.table('issued_stock').delete().eq('id', issued_id).execute()

            # Add back to stock
            stock_resp = (
                supabase.table('stock')
                .select('id, quantity')
                .eq('item_id', item_id)
                .eq('container_id', container_id)
                .execute()
            )
            stock_records = stock_resp.data or []

            if stock_records:
                stock_id = stock_records[0]['id']
                stock_qty = stock_records[0]['quantity']
                supabase.table('stock').update({'quantity': stock_qty + quantity}).eq('id', stock_id).execute()
            else:
                supabase.table('stock').insert({
                    'item_id': item_id,
                    'container_id': container_id,
                    'quantity': quantity
                }).execute()

            flash(f"Returned {quantity} {item_type}(s) to stock.", "success")

        elif action == "lost":
            new_quantity = current_quantity - quantity
            if new_quantity > 0:
                supabase.table('issued_stock').update({'quantity': new_quantity}).eq('id', issued_id).execute()
            else:
                supabase.table('issued_stock').delete().eq('id', issued_id).execute()

            flash(f"Marked {quantity} {item_type}(s) as lost.", "success")

        else:
            flash("Invalid action.", "danger")

    except Exception as e:
        flash(f"Error processing request: {str(e)}", "danger")

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