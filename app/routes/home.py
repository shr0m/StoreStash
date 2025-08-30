from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from app.db import get_supabase_client
from app.utils.otp_utils import redirect_if_password_change_required
from app import limiter

home_bp = Blueprint('home', __name__)

def has_edit_privileges():
    return session.get('privilege') in ['admin', 'edit']

@home_bp.route('/')
@limiter.limit("100 per minute")
def root():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp
    return redirect(url_for('home.home'))

@home_bp.route('/home')
@limiter.limit("100 per minute")
def home():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    supabase = get_supabase_client()

    # Fetch all containers
    containers_response = supabase.table('containers').select('id, name').execute()
    containers = containers_response.data or []

    # Count stock items in each container
    stock_response = supabase.table('stock').select('id, container_id').execute()
    stock_items = stock_response.data or []

    stock_count_by_container = {}
    for item in stock_items:
        cid = item.get('container_id')
        if cid:
            stock_count_by_container[cid] = stock_count_by_container.get(cid, 0) + 1

    # Attach stock counts to container objects
    for c in containers:
        c['total_stock'] = stock_count_by_container.get(c['id'], 0)

    return render_template('home.html', containers=containers, has_edit=has_edit_privileges())


@home_bp.route('/add_container', methods=['POST'])
@limiter.limit("50 per minute")
def add_container():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    if not has_edit_privileges():
        flash("You do not have permission to add containers.", "danger")
        return redirect(url_for('home.home'))

    name = request.form.get('container_name')
    if not name:
        flash("Container name cannot be empty.", "danger")
        return redirect(url_for('home.home'))

    supabase = get_supabase_client()
    supabase.table('containers').insert({'name': name}).execute()

    flash(f"Container '{name}' added successfully!", "success")
    return redirect(url_for('home.home'))
