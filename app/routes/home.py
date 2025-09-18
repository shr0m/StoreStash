from flask import Blueprint, render_template, redirect, url_for, session
from app.db import get_supabase_client
from app.utils.otp_utils import redirect_if_password_change_required
from app import limiter

home_bp = Blueprint('home', __name__)


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

    if len(containers) == 1:
        container_id = containers[0]['id']
        return redirect(url_for('dashboard.dashboard', container_id=container_id))

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

    return render_template('home.html', containers=containers)

