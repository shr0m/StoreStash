from flask import Blueprint, render_template, redirect, url_for, session, flash
from app.db import get_supabase_client
from app.utils.otp_utils import redirect_if_password_change_required, get_client_id
from app import limiter
import os

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

    # Check client_id valid
    client_id = get_client_id()
    if not client_id:
        flash("Invalid client_id", "danger")
        return redirect(url_for('auth.login'))

    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    supabase = get_supabase_client()

    # Fetch all containers for this client
    containers_response = supabase.table('containers') \
        .select('id, name') \
        .eq('client_id', client_id) \
        .execute()
    containers = containers_response.data or []

    if len(containers) == 1:
        container_id = containers[0]['id']
        return redirect(url_for('dashboard.dashboard', container_id=container_id))

    # Fetch stock in batches for this client
    stock_items = []
    batch_size = 1000
    start = 0

    while True:
        resp = supabase.table('stock') \
            .select('id, container_id, quantity') \
            .eq('client_id', client_id) \
            .range(start, start + batch_size - 1) \
            .execute()

        data = resp.data or []
        stock_items.extend(data)

        if len(data) < batch_size:
            break
        start += batch_size

    # Sum quantity per container
    stock_count_by_container = {}
    for item in stock_items:
        cid = item.get('container_id')
        qty = item.get('quantity', 0)
        if cid:
            stock_count_by_container[cid] = stock_count_by_container.get(cid, 0) + qty

    for c in containers:
        c['total_stock'] = stock_count_by_container.get(c['id'], 0)

    return render_template('home.html', containers=containers)