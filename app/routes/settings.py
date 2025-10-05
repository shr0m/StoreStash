from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from app.db import get_supabase_client
from app import limiter
from app.utils.otp_utils import redirect_if_password_change_required
from app.utils.email_utils import fetch_github_releases

settings_bp = Blueprint('settings', __name__)

@settings_bp.route('/settings', methods=['GET', 'POST'])
@limiter.limit("100 per minute")
def settings():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    
    redirect_resp = redirect_if_password_change_required()
    if redirect_resp:
        return redirect_resp

    user_id = session['user_id']
    supabase = get_supabase_client()

    if request.method == 'POST':
        new_theme = 'dark' if request.form.get('theme') == 'dark' else 'light'
        supabase.table('users').update({'theme': new_theme}).eq('id', user_id).execute()
        flash("Theme updated successfully.", "success")
        return redirect(url_for('settings.settings'))

    response = supabase.table('users').select('theme').eq('id', user_id).single().execute()
    current_theme = response.data.get('theme') if response.data else 'light'

    # Patch notes
    patch_notes = fetch_github_releases("shr0m/StoreStash", limit=5)

    return render_template(
        'settings.html',
        current_theme=current_theme,
        patch_notes=patch_notes
    )

@settings_bp.route('/hard_reset')
@limiter.limit("1 per minute")
def hard_reset():
    return redirect("https://www.youtube.com/watch?v=dQw4w9WgXcQ")