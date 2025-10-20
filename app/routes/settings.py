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

    try:
        # Fetch Auth user to get metadata
        auth_resp = supabase.auth.admin.get_user_by_id(user_id)
        auth_user = getattr(auth_resp, "user", None) or (auth_resp.get("user") if isinstance(auth_resp, dict) else None)
        metadata = getattr(auth_user, "user_metadata", {}) or {}
    except Exception as e:
        print(f"Error fetching Auth user metadata: {e}")
        metadata = {}

    if request.method == 'POST':
        new_theme = 'dark' if request.form.get('theme') == 'dark' else 'light'
        metadata['theme'] = new_theme

        try:
            supabase.auth.admin.update_user_by_id(user_id, {"user_metadata": metadata})
            flash("Theme updated successfully.", "success")
        except Exception as e:
            flash(f"Failed to update theme: {e}", "danger")

        return redirect(url_for('settings.settings'))

    # Patch notes
    patch_notes = fetch_github_releases("shr0m/StoreStash", limit=5)

    return render_template(
        'settings.html',
        patch_notes=patch_notes
    )


@settings_bp.route('/hard_reset')
@limiter.limit("1 per minute")
def hard_reset():
    return redirect("https://www.youtube.com/watch?v=dQw4w9WgXcQ")