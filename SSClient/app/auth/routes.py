from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from app.auth import bp
from app.models import User
from app import db

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('stock.dashboard'))  # Redirect to default dashboard

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            if user.requires_password_change:
                return redirect(url_for('auth.change_password'))
            return redirect(url_for('stock.dashboard'))  # Assuming 'stock.dashboard' exists
        else:
            flash('Invalid username or password', 'danger')
            return redirect(url_for('auth.login'))

    return render_template('auth/login.html')

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You've been logged out.", 'info')
    return redirect(url_for('auth.login'))

@bp.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        new_password = request.form['new_password']
        hashed = generate_password_hash(new_password)

        current_user.password_hash = hashed
        current_user.requires_password_change = False
        db.session.commit()

        flash('Password updated successfully!', 'success')
        return redirect(url_for('stock.dashboard'))

    return render_template('auth/change_password.html')