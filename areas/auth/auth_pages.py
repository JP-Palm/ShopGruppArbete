from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from flask_login import login_user, logout_user
from functools import wraps
from areas.auth.auth_services import register_user, validate_login
from models import User


auth_blueprint = Blueprint('auth', __name__, template_folder='templates')


@auth_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('auth.register'))

        if register_user(first_name, last_name, email, password):
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash('Email already registered.', 'danger')
            return redirect(url_for('auth.register'))

    return render_template('auth/register.html')


@auth_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        success, message, is_admin = validate_login(email, password)
        
        if success:
            user = User.query.filter_by(email=email).first()
            login_user(user)  
            flash('You were successfully logged in', 'success')
            return redirect(url_for('product.index'))
        else:
            flash('Login failed. Please try again.', 'danger')  
            return redirect(url_for('auth.login'))
        
    return render_template('auth/login.html')


@auth_blueprint.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('auth.login'))


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('is_admin') is not True:
            flash('You need to be an admin to access this page.')
            return redirect(url_for('product.index'))  
        return f(*args, **kwargs)
    return decorated_function