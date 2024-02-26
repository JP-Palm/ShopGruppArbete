from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from .auth_services import register_user, validate_login

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
        
        # Assuming validate_login returns a boolean indicating success, and a message
        success, message = validate_login(email, password)
        
        if success:
            session['user_email'] = email  # Or set another appropriate session value
            flash('You were successfully logged in', 'success')
            return redirect(url_for('index'))  # Redirect to a different page upon successful login
        else:
            flash(message, 'danger')  # Show error message from validation
        
    return render_template('auth/login.html')