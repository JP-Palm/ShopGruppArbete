
import click
from flask import Flask, request, current_app
from flask.cli import with_appcontext
from flask_login import current_user
from flask_mail import Mail
from flask_migrate import Migrate, upgrade
from flask_security import SQLAlchemyUserDatastore, Security
from flask_security import auth_required, logout_user, roles_accepted
from os import environ

from areas.auth.auth_pages import auth_blueprint
from areas.admin.admin_pages import admin_blueprint
from areas.products.productPages import productBluePrint
from areas.site.sitePages import siteBluePrint
from dotenv import load_dotenv
from extensions import mail
from models import db, User, Role, seedData

load_dotenv()

app = Flask(__name__)
# app.config.from_object('config.ConfigDebug')
app.config['SQLALCHEMY_DATABASE_URI'] = environ.get('SQLALCHEMY_DATABASE_URI')
app.config['SECRET_KEY'] = environ.get('SECRET_KEY')
app.config['SECURITY_REGISTERABLE'] = environ.get('SECURITY_REGISTERABLE')
app.config['SECURITY_PASSWORD_SALT'] = environ.get('SECURITY_PASSWORD_SALT')

app.config['MAIL_SERVER'] = environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = environ.get('MAIL_PORT')
app.config['MAIL_DEFAULT_SENDER'] = environ.get('MAIL_DEFAULT_SENDER')
# app.config['MAIL_USE_SSL'] = environ.get('MAIL_USE_SSL')      Only used in production
# app.config['MAIL_USE_TLS'] = environ.get('MAIL_USE_TLS')      |
# app.config['MAIL_USERNAME'] = environ.get('MAIL_USERNAME')    |
# app.config['MAIL_PASSWORD'] = environ.get('MAIL_PASSWORD')    V

app.config['TEMP_ADMIN_ACCESS'] = True  # Temporary flag for admin access without login

db.app = app
db.init_app(app)
migrate = Migrate(app,db)
mail.init_app(app)
# user_manager.app = app
# user_manager.init_app(app,db,User)

# Register blueprints
app.register_blueprint(siteBluePrint)
app.register_blueprint(productBluePrint)
app.register_blueprint(admin_blueprint)
app.register_blueprint(auth_blueprint, url_prefix='/auth')

# Seeding Command
@click.command('seed-db')
@with_appcontext
def seed_db_command():
    """Seeds the database."""
    seedData(app)
    click.echo('Database seeded.')

app.cli.add_command(seed_db_command)

# Temporary check for admin access
# This is a placeholder, should be replaced with actual authentication logic
@app.before_request
def before_request():
    if 'admin' in request.path:
        temp_admin_access = request.args.get('temp_admin', '0') == '1'
        if not (temp_admin_access or current_app.config.get('TEMP_ADMIN_ACCESS', False)):
            return "Access Denied", 403


if __name__  == "__main__":
    with app.app_context():
        upgrade()
        seedData(app)
    app.run(debug=True)
