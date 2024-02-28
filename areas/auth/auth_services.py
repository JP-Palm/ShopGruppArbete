import uuid
from models import User, db
from flask_security.utils import hash_password, verify_password 


def register_user(first_name, last_name, email, password):
    existing_user = User.query.filter_by(email=email).first()
    if not existing_user:
        hashed_password = hash_password(password)  
        new_user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=hashed_password,
            active=True,
            fs_uniquifier=str(uuid.uuid4())  
        )
        db.session.add(new_user)
        db.session.commit()
        return True
    return False


def validate_login(email, password):
    user = User.query.filter_by(email=email).first()
    
    if user and verify_password(password, user.password):  
        # Check if the user has an admin role
        is_admin = 'Admin' in [role.name for role in user.roles]
        return True, 'Login successful', is_admin
    else:
        return False, 'Invalid username or password', False
