import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from models import User, db

def register_user(first_name, last_name, email, password):
    existing_user = User.query.filter_by(email=email).first()
    if not existing_user:
        hashed_password = generate_password_hash(password)
        new_user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=hashed_password,
            active=True,
            fs_uniquifier=str(uuid.uuid4())  # Generate a unique identifier
        )
        db.session.add(new_user)
        db.session.commit()
        return True
    return False


def validate_login(email, password):
    user = User.query.filter_by(email=email).first()
    
    if user and check_password_hash(user.password, password):
        return True, 'Login successful'
    else:
        return False, 'Invalid username or password'