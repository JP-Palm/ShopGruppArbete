from flask import Blueprint, render_template
from models import User, db,Subscriber

siteBluePrint = Blueprint('site', __name__)

@siteBluePrint.route('/contact')
def contact() -> str:
     return render_template('site/contact.html')

@siteBluePrint.route('/terms')
def terms() -> str:
     return render_template('site/terms.html')

@siteBluePrint.route('/about')
def about() -> str:
     return render_template('site/about.html')

# @productBluePrint.route('/subscribe', methods=['POST'])
# def subscribe():
#     email = request.form.get('email')
#     #print(email)
#     existing_subscriber = Subscriber.query.filter_by(email=email).first()
#     if existing_subscriber:
#         flash('Email already used. Please choose another one.', 'error')
#     else:
#         new_subscriber = Subscriber(email=email, active=True)
#         db.session.add(new_subscriber)
#         db.session.commit()
#         flash('Subscription successful', 'success')

#         return 'Welcome to the Group3 family! 🎉 Get ready for a delightful dose of inspiration, insights, and exclusive content delivered straight to your inbox.'